"""Unified-diff parsing with post-image line numbers (REV-001, REV-007).

Everything the review capability claims has to land on a line a reviewer can open. A
model asked to "review this diff" will happily cite ``src/foo.py:412`` for a file whose
diff stops at line 90, and a finding nobody can navigate to is worse than no finding:
it costs a reviewer the same attention and returns nothing.

So the diff is parsed once, here, into the two facts the rest of the package checks
every finding against:

* which files the change touches, and whether each is source, test or neither;
* for each file, the exact set of **post-image** line numbers the change produced, and
  the text of each of those lines.

A location outside that set is not a location this change is responsible for. The
reviewer (:mod:`aica.review.reviewer`) uses it to anchor, move or drop findings rather
than passing a plausible-looking number through to the report.

Nothing here calls a model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath

# @@ -old,count +new,count @@ optional heading
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_OLD_PATH = re.compile(r"^--- (?:a/)?(.*)$")
_NEW_PATH = re.compile(r"^\+\+\+ (?:b/)?(.*)$")
_DEV_NULL = "/dev/null"

# Test files, by the conventions the ecosystems in BRD 9.1 actually use.
_TEST_PATTERNS = (
    re.compile(r"(^|/)tests?/"),
    re.compile(r"(^|/)test_[^/]+$"),
    re.compile(r"[._-]test\.[^./]+$"),
    re.compile(r"[._-]spec\.[^./]+$"),
    re.compile(r"(^|/)[^/]+Test\.(java|kt|cs)$"),
    re.compile(r"(^|/)__tests__/"),
)

_SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".java",
        ".kt",
        ".go",
        ".rs",
        ".rb",
        ".php",
        ".cs",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".hpp",
        ".swift",
        ".scala",
        ".sh",
        ".sql",
    }
)


class ChangeKind(StrEnum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"


@dataclass(frozen=True)
class DiffLine:
    """One line of the post-image that this change shows."""

    number: int  # line number in the file *after* the change
    text: str
    added: bool  # False for context lines carried along by the hunk


@dataclass
class Hunk:
    old_start: int
    new_start: int
    lines: list[DiffLine] = field(default_factory=list)

    @property
    def new_end(self) -> int:
        return self.lines[-1].number if self.lines else self.new_start


@dataclass
class ChangedFile:
    """One file in a unified diff."""

    path: str  # post-image path; for a deletion, the pre-image path
    old_path: str | None = None
    kind: ChangeKind = ChangeKind.MODIFIED
    hunks: list[Hunk] = field(default_factory=list)
    removed_count: int = 0

    # ------------------------------------------------------------------ shape
    @property
    def added_lines(self) -> list[DiffLine]:
        return [line for hunk in self.hunks for line in hunk.lines if line.added]

    @property
    def touched_lines(self) -> set[int]:
        """Post-image line numbers this change added (context excluded)."""
        return {line.number for line in self.added_lines}

    @property
    def visible_lines(self) -> set[int]:
        """Post-image line numbers visible in the diff, added or context.

        A finding may legitimately point at a context line - an added call whose bug is
        that the function two lines above it already closed the handle. Those lines are
        in front of the model, so they are fair targets; anything else is not.
        """
        return {line.number for hunk in self.hunks for line in hunk.lines}

    def line_text(self, number: int) -> str | None:
        for hunk in self.hunks:
            for line in hunk.lines:
                if line.number == number:
                    return line.text
        return None

    def nearest_line(self, number: int, within: int = 6) -> int | None:
        """The closest visible line to ``number``, when one is close enough to be the same place.

        Models are routinely off by a few lines when they count through a hunk. Within a
        short distance the intent is unambiguous and re-anchoring is honest; beyond it the
        number is a guess, and the caller drops the finding instead.
        """
        visible = self.visible_lines
        if not visible:
            return None
        if number in visible:
            return number
        closest = min(visible, key=lambda candidate: (abs(candidate - number), candidate))
        return closest if abs(closest - number) <= within else None

    # ------------------------------------------------------------- classification
    @property
    def is_test(self) -> bool:
        return is_test_path(self.path)

    @property
    def is_source(self) -> bool:
        return PurePosixPath(self.path).suffix in _SOURCE_SUFFIXES and not self.is_test

    @property
    def language(self) -> str:
        return PurePosixPath(self.path).suffix.lstrip(".") or "text"

    def render(self) -> str:
        """The file's hunks as the model sees them, with post-image line numbers.

        Numbers are put in front of every line on purpose: a model that has to read them
        off the prompt cannot cite one that is not there, so the anchoring check has far
        less to repair.
        """
        out = [f"--- {self.path} ({self.kind})"]
        for hunk in self.hunks:
            out.append(f"@@ line {hunk.new_start} @@")
            for line in hunk.lines:
                out.append(f"{line.number:>6} {'+' if line.added else ' '} {line.text}")
        return "\n".join(out)


def is_test_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return any(pattern.search(normalized) for pattern in _TEST_PATTERNS)


@dataclass
class ParsedDiff:
    files: list[ChangedFile] = field(default_factory=list)
    truncated: bool = False

    def __bool__(self) -> bool:
        return bool(self.files)

    def by_path(self, path: str) -> ChangedFile | None:
        normalized = path.replace("\\", "/").lstrip("./")
        for changed in self.files:
            if changed.path == normalized or changed.path.endswith("/" + normalized):
                return changed
        return None

    @property
    def source_files(self) -> list[ChangedFile]:
        return [f for f in self.files if f.is_source]

    @property
    def test_files(self) -> list[ChangedFile]:
        return [f for f in self.files if f.is_test]

    @property
    def added_line_count(self) -> int:
        return sum(len(f.added_lines) for f in self.files)

    @property
    def removed_line_count(self) -> int:
        return sum(f.removed_count for f in self.files)

    def render(self, max_chars: int = 60_000) -> tuple[str, bool]:
        """The whole change, numbered. Returns ``(text, truncated)``."""
        blocks: list[str] = []
        used = 0
        for changed in self.files:
            block = changed.render()
            if used + len(block) > max_chars:
                return "\n\n".join(blocks), True
            blocks.append(block)
            used += len(block) + 2
        return "\n\n".join(blocks), self.truncated


def parse_diff(diff: str, max_chars: int = 400_000) -> ParsedDiff:
    """Parse a unified diff. Preamble, mode changes and binary files are skipped, not guessed."""
    truncated = False
    if len(diff) > max_chars:
        diff = diff[:max_chars]
        truncated = True

    parsed = ParsedDiff(truncated=truncated)
    current: ChangedFile | None = None
    hunk: Hunk | None = None
    new_no = 0
    pending_old: str | None = None

    def close() -> None:
        nonlocal current, hunk
        if current is not None and current.hunks:
            parsed.files.append(current)
        current, hunk = None, None

    for raw in diff.splitlines():
        if raw.startswith("diff --git "):
            close()
            pending_old = None
            continue
        if raw.startswith("--- "):
            match = _OLD_PATH.match(raw)
            pending_old = None if match is None or match.group(1) == _DEV_NULL else match.group(1)
            continue
        if raw.startswith("+++ "):
            close()
            match = _NEW_PATH.match(raw)
            if match is None:
                continue
            new_path = match.group(1).strip()
            if new_path == _DEV_NULL:
                # Deletion: the file is identified by its pre-image path.
                current = ChangedFile(path=pending_old or "", kind=ChangeKind.DELETED)
            elif pending_old is None:
                current = ChangedFile(path=new_path, kind=ChangeKind.ADDED)
            elif pending_old != new_path:
                current = ChangedFile(path=new_path, old_path=pending_old, kind=ChangeKind.RENAMED)
            else:
                current = ChangedFile(path=new_path, kind=ChangeKind.MODIFIED)
            hunk = None
            continue
        if current is None:
            continue
        match = _HUNK.match(raw)
        if match is not None:
            hunk = Hunk(old_start=int(match.group(1)), new_start=int(match.group(3)))
            current.hunks.append(hunk)
            new_no = hunk.new_start
            continue
        if hunk is None:
            continue
        if raw.startswith("+"):
            hunk.lines.append(DiffLine(number=new_no, text=raw[1:], added=True))
            new_no += 1
        elif raw.startswith("-"):
            current.removed_count += 1
        elif raw.startswith(" ") or raw == "":
            hunk.lines.append(DiffLine(number=new_no, text=raw[1:], added=False))
            new_no += 1
        # "\ No newline at end of file" and anything else: not a line of the post-image.

    close()
    return parsed
