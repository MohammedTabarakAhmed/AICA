"""Test adequacy (REV-004), decided without a model.

REV-004 asks for "changed logic lacking appropriate tests". Two parts of that are
facts, not judgement, and this module answers them by reading the diff and the
repository:

1. **Did the change alter logic at all?** Reformatting, comments, docstrings, imports
   and pure data edits are changes that need no new test, and reporting them as
   untested is the noise that makes reviewers stop reading a tool's output.
2. **Does anything test the changed file?** Either a test file changed alongside it in
   the same diff, or a test file in the repository already names it.

What stays a judgement - whether the *existing* tests cover the *specific* branch that
changed - is left to the model, which is given these facts rather than asked to guess
them. The split matters: a deterministic signal can be trusted at face value, so it is
reported with ``model=None`` and the reader can tell the two apart.

Both signals are conservative in the same direction: they only claim a gap when no test
evidence can be found at all. An over-eager "untested" is a false positive a reviewer
pays for on every change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from aica.review.diff import ChangedFile, ParsedDiff
from aica.review.findings import Category, Finding, Severity

# Lines that change a file without changing what it does.
_TRIVIAL = re.compile(
    r"^\s*(#|//|/\*|\*|\*/|\"\"\"|'''|$)"  # comment / docstring delimiter / blank
    r"|^\s*(import|from|using|package|require|use)\b"  # imports
    r"|^\s*[)\]}]+[,;]?\s*$"  # closing brackets left by reformatting
)

# Constructs that are logic worth a test, across the BRD 9.1 languages.
#
# Keywords are only counted where code actually puts them - opening a statement - rather
# than anywhere in the line. A bare ``\b(if|for|or|not)\b`` matches ordinary English, so
# it fires on every docstring, comment block and help string in a change and reports the
# file as untested logic. Running this module against its own repository is how that was
# found: a line of the CLI's module docstring was flagged because it contained "for".
_LOGIC = re.compile(
    # A control-flow or definition keyword opening a statement.
    r"^\s*[\w.\[\]]*\s*(if|elif|else|for|while|switch|case|do|try|catch|except|finally"
    r"|with|raise|throw|return|yield|assert|break|continue|match|del"
    r"|def|class|function|func|fn|public|private|protected|static|async)\b"
    # An assignment, comparison or augmented assignment.
    r"|[=!<>]=|[-+*/%|&^]=|(?<![=!<>+\-*/%|&^])=(?![=>])"
    # A call, or a boolean / null-coalescing operator.
    r"|\w\(|&&|\|\||\?\?"
)

# How many test files to open when looking for an existing reference.
MAX_TEST_FILES_SCANNED = 400
MAX_TEST_FILE_BYTES = 400_000


@dataclass
class FileAdequacy:
    """The test evidence for one changed source file."""

    path: str
    logic_lines: list[int] = field(default_factory=list)
    changed_tests: list[str] = field(default_factory=list)  # test files in the same diff
    existing_tests: list[str] = field(default_factory=list)  # test files that name this module

    @property
    def changes_logic(self) -> bool:
        return bool(self.logic_lines)

    @property
    def has_test_evidence(self) -> bool:
        return bool(self.changed_tests or self.existing_tests)

    @property
    def gap(self) -> bool:
        """Changed logic with no test evidence anywhere - the REV-004 case."""
        return self.changes_logic and not self.has_test_evidence

    @property
    def untested_change(self) -> bool:
        """Changed logic covered only by tests that were not themselves updated.

        Weaker than :attr:`gap` and reported as such: tests exist, but nothing in this
        change exercises the new behaviour, so they may all still pass unchanged.
        """
        return self.changes_logic and bool(self.existing_tests) and not self.changed_tests


def logic_lines(changed: ChangedFile) -> list[int]:
    """The added lines in ``changed`` that alter behaviour rather than presentation."""
    return [
        line.number
        for line in changed.added_lines
        if line.text.strip() and not _TRIVIAL.match(line.text) and _LOGIC.search(line.text)
    ]


def _module_tokens(path: str, *, specific_only: bool = False) -> set[str]:
    """Names a test would use to refer to this file: stem, module path and package.

    ``specific_only`` drops the bare package name. A package name is a useful hint in a
    *path* (``tests/pkg/...`` tests ``pkg``), but matching it against a test's *contents*
    credits every module in a package with any test that imports any sibling.
    """
    posix = PurePosixPath(path.replace("\\", "/"))
    tokens = {posix.stem}
    parts = [p for p in posix.parts[:-1] if p not in {"src", "lib", "app", "."}]
    if parts:
        tokens.add(".".join([*parts, posix.stem]))
        tokens.add("/".join([*parts, posix.stem]))
        if not specific_only:
            tokens.add(parts[-1])
    return {token for token in tokens if len(token) > 2 and token not in {"index", "main", "init"}}


def find_existing_tests(root: Path | None, source_path: str, limit: int = 8) -> list[str]:
    """Test files in the repository that mention ``source_path``'s module.

    A textual reference, not an import graph: a test that names the module is evidence
    the module is under test, and claiming more precision than a grep can support would
    be the kind of unearned confidence the rest of this package avoids.
    """
    if root is None or not root.is_dir():
        return []
    from aica.review.diff import is_test_path

    tokens = _module_tokens(source_path)
    if not tokens:
        return []
    hits: list[str] = []
    scanned = 0
    for candidate in sorted(root.rglob("*")):
        if scanned >= MAX_TEST_FILES_SCANNED or len(hits) >= limit:
            break
        if not candidate.is_file():
            continue
        try:
            relative = candidate.relative_to(root).as_posix()
        except ValueError:  # pragma: no cover - rglob yields only descendants
            continue
        if any(
            part.startswith(".") or part in {"node_modules", "__pycache__"}
            for part in PurePosixPath(relative).parts
        ):
            continue
        if not is_test_path(relative):
            continue
        scanned += 1
        try:
            if candidate.stat().st_size > MAX_TEST_FILE_BYTES:
                continue
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(token in text for token in tokens):
            hits.append(relative)
    return hits


def _changed_test_contents(parsed: ParsedDiff, root: Path | None) -> dict[str, str]:
    """The text of each test file in the diff: its added lines, plus the file on disk.

    Matching a changed test to its source by filename alone misses the common case where
    one test file covers several modules - ``tests/test_review_surfaces.py`` exercises
    ``cli.py`` without naming it. Reading what the test actually references fixes that,
    and this was found by running the reviewer on its own change.
    """
    contents: dict[str, str] = {}
    for test in parsed.test_files:
        text = "\n".join(line.text for line in test.added_lines)
        if root is not None:
            candidate = root / test.path
            try:
                if candidate.is_file() and candidate.stat().st_size <= MAX_TEST_FILE_BYTES:
                    text = candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        contents[test.path] = text
    return contents


def analyze(parsed: ParsedDiff, root: Path | None = None) -> list[FileAdequacy]:
    """Test evidence for every changed source file in ``parsed``."""
    changed_tests = [f.path for f in parsed.test_files]
    test_contents = _changed_test_contents(parsed, root)
    results: list[FileAdequacy] = []
    for changed in parsed.source_files:
        tokens = _module_tokens(changed.path)
        content_tokens = _module_tokens(changed.path, specific_only=True)
        same_diff = [
            test
            for test in changed_tests
            if any(token in test for token in tokens)
            or any(token in test_contents.get(test, "") for token in content_tokens)
        ]
        # A test file changed in the same diff but not obviously tied to this source file
        # is still evidence when it is the only test file in the change.
        if not same_diff and len(changed_tests) == 1 and len(parsed.source_files) == 1:
            same_diff = list(changed_tests)
        results.append(
            FileAdequacy(
                path=changed.path,
                logic_lines=logic_lines(changed),
                changed_tests=same_diff,
                existing_tests=[] if same_diff else find_existing_tests(root, changed.path),
            )
        )
    return results


def findings(adequacy: list[FileAdequacy], parsed: ParsedDiff) -> list[Finding]:
    """REV-004 findings from the deterministic evidence, anchored to a real changed line."""
    out: list[Finding] = []
    for entry in adequacy:
        if not (entry.gap or entry.untested_change):
            continue
        changed = parsed.by_path(entry.path)
        line = entry.logic_lines[0]
        code = changed.line_text(line) if changed else ""
        if entry.gap:
            out.append(
                Finding(
                    file=entry.path,
                    line=line,
                    severity=Severity.HIGH,
                    category=Category.TEST,
                    title="Changed logic with no test covering this file",
                    detail=(
                        f"{len(entry.logic_lines)} added line(s) change behaviour, and no test "
                        "file was changed alongside them or found in the repository referring "
                        "to this module."
                    ),
                    suggestion=f"Add a test exercising the new behaviour in {entry.path}.",
                    code=code or "",
                    origin="test-adequacy",
                    model=None,
                )
            )
        else:
            out.append(
                Finding(
                    file=entry.path,
                    line=line,
                    severity=Severity.MEDIUM,
                    category=Category.TEST,
                    title="Changed logic, but no test changed with it",
                    detail=(
                        f"{len(entry.logic_lines)} added line(s) change behaviour. Existing "
                        f"tests reference this module ({', '.join(entry.existing_tests[:3])}), "
                        "but none of them changed, so they may pass without exercising the "
                        "new behaviour."
                    ),
                    suggestion="Extend the existing tests to cover the changed branch.",
                    code=code or "",
                    origin="test-adequacy",
                    model=None,
                )
            )
    return out


def render(adequacy: list[FileAdequacy]) -> str:
    """The evidence as a prompt block, so the model judges coverage instead of inventing it."""
    if not adequacy:
        return ""
    lines = ["Test evidence for the changed source files (established by static analysis):"]
    for entry in adequacy:
        if not entry.changes_logic:
            lines.append(f"- {entry.path}: no behavioural change detected in the added lines.")
        elif entry.changed_tests:
            lines.append(
                f"- {entry.path}: {len(entry.logic_lines)} behavioural line(s); "
                f"tests changed with it: {', '.join(entry.changed_tests)}."
            )
        elif entry.existing_tests:
            lines.append(
                f"- {entry.path}: {len(entry.logic_lines)} behavioural line(s); "
                f"existing tests reference it ({', '.join(entry.existing_tests[:3])}) "
                "but none changed."
            )
        else:
            lines.append(
                f"- {entry.path}: {len(entry.logic_lines)} behavioural line(s); "
                "no test file changed and none found referring to it."
            )
    return "\n".join(lines)
