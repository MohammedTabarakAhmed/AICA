"""Accept, reject or partially accept an agent's changes (CC-005).

An agent's edit to a file is a sequence of *hunks* - the non-equal blocks between the file
as it was before the task and as the task left it. A reviewer keeps any subset of them:
all of them is accept, none is reject, anything in between is partial acceptance. The
result is computed exactly from the two texts with ``difflib``, never by re-applying a
textual patch, so there is no fuzz factor and no hunk that "applies with offset".

The one rule that matters for safety: **a decision is refused if the file is no longer
what the agent left.** Otherwise rejecting the agent's change would also discard whatever
a person wrote in that file since, which is the GIT-010 hazard in a new form. The caller
records a fingerprint of each file when the task finishes and passes it back here.
"""

from __future__ import annotations

import difflib
import hashlib
from dataclasses import dataclass


def fingerprint(text: str | None) -> str:
    """Content hash of a file's text; a missing file has its own fingerprint."""
    if text is None:
        return "missing"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class ChangedSinceTask(RuntimeError):
    """The file was edited after the agent finished; deciding would discard that edit."""


@dataclass(frozen=True)
class Hunk:
    index: int
    old_start: int  # 1-based line in the original
    old_lines: list[str]
    new_start: int  # 1-based line in the agent's version
    new_lines: list[str]

    def to_json(self) -> dict[str, object]:
        return {
            "index": self.index,
            "old_start": self.old_start,
            "old_lines": self.old_lines,
            "new_start": self.new_start,
            "new_lines": self.new_lines,
        }


def _lines(text: str) -> list[str]:
    return text.splitlines(keepends=True)


def hunks(original: str, final: str) -> list[Hunk]:
    """The agent's edit as independently decidable hunks, in file order."""
    old, new = _lines(original), _lines(final)
    matcher = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
    out: list[Hunk] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        out.append(
            Hunk(
                index=len(out),
                old_start=i1 + 1,
                old_lines=[line.rstrip("\r\n") for line in old[i1:i2]],
                new_start=j1 + 1,
                new_lines=[line.rstrip("\r\n") for line in new[j1:j2]],
            )
        )
    return out


def merge(original: str, final: str, accepted: set[int]) -> str:
    """The file with only the ``accepted`` hunks of the agent's edit applied."""
    old, new = _lines(original), _lines(final)
    matcher = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
    result: list[str] = []
    index = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            result.extend(old[i1:i2])
            continue
        result.extend(new[j1:j2] if index in accepted else old[i1:i2])
        index += 1
    unknown = accepted - set(range(index))
    if unknown:
        raise ValueError(f"no such hunk(s): {sorted(unknown)} (the edit has {index})")
    return "".join(result)


def require_unchanged(path: str, current: str | None, expected: str) -> None:
    """Refuse a decision when the file differs from what the task left behind."""
    if fingerprint(current) != expected:
        raise ChangedSinceTask(
            f"{path} has changed since the task finished; deciding on the agent's edit now "
            "would discard that later change. Review it by hand (CC-005, GIT-010)"
        )
