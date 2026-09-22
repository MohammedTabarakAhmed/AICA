"""Final task report (AG-010, UX-009, TEST-009, BRD section 18).

A report cannot claim success unless the verification ledger says every required check
passed. When checks failed or were skipped, the disclosure is rendered into the report
and ``succeeded`` is False — this is the structural guarantee behind TEST-009.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aica.testing.results import VerificationLedger


@dataclass
class FileChange:
    path: str
    action: str  # created | modified | deleted | moved
    diff: str = ""
    snapshot_id: str | None = None


@dataclass
class TaskReport:
    task: str
    model: str
    changes: list[FileChange] = field(default_factory=list)
    ledger: VerificationLedger = field(default_factory=VerificationLedger)
    warnings: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    steps_used: int = 0
    duration_ms: int = 0
    session_id: str | None = None
    cancelled: bool = False

    @property
    def succeeded(self) -> bool:
        """Never true when required verification did not pass (TEST-009, AG-009)."""
        return not self.cancelled and self.ledger.can_report_success and not self.unresolved

    def outcome(self) -> str:
        if self.cancelled:
            return "CANCELLED"
        if self.succeeded:
            return "SUCCESS"
        return "INCOMPLETE"

    def render(self, *, include_diffs: bool = False) -> str:
        lines = [
            f"# Task report: {self.task}",
            "",
            f"**Outcome:** {self.outcome()}",
            f"**Model:** {self.model}",
        ]
        if self.session_id:
            lines.append(f"**Session:** {self.session_id}")
        lines.append(f"**Steps:** {self.steps_used}   **Duration:** {self.duration_ms} ms")
        lines += ["", "## Files changed"]
        if self.changes:
            for c in self.changes:
                lines.append(
                    f"- {c.action}: `{c.path}`"
                    + (f" (snapshot {c.snapshot_id})" if c.snapshot_id else "")
                )
        else:
            lines.append("- (none)")
        lines += ["", "## Verification"]
        summaries = self.ledger.summary_lines()
        lines += [f"- {s}" for s in summaries] if summaries else ["- (no checks run)"]
        lines += ["", self.ledger.disclosure()]
        if self.warnings:
            lines += ["", "## Warnings"] + [f"- {w}" for w in self.warnings]
        lines += ["", "## Unresolved"]
        lines += [f"- {u}" for u in self.unresolved] if self.unresolved else ["- (none)"]
        if include_diffs and self.changes:
            lines += ["", "## Diffs"]
            for c in self.changes:
                if c.diff:
                    lines += [f"### {c.path}", "```diff", c.diff.rstrip(), "```"]
        return "\n".join(lines)
