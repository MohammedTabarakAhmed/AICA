"""Test result parsing, failure analysis and the false-success guard (TEST-002/005/008/009).

``VerificationLedger`` is the mechanism behind TEST-009 and AG-009: a task may only be
reported as successful when every required check has actually been run and passed. Skipped
or failed checks make ``can_report_success`` false, and the ledger renders the disclosure
text that must accompany the report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum


class CheckStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"
    NOT_RUN = "not_run"


@dataclass(frozen=True)
class TestFailure:
    test: str
    file: str | None
    line: int | None
    message: str

    @property
    def location(self) -> str:
        if self.file and self.line:
            return f"{self.file}:{self.line}"
        return self.file or "(unknown)"


@dataclass
class TestOutcome:
    kind: str
    command: str
    status: CheckStatus
    exit_code: int | None = None
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    duration_ms: int = 0
    failures: list[TestFailure] = field(default_factory=list)
    coverage_percent: float | None = None
    output_tail: str = ""

    @property
    def ok(self) -> bool:
        return self.status is CheckStatus.PASSED

    def summary(self) -> str:
        if self.status is CheckStatus.NOT_RUN:
            return f"{self.kind}: NOT RUN ({self.command})"
        counts = f"{self.passed} passed, {self.failed} failed, {self.skipped} skipped"
        cov = (
            f", coverage {self.coverage_percent:.0f}%" if self.coverage_percent is not None else ""
        )
        return f"{self.kind}: {self.status.value.upper()} - {counts}{cov} ({self.command})"


# ---------------------------------------------------------------- parsers

_PYTEST_COUNTS = re.compile(r"(\d+)\s+(passed|failed|error|errors|skipped|xfailed|xpassed)")
_PYTEST_FAILURE = re.compile(r"^(?:FAILED|ERROR)\s+([^\s:]+)::(\S+)(?:\s+-\s+(.*))?$", re.M)
_PYTEST_ASSERT_LOC = re.compile(r"^([\w./\\-]+\.py):(\d+):", re.M)
_COVERAGE = re.compile(r"^TOTAL\s+.*?(\d+(?:\.\d+)?)%", re.M)
_JEST_COUNTS = re.compile(r"Tests:\s+(?:(\d+) failed,\s*)?(?:(\d+) skipped,\s*)?(\d+) passed")
_GO_FAIL = re.compile(r"^---\s+FAIL:\s+(\S+)", re.M)
_GO_COUNTS = re.compile(r"^(ok|FAIL)\s+(\S+)", re.M)
_MAVEN_COUNTS = re.compile(
    r"Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+),\s*Skipped:\s*(\d+)"
)
_CARGO_COUNTS = re.compile(
    r"test result:\s+(\w+)\.\s+(\d+) passed;\s+(\d+) failed;\s+(\d+) ignored"
)


def parse_output(
    kind: str, command: str, stdout: str, stderr: str, exit_code: int | None, duration_ms: int = 0
) -> TestOutcome:
    text = f"{stdout}\n{stderr}"
    outcome = TestOutcome(
        kind=kind,
        command=command,
        status=CheckStatus.PASSED if exit_code == 0 else CheckStatus.FAILED,
        exit_code=exit_code,
        duration_ms=duration_ms,
        output_tail=text[-4000:],
    )
    if exit_code is None:
        outcome.status = CheckStatus.ERROR

    # Runner-specific formats are tried first: their summary lines also contain
    # "N passed"/"N failed", so the generic pytest counter would shadow them.
    counts = {m.group(2): int(m.group(1)) for m in _PYTEST_COUNTS.finditer(text)}
    if (cm := _CARGO_COUNTS.search(text)) is not None:
        outcome.passed = int(cm.group(2))
        outcome.failed = int(cm.group(3))
        outcome.skipped = int(cm.group(4))
    elif (mm := _MAVEN_COUNTS.search(text)) is not None:
        total, failures, errors, skipped = (int(g) for g in mm.groups())
        outcome.failed = failures + errors
        outcome.skipped = skipped
        outcome.passed = max(total - outcome.failed - skipped, 0)
    elif (jm := _JEST_COUNTS.search(text)) is not None:
        outcome.failed = int(jm.group(1) or 0)
        outcome.skipped = int(jm.group(2) or 0)
        outcome.passed = int(jm.group(3) or 0)
    elif counts:
        outcome.passed = counts.get("passed", 0) + counts.get("xpassed", 0)
        outcome.failed = counts.get("failed", 0) + counts.get("error", 0) + counts.get("errors", 0)
        outcome.skipped = counts.get("skipped", 0) + counts.get("xfailed", 0)
        for m in _PYTEST_FAILURE.finditer(text):
            file, test, message = m.group(1), m.group(2), (m.group(3) or "").strip()
            loc = _PYTEST_ASSERT_LOC.search(text[m.end() : m.end() + 2000])
            outcome.failures.append(
                TestFailure(
                    test=test, file=file, line=int(loc.group(2)) if loc else None, message=message
                )
            )
    elif _GO_COUNTS.search(text):
        fails = _GO_FAIL.findall(text)
        outcome.failed = len(fails)
        outcome.passed = len([m for m in _GO_COUNTS.finditer(text) if m.group(1) == "ok"])
        outcome.failures = [
            TestFailure(test=name, file=None, line=None, message="go test failure")
            for name in fails
        ]

    if (cov := _COVERAGE.search(text)) is not None:
        outcome.coverage_percent = float(cov.group(1))
    if outcome.failed and outcome.status is CheckStatus.PASSED:
        outcome.status = CheckStatus.FAILED  # never trust exit code alone
    return outcome


def analyze_failures(outcome: TestOutcome, max_items: int = 10) -> str:
    """TEST-005: map failures to likely code locations for the agent's next step."""
    if outcome.ok:
        return "No failures."
    lines = [f"{outcome.failed} failing test(s) from `{outcome.command}`:"]
    for f in outcome.failures[:max_items]:
        lines.append(f"- {f.test} at {f.location}: {f.message or '(see output)'}")
    if not outcome.failures:
        lines.append("- No structured failures parsed; inspect the output tail:")
        lines.append(outcome.output_tail[-1500:])
    return "\n".join(lines)


# ---------------------------------------------------------------- TEST-009


@dataclass
class VerificationLedger:
    """Records which checks were required, run and passed. Prevents false success."""

    required: dict[str, CheckStatus] = field(default_factory=dict)
    outcomes: list[TestOutcome] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def require(self, kind: str) -> None:
        self.required.setdefault(kind, CheckStatus.NOT_RUN)

    def record(self, outcome: TestOutcome) -> None:
        # The most recent run reflects the current state of that check: a later pass clears
        # an earlier failure (the agent fixed it), a later failure revokes an earlier pass.
        self.outcomes.append(outcome)
        self.required[outcome.kind] = outcome.status

    def skip(self, kind: str, reason: str) -> None:
        self.required[kind] = CheckStatus.SKIPPED
        self.notes.append(f"{kind} skipped: {reason}")

    @property
    def unmet(self) -> dict[str, CheckStatus]:
        return {k: v for k, v in self.required.items() if v is not CheckStatus.PASSED}

    @property
    def can_report_success(self) -> bool:
        return bool(self.required) and not self.unmet

    def disclosure(self) -> str:
        """The text that MUST accompany any report when checks did not all pass."""
        if not self.required:
            return "No verification was required or run for this task."
        if self.can_report_success:
            return "All required verification passed: " + ", ".join(sorted(self.required))
        parts = [f"{k}: {v.value}" for k, v in sorted(self.unmet.items())]
        text = "VERIFICATION INCOMPLETE - " + "; ".join(parts)
        if self.notes:
            text += "\n" + "\n".join(f"- {n}" for n in self.notes)
        return text

    def summary_lines(self) -> list[str]:
        return [o.summary() for o in self.outcomes]
