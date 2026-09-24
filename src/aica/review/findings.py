"""Findings and the review report (REV-006, REV-007).

A finding is a claim about a specific place in a specific file. This module is what
makes that claim well-formed before anything renders or acts on it:

* **Severity is a closed set**, so grouping is meaningful and a gate can be written
  against it. A model that answers ``"severity": "pretty bad"`` gets normalised or
  rejected, never passed through as a new severity that no policy covers.
* **A location is required.** REV-007 asks that a reviewer can navigate directly to
  the code; a finding without a resolvable ``file`` and ``line`` cannot do that, so
  the type does not allow one.
* **Provenance is recorded per finding** (``origin``: which check produced it, and
  ``model``: which model, or ``None`` for a deterministic check). A report that mixes
  model judgement with static analysis has to say which is which, or a reviewer cannot
  calibrate how much to trust any single line of it.

The report groups by severity and by file (REV-006) and renders both text and JSON.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Ordered worst-first; :func:`severity_rank` gives the sort key."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


_RANK = {s: i for i, s in enumerate(Severity)}

# What models write instead of the words above.
_SEVERITY_ALIASES = {
    "blocker": Severity.CRITICAL,
    "severe": Severity.CRITICAL,
    "major": Severity.HIGH,
    "important": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "normal": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "minor": Severity.LOW,
    "nit": Severity.LOW,
    "nitpick": Severity.LOW,
    "suggestion": Severity.LOW,
    "note": Severity.INFO,
    "informational": Severity.INFO,
    "style": Severity.INFO,
}


def severity_rank(severity: Severity) -> int:
    return _RANK[severity]


def parse_severity(value: object, default: Severity = Severity.MEDIUM) -> Severity:
    """Normalise a model-supplied severity. Unknown words fall back rather than crash."""
    text = str(value or "").strip().lower()
    if text in _RANK:
        return Severity(text)
    return _SEVERITY_ALIASES.get(text, default)


class Category(StrEnum):
    """Which BRD review requirement a finding answers. One per requirement, deliberately."""

    CORRECTNESS = "correctness"  # REV-001
    BUG = "bug"  # REV-002
    MAINTAINABILITY = "maintainability"  # REV-001
    CONVENTION = "convention"  # REV-003
    TEST = "test"  # REV-004
    SECURITY = "security"  # REV-005


_CATEGORY_ALIASES = {
    "correct": Category.CORRECTNESS,
    "logic": Category.BUG,
    "edge_case": Category.BUG,
    "edge-case": Category.BUG,
    "edgecase": Category.BUG,
    "maintainability": Category.MAINTAINABILITY,
    "readability": Category.MAINTAINABILITY,
    "design": Category.MAINTAINABILITY,
    "style": Category.CONVENTION,
    "conventions": Category.CONVENTION,
    "tests": Category.TEST,
    "testing": Category.TEST,
    "coverage": Category.TEST,
    "vulnerability": Category.SECURITY,
    "sec": Category.SECURITY,
}

# Which requirement each category evidences, for the traceability line in the report.
REQUIREMENT_BY_CATEGORY = {
    Category.CORRECTNESS: "REV-001",
    Category.BUG: "REV-002",
    Category.MAINTAINABILITY: "REV-001",
    Category.CONVENTION: "REV-003",
    Category.TEST: "REV-004",
    Category.SECURITY: "REV-005",
}


def parse_category(value: object, default: Category = Category.CORRECTNESS) -> Category:
    text = str(value or "").strip().lower().replace(" ", "_")
    if text in {c.value for c in Category}:
        return Category(text)
    return _CATEGORY_ALIASES.get(text, default)


@dataclass(frozen=True)
class Finding:
    """One reviewable claim, anchored to a line a reviewer can open (REV-007)."""

    file: str
    line: int
    severity: Severity
    category: Category
    title: str
    detail: str = ""
    suggestion: str = ""
    end_line: int | None = None
    code: str = ""  # the source line the finding points at, quoted back for context
    origin: str = "model"  # which check produced it: "model" or a static check's name
    model: str | None = None  # None = deterministic, not a model judgement
    confirmed_location: bool = True  # False when the line was re-anchored from a near miss

    @property
    def location(self) -> str:
        """``path:line`` - the clickable form REV-007 asks for."""
        if self.end_line and self.end_line != self.line:
            return f"{self.file}:{self.line}-{self.end_line}"
        return f"{self.file}:{self.line}"

    @property
    def requirement(self) -> str:
        return REQUIREMENT_BY_CATEGORY[self.category]

    @property
    def generated(self) -> bool:
        return self.model is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "location": self.location,
            "severity": self.severity.value,
            "category": self.category.value,
            "requirement": self.requirement,
            "title": self.title,
            "detail": self.detail,
            "suggestion": self.suggestion,
            "code": self.code,
            "origin": self.origin,
            "model": self.model,
            "confirmed_location": self.confirmed_location,
        }


@dataclass
class DroppedFinding:
    """A finding the reviewer refused, kept so the report can say what it threw away.

    Silently discarding a model's output would make the review look cleaner than it was.
    The count of these is part of the report: a review that dropped nine of twelve
    findings for unresolvable locations is telling the reader something about the model.
    """

    reason: str
    raw: dict[str, Any]


@dataclass
class ReviewReport:
    """Findings grouped by severity and file (REV-006), with the provenance to read them by."""

    findings: list[Finding] = field(default_factory=list)
    dropped: list[DroppedFinding] = field(default_factory=list)
    files_reviewed: list[str] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    checks_failed: dict[str, str] = field(default_factory=dict)
    model: str | None = None
    truncated: bool = False
    summary: str = ""

    # ------------------------------------------------------------------ grouping
    @property
    def ordered(self) -> list[Finding]:
        """Worst first, then by file and line - the order a reviewer should read them in."""
        return sorted(
            self.findings, key=lambda f: (severity_rank(f.severity), f.file, f.line, f.title)
        )

    def by_severity(self) -> dict[Severity, list[Finding]]:
        grouped: dict[Severity, list[Finding]] = {}
        for finding in self.ordered:
            grouped.setdefault(finding.severity, []).append(finding)
        return grouped

    def by_file(self) -> dict[str, list[Finding]]:
        grouped: defaultdict[str, list[Finding]] = defaultdict(list)
        for finding in self.ordered:
            grouped[finding.file].append(finding)
        return {path: grouped[path] for path in sorted(grouped)}

    def counts(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def at_or_above(self, severity: Severity) -> list[Finding]:
        limit = severity_rank(severity)
        return [f for f in self.ordered if severity_rank(f.severity) <= limit]

    @property
    def complete(self) -> bool:
        """False when a check could not run, so the report must not read as a clean bill.

        Same rule as the verification ledger (TEST-009): a check that did not run is not
        a check that passed, and "no findings" from a review that half-failed is a false
        success. Callers gate on this before treating an empty report as approval.
        """
        return not self.checks_failed and not self.truncated

    # ------------------------------------------------------------------ rendering
    def render(self, *, show_dropped: bool = False) -> str:
        lines: list[str] = []
        counts = self.counts()
        headline = ", ".join(f"{counts[s.value]} {s.value}" for s in Severity if counts[s.value])
        lines.append(f"# Code review: {len(self.findings)} finding(s)")
        if headline:
            lines.append(f"Severity: {headline}")
        lines.append(
            f"Files reviewed: {len(self.files_reviewed)} | "
            f"checks: {', '.join(self.checks_run) or 'none'}"
            + (f" | model: {self.model}" if self.model else " | model: none")
        )
        if not self.complete:
            problems = [f"{name} ({reason})" for name, reason in self.checks_failed.items()]
            if self.truncated:
                problems.append("diff truncated: part of the change was not reviewed")
            lines.append(
                "INCOMPLETE - this review did not cover everything: " + "; ".join(problems)
            )
        if self.summary:
            lines.extend(["", self.summary.strip()])

        for severity, group in self.by_severity().items():
            lines.extend(["", f"## {severity.value.upper()} ({len(group)})"])
            current_file = None
            for finding in group:
                if finding.file != current_file:
                    current_file = finding.file
                    lines.append(f"### {current_file}")
                origin = finding.model or finding.origin
                anchor = "" if finding.confirmed_location else " [line re-anchored]"
                lines.append(
                    f"- {finding.location} [{finding.category.value}/{finding.requirement}] "
                    f"{finding.title}{anchor}"
                )
                if finding.code:
                    lines.append(f"    | {finding.code.strip()}")
                if finding.detail:
                    lines.append(f"    {finding.detail.strip()}")
                if finding.suggestion:
                    lines.append(f"    suggestion: {finding.suggestion.strip()}")
                lines.append(f"    ({origin})")

        if not self.findings:
            lines.extend(["", "No findings." if self.complete else "", ""])
        if show_dropped and self.dropped:
            lines.extend(["", f"## Dropped ({len(self.dropped)})"])
            for dropped in self.dropped:
                title = str(dropped.raw.get("title") or dropped.raw.get("file") or "?")
                lines.append(f"- {title}: {dropped.reason}")
        return "\n".join(line for line in lines if line is not None).strip() + "\n"

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "complete": self.complete,
            "truncated": self.truncated,
            "model": self.model,
            "files_reviewed": self.files_reviewed,
            "checks_run": self.checks_run,
            "checks_failed": self.checks_failed,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.ordered],
            "by_file": {
                path: [f.to_dict() for f in group] for path, group in self.by_file().items()
            },
            "dropped": [{"reason": d.reason, "raw": d.raw} for d in self.dropped],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)
