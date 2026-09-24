"""The review capability (REV-001..007).

:class:`CodeReviewer` runs a set of checks over one diff and returns a
:class:`~aica.review.findings.ReviewReport`. Each check is a separate model call with a
prompt narrowed to one question, plus the two deterministic checks that answer their
question without a model at all.

Three properties are the point of this module:

**A finding must land on a line in the diff.** Every model-proposed finding is resolved
against the parsed diff before it enters the report: exact line, or a re-anchor to the
nearest visible line within a few rows (marked as re-anchored), or dropped with a
recorded reason. This is what makes REV-007 a property of the system rather than a hope
about the model's arithmetic.

**A check that fails is not a check that passed.** A model error, an unparseable
response or a truncated diff is recorded in ``checks_failed``/``truncated`` and makes
``ReviewReport.complete`` false. An empty report from a broken review must not read as
approval - the same rule the verification ledger applies to tests (TEST-009).

**The diff is untrusted data.** Code under review routinely contains comments, strings
and fixtures that read like instructions; all of it is fenced with
:func:`~aica.safety.injection.wrap_untrusted` and the system prompt says findings are
the only thing to produce (SAFE-007). Review is read-only: nothing here writes a file,
stages a change or commits.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from aica.models.base import ChatMessage, ModelAdapter, ModelError
from aica.review import adequacy, security
from aica.review.diff import ParsedDiff, parse_diff
from aica.review.findings import (
    Category,
    DroppedFinding,
    Finding,
    ReviewReport,
    Severity,
    parse_category,
    parse_severity,
    severity_rank,
)
from aica.safety.injection import wrap_untrusted
from aica.safety.redaction import redact

MAX_DIFF_CHARS = 60_000
MAX_FINDINGS_PER_CHECK = 25
LINE_ANCHOR_TOLERANCE = 6

REVIEW_SYSTEM = """You are a senior engineer reviewing a change for a professional team.

Report only problems you can point at in the diff you were given. For each finding give
the exact file path and the post-image line number printed beside the line - never a
number you counted yourself, and never a file that is not in the diff.

Rules:
- A finding must be actionable: what is wrong, why it matters, what to do instead.
- Do not report on code the diff does not change, and do not restate what the change does.
- Do not invent APIs, behaviour, requirements or ticket numbers. If you are unsure whether
  something is a problem, either say so in the detail or leave it out.
- No praise, no summary, no markdown outside the JSON.

Answer with a JSON array only, each element:
{"file": "<path from the diff>", "line": <number printed in the diff>,
 "severity": "critical|high|medium|low|info", "category": "<category>",
 "title": "<one line>", "detail": "<why it is a problem>", "suggestion": "<what to do>"}
An empty array is a valid answer when there is nothing to report."""

SUMMARY_SYSTEM = """You summarise a completed code review for the change's author.

Write 2-5 sentences: what the change does, then what must be addressed before it merges.
Only use the findings you are given - do not add new ones, and do not invent severities.
If the review is marked incomplete, say plainly what was not covered. Plain prose only."""


class ReviewCheck(StrEnum):
    """One reviewable question. The BRD requirement each answers is in the docstring below."""

    CORRECTNESS = "correctness"  # REV-001, REV-002
    CONVENTIONS = "conventions"  # REV-003
    TESTS = "tests"  # REV-004
    SECURITY = "security"  # REV-005


DEFAULT_CHECKS: tuple[ReviewCheck, ...] = tuple(ReviewCheck)

_CHECK_PROMPTS: dict[ReviewCheck, str] = {
    ReviewCheck.CORRECTNESS: (
        "Review this change for correctness and maintainability (REV-001, REV-002).\n"
        "Look for: logic that does not do what the surrounding code implies it should; "
        "unhandled edge cases (empty, zero, negative, missing, duplicate, concurrent); "
        "off-by-one and boundary errors; resources that are not released on every path; "
        "errors swallowed or reported as success; state mutated while iterated; "
        "a changed signature or contract whose callers were not updated.\n"
        'Use category "bug" for a defect that can produce a wrong result or a crash, '
        '"correctness" for a contract or interface problem, and "maintainability" for '
        "code that works but will be expensive to keep."
    ),
    ReviewCheck.CONVENTIONS: (
        "Review this change against the project's own conventions (REV-003).\n"
        "Compare it with the conventions stated below and with the surrounding code in the "
        "diff. Report only a real departure from how this project writes code: naming, "
        "error handling, logging, typing, layering, module boundaries, import style, test "
        "placement. Do not report personal preference, and do not report anything an "
        "auto-formatter or linter would fix.\n"
        'Use category "convention". Severity is rarely above "low" unless the departure '
        "breaks a pattern the rest of the system depends on."
    ),
    ReviewCheck.TESTS: (
        "Review the test adequacy of this change (REV-004).\n"
        "The static evidence below already says which files have tests. Your job is the part "
        "it cannot decide: given the logic this change adds, which specific behaviour is not "
        "exercised. Name the case - the input, branch or failure path that no test reaches. "
        "Do not repeat the static findings, and do not ask for tests for code the change does "
        "not alter.\n"
        'Use category "test" and anchor each finding to the untested logic, not to the test file.'
    ),
    ReviewCheck.SECURITY: (
        "Review this change for security weaknesses (REV-005).\n"
        "Look for what a single-line pattern cannot see: a value crossing a trust boundary "
        "without validation; an authorisation check that is missing, or that runs after the "
        "effect it guards; a secret reaching a log, an error message or a prompt; a limit, "
        "timeout or quota removed; a permission widened; untrusted input reaching a command, "
        "query, path, template or deserialiser several lines later.\n"
        'Use category "security" and name the weakness class (and its CWE if you are sure).'
    ),
}

_JSON_ARRAY = re.compile(r"\[.*\]", re.DOTALL)
_FENCE = re.compile(r"^```[\w-]*\s*|\s*```$")


@dataclass
class ReviewRequest:
    """What to review and with what context."""

    diff: str
    checks: tuple[ReviewCheck, ...] = DEFAULT_CHECKS
    focus: str = ""
    conventions: str = ""
    description: str = ""  # what the change is meant to do, when the caller knows
    summarize: bool = True


@dataclass
class _CheckOutcome:
    findings: list[Finding] = field(default_factory=list)
    dropped: list[DroppedFinding] = field(default_factory=list)
    error: str | None = None


class CodeReviewer:
    """Reviews a diff. Read-only: it never writes, stages or commits anything."""

    def __init__(
        self,
        adapter: ModelAdapter | None = None,
        *,
        root: str | Path | None = None,
        conventions: str = "",
        max_diff_chars: int = MAX_DIFF_CHARS,
        max_tokens: int = 2000,
    ) -> None:
        self.adapter = adapter
        self.root = Path(root) if root is not None else None
        self.conventions = conventions
        self.max_diff_chars = max_diff_chars
        self.max_tokens = max_tokens

    # ------------------------------------------------------------------ entry point
    def review(self, request: ReviewRequest) -> ReviewReport:
        parsed = parse_diff(request.diff)
        rendered, truncated = parsed.render(self.max_diff_chars)
        report = ReviewReport(
            files_reviewed=[f.path for f in parsed.files],
            truncated=truncated,
            model=self.adapter.info.version if self.adapter is not None else None,
        )
        if not parsed.files:
            report.summary = "No reviewable change: the diff contains no file hunks."
            return report

        # Deterministic evidence first: the model checks are given it rather than asked
        # to reconstruct it, and it stands on its own when no model is available.
        evidence = adequacy.analyze(parsed, self.root)
        static_security = security.scan(parsed)

        for check in request.checks:
            if check is ReviewCheck.TESTS:
                report.findings.extend(adequacy.findings(evidence, parsed))
            if check is ReviewCheck.SECURITY:
                report.findings.extend(static_security)
            outcome = self._run_model_check(
                check, request, parsed, rendered, evidence, static_security
            )
            report.checks_run.append(check.value)
            report.findings.extend(outcome.findings)
            report.dropped.extend(outcome.dropped)
            if outcome.error is not None:
                report.checks_failed[check.value] = outcome.error

        report.findings = _deduplicate(report.findings)
        report.summary = self._summarize(report, request)
        return report

    def review_diff(self, diff: str, **kwargs: Any) -> ReviewReport:
        """Convenience wrapper: ``review_diff(diff, checks=..., focus=...)``."""
        return self.review(ReviewRequest(diff=diff, **kwargs))

    # ------------------------------------------------------------------ model checks
    def _run_model_check(
        self,
        check: ReviewCheck,
        request: ReviewRequest,
        parsed: ParsedDiff,
        rendered: str,
        evidence: list[adequacy.FileAdequacy],
        static_security: list[Finding],
    ) -> _CheckOutcome:
        if self.adapter is None:
            # Not an error: the deterministic checks ran and said so. A review with no
            # model is a narrower review, and the report's provenance already shows it.
            if check in {ReviewCheck.TESTS, ReviewCheck.SECURITY}:
                return _CheckOutcome()
            return _CheckOutcome(error="no model available")

        parts = [_CHECK_PROMPTS[check]]
        if request.description.strip():
            parts.append(f"The change is intended to: {request.description.strip()}")
        if request.focus.strip():
            parts.append(f"The reviewer asked you to focus on: {request.focus.strip()}")
        if check is ReviewCheck.CONVENTIONS:
            conventions = request.conventions or self.conventions
            parts.append(
                conventions.strip()
                if conventions.strip()
                else "No conventions were detected for this project, so report only departures "
                "from the style visible in the diff itself."
            )
        if check is ReviewCheck.TESTS:
            parts.append(adequacy.render(evidence))
        if check is ReviewCheck.SECURITY:
            parts.append(security.render(static_security))
        parts.append(
            "The change under review, with post-image line numbers:\n"
            + wrap_untrusted(rendered, "diff")
        )
        parts.append("Valid file paths for this review: " + ", ".join(f.path for f in parsed.files))

        try:
            response = self.adapter.chat(
                [
                    ChatMessage(role="system", content=REVIEW_SYSTEM),
                    ChatMessage(role="user", content="\n\n".join(parts)),
                ],
                temperature=0.1,
                max_tokens=self.max_tokens,
            )
        except (ModelError, PermissionError) as exc:
            return _CheckOutcome(error=f"model call failed: {exc}")

        raw = redact(response.content).text
        try:
            items = _parse_findings_json(raw)
        except ValueError as exc:
            return _CheckOutcome(error=str(exc))
        return self._resolve(items, parsed, check, response.model)

    # ------------------------------------------------------------------ anchoring
    def _resolve(
        self,
        items: list[dict[str, Any]],
        parsed: ParsedDiff,
        check: ReviewCheck,
        model: str,
    ) -> _CheckOutcome:
        """Turn raw model output into findings that point at real lines, or drop it."""
        outcome = _CheckOutcome()
        default_category = {
            ReviewCheck.CONVENTIONS: Category.CONVENTION,
            ReviewCheck.TESTS: Category.TEST,
            ReviewCheck.SECURITY: Category.SECURITY,
        }.get(check, Category.CORRECTNESS)

        for item in items[:MAX_FINDINGS_PER_CHECK]:
            if not isinstance(item, dict):
                outcome.dropped.append(DroppedFinding("not an object", {"raw": repr(item)[:200]}))
                continue
            title = str(item.get("title") or "").strip()
            if not title:
                outcome.dropped.append(DroppedFinding("no title", item))
                continue

            path = str(item.get("file") or item.get("path") or "").strip()
            changed = parsed.by_path(path) if path else None
            if changed is None:
                outcome.dropped.append(
                    DroppedFinding(f"file not in the diff: {path or '(none)'}", item)
                )
                continue

            requested = _optional_int(item.get("line"))
            if requested is None:
                outcome.dropped.append(DroppedFinding("no usable line number", item))
                continue

            anchored = changed.nearest_line(requested, LINE_ANCHOR_TOLERANCE)
            if anchored is None:
                outcome.dropped.append(
                    DroppedFinding(
                        f"line {requested} is not in the reviewed hunks of {changed.path}", item
                    )
                )
                continue

            end_line = _optional_int(item.get("end_line"))
            if end_line is not None and (
                end_line < anchored or end_line not in changed.visible_lines
            ):
                end_line = None

            outcome.findings.append(
                Finding(
                    file=changed.path,
                    line=anchored,
                    end_line=end_line,
                    severity=parse_severity(item.get("severity")),
                    category=parse_category(item.get("category"), default_category),
                    title=title[:200],
                    detail=str(item.get("detail") or "").strip()[:2000],
                    suggestion=str(item.get("suggestion") or "").strip()[:1000],
                    code=(changed.line_text(anchored) or "").strip(),
                    origin=check.value,
                    model=model,
                    confirmed_location=anchored == requested,
                )
            )
        return outcome

    # ------------------------------------------------------------------ REV-006
    def _summarize(self, report: ReviewReport, request: ReviewRequest) -> str:
        deterministic = _deterministic_summary(report)
        if not request.summarize or self.adapter is None or not report.findings:
            return deterministic
        listing = "\n".join(
            f"- [{f.severity.value}] {f.location} {f.title}" for f in report.ordered[:40]
        )
        status = (
            "complete"
            if report.complete
            else (
                "INCOMPLETE: "
                + "; ".join(f"{name} ({reason})" for name, reason in report.checks_failed.items())
                + ("; diff truncated" if report.truncated else "")
            )
        )
        try:
            response = self.adapter.chat(
                [
                    ChatMessage(role="system", content=SUMMARY_SYSTEM),
                    ChatMessage(
                        role="user",
                        content=(
                            f"Files changed: {', '.join(report.files_reviewed[:30])}\n"
                            f"Review status: {status}\n\nFindings:\n{listing}"
                        ),
                    ),
                ],
                temperature=0.2,
                max_tokens=400,
            )
        except (ModelError, PermissionError):
            return deterministic
        text = _FENCE.sub("", redact(response.content).text).strip()
        # The deterministic counts stay in front of the prose: they are the part that
        # cannot drift from the findings actually in the report.
        return f"{deterministic}\n\n{text}" if text else deterministic


# ---------------------------------------------------------------------- helpers
def _optional_int(value: object) -> int | None:
    """An integer from whatever the model put in the field, or None. Never raises."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_findings_json(text: str) -> list[dict[str, Any]]:
    """Extract the JSON array from a model response. Raises ValueError when there is none."""
    cleaned = _FENCE.sub("", text.strip()).strip()
    if not cleaned:
        raise ValueError("model returned an empty response")
    candidate = cleaned
    if not candidate.startswith("["):
        match = _JSON_ARRAY.search(cleaned)
        if match is None:
            raise ValueError("model response contained no JSON array of findings")
        candidate = match.group(0)
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise ValueError(f"model response was not valid JSON: {exc.msg}") from exc
    if not isinstance(data, list):
        raise ValueError("model response was not a JSON array")
    return data


def _normalize_title(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", title.lower()).strip()


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """One finding per place and problem, keeping the most severe and preferring a static one.

    Checks overlap on purpose - the security prompt and the correctness prompt will both
    notice a swallowed exception - and two entries for one line make a reviewer fix it
    twice or trust the report less.
    """
    best: dict[tuple[str, int, Category, str], Finding] = {}
    order: list[tuple[str, int, Category, str]] = []
    for finding in findings:
        key = (finding.file, finding.line, finding.category, _normalize_title(finding.title))
        existing = best.get(key)
        if existing is None:
            best[key] = finding
            order.append(key)
            continue
        # A deterministic finding outranks a model finding of equal severity: it is the
        # one whose claim can be checked.
        better = (
            severity_rank(finding.severity),
            finding.model is not None,
        ) < (
            severity_rank(existing.severity),
            existing.model is not None,
        )
        if better:
            best[key] = finding
    return [best[key] for key in order]


def _deterministic_summary(report: ReviewReport) -> str:
    counts = report.counts()
    blocking = len(report.at_or_above(Severity.HIGH))
    parts = [
        f"{len(report.findings)} finding(s) across {len(report.files_reviewed)} changed file(s)"
        f" ({', '.join(f'{counts[s.value]} {s.value}' for s in Severity if counts[s.value]) or 'none'})."
    ]
    if blocking:
        parts.append(f"{blocking} at high severity or above should be addressed before merge.")
    if not report.complete:
        parts.append(
            "This review is incomplete, so the absence of further findings means nothing: "
            + "; ".join(f"{name} ({reason})" for name, reason in report.checks_failed.items())
            + ("; the diff was truncated." if report.truncated else ".")
        )
    if report.dropped:
        parts.append(
            f"{len(report.dropped)} proposed finding(s) were discarded for pointing outside "
            "the reviewed change."
        )
    return " ".join(parts)
