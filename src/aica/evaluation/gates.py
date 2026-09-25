"""Release gates and model comparison (EVAL-006, EVAL-008).

EVAL-008 asks that a candidate model pass release gates before promotion. A gate here is a
set of thresholds plus, optionally, a baseline report to compare against - because an absolute
threshold alone cannot catch a model that is still above the bar but clearly worse than what
is already approved.

Two rules are deliberate:

* **A gate may only be evaluated against the same suite revision.** Comparing a candidate on
  one set of tasks with a baseline on another is not a comparison, so it is refused rather
  than reported with a caveat nobody reads.
* **A single false success fails the gate outright**, whatever the aggregate numbers say. A
  model that claims work it did not do is not a candidate for promotion at any score.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aica.evaluation.metrics import SuiteReport


class GateError(RuntimeError):
    """The gate could not be evaluated, as opposed to failing."""


@dataclass(frozen=True)
class ReleaseGate:
    """Thresholds a candidate must clear (EVAL-008).

    The defaults are deliberately not 100%: a gate nobody can pass gets switched off, and a
    switched-off gate protects nothing. They are a floor to be raised as the suite grows.
    """

    min_completion_rate: float = 0.8
    min_correctness: float = 0.8
    min_tool_reliability: float = 0.9
    max_p95_ms: int | None = None
    min_retrieval_recall: float | None = None
    # How much worse than the baseline a candidate may be on each rate before it fails.
    max_regression: float = 0.05
    # A task the baseline passed and the candidate fails is a regression whatever the rates
    # say, because the aggregate can hide it behind an unrelated improvement.
    forbid_task_regressions: bool = True


@dataclass
class GateDecision:
    passed: bool
    failures: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [f"Release gate: {'PASSED' if self.passed else 'FAILED'}"]
        lines += [f"- FAIL: {f}" for f in self.failures]
        lines += [f"- {n}" for n in self.notes]
        return "\n".join(lines)


def evaluate_gate(
    candidate: SuiteReport,
    gate: ReleaseGate | None = None,
    baseline: SuiteReport | None = None,
) -> GateDecision:
    """Decide whether ``candidate`` may be promoted (EVAL-008)."""
    gate = gate or ReleaseGate()
    failures: list[str] = []
    notes: list[str] = []

    if not candidate.results:
        raise GateError("the candidate report contains no results")

    false_successes = candidate.false_successes
    if false_successes:
        # Not a threshold: any claim of work that was not done disqualifies the candidate.
        failures.append(
            f"{len(false_successes)} false success(es): "
            + ", ".join(r.task for r in false_successes)
        )

    metrics = candidate.metrics()
    if candidate.completion_rate < gate.min_completion_rate:
        failures.append(
            f"completion rate {candidate.completion_rate:.0%} < {gate.min_completion_rate:.0%}"
        )
    if candidate.correctness < gate.min_correctness:
        failures.append(f"correctness {candidate.correctness:.0%} < {gate.min_correctness:.0%}")
    if candidate.tool_reliability < gate.min_tool_reliability:
        failures.append(
            f"tool reliability {candidate.tool_reliability:.0%} < {gate.min_tool_reliability:.0%}"
        )
    if gate.max_p95_ms is not None and candidate.p95_ms > gate.max_p95_ms:
        failures.append(f"p95 latency {candidate.p95_ms} ms > {gate.max_p95_ms} ms")
    if gate.min_retrieval_recall is not None:
        recall = candidate.retrieval_recall
        if recall is None:
            notes.append("no retrieval tasks ran, so retrieval recall was not checked")
        elif recall < gate.min_retrieval_recall:
            failures.append(f"retrieval recall {recall:.2f} < {gate.min_retrieval_recall:.2f}")
    if candidate.errors:
        failures.append(
            f"{len(candidate.errors)} task(s) errored: "
            + ", ".join(r.task for r in candidate.errors)
        )

    if baseline is not None:
        if baseline.provenance.suite_checksum != candidate.provenance.suite_checksum:
            raise GateError(
                "candidate and baseline ran different suite revisions "
                f"({candidate.provenance.suite_checksum} vs {baseline.provenance.suite_checksum}); "
                "re-run the baseline before comparing"
            )
        notes.append(f"baseline: {baseline.provenance.label()}")
        for label, now, before in (
            ("completion rate", candidate.completion_rate, baseline.completion_rate),
            ("correctness", candidate.correctness, baseline.correctness),
            ("tool reliability", candidate.tool_reliability, baseline.tool_reliability),
        ):
            if before - now > gate.max_regression:
                failures.append(
                    f"{label} regressed from {before:.0%} to {now:.0%} "
                    f"(more than the {gate.max_regression:.0%} allowance)"
                )
        if gate.forbid_task_regressions:
            passed_before = {r.task for r in baseline.results if r.passed}
            now_failing = sorted(
                r.task for r in candidate.results if r.task in passed_before and not r.passed
            )
            if now_failing:
                failures.append("task(s) the baseline passed now fail: " + ", ".join(now_failing))

    notes.append(
        f"candidate: {candidate.provenance.label()} on suite {candidate.provenance.suite} "
        f"({candidate.provenance.suite_checksum}), {metrics['tasks']} task(s)"
    )
    if candidate.provenance.model == "scripted":
        # Worth saying out loud: a scripted run measures this harness, not a model, so it can
        # never be evidence for promoting one.
        notes.append(
            "this report came from the scripted adapter, so it measures the harness and the "
            "tools - it is not evidence about a model"
        )
    return GateDecision(passed=not failures, failures=failures, notes=notes)


@dataclass
class Comparison:
    """EVAL-006: several models over the identical suite revision."""

    reports: list[SuiteReport] = field(default_factory=list)

    def add(self, report: SuiteReport) -> None:
        if self.reports:
            expected = self.reports[0].provenance.suite_checksum
            if report.provenance.suite_checksum != expected:
                raise GateError(
                    "models must be compared on the identical suite revision "
                    f"({report.provenance.suite_checksum} != {expected})"
                )
        self.reports.append(report)

    @property
    def suite_checksum(self) -> str:
        return self.reports[0].provenance.suite_checksum if self.reports else ""

    def best(self) -> SuiteReport | None:
        """The strongest candidate: correctness first, then reliability, then speed.

        Any report with a false success is excluded rather than ranked, for the same reason
        the gate fails on one.
        """
        eligible = [r for r in self.reports if not r.false_successes]
        if not eligible:
            return None
        return max(
            eligible,
            key=lambda r: (r.correctness, r.completion_rate, r.tool_reliability, -r.p95_ms),
        )

    def render(self) -> str:
        if not self.reports:
            return "no reports to compare"
        header = (
            f"{'model':<34}{'correct':>9}{'complete':>10}{'tools':>8}"
            f"{'p50 ms':>9}{'p95 ms':>9}{'false':>7}"
        )
        lines = [
            f"# Model comparison on suite {self.reports[0].provenance.suite} "
            f"({self.suite_checksum})",
            "",
            header,
            "-" * len(header),
        ]
        for report in self.reports:
            lines.append(
                f"{report.provenance.label()[:33]:<34}"
                f"{report.correctness:>8.0%} "
                f"{report.completion_rate:>9.0%} "
                f"{report.tool_reliability:>7.0%} "
                f"{report.p50_ms:>8} "
                f"{report.p95_ms:>8} "
                f"{len(report.false_successes):>6}"
            )
        winner = self.best()
        lines += [""]
        if winner is None:
            lines.append(
                "No model is eligible: every candidate claimed at least one success that "
                "verification did not support."
            )
        else:
            lines.append(f"Strongest on this suite: {winner.provenance.label()}")
        # Per-task disagreement is where a comparison earns its keep: two models with the same
        # score can fail on entirely different tasks.
        tasks = sorted({r.task for report in self.reports for r in report.results})
        split = [
            task for task in tasks if len({_passed(report, task) for report in self.reports}) > 1
        ]
        if split:
            lines += ["", "Tasks the models disagree on:"]
            for task in split:
                who = ", ".join(
                    f"{report.provenance.label()}={'pass' if _passed(report, task) else 'fail'}"
                    for report in self.reports
                )
                lines.append(f"- {task}: {who}")
        return "\n".join(lines)


def _passed(report: SuiteReport, task: str) -> bool:
    return any(r.task == task and r.passed for r in report.results)
