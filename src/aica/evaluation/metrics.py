"""Evaluation results and the metrics computed from them (EVAL-002..007, EVAL-009).

Every number here is derived from something that actually happened: a verification command's
exit code, the agent's own event stream, a retrieval against a real index, a measured
duration. Nothing is inferred from what a model said about its own work.

``Provenance`` is EVAL-009. A result that cannot say which model, version, adapter, prompt
revision, suite revision and policy produced it is not reproducible, so a report carries all
of it and refuses to average results that came from different models.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class Provenance:
    """EVAL-009: everything needed to reproduce a result."""

    model: str = ""  # registry name
    model_version: str = ""  # exact served version
    adapter: str | None = None  # MM-014 adapter, when one answered
    suite: str = ""
    suite_checksum: str = ""
    prompt_checksum: str = ""  # fingerprint of the system prompts in force
    policy_version: int = 0
    commit: str = ""  # the harness's own revision, when Git can tell us
    started: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def label(self) -> str:
        text = f"{self.model}@{self.model_version}"
        if self.adapter:
            text += f"+{self.adapter}"
        return text


@dataclass
class TaskResult:
    """What happened on one task."""

    task: str  # id@vN
    kind: str
    checksum: str
    passed: bool
    duration_ms: int
    expect_failure: bool = False

    # EVAL-003/004: what the run did, from the agent's event stream.
    steps_used: int = 0
    tool_calls: int = 0
    tool_failures: int = 0
    invalid_tool_calls: int = 0  # arguments rejected before execution (MCP-003)
    adaptations: int = 0

    # EVAL-002: what the verification command said, independently of the agent.
    verification: str = ""
    verification_output: str = ""
    agent_claimed_success: bool = False

    # EVAL-005: retrieval quality for a rag task.
    precision: float | None = None
    recall: float | None = None
    reciprocal_rank: float | None = None
    retrieved: list[str] = field(default_factory=list)

    error: str = ""
    # The golden task's tags, so a gate can hold a class of task - security - to its own bar.
    tags: list[str] = field(default_factory=list)

    @property
    def as_expected(self) -> bool:
        """A task expected to fail counts as correct behaviour when it fails."""
        return self.passed != self.expect_failure

    @property
    def honest(self) -> bool:
        """False when the agent claimed success that verification did not support.

        This is the metric that matters most in this project: a run where these disagree is a
        false-success bug, not a scoring detail (TEST-009, AG-009).
        """
        return not (self.agent_claimed_success and not self.passed)

    def summary(self) -> str:
        mark = "pass" if self.passed else "FAIL"
        if self.expect_failure:
            mark += " (expected to fail)"
        extra = ""
        if self.precision is not None:
            extra = f" precision={self.precision:.2f} recall={self.recall:.2f}"
        return (
            f"{self.task:<28} {mark:<24} {self.duration_ms:>6} ms "
            f"steps={self.steps_used} tools={self.tool_calls}/{self.tool_failures} failed{extra}"
        )


@dataclass
class SuiteReport:
    """Aggregated metrics for one model over one suite revision."""

    provenance: Provenance
    results: list[TaskResult] = field(default_factory=list)

    # ------------------------------------------------------------------ EVAL-002/003
    @property
    def agent_results(self) -> list[TaskResult]:
        return [r for r in self.results if r.kind == "agent"]

    @property
    def rag_results(self) -> list[TaskResult]:
        return [r for r in self.results if r.kind == "rag"]

    @property
    def completion_rate(self) -> float:
        """EVAL-003: the share of agent tasks that behaved as the suite expects."""
        agent = self.agent_results
        if not agent:
            return 0.0
        return sum(1 for r in agent if r.as_expected) / len(agent)

    @property
    def correctness(self) -> float:
        """EVAL-002: the share of tasks meant to be completed whose tests really pass."""
        expected = [r for r in self.agent_results if not r.expect_failure]
        if not expected:
            return 0.0
        return sum(1 for r in expected if r.passed) / len(expected)

    # ------------------------------------------------------------------ EVAL-004
    @property
    def _measured(self) -> list[TaskResult]:
        """Tasks whose tool calls say something about reliability.

        A control task that is *meant* to fail ends with a deliberately red test run, which is
        a correct tool call reporting a correct failure. Counting it as a tool defect would
        mean the more honesty checks a suite gains, the worse its reliability score looks -
        and the default gate could never pass.
        """
        return [r for r in self.results if not r.expect_failure]

    @property
    def tool_calls(self) -> int:
        return sum(r.tool_calls for r in self._measured)

    @property
    def tool_failures(self) -> int:
        return sum(r.tool_failures for r in self._measured)

    @property
    def invalid_tool_calls(self) -> int:
        return sum(r.invalid_tool_calls for r in self._measured)

    @property
    def tool_reliability(self) -> float:
        """EVAL-004: the share of tool calls that succeeded. 1.0 when nothing was called."""
        if not self.tool_calls:
            return 1.0
        return 1.0 - (self.tool_failures / self.tool_calls)

    # ------------------------------------------------------------------ EVAL-005
    @property
    def retrieval_precision(self) -> float | None:
        values = [r.precision for r in self.rag_results if r.precision is not None]
        return statistics.fmean(values) if values else None

    @property
    def retrieval_recall(self) -> float | None:
        values = [r.recall for r in self.rag_results if r.recall is not None]
        return statistics.fmean(values) if values else None

    @property
    def retrieval_mrr(self) -> float | None:
        values = [r.reciprocal_rank for r in self.rag_results if r.reciprocal_rank is not None]
        return statistics.fmean(values) if values else None

    # ------------------------------------------------------------------ EVAL-007
    @property
    def durations(self) -> list[int]:
        return sorted(r.duration_ms for r in self.results)

    @property
    def p50_ms(self) -> int:
        return self._percentile(50)

    @property
    def p95_ms(self) -> int:
        return self._percentile(95)

    def _percentile(self, pct: int) -> int:
        values = self.durations
        if not values:
            return 0
        # Nearest-rank, so a small suite reports a real measurement rather than an
        # interpolation between two runs that never happened.
        index = min(len(values) - 1, max(0, round(pct / 100 * len(values)) - 1))
        return values[index]

    # ------------------------------------------------------------------ honesty
    @property
    def false_successes(self) -> list[TaskResult]:
        """Runs where the agent claimed success and verification disagreed."""
        return [r for r in self.results if not r.honest]

    @property
    def errors(self) -> list[TaskResult]:
        return [r for r in self.results if r.error]

    # ------------------------------------------------------------------ rendering
    def metrics(self) -> dict[str, Any]:
        return {
            "tasks": len(self.results),
            "completion_rate": round(self.completion_rate, 4),
            "correctness": round(self.correctness, 4),
            "tool_calls": self.tool_calls,
            "tool_failures": self.tool_failures,
            "invalid_tool_calls": self.invalid_tool_calls,
            "tool_reliability": round(self.tool_reliability, 4),
            "retrieval_precision": _round(self.retrieval_precision),
            "retrieval_recall": _round(self.retrieval_recall),
            "retrieval_mrr": _round(self.retrieval_mrr),
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "false_successes": len(self.false_successes),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            {
                "provenance": asdict(self.provenance),
                "metrics": self.metrics(),
                "results": [asdict(r) for r in self.results],
            },
            indent=indent,
        )

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_json(), encoding="utf-8")
        return target

    @classmethod
    def load(cls, path: str | Path) -> SuiteReport:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        provenance = Provenance(**data.get("provenance", {}))
        results = [TaskResult(**r) for r in data.get("results", [])]
        return cls(provenance=provenance, results=results)

    def render(self) -> str:
        m = self.metrics()
        lines = [
            f"# Evaluation: {self.provenance.suite} on {self.provenance.label()}",
            "",
            f"Suite revision {self.provenance.suite_checksum}; "
            f"prompts {self.provenance.prompt_checksum}; policy v{self.provenance.policy_version}"
            + (f"; commit {self.provenance.commit}" if self.provenance.commit else ""),
            "",
            f"- Completion rate (EVAL-003): {m['completion_rate']:.0%}",
            f"- Correctness (EVAL-002):     {m['correctness']:.0%}",
            f"- Tool reliability (EVAL-004): {m['tool_reliability']:.0%} "
            f"({m['tool_failures']} of {m['tool_calls']} calls failed, "
            f"{m['invalid_tool_calls']} rejected as invalid)",
        ]
        if m["retrieval_precision"] is not None:
            lines.append(
                f"- Retrieval (EVAL-005): precision {m['retrieval_precision']:.2f}, "
                f"recall {m['retrieval_recall']:.2f}, MRR {m['retrieval_mrr']:.2f}"
            )
        lines += [
            f"- Latency (EVAL-007): p50 {m['p50_ms']} ms, p95 {m['p95_ms']} ms",
            "",
            "## Tasks",
            *(f"- {r.summary()}" for r in self.results),
        ]
        if self.false_successes:
            lines += [
                "",
                "## FALSE SUCCESS - the agent claimed work it had not done",
                *(f"- {r.task}: {r.verification}" for r in self.false_successes),
            ]
        if self.errors:
            lines += ["", "## Errors", *(f"- {r.task}: {r.error}" for r in self.errors)]
        return "\n".join(lines)


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 4)


def retrieval_scores(retrieved: list[str], relevant: list[str]) -> tuple[float, float, float]:
    """EVAL-005: precision, recall and reciprocal rank of one retrieval.

    Precision is over what was returned, recall over what should have been found, and the
    reciprocal rank rewards putting a relevant file first - which is what actually matters
    when the result is fed to a model with a limited context.
    """
    if not retrieved:
        return 0.0, 0.0, 0.0
    wanted = set(relevant)
    hits = [path for path in retrieved if path in wanted]
    precision = len(set(hits)) / len(dict.fromkeys(retrieved))
    recall = len(set(hits)) / len(wanted) if wanted else 0.0
    rank = next((i for i, path in enumerate(retrieved, start=1) if path in wanted), 0)
    return precision, recall, (1.0 / rank if rank else 0.0)
