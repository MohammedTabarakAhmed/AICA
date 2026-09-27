"""Running the golden suite (EVAL-002..007, EVAL-009).

Each task runs in a throwaway workspace this module creates, with the real agent loop, the
real tool registry and the real guards. Then - and this is the part that matters - success is
decided by running the task's own verification command as a separate process. The agent's
report is recorded alongside it, and any disagreement between the two is reported as a false
success rather than averaged away.

The model is supplied by a factory, so the same suite runs against a scripted adapter (which
measures this harness and the tools, *not* a model) or against any approved model through the
router (which measures the model). A report always says which it was.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from aica.agent.events import EventType, ListSink
from aica.agent.loop import AgentLoop, AgentState
from aica.agent.plan import ADAPT_SYSTEM, PLANNER_SYSTEM
from aica.approvals import AllowAllApprover
from aica.audit import AuditLog, InMemoryAuditSink
from aica.evaluation.metrics import Provenance, SuiteReport, TaskResult, retrieval_scores
from aica.evaluation.tasks import GoldenTask, TaskSuite, TaskType
from aica.models.base import ModelAdapter
from aica.models.fake import ScriptedAdapter
from aica.models.routing import ModelRouter, TaskKind
from aica.policy import Policy
from aica.policy.budget import RunBudget
from aica.rag.index import RepositoryIndex
from aica.tools import ToolContext, default_registry
from aica.workspace import WorkspaceGuard

ModelFactory = Callable[[GoldenTask], ModelAdapter]
# Sees each agent task once its verification has run: the task, the result, the agent's final
# state. Practice runs (BRD 13) use it to keep independently verified runs as training data.
AgentObserver = Callable[[GoldenTask, TaskResult, AgentState | None], None]

# A reply the scripted adapter falls back to when a task defines no canned plan: refusing to
# invent one keeps "the harness works" and "the model works" from being confused.
NO_SCRIPT = "the task defines no scripted reply"


def prompt_checksum() -> str:
    """EVAL-009: a fingerprint of the prompts in force, so a result names its prompt revision."""
    digest = hashlib.sha256()
    for prompt in (PLANNER_SYSTEM, ADAPT_SYSTEM):
        digest.update(prompt.encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()[:16]


def repository_commit(root: Path | None = None) -> str:
    """The harness's own revision, when Git can tell us. Never fatal."""
    try:
        git = shutil.which("git")
        if git is None:  # pragma: no cover - git is present wherever this is developed
            return ""
        done = subprocess.run(  # noqa: S603 - a fixed argv, with git resolved from PATH
            [git, "rev-parse", "--short", "HEAD"],
            cwd=root or Path.cwd(),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - git missing or odd
        return ""
    return done.stdout.strip() if done.returncode == 0 else ""


def scripted_factory(task: GoldenTask) -> ModelAdapter:
    """The offline factory: each task's own canned replies.

    What this measures is the harness, the tools and the verification path - not a model. A
    report produced this way says ``scripted`` as its model, and nothing here pretends
    otherwise.
    """
    return ScriptedAdapter(list(task.scripted) or [NO_SCRIPT], name="scripted")


def router_factory(
    router: ModelRouter, kind: TaskKind = TaskKind.PLANNING, *, requested: str | None = None
) -> ModelFactory:
    """MM-004 + EVAL-006: the same routing rules the product uses, for every task.

    A ``requested`` model is measured alone, with no fallback chain: a report that names it
    must never contain another model's answers (found live: `--model` was recorded in the
    report while the agent was served by the routing default).
    """

    def factory(task: GoldenTask) -> ModelAdapter:
        if requested is not None:
            return router.gateway.get(requested)
        return router.select(kind).adapter

    return factory


@dataclass
class Evaluator:
    """Runs a suite and returns a report. One instance per model under evaluation."""

    policy: Policy | None = None
    workspace_root: Path | None = None  # where task workspaces are created (default: temp)
    keep_workspaces: bool = False  # for debugging a failing task
    observer: AgentObserver | None = None

    def _context(self, root: Path) -> tuple[ToolContext, RepositoryIndex]:
        policy = self.policy or Policy()
        guard = WorkspaceGuard(root, policy.autonomy.allowed_directories)
        index = RepositoryIndex(guard)
        context = ToolContext(
            workspace=guard,
            policy=policy,
            audit=AuditLog(InMemoryAuditSink(), actor="evaluation"),
            # The workspace is a throwaway directory created for this one task, so approving
            # automatically here grants nothing outside it. A gate that always denies would
            # measure the approver rather than the agent.
            approver=AllowAllApprover(),
            index=index,
        )
        return context, index

    # ------------------------------------------------------------------ one task
    def run_task(self, task: GoldenTask, factory: ModelFactory, root: Path) -> TaskResult:
        started = time.monotonic()
        result = TaskResult(
            task=task.ref,
            kind=task.kind.value,
            checksum=task.checksum(),
            passed=False,
            duration_ms=0,
            expect_failure=task.expect_failure,
            tags=list(task.tags),
        )
        task.materialize(root)
        context, index = self._context(root)
        try:
            if task.kind is TaskType.RAG:
                self._retrieval(task, result, index)
            else:
                self._agent(task, factory, result, context, index)
        except Exception as exc:  # noqa: BLE001 - one broken task must not stop the suite
            result.error = f"{type(exc).__name__}: {exc}"[:500]
        finally:
            index.close()
            result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    def _retrieval(self, task: GoldenTask, result: TaskResult, index: RepositoryIndex) -> None:
        """EVAL-005: retrieval quality against files known to answer the query."""
        index.index_repository()
        found = index.search(task.query, task.retrieve)
        result.retrieved = [hit.path for hit in found]
        precision, recall, rank = retrieval_scores(result.retrieved, task.relevant_paths)
        result.precision, result.recall, result.reciprocal_rank = precision, recall, rank
        # A retrieval task passes when at least one genuinely relevant file came back: that is
        # the property the agent depends on. Precision and recall are reported as numbers.
        result.passed = recall > 0
        result.verification = (
            f"recall {recall:.2f} over {len(task.relevant_paths)} relevant file(s), "
            f"precision {precision:.2f} over {len(result.retrieved)} returned"
        )

    def _agent(
        self,
        task: GoldenTask,
        factory: ModelFactory,
        result: TaskResult,
        context: ToolContext,
        index: RepositoryIndex,
    ) -> None:
        sink = ListSink()
        loop = AgentLoop(factory(task), default_registry(), sink=sink)
        budget = RunBudget(max_steps=task.max_steps, max_seconds=float(task.max_seconds))
        report = loop.run(task.task, context, budget=budget)

        result.steps_used = report.steps_used
        result.agent_claimed_success = report.succeeded
        # EVAL-004 from the event stream: what was called, and what came back.
        result.tool_calls = len(sink.of_type(EventType.TOOL_CALLED))
        failures = sink.of_type(EventType.TOOL_FAILED)
        result.tool_failures = len(failures)
        result.invalid_tool_calls = sum(1 for e in failures if "invalid arguments" in e.message)
        result.adaptations = len(sink.of_type(EventType.PLAN_REVISED))

        # EVAL-002: the task's own command decides, in its own process, after the fact.
        passed, output = task.run_verification(Path(context.workspace.root))
        result.passed = passed
        result.verification_output = output[-2000:]
        result.verification = f"`{task.verify}` -> {'passed' if passed else 'failed'}"
        if result.agent_claimed_success and not passed:
            result.verification += " while the agent reported SUCCESS"
        if self.observer is not None:
            self.observer(task, result, loop.state)

    # ------------------------------------------------------------------ the suite
    def run(
        self,
        suite: TaskSuite,
        factory: ModelFactory = scripted_factory,
        provenance: Provenance | None = None,
    ) -> SuiteReport:
        """Run every task in ``suite`` and return the report with its provenance filled in."""
        policy = self.policy or Policy()
        record = provenance or Provenance(model="scripted", model_version="scripted")
        record.suite = suite.name
        record.suite_checksum = suite.checksum()
        record.prompt_checksum = prompt_checksum()
        record.policy_version = policy.version
        record.commit = record.commit or repository_commit()
        report = SuiteReport(provenance=record)

        base = self.workspace_root
        with tempfile.TemporaryDirectory(prefix="aica-eval-") as temporary:
            parent = base or Path(temporary)
            for task in suite.tasks:
                root = parent / f"{task.id}-{int(time.time() * 1000)}"
                report.results.append(self.run_task(task, factory, root))
        return report
