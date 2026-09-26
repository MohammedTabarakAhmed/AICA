"""Practice runs: real agent runs that can become training data (BRD 13).

Collection (``aica adapt collect``) can only learn from agent runs that exist, and a
single developer's day produces a handful. Practice runs make more, without inventing
anything:

* **The runs are real.** Each training task is materialised in a throwaway workspace and
  run by the real agent loop, the real tools and a real routed model - exactly the
  evaluator's path (EVAL-002), which this module reuses rather than copies.
* **Only independently verified runs are kept.** The task's own verification command runs
  in its own process after the agent finishes; a run the agent called a success but that
  fails that command is discarded (TEST-009). Kept runs are saved as ordinary sessions, so
  they reach a dataset only through the usual path: the collection screen, then a human's
  approval, then the build-time screen.
* **Training tasks never overlap the golden suite.** A task whose id is also a golden
  task is refused: an adapter trained on the tasks it is graded on would pass its gate
  by memory, not by skill.

Each run's time and token usage is measured, so the cost of producing a dataset is known
before anyone commits to it.
"""

from __future__ import annotations

import json
import shutil
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from aica.agent.loop import STATE_KEY, AgentState
from aica.chat.session import Session, SessionStore
from aica.evaluation.metrics import TaskResult
from aica.evaluation.runner import Evaluator, ModelFactory
from aica.evaluation.tasks import GoldenTask, SuiteError, TaskSuite, TaskType
from aica.models.base import ChatMessage, ModelAdapter, ModelInfo, ModelResponse, StreamChunk
from aica.policy import Policy

DEFAULT_TRAINING_DIR = Path("evaluation/training")
PRACTICE_KEY = "practice"  # session.task_state entry naming the task a run came from


class UsageMeter:
    """A pass-through adapter that counts calls and tokens (streamed calls are counted,
    their tokens are not: providers do not report usage for them consistently)."""

    def __init__(self, inner: ModelAdapter) -> None:
        self._inner = inner
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0

    @property
    def info(self) -> ModelInfo:
        return self._inner.info

    def _count(self, response: ModelResponse) -> ModelResponse:
        self.calls += 1
        self.prompt_tokens += response.usage.prompt_tokens
        self.completion_tokens += response.usage.completion_tokens
        return response

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> ModelResponse:
        return self._count(
            self._inner.chat(messages, temperature=temperature, max_tokens=max_tokens)
        )

    def stream(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> Iterator[StreamChunk]:
        self.calls += 1
        return self._inner.stream(messages, temperature=temperature, max_tokens=max_tokens)

    def complete(self, prefix: str, suffix: str = "", *, max_tokens: int = 256) -> ModelResponse:
        return self._count(self._inner.complete(prefix, suffix, max_tokens=max_tokens))

    def embed(self, texts: list[str]) -> list[list[float]]:
        return self._inner.embed(texts)


@dataclass
class PracticeOutcome:
    task: str
    passed: bool
    claimed_success: bool
    seconds: float
    model: str = ""
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    steps: int = 0
    session_id: str | None = None  # set only when the run was kept
    detail: str = ""

    @property
    def tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


@dataclass
class PracticeReport:
    outcomes: list[PracticeOutcome] = field(default_factory=list)

    @property
    def kept(self) -> list[PracticeOutcome]:
        return [o for o in self.outcomes if o.session_id]

    def summary(self) -> str:
        runs = len(self.outcomes)
        if not runs:
            return "no practice runs"
        seconds = sum(o.seconds for o in self.outcomes)
        tokens = sum(o.tokens for o in self.outcomes)
        return (
            f"{len(self.kept)}/{runs} run(s) passed independent verification and were kept; "
            f"{seconds / runs:.0f}s and {tokens // runs:,} tokens per run on average "
            f"({seconds:.0f}s, {tokens:,} tokens in total)"
        )


def check_disjoint(training: TaskSuite, golden: TaskSuite) -> None:
    """Refuse training tasks that are also graded tasks."""
    overlap = sorted({t.id for t in training.tasks} & {t.id for t in golden.tasks})
    if overlap:
        raise SuiteError(
            f"training task(s) {', '.join(overlap)} are also golden tasks; an adapter trained "
            "on its own exam would pass the gate by memory (BRD 13)"
        )
    golden_sums = {t.checksum() for t in golden.tasks}
    copies = sorted(t.id for t in training.tasks if t.checksum() in golden_sums)
    if copies:
        raise SuiteError(f"training task(s) {', '.join(copies)} duplicate a golden task")


def run_practice(
    root: str | Path,
    suite: TaskSuite,
    model_for: Callable[[], ModelAdapter],
    policy: Policy,
    owner: str,
    *,
    keep_workspaces: bool = False,
    on_outcome: Callable[[PracticeOutcome], None] | None = None,
) -> PracticeReport:
    """Run every agent task in ``suite``; save the independently verified runs as sessions."""
    project = Path(root).resolve()
    store = SessionStore(project)
    workspaces = project / ".aica" / "adaptation" / "practice"
    report = PracticeReport()
    meters: dict[str, UsageMeter] = {}
    pending: dict[str, str] = {}  # task ref -> session id of the kept run

    def keep(task: GoldenTask, result: TaskResult, state: AgentState | None) -> None:
        if not result.passed or state is None:
            return
        session = Session(
            workspace=str(project),
            title=f"practice: {task.ref}",
            owner=owner,
            model_name=meters[task.ref].info.name,
            policy_version=policy.version,
        )
        session.task_state[STATE_KEY] = state.to_json()
        session.task_state[PRACTICE_KEY] = json.dumps(
            {
                "task": task.ref,
                "checksum": task.checksum(),
                "verification": result.verification,
            }
        )
        session.add("user", task.task)
        store.save(session)
        pending[task.ref] = session.session_id

    def factory(task: GoldenTask) -> ModelAdapter:
        meter = UsageMeter(model_for())
        meters[task.ref] = meter
        return meter

    metered: ModelFactory = factory
    evaluator = Evaluator(policy=policy, keep_workspaces=keep_workspaces, observer=keep)
    for task in suite.tasks:
        if task.kind is TaskType.RAG or task.expect_failure:
            continue  # nothing to learn a plan from
        workdir = workspaces / f"{task.id}-{int(time.time() * 1000)}"
        started = time.monotonic()
        result = evaluator.run_task(task, metered, workdir)
        meter = meters.get(task.ref)
        outcome = PracticeOutcome(
            task=task.ref,
            passed=result.passed,
            claimed_success=bool(result.agent_claimed_success),
            seconds=time.monotonic() - started,
            model=meter.info.version if meter else "",
            calls=meter.calls if meter else 0,
            prompt_tokens=meter.prompt_tokens if meter else 0,
            completion_tokens=meter.completion_tokens if meter else 0,
            steps=result.steps_used,
            session_id=pending.get(task.ref),
            detail=result.error or result.verification,
        )
        report.outcomes.append(outcome)
        if on_outcome is not None:
            on_outcome(outcome)
        if not keep_workspaces:
            shutil.rmtree(workdir, ignore_errors=True)
    return report
