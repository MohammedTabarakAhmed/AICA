"""The agent loop: plan, execute, observe, adapt, verify, report (AG-001..AG-010).

The loop owns no permissions of its own. Every step goes through ``ToolRegistry.call``, so
the workspace guard, the approval gates, the uncommitted-change protection and the audit log
apply exactly as they do to a human-driven call. The loop's own job is the control flow:

* it may not run more steps or longer than the policy's ``RunBudget`` allows (AG-007);
* it stops immediately on cancellation (AG-006, SAFE-008);
* when a step fails it asks the model what to do instead, a bounded number of times (AG-004);
* it can pause and resume, because its whole state is serialisable (AG-005, NFR-002);
* it finishes through ``VerificationLedger``, so a success report is structurally impossible
  unless the required checks actually ran and passed (AG-009, TEST-009).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from aica.agent.events import AgentEvent, EventSink, EventType, NullSink, StepStatus
from aica.agent.plan import (
    ADAPT_SYSTEM,
    Adaptation,
    Plan,
    PlanError,
    Planner,
    PlanStep,
    parse_adaptation,
    tool_catalogue,
)
from aica.agent.subagents import DELEGATE_TOOL, Delegation, fold_into
from aica.approvals import ApprovalRequired
from aica.audit import EventCategory, Outcome
from aica.chat.report import FileChange, TaskReport
from aica.models.base import ChatMessage, ModelAdapter, ModelError
from aica.policy.budget import BudgetExceeded, Cancelled, RunBudget
from aica.safety.redaction import redact
from aica.testing.results import CheckStatus, VerificationLedger, parse_output
from aica.tools.base import ToolContext, ToolError, ToolNotAllowed
from aica.tools.registry import ToolRegistry

MAX_RESULT_CHARS = 4000
STATE_KEY = "agent"

# Tools whose success means a file changed - collected for the report (UX-004, AG-010).
_MUTATING: dict[str, str] = {
    "fs.write": "modified",
    "fs.edit": "modified",
    "fs.move": "moved",
    "fs.delete": "deleted",
    "fs.rollback": "modified",
}


class TaskAborted(RuntimeError):
    """The agent decided, or was told, that the task cannot continue."""


class TaskPaused(RuntimeError):
    """The run stopped at a resumable point (AG-005, UX-006)."""


@dataclass
class AgentState:
    """Everything needed to resume a run (AG-005, NFR-002, MEM-003)."""

    task: str
    plan: Plan
    ledger: VerificationLedger = field(default_factory=VerificationLedger)
    changes: list[FileChange] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    adaptations: int = 0
    steps_used: int = 0

    def to_json(self) -> str:
        return json.dumps(
            {
                "task": self.task,
                "plan": self.plan.model_dump(mode="json"),
                "required": {k: v.value for k, v in self.ledger.required.items()},
                "notes": self.ledger.notes,
                "changes": [
                    {"path": c.path, "action": c.action, "snapshot_id": c.snapshot_id}
                    for c in self.changes
                ],
                "warnings": self.warnings,
                "adaptations": self.adaptations,
                "steps_used": self.steps_used,
            }
        )

    @classmethod
    def from_json(cls, raw: str) -> AgentState:
        data = json.loads(raw)
        ledger = VerificationLedger()
        for kind, status in data.get("required", {}).items():
            ledger.required[kind] = CheckStatus(status)
        ledger.notes = list(data.get("notes", []))
        return cls(
            task=data["task"],
            plan=Plan.model_validate(data["plan"]),
            ledger=ledger,
            changes=[
                FileChange(path=c["path"], action=c["action"], snapshot_id=c.get("snapshot_id"))
                for c in data.get("changes", [])
            ],
            warnings=list(data.get("warnings", [])),
            adaptations=int(data.get("adaptations", 0)),
            steps_used=int(data.get("steps_used", 0)),
        )


class AgentLoop:
    """AG-001: takes a high-level task and carries it out under policy."""

    def __init__(
        self,
        adapter: ModelAdapter,
        registry: ToolRegistry,
        *,
        sink: EventSink | None = None,
        max_adaptations: int | None = None,
        delegation: Delegation | None = None,
    ) -> None:
        self.adapter = adapter
        self.registry = registry
        self.sink = sink or NullSink()
        self._max_adaptations = max_adaptations
        # AG-008: when set, this run may delegate sub-tasks to specialist subagents. A
        # subagent always runs with fewer tools and a slice of this run's budget; see
        # aica.agent.subagents for why neither can be widened from the inside.
        self.delegation = delegation
        # The state of the most recent run: what a caller persists to resume it later
        # (AG-005, NFR-002). Set as soon as a plan exists, so it is available even when the
        # run then fails, is cancelled or exhausts its budget.
        self.state: AgentState | None = None

    # ------------------------------------------------------------------ plumbing
    def _emit(self, **kwargs: Any) -> None:
        self.sink.emit(AgentEvent(**kwargs))

    def _budget(self, ctx: ToolContext, budget: RunBudget | None) -> RunBudget:
        if budget is not None:
            return budget
        limits = ctx.policy.autonomy
        return RunBudget(
            max_steps=limits.max_steps,
            max_seconds=float(limits.max_seconds),
            token=ctx.cancel,
        )

    def _adaptation_limit(self, ctx: ToolContext) -> int:
        if self._max_adaptations is not None:
            return self._max_adaptations
        return ctx.policy.autonomy.max_test_retries  # TEST-006 bound, reused for AG-004

    # ------------------------------------------------------------------ AG-001..AG-010
    def run(
        self,
        task: str,
        ctx: ToolContext,
        *,
        budget: RunBudget | None = None,
        context: str = "",
        conventions: str = "",
        state: AgentState | None = None,
    ) -> TaskReport:
        """Plan and execute ``task``. Always returns a report - it never raises on failure."""
        started = time.monotonic()
        budget = self._budget(ctx, budget)
        resumed = state is not None
        self._emit(
            type=EventType.RESUMED if resumed else EventType.TASK_STARTED,
            message=task,
            data={"max_steps": budget.max_steps, "max_seconds": budget.max_seconds},
        )

        base_registry = self.registry
        if self.delegation is not None:
            # agent.delegate exists for this run only, bound to this run's budget (AG-008).
            self.registry = self.delegation.registry_for(base_registry, budget)

        self.state = state
        try:
            if state is None:
                state = self._plan(task, ctx, context=context, conventions=conventions)
                self.state = state
            self._execute(state, ctx, budget)
            self._verify(state, ctx, budget)
            cancelled = False
            aborted = ""
        except Cancelled as exc:
            cancelled = True
            aborted = ""
            state = state or AgentState(task=task, plan=Plan(task=task))
            self.state = state
            self._emit(type=EventType.CANCELLED, message=str(exc))
        except (TaskAborted, PlanError, BudgetExceeded, ModelError) as exc:
            cancelled = False
            aborted = str(exc)
            state = state or AgentState(task=task, plan=Plan(task=task))
            self.state = state
            state.warnings.append(aborted)
            self._emit(type=EventType.OBSERVATION, message=f"run stopped: {aborted}")
        else:
            pass
        finally:
            self.registry = base_registry

        report = self._report(state, ctx, budget, started, cancelled=cancelled, aborted=aborted)
        self._emit(
            type=EventType.TASK_FINISHED,
            message=report.outcome(),
            data={
                "succeeded": report.succeeded,
                "changes": len(report.changes),
                "verification": report.ledger.disclosure(),
            },
        )
        return report

    # ------------------------------------------------------------------ AG-002
    def _plan(self, task: str, ctx: ToolContext, *, context: str, conventions: str) -> AgentState:
        planner = Planner(self.adapter, self.registry)
        plan = planner.create(task, ctx, context=context, conventions=conventions)
        state = AgentState(task=task, plan=plan)
        for kind in plan.verification:
            state.ledger.require(kind)
        self._emit(
            type=EventType.PLAN_CREATED,
            message=plan.summary or f"{len(plan.steps)} step(s)",
            total_steps=len(plan.steps),
            data={
                "plan": plan.render(),
                "steps": [{"id": s.id, "intent": s.intent, "tool": s.tool} for s in plan.steps],
                "verification": plan.verification,
                "model": plan.model,
            },
        )
        ctx.audit.record(
            category=EventCategory.TASK,
            action=f"plan: {task}",
            outcome=Outcome.SUCCESS,
            details={"steps": len(plan.steps), "model": plan.model},
            session_id=ctx.session_id,
        )
        return state

    # ------------------------------------------------------------------ AG-003, AG-004
    def _execute(self, state: AgentState, ctx: ToolContext, budget: RunBudget) -> None:
        limit = self._adaptation_limit(ctx)
        guard = 0
        while True:
            step = next((s for s in state.plan.steps if s.status is StepStatus.PENDING), None)
            if step is None:
                return
            guard += 1
            if guard > budget.max_steps * 2 + 10:  # defensive: never spin forever
                raise TaskAborted("step scheduling made no progress")

            budget.check()  # AG-006/AG-007 before anything happens
            number = budget.consume_step()
            state.steps_used = budget.steps_used
            step.status = StepStatus.RUNNING
            step.attempts += 1
            self._emit(
                type=EventType.STEP_STARTED,
                message=step.intent,
                step_id=step.id,
                step_number=number,
                total_steps=len(state.plan.steps),
                tool=step.tool,
                status=StepStatus.RUNNING,
            )
            self._emit(
                type=EventType.TOOL_CALLED,
                message=step.intent,
                step_id=step.id,
                step_number=number,
                tool=step.tool,
                status=StepStatus.RUNNING,
                data={"arguments": step.arguments},
            )

            try:
                result = self.registry.call(step.tool, step.arguments, ctx)
            except ApprovalRequired as exc:
                # SAFE-001/003: a denied approval is a decision, not a bug. Stop cleanly.
                step.status = StepStatus.FAILED
                step.error = str(exc)
                self._emit(
                    type=EventType.APPROVAL_REQUESTED,
                    message=str(exc),
                    step_id=step.id,
                    tool=step.tool,
                    status=StepStatus.FAILED,
                )
                raise TaskAborted(f"approval required and not granted: {exc}") from exc
            except (ToolNotAllowed, PermissionError) as exc:
                step.status = StepStatus.FAILED
                step.error = str(exc)
                self._emit(
                    type=EventType.TOOL_FAILED,
                    message=str(exc),
                    step_id=step.id,
                    tool=step.tool,
                    status=StepStatus.FAILED,
                )
                raise TaskAborted(f"policy denied {step.tool}: {exc}") from exc
            except (ToolError, ValueError, OSError) as exc:
                step.status = StepStatus.FAILED
                step.error = redact(str(exc)).text[:MAX_RESULT_CHARS]
                self._emit(
                    type=EventType.TOOL_FAILED,
                    message=step.error,
                    step_id=step.id,
                    step_number=number,
                    tool=step.tool,
                    status=StepStatus.FAILED,
                )
                self._fail_step(state, step, ctx, limit, cause=exc)
                continue

            step.result = redact(result.output).text[:MAX_RESULT_CHARS]
            # Record effects before judging the step: a failing test run still has to reach the
            # ledger, or a later passing run could mask it (AG-009).
            self._record_effects(state, step, result.data)
            payload = {
                k: v for k, v in result.data.items() if isinstance(v, str | int | float | bool)
            }

            if not result.ok:
                # A tool can report failure without raising - a red test suite, a command with a
                # non-zero exit. That is a failed step, not a completed one.
                step.status = StepStatus.FAILED
                step.error = step.result or f"{step.tool} reported failure"
                self._emit(
                    type=EventType.TOOL_FAILED,
                    message=step.error.splitlines()[0][:200],
                    step_id=step.id,
                    step_number=number,
                    tool=step.tool,
                    status=StepStatus.FAILED,
                    data=payload,
                )
                self._fail_step(state, step, ctx, limit)
                continue

            step.status = StepStatus.SUCCEEDED
            self._emit(
                type=EventType.TOOL_SUCCEEDED,
                message=step.result.splitlines()[0][:200] if step.result else "ok",
                step_id=step.id,
                step_number=number,
                tool=step.tool,
                status=StepStatus.SUCCEEDED,
                data=payload,
            )

    def _fail_step(
        self,
        state: AgentState,
        step: PlanStep,
        ctx: ToolContext,
        limit: int,
        *,
        cause: Exception | None = None,
    ) -> None:
        """AG-004/AG-007: adapt after a failed step, or stop once the allowance is spent."""
        if state.adaptations >= limit:
            raise TaskAborted(
                f"step {step.id} failed and the adaptation limit ({limit}) is reached: {step.error}"
            ) from cause
        state.adaptations += 1
        self._adapt(state, step, ctx)

    def _record_effects(self, state: AgentState, step: PlanStep, data: dict[str, Any]) -> None:
        """Collect file changes and test outcomes as they happen (AG-010, AG-009)."""
        action = _MUTATING.get(step.tool)
        if action is not None:
            path = str(step.arguments.get("path") or data.get("path") or "(unknown)")
            state.changes.append(
                FileChange(
                    path=path,
                    action=action,
                    diff=str(data.get("diff", "")),
                    snapshot_id=(str(data["snapshot_id"]) if data.get("snapshot_id") else None),
                )
            )
        if step.tool == "test.run":
            kind = str(data.get("kind", "unit"))
            outcome = parse_output(
                kind,
                str(data.get("command", "")),
                step.result,
                "",
                int(data["exit_code"]) if isinstance(data.get("exit_code"), int) else None,
            )
            # Trust the tool's parsed counts over a re-parse of the rendered summary.
            for attr in ("passed", "failed", "skipped"):
                if isinstance(data.get(attr), int):
                    setattr(outcome, attr, data[attr])
            outcome.status = (
                CheckStatus.PASSED if data.get("status") == "passed" else outcome.status
            )
            state.ledger.require(kind)
            state.ledger.record(outcome)
            self._emit(
                type=EventType.VERIFICATION,
                message=outcome.summary(),
                tool=step.tool,
                status=StepStatus.SUCCEEDED if outcome.ok else StepStatus.FAILED,
                data={"kind": kind, "passed": outcome.passed, "failed": outcome.failed},
            )
        if step.tool == DELEGATE_TOOL:
            self._fold_subagents(state)

    def _fold_subagents(self, state: AgentState) -> None:
        """AG-008 + AG-009: a subagent's changes and verification become the parent's.

        A check the child failed, or could not run, stays required here, so delegating work
        can never be a way to report a success the parent has not earned (TEST-009).
        """
        if self.delegation is None:  # pragma: no cover - only called when delegation is on
            return
        for result in self.delegation.take_results():
            state.changes += result.report.changes
            for outcome in result.report.ledger.outcomes:
                state.ledger.require(outcome.kind)
                state.ledger.record(outcome)
            warnings, unmet = fold_into(result)
            state.warnings += warnings
            for kind in unmet:
                state.ledger.require(kind)
            self._emit(
                type=EventType.VERIFICATION,
                message=f"{result.role.value} subagent: {result.report.outcome()}",
                tool=DELEGATE_TOOL,
                status=StepStatus.SUCCEEDED if result.completed else StepStatus.FAILED,
                data={
                    "role": result.role.value,
                    "steps": result.report.steps_used,
                    "changes": len(result.report.changes),
                    "verification": result.report.ledger.disclosure()[:500],
                },
            )

    def _adapt(self, state: AgentState, failed: PlanStep, ctx: ToolContext) -> None:
        """AG-004: observe the failure and change course."""
        history = "\n".join(
            f"{s.id} [{s.status.value}] {s.intent} ({s.tool})"
            + (f" -> {s.error}" if s.error else "")
            for s in state.plan.steps
        )
        messages = [
            ChatMessage(role="system", content=ADAPT_SYSTEM),
            ChatMessage(
                role="system", content="Tools available:\n" + tool_catalogue(self.registry, ctx)
            ),
            ChatMessage(
                role="user",
                content=(
                    f"Task: {state.task}\n\nPlan so far:\n{history}\n\n"
                    f"Failed step: {failed.id} ({failed.tool}) attempt {failed.attempts}\n"
                    f"Arguments: {json.dumps(failed.arguments)[:2000]}\n"
                    f"Error: {failed.error}\n\nWhat next?"
                ),
            ),
        ]
        try:
            response = self.adapter.chat(messages, temperature=0.0)
            adaptation = parse_adaptation(
                response.content, self.registry, ctx, offset=len(state.plan.steps)
            )
        except (PlanError, ModelError) as exc:
            raise TaskAborted(f"could not adapt after {failed.id} failed: {exc}") from exc

        self._apply_adaptation(state, failed, adaptation)

    def _apply_adaptation(
        self, state: AgentState, failed: PlanStep, adaptation: Adaptation
    ) -> None:
        if adaptation.action == "abort":
            raise TaskAborted(adaptation.reason or f"agent aborted after {failed.id} failed")
        if adaptation.action == "retry":
            if failed.attempts >= 2:
                raise TaskAborted(
                    f"{failed.id} failed twice with the same approach: {failed.error}"
                )
            failed.status = StepStatus.PENDING
            failed.error = ""
        elif adaptation.action == "skip":
            failed.status = StepStatus.SKIPPED
            state.warnings.append(f"{failed.id} skipped: {adaptation.reason}")
        else:  # replace
            failed.status = StepStatus.FAILED
            failed.superseded = True
            index = state.plan.steps.index(failed)
            state.plan.steps[index + 1 : index + 1] = adaptation.steps
        state.plan.revisions += 1
        self._emit(
            type=EventType.PLAN_REVISED,
            message=f"{adaptation.action}: {adaptation.reason}",
            step_id=failed.id,
            data={"action": adaptation.action, "plan": state.plan.render()},
        )

    # ------------------------------------------------------------------ AG-009
    def _verify(self, state: AgentState, ctx: ToolContext, budget: RunBudget) -> None:
        """Run any required check the plan did not already run. Failures are not fatal here:
        they must surface in the report rather than crash the run (TEST-009)."""
        for kind, status in list(state.ledger.required.items()):
            if status is CheckStatus.PASSED:
                continue
            try:
                budget.check()
            except (BudgetExceeded, Cancelled):
                state.ledger.skip(kind, "run budget exhausted before verification")
                raise
            budget.consume_step()
            try:
                result = self.registry.call("test.run", {"kind": kind}, ctx)
            except ApprovalRequired as exc:
                state.ledger.skip(kind, f"approval not granted: {exc}")
                continue
            except (ToolError, ToolNotAllowed, PermissionError, ValueError, OSError) as exc:
                state.ledger.skip(kind, str(exc))
                self._emit(
                    type=EventType.VERIFICATION,
                    message=f"{kind} could not run: {exc}",
                    status=StepStatus.SKIPPED,
                    data={"kind": kind},
                )
                continue
            step = PlanStep(id=f"verify-{kind}", intent=f"verify {kind}", tool="test.run")
            step.result = redact(result.output).text[:MAX_RESULT_CHARS]
            self._record_effects(state, step, result.data)

    # ------------------------------------------------------------------ AG-010
    def _report(
        self,
        state: AgentState,
        ctx: ToolContext,
        budget: RunBudget,
        started: float,
        *,
        cancelled: bool,
        aborted: str,
    ) -> TaskReport:
        unresolved: list[str] = []
        if aborted:
            unresolved.append(aborted)
        unresolved += [
            f"{s.id} ({s.tool}) did not complete: {s.error or s.status.value}"
            for s in state.plan.steps
            if s.status in {StepStatus.PENDING, StepStatus.FAILED, StepStatus.RUNNING}
            and not s.superseded
        ]
        # A superseded failure is still worth surfacing - it just does not block success.
        state.warnings += [
            f"{s.id} ({s.tool}) failed and was replaced: {s.error.splitlines()[0][:200]}"
            for s in state.plan.steps
            if s.superseded and s.error
        ]
        report = TaskReport(
            task=state.task,
            model=self.adapter.info.version,
            changes=state.changes,
            ledger=state.ledger,
            warnings=state.warnings,
            unresolved=unresolved,
            steps_used=budget.steps_used,
            duration_ms=int((time.monotonic() - started) * 1000),
            session_id=ctx.session_id,
            cancelled=cancelled,
        )
        ctx.audit.record(
            category=EventCategory.TASK,
            action=f"task finished: {state.task}",
            outcome=Outcome.SUCCESS if report.succeeded else Outcome.FAILURE,
            details={
                "outcome": report.outcome(),
                "steps": budget.steps_used,
                "changes": len(state.changes),
                "verification": state.ledger.disclosure()[:500],
            },
            session_id=ctx.session_id,
        )
        return report
