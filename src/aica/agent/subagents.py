"""Specialist subagents (AG-008): bounded delegation to a focused agent.

BRD 7.3 AG-008 - "Separate agents may handle research, implementation, testing or review."

A subagent is not a second privilege domain. It is the same machinery - the same tool
objects, the same workspace guard, the same approver, the same audit log - run with *less*:
a named subset of the tools, a slice of the parent's remaining budget, its own plan and its
own verification ledger.

Three properties matter more here than any feature:

* **A subagent can never widen its own permissions.** Its tools are the intersection of the
  role's list with what the parent actually holds, and its policy's ``allowed_tools`` is the
  intersection of the corresponding groups. Both narrowings run through the existing
  enforcement points - ``ToolRegistry.get`` and plan validation - so a delegated plan that
  names a tool outside the role is refused before anything executes, exactly as for a parent.
* **A subagent cannot buy its parent more autonomy.** Its steps are carved out of the
  parent's remaining budget and charged back to it when it finishes, and it shares the
  parent's cancellation token, so one stop request halts the whole tree (AG-006, SAFE-008).
* **Delegation cannot launder a false success.** The child's ledger is folded into the
  parent's: a check the child failed, or could not run, leaves the parent's report
  incomplete as well (AG-009, TEST-009).

Nesting is bounded too. A role's tool list never contains the delegation tool, and the loop
a subagent runs is constructed without a delegation capability, so a subagent cannot
delegate further.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from aica.agent.events import AgentEvent, EventSink, NullSink
from aica.chat.report import TaskReport
from aica.models.base import ModelAdapter
from aica.policy.budget import RunBudget
from aica.policy.models import AutonomyLimits
from aica.testing.results import CheckStatus
from aica.tools.base import Tool, ToolContext, ToolError, ToolResult
from aica.tools.registry import ToolRegistry

if TYPE_CHECKING:  # the loop imports this module, so the import back is annotation-only
    from aica.agent.loop import AgentLoop

DELEGATE_TOOL = "agent.delegate"
DELEGATE_GROUP = "agent"
MAX_DELEGATIONS = 4


class DelegationError(ToolError):
    """Delegation was refused: an unknown role, no budget left, or no tools in common."""


class SubagentRole(StrEnum):
    """The four roles BRD AG-008 names."""

    RESEARCH = "research"
    IMPLEMENTATION = "implementation"
    TESTING = "testing"
    REVIEW = "review"


# Read-only investigation: the tools that answer "how does this work" and nothing else.
_READ_TOOLS = frozenset(
    {
        "fs.read",
        "fs.list",
        "fs.diff",
        "git.status",
        "git.diff",
        "git.log",
        "git.branches",
        "repo.search",
        "repo.dependencies",
        "repo.stats",
        "test.discover",
    }
)


@dataclass(frozen=True)
class SubagentSpec:
    """What one role may do. ``tools`` is a ceiling, never a grant."""

    role: SubagentRole
    tools: frozenset[str]
    focus: str
    max_steps: int

    @property
    def writes(self) -> bool:
        return bool(self.tools & {"fs.write", "fs.edit", "fs.move", "fs.delete"})


SUBAGENTS: dict[SubagentRole, SubagentSpec] = {
    SubagentRole.RESEARCH: SubagentSpec(
        role=SubagentRole.RESEARCH,
        tools=_READ_TOOLS | {"repo.index"},
        focus=(
            "You are a research subagent. Your job is to find and report facts about this "
            "repository: where something lives, how it works, what depends on it. You may "
            "only read - you have no tool that changes a file, runs a command or reaches a "
            "database. Finish with the locations you found, not with a proposed edit."
        ),
        max_steps=12,
    ),
    SubagentRole.IMPLEMENTATION: SubagentSpec(
        role=SubagentRole.IMPLEMENTATION,
        tools=_READ_TOOLS
        | {
            "fs.write",
            "fs.edit",
            "fs.move",
            "fs.snapshot",
            "fs.rollback",
            "shell.run",
            "test.run",
        },
        focus=(
            "You are an implementation subagent. Make the smallest coherent change that "
            "achieves the objective, then verify it. You cannot commit, delete files or "
            "switch branches - the parent agent owns the repository's history."
        ),
        max_steps=25,
    ),
    SubagentRole.TESTING: SubagentSpec(
        role=SubagentRole.TESTING,
        tools=_READ_TOOLS | {"fs.write", "fs.edit", "fs.snapshot", "test.run", "shell.run"},
        focus=(
            "You are a testing subagent. Write or repair tests and run them. A test that "
            "passes because it asserts nothing is worse than no test: assert the behaviour "
            "the objective describes. Never weaken an assertion to make a suite green."
        ),
        max_steps=20,
    ),
    SubagentRole.REVIEW: SubagentSpec(
        role=SubagentRole.REVIEW,
        tools=_READ_TOOLS,
        focus=(
            "You are a review subagent. Read the change and report what is wrong with it: "
            "correctness, security, missing verification, accidental edits. You may only "
            "read. Report findings with file and line, and say plainly when you find none."
        ),
        max_steps=12,
    ),
}


def spec_for(role: SubagentRole | str) -> SubagentSpec:
    try:
        spec = SUBAGENTS[SubagentRole(role)]
    except ValueError as exc:
        raise DelegationError(
            f"unknown subagent role {role!r}; available: "
            + ", ".join(r.value for r in SubagentRole)
        ) from exc
    if DELEGATE_TOOL in spec.tools:  # pragma: no cover - a structural invariant
        raise DelegationError(f"the {spec.role.value} role must not be able to delegate further")
    return spec


# ---------------------------------------------------------------- the narrowing


def narrow_registry(registry: ToolRegistry, spec: SubagentSpec) -> ToolRegistry:
    """The role's tools, intersected with what this registry actually holds."""
    child = registry.subset(spec.tools)
    if not child.names():
        raise DelegationError(
            f"the {spec.role.value} role has no tools in common with this registry"
        )
    return child


def narrow_context(parent: ToolContext, registry: ToolRegistry) -> ToolContext:
    """A context identical to the parent's except that fewer tool groups are permitted.

    The intersection is the point: a role may list ``shell.run``, but if the parent's policy
    does not allow the ``shell`` group then neither does the child's.
    """
    parent_groups = set(parent.policy.autonomy.allowed_tools)
    groups = {registry.group_of(name) for name in registry.names()} & parent_groups
    if not groups:
        raise DelegationError(
            "policy allows none of the tool groups this role needs (allowed: "
            + (", ".join(sorted(parent_groups)) or "none")
            + ")"
        )
    limits = AutonomyLimits.model_validate(
        {**parent.policy.autonomy.model_dump(mode="json"), "allowed_tools": sorted(groups)}
    )
    policy = parent.policy.model_copy(update={"autonomy": limits})
    return replace(parent, policy=policy)


def child_budget(parent: RunBudget, spec: SubagentSpec, requested: int | None = None) -> RunBudget:
    """Carve a budget out of the parent's remaining allowance (AG-007)."""
    parent.check()  # a cancelled or exhausted parent delegates nothing
    steps = min(min(requested or spec.max_steps, spec.max_steps), parent.steps_remaining)
    # The two guards below are belt-and-braces: ``check()`` above already raises
    # BudgetExceeded when the parent is out of steps or time, so a caller sees that error
    # rather than these. They stay because handing a subagent a zero-step budget would be a
    # silent failure, and this file is where the bound has to hold.
    if steps <= 0:  # pragma: no cover - parent.check() above already raises in this case
        raise DelegationError("the parent's step budget is exhausted; nothing left to delegate")
    seconds = parent.max_seconds - parent.elapsed
    if seconds <= 0:  # pragma: no cover - as above
        raise DelegationError("the parent's time budget is exhausted; nothing left to delegate")
    # The shared token is what makes one cancellation stop the whole tree.
    return RunBudget(max_steps=steps, max_seconds=seconds, token=parent.token)


class SubagentSink:
    """Tags a subagent's events so a surface can nest them under the delegating step."""

    def __init__(self, inner: EventSink, role: SubagentRole, step_id: str | None = None) -> None:
        self._inner = inner
        self._role = role
        self._step_id = step_id

    def emit(self, event: AgentEvent) -> None:
        tagged: dict[str, object] = {"subagent": self._role.value}
        if self._step_id:
            tagged["parent_step"] = self._step_id
        self._inner.emit(event.model_copy(update={"data": {**event.data, **tagged}}))


@dataclass
class SubagentResult:
    role: SubagentRole
    objective: str
    report: TaskReport

    @property
    def completed(self) -> bool:
        """Did the child finish its plan and leave no required check unmet?

        Deliberately not ``report.succeeded``: a report says SUCCESS only when a required
        check actually passed, and a read-only research or review subagent has nothing to
        verify - it would always look like a failure. What a parent needs to know is whether
        the child finished and left nothing unmet. Nothing is waived by asking the narrower
        question, because the child's checks are inherited by the parent either way.
        """
        report = self.report
        return not report.cancelled and not report.unresolved and not report.ledger.unmet

    def summary(self) -> str:
        report = self.report
        lines = [
            f"{self.role.value} subagent: {report.outcome()} in {report.steps_used} step(s)",
            f"objective: {self.objective}",
        ]
        if report.changes:
            lines.append("changed: " + ", ".join(f"{c.path} ({c.action})" for c in report.changes))
        lines += report.ledger.summary_lines()
        lines += [f"unresolved: {u}" for u in report.unresolved]
        return "\n".join(lines)


class Subagent:
    """One delegated run: narrower tools, a slice of the budget, its own report."""

    def __init__(
        self,
        role: SubagentRole | str,
        adapter: ModelAdapter,
        registry: ToolRegistry,
        *,
        sink: EventSink | None = None,
    ) -> None:
        self.spec = spec_for(role)
        self.adapter = adapter
        self.registry = registry
        self.sink = sink or NullSink()

    def prepare(
        self, parent_ctx: ToolContext, parent_budget: RunBudget, *, max_steps: int | None = None
    ) -> tuple[ToolRegistry, ToolContext, RunBudget]:
        """Everything the child runs under, built before the child exists."""
        registry = narrow_registry(self.registry, self.spec)
        ctx = narrow_context(parent_ctx, registry)
        budget = child_budget(parent_budget, self.spec, max_steps)
        return registry, ctx, budget

    def run(
        self,
        objective: str,
        parent_ctx: ToolContext,
        parent_budget: RunBudget,
        *,
        context: str = "",
        max_steps: int | None = None,
        step_id: str | None = None,
    ) -> SubagentResult:
        # Imported here: loop.py imports this module, so a module-level import would cycle.
        from aica.agent.loop import AgentLoop

        registry, ctx, budget = self.prepare(parent_ctx, parent_budget, max_steps=max_steps)
        loop: AgentLoop = AgentLoop(
            self.adapter,
            registry,
            sink=SubagentSink(self.sink, self.spec.role, step_id),
            # No delegation capability is passed: a subagent does not spawn subagents.
        )
        try:
            report = loop.run(
                objective, ctx, budget=budget, context=context, conventions=self.spec.focus
            )
        finally:
            # The child's steps are the parent's steps, whatever the outcome (AG-007).
            parent_budget.steps_used += budget.steps_used
        return SubagentResult(role=self.spec.role, objective=objective, report=report)


# ---------------------------------------------------------------- the tool


class Delegation:
    """The run-scoped delegation capability handed to one parent loop.

    It holds the model adapter and collects each subagent's report, so the parent loop can
    fold the child's file changes and verification into its own.
    """

    def __init__(
        self,
        adapter: ModelAdapter,
        *,
        sink: EventSink | None = None,
        roles: set[SubagentRole] | None = None,
        max_delegations: int = MAX_DELEGATIONS,
    ) -> None:
        self.adapter = adapter
        self.sink = sink or NullSink()
        self.roles = set(roles) if roles else set(SubagentRole)
        self.max_delegations = max(1, max_delegations)
        self.used = 0
        # ``results`` is a hand-off queue the parent loop drains; ``history`` keeps every
        # report for the whole run, so a caller can still inspect what each subagent did.
        self.results: list[SubagentResult] = []
        self.history: list[SubagentResult] = []

    def registry_for(self, base: ToolRegistry, budget: RunBudget) -> ToolRegistry:
        """The parent's registry plus ``agent.delegate``, for this run only."""
        registry = base.clone()
        registry.register(DelegateTool(self, base, budget), DELEGATE_GROUP)
        return registry

    def record(self, result: SubagentResult) -> None:
        self.used += 1
        self.results.append(result)
        self.history.append(result)

    def take_results(self) -> list[SubagentResult]:
        """Hand over the reports collected so far; the caller folds them into its ledger."""
        out = self.results
        self.results = []
        return out


class DelegateTool(Tool):
    """AG-008: hand a bounded sub-task to a specialist agent."""

    name: ClassVar[str] = DELEGATE_TOOL
    description: ClassVar[str] = (
        "Delegate a self-contained sub-task to a specialist subagent and return its report. "
        "Roles: research (read-only investigation), implementation (edit and verify), "
        "testing (write and run tests), review (read-only critique). A subagent has fewer "
        "tools than you, spends steps from your budget, and cannot delegate further. Use it "
        "when a sub-task is genuinely separable; otherwise plan the steps yourself."
    )

    class Args(BaseModel):
        model_config = ConfigDict(extra="forbid")

        role: SubagentRole
        objective: str = Field(min_length=1, max_length=2000)
        context: str = Field(default="", max_length=20_000)
        max_steps: int | None = Field(default=None, ge=1, le=100)

    def __init__(self, delegation: Delegation, registry: ToolRegistry, budget: RunBudget) -> None:
        self._delegation = delegation
        self._registry = registry
        self._budget = budget

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        if not isinstance(args, DelegateTool.Args):  # pragma: no cover - parse_args guarantees it
            raise DelegationError("agent.delegate received the wrong argument type")
        delegation = self._delegation
        if args.role not in delegation.roles:
            raise DelegationError(
                f"the {args.role.value} role is not enabled for this run; enabled: "
                + (", ".join(sorted(r.value for r in delegation.roles)) or "none")
            )
        if delegation.used >= delegation.max_delegations:
            raise DelegationError(
                f"delegation limit reached ({delegation.max_delegations}); do the remaining "
                "work in your own plan"
            )
        subagent = Subagent(args.role, delegation.adapter, self._registry, sink=delegation.sink)
        result = subagent.run(
            args.objective,
            ctx,
            self._budget,
            context=args.context,
            max_steps=args.max_steps,
        )
        delegation.record(result)
        report = result.report
        return ToolResult(
            ok=result.completed,
            output=result.summary(),
            data={
                "role": args.role.value,
                "outcome": report.outcome(),
                "steps": report.steps_used,
                "changes": len(report.changes),
                "verification": report.ledger.disclosure()[:1000],
                "unresolved": len(report.unresolved),
            },
        )


def fold_into(result: SubagentResult) -> tuple[list[str], dict[str, CheckStatus]]:
    """The parts of a child's report the parent inherits: warnings, and unmet checks.

    Test outcomes are folded separately by the loop, which owns the ledger. This helper
    exists so the rule - *a check the child did not pass stays required for the parent* - is
    stated in one place and can be tested on its own.
    """
    warnings = [f"[{result.role.value}] {w}" for w in result.report.warnings]
    warnings += [f"[{result.role.value}] unresolved: {u}" for u in result.report.unresolved]
    warnings += [f"[{result.role.value}] {n}" for n in result.report.ledger.notes]
    unmet: dict[str, CheckStatus] = {
        kind: status
        for kind, status in result.report.ledger.required.items()
        if status is not CheckStatus.PASSED
    }
    return warnings, unmet
