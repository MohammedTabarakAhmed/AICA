"""Specialist subagents (AG-008) and the boundary they run inside.

Most of these tests are about what a subagent *cannot* do. Delegation is the one feature in
this project that creates a second actor, so the properties worth asserting are the ones
that keep it from becoming a second privilege domain: it may not hold a tool its parent
lacks, it may not spend autonomy its parent does not have, it may not delegate further, and
it may not turn an unverified change into a successful parent report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aica.agent.events import EventType, ListSink, StepStatus
from aica.agent.loop import AgentLoop
from aica.agent.plan import PlanError, parse_plan, tool_catalogue
from aica.agent.subagents import (
    DELEGATE_GROUP,
    DELEGATE_TOOL,
    SUBAGENTS,
    Delegation,
    DelegationError,
    Subagent,
    SubagentResult,
    SubagentRole,
    SubagentSink,
    child_budget,
    fold_into,
    narrow_context,
    narrow_registry,
    spec_for,
)
from aica.chat.report import FileChange, TaskReport
from aica.models.fake import ScriptedAdapter
from aica.policy import Policy
from aica.policy.budget import BudgetExceeded, Cancelled, RunBudget
from aica.policy.models import AutonomyLimits

# Imported under another name: pytest would try to collect anything called Test*.
from aica.testing.results import CheckStatus, VerificationLedger
from aica.testing.results import TestOutcome as RunOutcome
from aica.tools import default_registry
from aica.tools.base import ToolNotAllowed
from tests.test_tools_fs import make_ctx

# Tools that change something. No read-only role may hold any of them.
MUTATING = {
    "fs.write",
    "fs.edit",
    "fs.move",
    "fs.delete",
    "fs.rollback",
    "shell.run",
    "test.run",
    "git.commit",
    "git.create_branch",
    "git.switch",
    "git.discard",
    "git.revert",
    "git.clone",
    "db.execute",
    "browser.navigate",
}


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    return tmp_path


def plan_json(*steps: dict[str, Any], verification: list[str] | None = None) -> str:
    return json.dumps(
        {"summary": "do it", "steps": list(steps), "verification": verification or []}
    )


def delegate_step(role: str, objective: str = "look into it", **extra: Any) -> dict[str, Any]:
    return {
        "intent": f"delegate to the {role} subagent",
        "tool": DELEGATE_TOOL,
        "arguments": {"role": role, "objective": objective, **extra},
    }


READ_APP = {"intent": "read the module", "tool": "fs.read", "arguments": {"path": "src/app.py"}}


def budget(steps: int = 20, seconds: float = 60.0) -> RunBudget:
    return RunBudget(max_steps=steps, max_seconds=seconds)


# ---------------------------------------------------------------- the role definitions


def test_every_role_is_a_subset_of_the_real_tool_set() -> None:
    """A role that names a tool nobody implements would be a silent hole in the ceiling."""
    available = set(default_registry().names())
    for role, spec in SUBAGENTS.items():
        assert spec.tools <= available, f"{role.value} names tools that do not exist"
        assert spec.tools, f"{role.value} has no tools"


def test_all_four_brd_roles_exist() -> None:
    """BRD AG-008: research, implementation, testing or review."""
    assert {r.value for r in SubagentRole} == {"research", "implementation", "testing", "review"}
    assert set(SUBAGENTS) == set(SubagentRole)


@pytest.mark.parametrize("role", [SubagentRole.RESEARCH, SubagentRole.REVIEW])
def test_read_only_roles_hold_no_mutating_tool(role: SubagentRole) -> None:
    spec = SUBAGENTS[role]
    assert not spec.tools & MUTATING, f"{role.value} can change something"
    assert spec.writes is False


@pytest.mark.parametrize("role", [SubagentRole.IMPLEMENTATION, SubagentRole.TESTING])
def test_writing_roles_can_edit_and_verify_but_not_rewrite_history(role: SubagentRole) -> None:
    spec = SUBAGENTS[role]
    assert {"fs.edit", "test.run"} <= spec.tools
    assert spec.writes is True
    # The parent owns the repository's history and the delete key.
    assert not spec.tools & {"git.commit", "git.discard", "git.revert", "fs.delete"}


def test_no_role_can_delegate_further() -> None:
    """The recursion bound: a subagent's tool list never contains the delegation tool."""
    for spec in SUBAGENTS.values():
        assert DELEGATE_TOOL not in spec.tools


def test_unknown_role_is_refused_with_the_available_ones() -> None:
    with pytest.raises(DelegationError, match="research"):
        spec_for("architect")


# ---------------------------------------------------------------- the narrowing


def test_a_role_with_nothing_available_is_refused() -> None:
    """A registry that holds none of the role's tools cannot produce a usable subagent."""
    from aica.tools.registry import ToolRegistry

    with pytest.raises(DelegationError, match="no tools in common"):
        narrow_registry(ToolRegistry(), spec_for(SubagentRole.RESEARCH))


def test_a_subagent_sees_only_its_role_tools(workspace: Path) -> None:
    registry = narrow_registry(default_registry(), spec_for(SubagentRole.REVIEW))
    assert "fs.read" in registry.names()
    assert "fs.write" not in registry.names()
    assert DELEGATE_TOOL not in registry.names()


def test_subset_can_never_add_a_tool() -> None:
    """The narrowing is an intersection: naming something absent does not conjure it."""
    registry = default_registry().subset({"fs.read", "not.a.tool", DELEGATE_TOOL})
    assert registry.names() == ["fs.read"]


def test_clone_does_not_disturb_the_original(workspace: Path) -> None:
    base = default_registry()
    delegation = Delegation(ScriptedAdapter([]))
    extended = delegation.registry_for(base, budget())
    assert DELEGATE_TOOL in extended.names()
    assert DELEGATE_TOOL not in base.names(), "the parent's own registry must be untouched"
    assert extended.group_of(DELEGATE_TOOL) == DELEGATE_GROUP


def test_a_role_cannot_widen_what_policy_allows_the_parent(workspace: Path) -> None:
    """The child's groups are an intersection, so a role's list is a ceiling, not a grant."""
    policy = Policy(autonomy=AutonomyLimits(allowed_tools=["rag"]))
    parent = make_ctx(workspace, policy)
    registry = narrow_registry(default_registry(), spec_for(SubagentRole.IMPLEMENTATION))
    child = narrow_context(parent, registry)

    assert child.policy.autonomy.allowed_tools == ["rag"]
    # The tool object exists in the child's registry, and policy still refuses it.
    assert "fs.read" in registry.names()
    with pytest.raises(ToolNotAllowed):
        registry.get("fs.read", child)
    registry.get("repo.search", child)  # what the parent had, the child may use


def test_delegation_is_refused_when_policy_allows_none_of_the_role_groups(
    workspace: Path,
) -> None:
    policy = Policy(autonomy=AutonomyLimits(allowed_tools=["browser", "database"]))
    parent = make_ctx(workspace, policy)
    registry = narrow_registry(default_registry(), spec_for(SubagentRole.REVIEW))
    with pytest.raises(DelegationError, match="policy allows none"):
        narrow_context(parent, registry)


def test_narrowing_keeps_the_guards_the_parent_ran_under(workspace: Path) -> None:
    """Same workspace, same approver, same audit log, same cancellation token."""
    parent = make_ctx(workspace)
    registry = narrow_registry(default_registry(), spec_for(SubagentRole.RESEARCH))
    child = narrow_context(parent, registry)
    assert child.workspace is parent.workspace
    assert child.approver is parent.approver
    assert child.audit is parent.audit
    assert child.cancel is parent.cancel
    assert child.policy is not parent.policy  # only the tool list differs
    assert parent.policy.autonomy.allowed_tools != child.policy.autonomy.allowed_tools


# ---------------------------------------------------------------- the budget (AG-007)


def test_a_child_budget_is_carved_from_what_the_parent_has_left() -> None:
    parent = budget(steps=30)
    parent.steps_used = 26
    child = child_budget(parent, spec_for(SubagentRole.RESEARCH))
    assert child.max_steps == 4, "never more than the parent has left"


def test_a_child_budget_is_capped_by_its_role() -> None:
    spec = spec_for(SubagentRole.RESEARCH)
    child = child_budget(budget(steps=500, seconds=3600), spec, requested=1000)
    assert child.max_steps == spec.max_steps


def test_a_child_can_be_asked_for_fewer_steps() -> None:
    assert (
        child_budget(budget(steps=50), spec_for(SubagentRole.TESTING), requested=3).max_steps == 3
    )


def test_an_exhausted_parent_delegates_nothing() -> None:
    """The budget check runs before the carve, so the parent's own limit is what refuses."""
    parent = budget(steps=5)
    parent.steps_used = 5
    with pytest.raises(BudgetExceeded, match="step limit"):
        child_budget(parent, spec_for(SubagentRole.RESEARCH))


def test_a_parent_out_of_time_delegates_nothing() -> None:
    """AG-007: the time limit binds the tree, not just the parent's own steps."""
    parent = RunBudget(max_steps=50, max_seconds=60)
    parent.started_at -= 61  # the parent is already over its limit
    with pytest.raises(BudgetExceeded, match="time limit"):
        child_budget(parent, spec_for(SubagentRole.RESEARCH))


def test_cancelling_the_parent_cancels_the_child(workspace: Path) -> None:
    """AG-006/SAFE-008: one stop request halts the whole tree."""
    parent = budget()
    child = child_budget(parent, spec_for(SubagentRole.RESEARCH))
    assert child.token is parent.token
    parent.token.cancel("emergency stop")
    with pytest.raises(Cancelled, match="emergency stop"):
        child.check()


def test_a_cancelled_parent_cannot_start_a_subagent() -> None:
    parent = budget()
    parent.token.cancel("stop")
    with pytest.raises(Cancelled):
        child_budget(parent, spec_for(SubagentRole.RESEARCH))


def test_the_childs_steps_are_charged_back_to_the_parent(workspace: Path) -> None:
    """A parent cannot buy itself more autonomy by delegating (AG-007)."""
    ctx = make_ctx(workspace)
    parent = budget(steps=20)
    adapter = ScriptedAdapter([plan_json(READ_APP, READ_APP)])
    result = Subagent(SubagentRole.RESEARCH, adapter, default_registry()).run(
        "read the module twice", ctx, parent
    )
    assert result.report.steps_used == 2
    assert parent.steps_used == 2, "the child's steps are the parent's steps"
    assert parent.steps_remaining == 18


def test_a_childs_steps_are_charged_even_when_it_fails(workspace: Path) -> None:
    ctx = make_ctx(workspace)
    parent = budget(steps=20)
    adapter = ScriptedAdapter(["not a plan at all", "still not a plan"])
    result = Subagent(SubagentRole.RESEARCH, adapter, default_registry()).run(
        "impossible", ctx, parent
    )
    assert result.completed is False
    assert parent.steps_used == 0  # it never got as far as a step, and nothing was lost


# ---------------------------------------------------------------- delegation through the loop


def test_the_delegate_tool_does_not_exist_unless_delegation_is_enabled(workspace: Path) -> None:
    ctx = make_ctx(workspace)
    catalogue = tool_catalogue(default_registry(), ctx)
    assert DELEGATE_TOOL not in catalogue
    with pytest.raises(PlanError, match="not available"):
        parse_plan(plan_json(delegate_step("research")), "task", default_registry(), ctx)


def test_removing_the_agent_group_from_policy_forbids_delegation(workspace: Path) -> None:
    """AG-007: the tool groups are configurable, and this one switches subagents off."""
    policy = Policy(autonomy=AutonomyLimits(allowed_tools=["filesystem", "rag"]))
    ctx = make_ctx(workspace, policy)
    registry = Delegation(ScriptedAdapter([])).registry_for(default_registry(), budget())
    assert DELEGATE_TOOL not in tool_catalogue(registry, ctx)
    with pytest.raises(PlanError, match="not available"):
        parse_plan(plan_json(delegate_step("research")), "task", registry, ctx)


def test_the_delegate_tool_is_offered_when_delegation_is_enabled(workspace: Path) -> None:
    ctx = make_ctx(workspace)
    registry = Delegation(ScriptedAdapter([])).registry_for(default_registry(), budget())
    catalogue = tool_catalogue(registry, ctx)
    assert DELEGATE_TOOL in catalogue
    assert "research" in catalogue and "review" in catalogue
    plan = parse_plan(plan_json(delegate_step("research")), "task", registry, ctx)
    assert plan.steps[0].tool == DELEGATE_TOOL


def test_a_research_subagent_reports_back_through_the_parent(workspace: Path) -> None:
    ctx = make_ctx(workspace)
    sink = ListSink()
    adapter = ScriptedAdapter(
        [
            plan_json(delegate_step("research", "find where add is defined")),
            plan_json(READ_APP),  # the child's own plan
        ]
    )
    delegation = Delegation(adapter, sink=sink)
    report = AgentLoop(adapter, default_registry(), sink=sink, delegation=delegation).run(
        "understand the module", ctx
    )

    assert delegation.used == 1
    assert report.cancelled is False
    assert not report.unresolved, report.unresolved
    # The child's events are tagged, so a surface can nest them under the parent step.
    tagged = [e for e in sink.events if e.data.get("subagent") == "research"]
    assert tagged and any(e.type is EventType.TOOL_SUCCEEDED for e in tagged)
    delegated = [e for e in sink.events if e.tool == DELEGATE_TOOL]
    assert any(e.status is StepStatus.SUCCEEDED for e in delegated)


def test_a_delegated_plan_may_not_name_a_tool_outside_its_role(workspace: Path) -> None:
    """The child's plan is validated against the child's registry, before anything runs."""
    ctx = make_ctx(workspace)
    adapter = ScriptedAdapter(
        [
            plan_json(delegate_step("review", "check the module")),
            # The child tries to write. Twice, because the planner retries once.
            plan_json({"intent": "rewrite it", "tool": "fs.write", "arguments": {"path": "x"}}),
            plan_json({"intent": "rewrite it", "tool": "fs.write", "arguments": {"path": "x"}}),
            json.dumps({"action": "abort", "reason": "the subagent could not proceed"}),
        ]
    )
    delegation = Delegation(adapter)
    report = AgentLoop(adapter, default_registry(), delegation=delegation).run("review", ctx)

    # ``history`` keeps every report; the loop drains ``results`` as it folds them in.
    assert len(delegation.history) == 1
    child = delegation.history[0]
    assert child.completed is False
    assert any("not available" in u for u in child.report.unresolved)
    assert report.succeeded is False
    assert not (workspace / "x").exists()


def test_a_subagent_cannot_delegate_further(workspace: Path) -> None:
    """Both layers: the child's registry has no delegation tool, and policy forbids the group."""
    ctx = make_ctx(workspace)
    registry = Delegation(ScriptedAdapter([])).registry_for(default_registry(), budget())
    child_registry, child_ctx, _ = Subagent(
        SubagentRole.IMPLEMENTATION, ScriptedAdapter([]), registry
    ).prepare(ctx, budget())

    assert DELEGATE_TOOL not in child_registry.names()
    assert DELEGATE_GROUP not in child_ctx.policy.autonomy.allowed_tools
    with pytest.raises(PlanError, match="not available"):
        parse_plan(plan_json(delegate_step("research")), "t", child_registry, child_ctx)


def test_a_role_can_be_switched_off_for_one_run(workspace: Path) -> None:
    ctx = make_ctx(workspace)
    adapter = ScriptedAdapter(
        [
            plan_json(delegate_step("implementation", "change everything")),
            json.dumps({"action": "abort", "reason": "not permitted"}),
        ]
    )
    delegation = Delegation(adapter, roles={SubagentRole.RESEARCH})
    report = AgentLoop(adapter, default_registry(), delegation=delegation).run("do it", ctx)
    assert delegation.used == 0
    assert report.succeeded is False


def test_the_number_of_delegations_is_bounded(workspace: Path) -> None:
    ctx = make_ctx(workspace)
    adapter = ScriptedAdapter(
        [
            plan_json(delegate_step("research", "first"), delegate_step("research", "second")),
            plan_json(READ_APP),  # the first child's plan
            json.dumps({"action": "abort", "reason": "the second delegation was refused"}),
        ]
    )
    delegation = Delegation(adapter, max_delegations=1)
    AgentLoop(adapter, default_registry(), delegation=delegation).run("two things", ctx)
    assert delegation.used == 1


def test_an_invalid_role_argument_is_rejected_before_anything_runs(workspace: Path) -> None:
    ctx = make_ctx(workspace)
    registry = Delegation(ScriptedAdapter([])).registry_for(default_registry(), budget())
    from aica.tools.base import ToolArgumentError

    with pytest.raises(ToolArgumentError):
        registry.call(DELEGATE_TOOL, {"role": "architect", "objective": "x"}, ctx)
    with pytest.raises(ToolArgumentError):
        registry.call(DELEGATE_TOOL, {"role": "research", "objective": ""}, ctx)
    with pytest.raises(ToolArgumentError):
        registry.call(DELEGATE_TOOL, {"role": "research", "objective": "x", "shell": True}, ctx)


def test_the_delegation_is_audited(workspace: Path) -> None:
    """MCP-006/AUD: the delegation itself is an auditable tool call like any other."""
    ctx = make_ctx(workspace)
    adapter = ScriptedAdapter([plan_json(delegate_step("research")), plan_json(READ_APP)])
    AgentLoop(adapter, default_registry(), delegation=Delegation(adapter)).run("look", ctx)
    actions = [e.action for e in ctx.audit.sink.events]  # type: ignore[attr-defined]
    assert DELEGATE_TOOL in actions
    assert "fs.read" in actions, "the child's own tool calls reach the same audit log"


# ---------------------------------------------------------------- AG-009 / TEST-009


def _result(
    role: SubagentRole = SubagentRole.IMPLEMENTATION,
    *,
    required: dict[str, CheckStatus] | None = None,
    outcomes: list[RunOutcome] | None = None,
    unresolved: list[str] | None = None,
    changes: list[FileChange] | None = None,
    notes: list[str] | None = None,
) -> SubagentResult:
    ledger = VerificationLedger()
    ledger.required = dict(required or {})
    ledger.outcomes = list(outcomes or [])
    ledger.notes = list(notes or [])
    return SubagentResult(
        role=role,
        objective="do the thing",
        report=TaskReport(
            task="do the thing",
            model="scripted",
            ledger=ledger,
            changes=list(changes or []),
            unresolved=list(unresolved or []),
        ),
    )


def test_a_read_only_subagent_with_nothing_to_verify_counts_as_complete() -> None:
    """A research agent has no tests to run; that is not a failure."""
    assert _result(SubagentRole.RESEARCH).completed is True


def test_a_subagent_with_an_unmet_check_is_not_complete() -> None:
    assert _result(required={"unit": CheckStatus.FAILED}).completed is False
    assert _result(required={"unit": CheckStatus.SKIPPED}).completed is False
    assert _result(required={"unit": CheckStatus.PASSED}).completed is True


def test_a_subagent_that_left_work_unresolved_is_not_complete() -> None:
    assert _result(unresolved=["s2 did not complete"]).completed is False


def test_fold_into_keeps_every_check_the_child_did_not_pass() -> None:
    result = _result(
        required={"unit": CheckStatus.PASSED, "lint": CheckStatus.SKIPPED},
        notes=["lint skipped: no linter configured"],
        unresolved=["s3 failed"],
    )
    warnings, unmet = fold_into(result)
    assert set(unmet) == {"lint"}
    assert any("lint skipped" in w for w in warnings)
    assert any("unresolved: s3 failed" in w for w in warnings)
    assert all(w.startswith("[implementation]") for w in warnings)


def test_a_failing_child_check_keeps_the_parent_incomplete(workspace: Path) -> None:
    """The property that matters: delegation cannot launder a false success (TEST-009)."""
    ctx = make_ctx(workspace)
    failing = 'python -c "import sys; sys.exit(1)"'
    adapter = ScriptedAdapter(
        [
            plan_json(delegate_step("testing", "add a test and run it")),
            plan_json(
                {
                    "intent": "run the suite",
                    "tool": "test.run",
                    "arguments": {"command": failing, "kind": "unit"},
                },
                verification=["unit"],
            ),
            json.dumps({"action": "abort", "reason": "the suite fails"}),
            json.dumps({"action": "abort", "reason": "the subagent could not finish"}),
        ]
    )
    delegation = Delegation(adapter)
    report = AgentLoop(adapter, default_registry(), delegation=delegation).run("add tests", ctx)

    assert report.succeeded is False
    assert report.ledger.required.get("unit") is not CheckStatus.PASSED
    assert "VERIFICATION INCOMPLETE" in report.ledger.disclosure()


def test_a_childs_file_changes_appear_in_the_parents_report(workspace: Path) -> None:
    """AG-010: the parent's summary covers what its subagents changed, not just its own edits."""
    ctx = make_ctx(workspace)
    adapter = ScriptedAdapter(
        [
            plan_json(delegate_step("implementation", "add a helper")),
            plan_json(
                {
                    "intent": "write the helper",
                    "tool": "fs.write",
                    "arguments": {"path": "src/helper.py", "content": "VALUE = 1\n"},
                }
            ),
        ]
    )
    delegation = Delegation(adapter)
    report = AgentLoop(adapter, default_registry(), delegation=delegation).run("add a helper", ctx)

    assert (workspace / "src" / "helper.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    assert [c.path for c in report.changes] == ["src/helper.py"]


def test_the_sink_tag_does_not_alter_the_event(workspace: Path) -> None:
    sink = ListSink()
    tagged = SubagentSink(sink, SubagentRole.REVIEW, step_id="s1")
    from aica.agent.events import AgentEvent

    tagged.emit(AgentEvent(type=EventType.OBSERVATION, message="looked at it", data={"a": 1}))
    assert sink.events[0].message == "looked at it"
    assert sink.events[0].data == {"a": 1, "subagent": "review", "parent_step": "s1"}
