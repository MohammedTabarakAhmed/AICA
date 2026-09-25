"""Quota management (ADM-005)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aica.admin.quotas import (
    QuotaExceeded,
    QuotaLimit,
    QuotaPolicy,
    QuotaScope,
    check,
    measure,
    report,
)
from aica.audit import AuditEvent, EventCategory, JsonlAuditSink, Outcome
from aica.policy import Policy
from aica.tools import default_registry
from tests.test_tools_fs import make_ctx

NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


def _event(actor: str = "alice", **kwargs: object) -> AuditEvent:
    base: dict[str, object] = {
        "category": EventCategory.COMMAND,
        "action": "echo hello",
        "outcome": Outcome.SUCCESS,
        "actor": actor,
        "timestamp": NOW,
    }
    base.update(kwargs)
    return AuditEvent.model_validate(base)


def _limit(**kwargs: object) -> QuotaLimit:
    return QuotaLimit.model_validate({"scope": QuotaScope.PRINCIPAL, "name": "alice", **kwargs})


def _policy(*limits: QuotaLimit) -> QuotaPolicy:
    return QuotaPolicy(enabled=True, limits=list(limits))


# ------------------------------------------------------------------ measuring
def test_usage_is_counted_from_the_audit_record() -> None:
    """One record, one answer: the number that stops you is the one an admin is shown."""
    events = [
        _event(duration_ms=1500),
        _event(category=EventCategory.MODEL_CALL, duration_ms=500),
        _event(actor="bob", duration_ms=9000),  # someone else
    ]
    used = measure(events, "alice", NOW - timedelta(days=1))
    assert used.actions == 2
    assert used.commands == 1 and used.model_calls == 1
    assert used.tool_seconds == 2  # 2000ms, floored


def test_events_outside_the_window_are_not_counted() -> None:
    events = [_event(timestamp=NOW - timedelta(days=5)), _event()]
    assert measure(events, "alice", NOW - timedelta(days=1)).actions == 1


# ------------------------------------------------------------------ the verdict
def test_quotas_disabled_allows_everything() -> None:
    events = [_event() for _ in range(100)]
    assert check(QuotaPolicy(limits=[_limit(max_actions=1)]), "alice", events, NOW).allowed


def test_a_principal_with_no_applicable_limit_is_allowed() -> None:
    policy = _policy(_limit(name="someone-else", max_actions=1))
    assert check(policy, "alice", [_event() for _ in range(10)], NOW).allowed


def test_exhaustion_refuses_and_says_what_and_when() -> None:
    """A quota that silently throttles is indistinguishable from a broken system."""
    policy = _policy(_limit(max_actions=2))
    verdict = check(policy, "alice", [_event(), _event()], NOW)
    assert not verdict.allowed
    assert verdict.measure == "actions" and verdict.used == 2 and verdict.cap == 2
    reason = verdict.reason()
    assert "quota exhausted" in reason and "actions 2/2" in reason and "resets at" in reason


def test_under_the_limit_is_allowed() -> None:
    assert check(_policy(_limit(max_actions=5)), "alice", [_event(), _event()], NOW).allowed


@pytest.mark.parametrize(
    ("field", "events"),
    [
        ("max_model_calls", [_event(category=EventCategory.MODEL_CALL) for _ in range(3)]),
        ("max_commands", [_event() for _ in range(3)]),
        ("max_tool_seconds", [_event(duration_ms=3000) for _ in range(1)]),
    ],
)
def test_each_measure_can_bound_independently(field: str, events: list[AuditEvent]) -> None:
    policy = _policy(_limit(**{field: 3}))
    assert not check(policy, "alice", events, NOW).allowed


def test_the_most_restrictive_applicable_limit_wins() -> None:
    """A team quota can tighten what a user may do; it must never loosen it."""
    generous = _limit(max_actions=100)
    strict = QuotaLimit(scope=QuotaScope.TEAM, name="core", members=["alice"], max_actions=2)
    verdict = check(_policy(generous, strict), "alice", [_event(), _event()], NOW)
    assert not verdict.allowed
    assert verdict.limit is not None and verdict.limit.scope is QuotaScope.TEAM


def test_a_project_limit_covers_everyone() -> None:
    policy = _policy(QuotaLimit(scope=QuotaScope.PROJECT, max_actions=1))
    assert not check(policy, "anyone-at-all", [_event(actor="anyone-at-all")], NOW).allowed


def test_a_team_limit_only_covers_its_members() -> None:
    policy = _policy(QuotaLimit(scope=QuotaScope.TEAM, name="core", members=["bob"], max_actions=1))
    assert check(policy, "alice", [_event() for _ in range(10)], NOW).allowed


def test_windows_are_per_limit() -> None:
    old = [_event(timestamp=NOW - timedelta(days=3)) for _ in range(5)]
    daily = _policy(_limit(window_days=1, max_actions=2))
    weekly = _policy(_limit(window_days=7, max_actions=2))
    assert check(daily, "alice", old, NOW).allowed  # all outside a 1-day window
    assert not check(weekly, "alice", old, NOW).allowed


def test_report_shows_used_against_each_applicable_cap() -> None:
    policy = _policy(_limit(max_actions=10, max_commands=5))
    rows = report(policy, "alice", [_event(), _event()], NOW)
    assert len(rows) == 1
    assert rows[0].used == {"actions": 2, "commands": 2}
    assert rows[0].caps == {"actions": 10, "commands": 5}
    assert "actions 2/10" in rows[0].describe()
    assert rows[0].to_dict()["scope"] == "principal"


def test_describe_names_the_scope_and_bounds() -> None:
    assert "principal 'alice'" in _limit(max_actions=3).describe()
    assert "the project" in QuotaLimit(scope=QuotaScope.PROJECT, max_actions=3).describe()


# ------------------------------------------------------------------ enforcement
@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    return tmp_path


def _ctx_with_quota(workspace: Path, policy: QuotaPolicy, recorded: int):  # type: ignore[no-untyped-def]
    sink = JsonlAuditSink(workspace / ".aica" / "audit")
    for _ in range(recorded):
        sink.write(_event(actor="alice", timestamp=datetime.now(UTC)))
    ctx = make_ctx(workspace, Policy(quotas=policy))
    ctx.audit.actor = "alice"
    ctx.audit_directory = workspace / ".aica" / "audit"
    return ctx


def test_a_tool_call_is_refused_once_the_quota_is_exhausted(workspace: Path) -> None:
    ctx = _ctx_with_quota(workspace, _policy(_limit(max_actions=3)), recorded=3)
    with pytest.raises(QuotaExceeded, match="quota exhausted"):
        default_registry().call("fs.read", {"path": "src/app.py"}, ctx)


def test_a_tool_call_proceeds_while_under_the_quota(workspace: Path) -> None:
    ctx = _ctx_with_quota(workspace, _policy(_limit(max_actions=10)), recorded=3)
    assert default_registry().call("fs.read", {"path": "src/app.py"}, ctx).ok


def test_no_quota_policy_means_no_enforcement(workspace: Path) -> None:
    ctx = _ctx_with_quota(workspace, QuotaPolicy(), recorded=50)
    assert default_registry().call("fs.read", {"path": "src/app.py"}, ctx).ok


def test_exhaustion_is_audited_as_a_policy_decision(workspace: Path) -> None:
    ctx = _ctx_with_quota(workspace, _policy(_limit(max_actions=1)), recorded=1)
    with pytest.raises(QuotaExceeded):
        default_registry().call("fs.read", {"path": "src/app.py"}, ctx)
    blocked = [e for e in ctx.audit.sink.events if e.outcome is Outcome.BLOCKED]  # type: ignore[attr-defined]
    assert any(e.details.get("rule") == "ADM-005" for e in blocked)


def test_a_context_without_an_audit_directory_does_not_enforce(workspace: Path) -> None:
    """Library and test use: no record to count from means no quota to enforce."""
    ctx = make_ctx(workspace, Policy(quotas=_policy(_limit(max_actions=0))))
    assert default_registry().call("fs.read", {"path": "src/app.py"}, ctx).ok
