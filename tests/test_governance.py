"""Environment classification and tool allow/deny (SEC-001, SEC-002, BRD section 16)."""

from __future__ import annotations

from pathlib import Path

import pytest

from aica.approvals import AllowAllApprover, ApprovalRequired, DenyAllApprover
from aica.policy import (
    ActionCategory,
    ApprovalPolicy,
    AutonomyLimits,
    Environment,
    Policy,
    ToolPolicy,
)
from aica.tools import default_registry
from aica.tools.base import ToolNotAllowed
from tests.test_tools_fs import make_ctx


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    return tmp_path


def _policy(**kwargs: object) -> Policy:
    return Policy(**kwargs)  # type: ignore[arg-type]


# ------------------------------------------------------------------ SEC-002 deny
def test_deny_blocks_a_tool_whose_group_is_allowed(workspace: Path) -> None:
    policy = _policy(tools=ToolPolicy(deny=["fs.write"]))
    ctx = make_ctx(workspace, policy)
    reg = default_registry()
    # The group is permitted and a sibling tool still works ...
    assert reg.call("fs.read", {"path": "src/app.py"}, ctx).output
    # ... but the denied tool does not.
    with pytest.raises(ToolNotAllowed, match="tools.deny"):
        reg.call("fs.write", {"path": "src/new.py", "content": "y = 2\n"}, ctx)


def test_deny_wins_over_allow(workspace: Path) -> None:
    """Denying must not depend on also remembering to remove it from every allowlist."""
    policy = _policy(tools=ToolPolicy(allow=["fs.write", "fs.read"], deny=["fs.write"]))
    ctx = make_ctx(workspace, policy)
    with pytest.raises(ToolNotAllowed, match="tools.deny"):
        default_registry().call("fs.write", {"path": "a.py", "content": "z\n"}, ctx)


def test_deny_matches_a_group_and_a_prefix(workspace: Path) -> None:
    ctx = make_ctx(workspace, _policy(tools=ToolPolicy(deny=["database", "git.c*"])))
    reg = default_registry()
    with pytest.raises(ToolNotAllowed, match="tools.deny"):
        reg.call("db.connections", {}, ctx)
    with pytest.raises(ToolNotAllowed, match="tools.deny"):
        reg.call("git.clone", {"url": "https://x.example/y.git", "directory": "v"}, ctx)
    # A git tool outside the prefix is untouched.
    assert reg.denial_reason("git.status", ctx) is None


def test_allow_narrows_but_cannot_widen(workspace: Path) -> None:
    """`allow` may only subtract from the group allowlist, never add to it."""
    policy = _policy(
        autonomy=AutonomyLimits(allowed_tools=["filesystem"]),  # no git group
        tools=ToolPolicy(allow=["fs.read", "git.status"]),  # names a git tool anyway
    )
    ctx = make_ctx(workspace, policy)
    reg = default_registry()
    assert reg.denial_reason("fs.read", ctx) is None
    # Named in `allow`, but its group is not permitted: still refused.
    assert "not in autonomy.allowed_tools" in str(reg.denial_reason("git.status", ctx))
    # In an allowed group but not named in `allow`: refused.
    assert "tools.allow" in str(reg.denial_reason("fs.write", ctx))


def test_denial_reason_names_the_list_that_refused(workspace: Path) -> None:
    """An operator should not have to guess which of several lists stopped a tool."""
    ctx = make_ctx(workspace, _policy(tools=ToolPolicy(deny=["shell"])))
    reason = default_registry().denial_reason("shell.run", ctx)
    assert reason is not None and "tools.deny" in reason and "'shell'" in reason


def test_denied_tools_are_absent_from_the_advertised_tool_list(workspace: Path) -> None:
    """MCP-002/SEC-002: a model must not be offered a tool policy will refuse."""
    ctx = make_ctx(workspace, _policy(tools=ToolPolicy(deny=["shell", "database"])))
    names = {t.name for t in default_registry().allowed(ctx)}
    assert "shell.run" not in names and "db.query" not in names
    assert "fs.read" in names


# ------------------------------------------------------------- SEC-001 environment
def test_production_gates_an_ordinary_write_that_development_allows(workspace: Path) -> None:
    """The gap this closes: a plain file write was previously ungated in every environment."""
    reg = default_registry()

    dev = make_ctx(workspace, _policy(), approver=DenyAllApprover())
    assert reg.call("fs.write", {"path": "src/dev.py", "content": "a = 1\n"}, dev).ok

    prod_policy = _policy(autonomy=AutonomyLimits(environment=Environment.PRODUCTION))
    prod = make_ctx(workspace, prod_policy, approver=DenyAllApprover())
    with pytest.raises(ApprovalRequired):
        reg.call("fs.write", {"path": "src/prod.py", "content": "a = 1\n"}, prod)
    assert not (workspace / "src" / "prod.py").exists()


def test_production_write_proceeds_once_approved(workspace: Path) -> None:
    prod_policy = _policy(autonomy=AutonomyLimits(environment=Environment.PRODUCTION))
    ctx = make_ctx(workspace, prod_policy, approver=AllowAllApprover())
    default_registry().call("fs.write", {"path": "src/ok.py", "content": "a = 1\n"}, ctx)
    assert (workspace / "src" / "ok.py").read_text(encoding="utf-8") == "a = 1\n"


def test_production_does_not_gate_read_only_tools(workspace: Path) -> None:
    """Gating reads would make a production classification unusable, so it does not."""
    prod_policy = _policy(autonomy=AutonomyLimits(environment=Environment.PRODUCTION))
    ctx = make_ctx(workspace, prod_policy, approver=DenyAllApprover())
    reg = default_registry()
    assert reg.call("fs.read", {"path": "src/app.py"}, ctx).ok
    assert reg.call("fs.list", {"path": "src"}, ctx).ok


def test_production_gate_can_be_blocked_outright(workspace: Path) -> None:
    policy = _policy(
        autonomy=AutonomyLimits(environment=Environment.PRODUCTION),
        approval=ApprovalPolicy(block=[ActionCategory.PRODUCTION]),
    )
    ctx = make_ctx(workspace, policy, approver=AllowAllApprover())
    with pytest.raises(PermissionError, match="blocked by policy"):
        default_registry().call("fs.write", {"path": "src/x.py", "content": "a\n"}, ctx)


def test_deny_in_production_applies_only_in_production(workspace: Path) -> None:
    tools = ToolPolicy(deny_in_production=["shell", "database"])
    reg = default_registry()

    dev = make_ctx(workspace, _policy(tools=tools))
    assert reg.denial_reason("shell.run", dev) is None

    prod = make_ctx(
        workspace,
        _policy(tools=tools, autonomy=AutonomyLimits(environment=Environment.PRODUCTION)),
    )
    reason = reg.denial_reason("shell.run", prod)
    assert reason is not None and "production environment" in reason


def test_test_environment_behaves_like_development_for_the_production_gate(
    workspace: Path,
) -> None:
    policy = _policy(autonomy=AutonomyLimits(environment=Environment.TEST))
    ctx = make_ctx(workspace, policy, approver=DenyAllApprover())
    assert default_registry().call("fs.write", {"path": "src/t.py", "content": "a\n"}, ctx).ok


def test_every_tool_that_changes_state_declares_itself_mutating() -> None:
    """A write tool that forgets `mutating` silently escapes the production gate.

    The check is by name rather than by inspection because there is no way to detect a
    side effect statically - so the list is written down, and this test fails when a new
    tool is added without deciding which side of it the tool belongs on.
    """
    expected_mutating = {
        "fs.write",
        "fs.edit",
        "fs.move",
        "fs.delete",
        "fs.rollback",
        "git.create_branch",
        "git.switch",
        "git.commit",
        "git.revert",
        "git.discard",
        "git.clone",
        "git.push",
        "repo.create_pull_request",
        "repo.comment",
        "shell.run",
        "db.execute",
        "browser.open",
        "browser.navigate",
        "browser.click",
        "browser.fill",
        "browser.press",
        "test.run",
    }
    reg = default_registry()
    actual = {name for name in reg.names() if reg.is_mutating(name)}
    assert actual == expected_mutating


def test_policy_rejects_an_empty_tool_pattern() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        ToolPolicy(deny=["fs.write", "  "])
