"""MCP servers end to end (TEST-003, MCP-001/004/005/007).

Real child processes speaking real JSON-RPC over stdio. The agent plans with a remote tool
through the ordinary registry, so the same policy, approval and audit apply to someone else's
code as to a built-in tool - which is the whole point of wrapping it rather than special-casing
it.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from aica.agent.loop import AgentLoop
from aica.agent.plan import PlanError, parse_plan, tool_catalogue
from aica.approvals import AllowAllApprover, DenyAllApprover
from aica.audit import AuditLog, InMemoryAuditSink
from aica.mcp.config import MCPConfig, ServerConfig
from aica.models.fake import ScriptedAdapter
from aica.policy import Policy
from aica.tools import ToolContext, default_registry
from aica.tools.mcp_tool import MCPSession
from aica.workspace import WorkspaceGuard

pytestmark = pytest.mark.integration

SERVER_SCRIPT = Path(__file__).parent.parent / "fixtures" / "mcp_echo_server.py"


def server(name: str = "demo", *flags: str, trusted: bool = True) -> ServerConfig:
    return ServerConfig(
        name=name,
        command=sys.executable,
        args=[str(SERVER_SCRIPT), *flags],
        trusted=trusted,
    )


def _ctx(root: Path, approve: bool = True, allow_mcp: bool = True) -> ToolContext:
    policy = Policy()
    if allow_mcp:
        policy.autonomy.allowed_tools = [*policy.autonomy.allowed_tools, "mcp"]
    return ToolContext(
        workspace=WorkspaceGuard(root, policy.autonomy.allowed_directories),
        policy=policy,
        audit=AuditLog(InMemoryAuditSink(), actor="mcp-integration", session_id="mcp-1"),
        approver=AllowAllApprover() if approve else DenyAllApprover(),
    )


@pytest.fixture
def session(tmp_path: Path) -> Iterator[MCPSession]:
    with MCPSession(MCPConfig(servers=[server()]), workspace_root=str(tmp_path)) as active:
        active.connect_all()
        yield active


def test_server_starts_discovers_and_answers(session: MCPSession, tmp_path: Path) -> None:
    """MCP-001/002: a real handshake, real discovery, a real call."""
    ctx = _ctx(tmp_path)
    registry = default_registry()
    registered = session.register_into(registry)
    assert set(registered) == {"mcp.demo.echo", "mcp.demo.add", "mcp.demo.fail"}

    result = registry.call("mcp.demo.add", {"a": 19, "b": 23}, ctx)
    assert result.output.strip() == "42.0"
    assert result.ok is True


def test_remote_tools_reach_the_planner_only_when_policy_allows(
    session: MCPSession, tmp_path: Path
) -> None:
    """MCP-004: the catalogue a planner sees follows the same allowed_tools list."""
    registry = default_registry()
    session.register_into(registry)

    allowed = tool_catalogue(registry, _ctx(tmp_path, allow_mcp=True))
    assert "mcp.demo.echo" in allowed

    denied = tool_catalogue(registry, _ctx(tmp_path, allow_mcp=False))
    assert "mcp.demo.echo" not in denied
    assert "fs.read" in denied  # the built-in tools are unaffected


def test_a_plan_naming_a_forbidden_remote_tool_is_rejected(
    session: MCPSession, tmp_path: Path
) -> None:
    """A model cannot reach an MCP tool the policy has not exposed."""
    registry = default_registry()
    session.register_into(registry)
    plan = json.dumps(
        {
            "summary": "use the remote tool",
            "steps": [{"intent": "echo", "tool": "mcp.demo.echo", "arguments": {"message": "hi"}}],
            "verification": [],
        }
    )
    with pytest.raises(PlanError, match="not available"):
        parse_plan(plan, "task", registry, _ctx(tmp_path, allow_mcp=False))


def test_the_agent_plans_and_runs_a_remote_tool(session: MCPSession, tmp_path: Path) -> None:
    """MCP-005/007: an organization's own server is just another tool to the agent."""
    ctx = _ctx(tmp_path)
    registry = default_registry()
    session.register_into(registry)
    plan = json.dumps(
        {
            "summary": "ask the remote server",
            "steps": [
                {
                    "intent": "echo the greeting",
                    "tool": "mcp.demo.echo",
                    "arguments": {"message": "from the agent", "times": 2},
                }
            ],
            "verification": [],
        }
    )
    loop = AgentLoop(ScriptedAdapter([plan]), registry)
    report = loop.run("greet through MCP", ctx)

    assert report.steps_used == 1
    assert loop.state is not None
    assert loop.state.plan.steps[0].result == "from the agent from the agent"


def test_a_remote_failure_makes_the_agent_adapt(session: MCPSession, tmp_path: Path) -> None:
    """AG-004: a server reporting isError is a failed step, not a completed one."""
    ctx = _ctx(tmp_path)
    registry = default_registry()
    session.register_into(registry)
    plan = json.dumps(
        {
            "summary": "call the failing tool",
            "steps": [{"intent": "call fail", "tool": "mcp.demo.fail", "arguments": {}}],
            "verification": [],
        }
    )
    adaptation = json.dumps(
        {
            "action": "replace",
            "reason": "that tool always fails; echo instead",
            "steps": [
                {"intent": "echo", "tool": "mcp.demo.echo", "arguments": {"message": "recovered"}}
            ],
        }
    )
    loop = AgentLoop(ScriptedAdapter([plan, adaptation]), registry)
    loop.run("do the thing", ctx)

    assert loop.state is not None
    statuses = [s.status.value for s in loop.state.plan.steps]
    assert statuses == ["failed", "succeeded"]
    assert loop.state.plan.steps[1].result == "recovered"


def test_untrusted_server_calls_need_approval_end_to_end(tmp_path: Path) -> None:
    """SAFE-001: third-party code is not run on a plan's say-so."""
    config = MCPConfig(servers=[server("untrusted", trusted=False)])
    ctx = _ctx(tmp_path, approve=False)
    registry = default_registry()
    with MCPSession(config, workspace_root=str(tmp_path)) as active:
        active.connect_all()
        active.register_into(registry)
        plan = json.dumps(
            {
                "summary": "call the untrusted server",
                "steps": [
                    {
                        "intent": "echo",
                        "tool": "mcp.untrusted.echo",
                        "arguments": {"message": "hi"},
                    }
                ],
                "verification": [],
            }
        )
        report = AgentLoop(ScriptedAdapter([plan]), registry).run("call it", ctx)

    assert report.succeeded is False
    assert any("approval" in item for item in report.unresolved)


def test_a_hostile_server_cannot_impersonate_a_builtin(tmp_path: Path) -> None:
    """SAFE-007: namespacing keeps a server's `fs.write` separate from the real one."""
    config = MCPConfig(servers=[server("evil", "--bad-name")])
    ctx = _ctx(tmp_path)
    registry = default_registry()
    builtin = registry.get("fs.write", ctx)
    with MCPSession(config, workspace_root=str(tmp_path)) as active:
        active.connect_all()
        active.register_into(registry)

        assert registry.get("fs.write", ctx) is builtin
        # The remote one is reachable only under its own namespaced name.
        result = registry.call("mcp.evil.fs.write", {"path": "anywhere"}, ctx)
        assert "pretended" in result.output
        # ...and it wrote nothing, because it is not the filesystem tool.
        assert not (tmp_path / "anywhere").exists()


def test_one_broken_server_does_not_stop_the_others(tmp_path: Path) -> None:
    config = MCPConfig(
        servers=[
            ServerConfig(name="broken", command="definitely-not-a-real-program-xyz"),
            server("healthy"),
        ]
    )
    with MCPSession(config, workspace_root=str(tmp_path)) as active:
        tools = active.connect_all()
        assert {t.name for t in tools} == {
            "mcp.healthy.echo",
            "mcp.healthy.add",
            "mcp.healthy.fail",
        }
        assert "broken" in active.errors
        catalogue = active.catalogue()
        assert "healthy" in catalogue and "ERROR" in catalogue


def test_server_processes_are_cleaned_up(tmp_path: Path) -> None:
    config = MCPConfig(servers=[server()])
    active = MCPSession(config, workspace_root=str(tmp_path))
    active.connect_all()
    client = active.clients["demo"]
    assert client.alive
    active.close()
    assert not client.alive
