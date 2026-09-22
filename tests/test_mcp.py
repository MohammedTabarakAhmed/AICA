"""MCP client, schema conversion and tool wrapping (MCP-001..MCP-007).

The server used here is a real child process speaking real JSON-RPC over stdio
(``tests/fixtures/mcp_echo_server.py``), so the transport, the handshake and the tool calls
are all genuinely exercised rather than stubbed.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from aica.approvals import ApprovalRequired, DenyAllApprover
from aica.audit import EventCategory
from aica.mcp.client import MCPClient, MCPError, RemoteTool, _content_text
from aica.mcp.config import MCPConfig, MCPConfigError, ServerConfig, load_mcp_config
from aica.mcp.protocol import TransportError, TransportTimeout
from aica.mcp.schema import SchemaError, model_from_schema
from aica.policy import Policy
from aica.policy.models import ActionCategory
from aica.tools import default_registry
from aica.tools.base import ToolArgumentError
from aica.tools.mcp_tool import (
    MCPSession,
    MCPTool,
    MCPToolError,
    describe_for_model,
    qualified_name,
)
from aica.tools.registry import ToolRegistry
from tests.test_tools_fs import make_ctx

SERVER_SCRIPT = Path(__file__).parent / "fixtures" / "mcp_echo_server.py"


def server_config(
    name: str = "demo", *flags: str, trusted: bool = False, **kwargs: Any
) -> ServerConfig:
    return ServerConfig(
        name=name,
        command=sys.executable,
        args=[str(SERVER_SCRIPT), *flags],
        trusted=trusted,
        **kwargs,
    )


# ---------------------------------------------------------------- configuration (MCP-001)


def test_command_with_shell_metacharacters_is_rejected() -> None:
    """The command runs with a fixed argv; a config that assumes a shell must fail loudly."""
    for bad in ["python && rm -rf /", "sh -c 'x' | tee", "run; other", "cmd `whoami`"]:
        with pytest.raises(ValueError, match="shell metacharacters"):
            ServerConfig(name="x", command=bad)


def test_environment_is_allowlisted_not_inherited(monkeypatch: pytest.MonkeyPatch) -> None:
    """SAFE-006: a server must not receive unrelated credentials from the parent process."""
    monkeypatch.setenv("UNRELATED_API_KEY", "super-secret")
    monkeypatch.setenv("SHARED_TOKEN", "passed-on-purpose")
    config = ServerConfig(
        name="x",
        command="python",
        env={"LITERAL": "value"},
        env_passthrough=["SHARED_TOKEN"],
    )
    environment = config.environment()
    assert environment["LITERAL"] == "value"
    assert environment["SHARED_TOKEN"] == "passed-on-purpose"
    assert "UNRELATED_API_KEY" not in environment


def test_missing_config_means_no_servers(tmp_path: Path) -> None:
    assert load_mcp_config(tmp_path / "absent.toml").servers == []


def test_invalid_config_fails_loudly(tmp_path: Path) -> None:
    path = tmp_path / "mcp.toml"
    path.write_text('[[servers]]\nname = "A B"\ncommand = "x"\n', encoding="utf-8")
    with pytest.raises(MCPConfigError, match="invalid MCP configuration"):
        load_mcp_config(path)


def test_duplicate_server_names_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate server names"):
        MCPConfig(
            servers=[
                ServerConfig(name="a", command="x"),
                ServerConfig(name="a", command="y"),
            ]
        )


def test_unknown_and_disabled_servers_are_refused() -> None:
    config = MCPConfig(
        servers=[
            ServerConfig(name="on", command="x"),
            ServerConfig(name="off", command="x", enabled=False),
        ]
    )
    assert config.get("on").name == "on"
    with pytest.raises(MCPConfigError, match="unknown MCP server"):
        config.get("nope")
    with pytest.raises(MCPConfigError, match="disabled"):
        config.get("off")
    assert [s.name for s in config.enabled()] == ["on"]


# ---------------------------------------------------------------- schema (MCP-003)


def test_schema_becomes_a_validating_model() -> None:
    model = model_from_schema(
        "echo",
        {
            "type": "object",
            "properties": {
                "message": {"type": "string"},
                "times": {"type": "integer", "default": 1},
            },
            "required": ["message"],
            "additionalProperties": False,
        },
    )
    assert model.model_validate({"message": "hi"}).model_dump()["times"] == 1
    with pytest.raises(ValueError, match="message"):
        model.model_validate({})  # required field missing
    with pytest.raises(ValueError, match="extra"):
        model.model_validate({"message": "hi", "surprise": 1})
    with pytest.raises(ValueError):
        model.model_validate({"message": "hi", "times": "many"})  # wrong type


def test_enum_becomes_a_literal() -> None:
    model = model_from_schema(
        "x", {"type": "object", "properties": {"mode": {"enum": ["fast", "slow"]}}}
    )
    assert model.model_validate({"mode": "fast"}).model_dump()["mode"] == "fast"
    with pytest.raises(ValueError):
        model.model_validate({"mode": "sideways"})


def test_nullable_union_is_optional() -> None:
    model = model_from_schema(
        "x", {"type": "object", "properties": {"note": {"type": ["string", "null"]}}}
    )
    assert model.model_validate({"note": None}).model_dump()["note"] is None
    assert model.model_validate({"note": "hi"}).model_dump()["note"] == "hi"


def test_array_items_are_typed() -> None:
    model = model_from_schema(
        "x",
        {"type": "object", "properties": {"tags": {"type": "array", "items": {"type": "string"}}}},
    )
    assert model.model_validate({"tags": ["a", "b"]}).model_dump()["tags"] == ["a", "b"]
    with pytest.raises(ValueError):
        model.model_validate({"tags": [{"not": "a string"}]})


@pytest.mark.parametrize("schema", [None, {}, {"type": "string"}, {"type": "object"}])
def test_missing_or_unusable_schema_accepts_anything(schema: Any) -> None:
    """A server that states no contract cannot have one invented for it."""
    model = model_from_schema("x", schema)
    assert model.model_validate({"anything": 1, "at": "all"}) is not None


def test_absurdly_wide_schema_is_refused() -> None:
    properties = {f"field_{i}": {"type": "string"} for i in range(200)}
    with pytest.raises(SchemaError, match="maximum"):
        model_from_schema("x", {"type": "object", "properties": properties})


def test_non_identifier_property_falls_back_to_permissive() -> None:
    model = model_from_schema("x", {"type": "object", "properties": {"not-an-identifier": {}}})
    assert model.model_validate({"not-an-identifier": 1}) is not None


# ---------------------------------------------------------------- client (MCP-001/002)


def test_handshake_and_tool_discovery_against_a_real_server() -> None:
    with MCPClient(server_config()) as client:
        info = client.start()
        assert info.name == "echo-server" and info.version == "1.2.3"
        assert info.protocol_version == "2024-11-05"
        tools = client.list_tools()
        assert {t.name for t in tools} == {"echo", "add", "fail"}
        assert tools[0].input_schema["required"] == ["message"]


def test_tool_call_returns_content() -> None:
    with MCPClient(server_config()) as client:
        text, is_error = client.call_tool("echo", {"message": "hello", "times": 2})
        assert text == "hello hello" and is_error is False


def test_tool_error_is_reported_as_an_error_not_a_success() -> None:
    with MCPClient(server_config()) as client:
        text, is_error = client.call_tool("fail", {})
        assert is_error is True and "failed" in text


def test_unknown_tool_surfaces_the_json_rpc_error() -> None:
    with MCPClient(server_config()) as client:
        with pytest.raises(Exception, match="unknown tool"):
            client.call_tool("no-such-tool", {})


def test_non_json_banner_does_not_break_the_handshake() -> None:
    """Real servers print banners to stdout; the client must skip them."""
    with MCPClient(server_config("demo", "--banner")) as client:
        assert client.start().name == "echo-server"
        assert len(client.list_tools()) == 3


def test_unsolicited_notifications_are_skipped() -> None:
    with MCPClient(server_config("demo", "--chatty")) as client:
        assert len(client.list_tools()) == 3


def test_a_server_that_never_answers_times_out() -> None:
    config = server_config("slow", "--slow-start", startup_timeout_seconds=1.0)
    client = MCPClient(config)
    try:
        with pytest.raises(MCPError, match="failed to initialize"):
            client.start()
    finally:
        client.close()


def test_a_server_that_dies_mid_call_is_reported() -> None:
    with MCPClient(server_config("dying", "--die-on-call")) as client:
        client.list_tools()
        with pytest.raises((TransportError, TransportTimeout, MCPError)):
            client.call_tool("echo", {"message": "hi"})


def test_a_command_that_does_not_exist_fails_clearly() -> None:
    client = MCPClient(ServerConfig(name="ghost", command="definitely-not-a-real-program-xyz"))
    with pytest.raises((MCPError, TransportError)):
        client.start()
    client.close()


def test_empty_tool_list_is_handled() -> None:
    with MCPClient(server_config("bare", "--no-tools")) as client:
        assert client.list_tools() == []


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (None, ""),
        ("plain", "plain"),
        ([{"type": "text", "text": "a"}, {"type": "text", "text": "b"}], "a\nb"),
        ([{"type": "image", "mimeType": "image/png"}], "[image: image/png]"),
        ([{"type": "resource", "resource": {"uri": "file:///x"}}], "[resource: file:///x]"),
        ([{"type": "weird"}], "[weird content]"),
    ],
)
def test_content_blocks_are_flattened(content: Any, expected: str) -> None:
    assert _content_text(content) == expected


def test_secrets_in_a_server_reply_are_redacted() -> None:
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123" not in _content_text(
        [{"type": "text", "text": "token ghp_abcdefghijklmnopqrstuvwxyz0123"}]
    )


# ---------------------------------------------------------------- tool wrapping (MCP-004..007)


def test_remote_tools_become_namespaced_local_tools(tmp_path: Path) -> None:
    config = MCPConfig(servers=[server_config(trusted=True)])
    with MCPSession(config) as session:
        tools = session.connect("demo")
        assert {t.name for t in tools} == {
            "mcp.demo.echo",
            "mcp.demo.add",
            "mcp.demo.fail",
        }
        echo = next(t for t in tools if t.name == "mcp.demo.echo")
        assert "MCP server 'demo'" in echo.description
        # MCP-002: the remote contract is discoverable.
        assert echo.schema()["parameters"]["properties"]["message"]["type"] == "string"


def test_a_server_cannot_shadow_a_builtin_tool(tmp_path: Path) -> None:
    """SAFE-007: a hostile server advertising `fs.write` gets its own namespace, not ours."""
    config = MCPConfig(servers=[server_config("evil", "--bad-name", trusted=True)])
    registry = default_registry()
    original = registry.get("fs.write", make_ctx(tmp_path))
    with MCPSession(config) as session:
        tools = session.connect("evil")
        assert [t.name for t in tools] == ["mcp.evil.fs.write"]
        session.register_into(registry)
        # The built-in tool is untouched.
        assert registry.get("fs.write", make_ctx(tmp_path)) is original
        assert registry.group_of("mcp.evil.fs.write") == "mcp"


def test_hostile_description_is_fenced_before_a_model_sees_it(tmp_path: Path) -> None:
    config = MCPConfig(servers=[server_config("evil", "--bad-name", trusted=True)])
    with MCPSession(config) as session:
        tools = session.connect("evil")
        fenced = describe_for_model(tools)
        assert "UNTRUSTED" in fenced
        assert "IGNORE ALL PREVIOUS INSTRUCTIONS" in fenced  # shown, but as data
        assert "UNTRUSTED" in tools[0].describe_untrusted()


def test_untrusted_server_requires_approval_per_call(tmp_path: Path) -> None:
    """MCP-004/SAFE-001: third-party code is not called without a decision."""
    config = MCPConfig(servers=[server_config(trusted=False)])
    ctx = make_ctx(tmp_path, approver=DenyAllApprover())
    with MCPSession(config) as session:
        echo = next(t for t in session.connect("demo") if t.name == "mcp.demo.echo")
        with pytest.raises(ApprovalRequired) as exc:
            echo.invoke({"message": "hi"}, ctx)
        assert ActionCategory.EXTERNAL in exc.value.request.categories


def test_trusted_server_runs_without_approval(tmp_path: Path) -> None:
    config = MCPConfig(servers=[server_config(trusted=True)])
    ctx = make_ctx(tmp_path, approver=DenyAllApprover())
    with MCPSession(config) as session:
        echo = next(t for t in session.connect("demo") if t.name == "mcp.demo.echo")
        result = echo.invoke({"message": "hi", "times": 3}, ctx)
        assert result.output == "hi hi hi" and result.ok is True


def test_arguments_are_validated_before_anything_is_sent(tmp_path: Path) -> None:
    """MCP-003: a malformed call fails locally, with a readable message."""
    config = MCPConfig(servers=[server_config(trusted=True)])
    ctx = make_ctx(tmp_path)
    with MCPSession(config) as session:
        echo = next(t for t in session.connect("demo") if t.name == "mcp.demo.echo")
        with pytest.raises(ToolArgumentError, match="message"):
            echo.invoke({}, ctx)
        with pytest.raises(ToolArgumentError):
            echo.invoke({"message": "hi", "unexpected": True}, ctx)


def test_remote_failure_is_a_failed_result_not_a_success(tmp_path: Path) -> None:
    config = MCPConfig(servers=[server_config(trusted=True)])
    ctx = make_ctx(tmp_path)
    with MCPSession(config) as session:
        fail = next(t for t in session.connect("demo") if t.name == "mcp.demo.fail")
        result = fail.invoke({}, ctx)
        assert result.ok is False and result.data["is_error"] is True


def test_mcp_calls_are_audited(tmp_path: Path) -> None:
    config = MCPConfig(servers=[server_config(trusted=True)])
    ctx = make_ctx(tmp_path)
    with MCPSession(config) as session:
        echo = next(t for t in session.connect("demo") if t.name == "mcp.demo.echo")
        echo.invoke({"message": "audit me"}, ctx)
    actions = [
        e.action
        for e in ctx.audit.sink.events
        if e.category is EventCategory.TOOL_CALL  # type: ignore[attr-defined]
    ]
    assert "mcp.demo.echo" in actions


def test_policy_can_withdraw_the_whole_mcp_group(tmp_path: Path) -> None:
    """MCP-004: MCP tools are a group like any other."""
    config = MCPConfig(servers=[server_config(trusted=True)])
    registry = default_registry()
    with MCPSession(config) as session:
        session.connect("demo")
        session.register_into(registry)

        allowed = Policy()
        allowed.autonomy.allowed_tools = [*allowed.autonomy.allowed_tools, "mcp"]
        assert any(t.name.startswith("mcp.") for t in registry.allowed(make_ctx(tmp_path, allowed)))

        denied = Policy()  # the default list does not include "mcp"
        assert not any(
            t.name.startswith("mcp.") for t in registry.allowed(make_ctx(tmp_path, denied))
        )


def test_a_failing_server_is_recorded_not_raised() -> None:
    """One broken server must not stop the others from being usable."""
    config = MCPConfig(
        servers=[
            ServerConfig(name="broken", command="definitely-not-a-real-program-xyz"),
            server_config("working", trusted=True),
        ]
    )
    with MCPSession(config) as session:
        tools = session.connect_all()
        assert {t.name for t in tools} == {
            "mcp.working.echo",
            "mcp.working.add",
            "mcp.working.fail",
        }
        assert "broken" in session.errors
        assert "working" in session.catalogue()


def test_registering_a_colliding_name_twice_is_recorded(tmp_path: Path) -> None:
    config = MCPConfig(servers=[server_config(trusted=True)])
    registry = ToolRegistry()
    with MCPSession(config) as session:
        session.connect("demo")
        first = session.register_into(registry)
        assert len(first) == 3
        second = session.register_into(registry)  # same tools again
        assert second == []
        assert any("duplicate" in error for error in session.errors.values())


def test_session_close_stops_the_server_processes() -> None:
    config = MCPConfig(servers=[server_config(trusted=True)])
    session = MCPSession(config)
    session.connect("demo")
    client = session.clients["demo"]
    assert client.alive is True
    session.close()
    assert client.alive is False


def test_qualified_name_shape() -> None:
    assert qualified_name("srv", "tool") == "mcp.srv.tool"


def test_wrapping_an_unusable_schema_is_reported() -> None:
    config = server_config(trusted=True)
    remote = RemoteTool(
        name="wide",
        description="",
        input_schema={
            "type": "object",
            "properties": {f"f{i}": {"type": "string"} for i in range(200)},
        },
    )
    with pytest.raises(MCPToolError, match="maximum"):
        MCPTool(config, remote, MCPClient(config))
