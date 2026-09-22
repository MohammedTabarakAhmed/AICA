"""Expose MCP server tools as ordinary AICA tools (MCP-001, MCP-004, MCP-005, MCP-007).

A remote tool is wrapped so that everything the rest of the system already guarantees keeps
applying: arguments are validated against the server's own schema before anything is sent
(MCP-003), policy decides whether the group is exposed at all (MCP-004), and every call is
audited with its arguments and outcome (MCP-006).

Two properties are specific to third-party servers and are enforced here:

* **Names are namespaced** as ``mcp.<server>.<tool>``. A server therefore cannot advertise a
  tool called ``fs.write`` and have a planner pick it up believing it is the built-in one.
  ``ToolRegistry.register`` also refuses duplicates, so a collision fails loudly.
* **Calls are gated.** A server marked ``trusted = false`` (the default) passes the EXTERNAL
  approval gate on every call, because it is code this project did not write, performing
  effects it cannot see.

Descriptions coming from a server are data, not instructions: they are redacted and bounded
by the client, and fenced when they are put in front of a model (SAFE-007).
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import BaseModel

from aica.audit import EventCategory, Outcome
from aica.mcp.client import MCPClient, MCPError, RemoteTool
from aica.mcp.config import MCPConfig, ServerConfig, load_mcp_config
from aica.mcp.protocol import JsonRpcError, TransportError
from aica.mcp.schema import SchemaError, model_from_schema
from aica.policy.models import ActionCategory
from aica.safety.injection import wrap_untrusted
from aica.tools.base import Tool, ToolContext, ToolError, ToolResult
from aica.tools.registry import ToolRegistry

MCP_GROUP = "mcp"
NAMESPACE = "mcp"


def qualified_name(server: str, tool: str) -> str:
    return f"{NAMESPACE}.{server}.{tool}"


class MCPToolError(ToolError):
    """The remote tool failed, or the server could not be reached."""


class MCPTool(Tool):
    """One remote tool, presented as a local tool."""

    name: ClassVar[str] = ""  # set per instance below
    description: ClassVar[str] = ""
    Args: ClassVar[type[BaseModel]]

    def __init__(self, server: ServerConfig, remote: RemoteTool, client: MCPClient) -> None:
        self.server = server
        self.remote = remote
        self.client = client
        # Instance attributes shadow the ClassVars: every wrapper has its own name/schema.
        self.name = qualified_name(server.name, remote.name)  # type: ignore[misc]
        trust = "trusted" if server.trusted else "requires approval per call"
        self.description = (  # type: ignore[misc]
            f"[MCP server '{server.name}', {trust}] {remote.description}".strip()
        )
        try:
            self.Args = model_from_schema(self.name, remote.input_schema)  # type: ignore[misc]
        except SchemaError as exc:
            raise MCPToolError(str(exc)) from exc

    def describe_untrusted(self) -> str:
        """The description as it should be shown to a model: fenced third-party text."""
        return wrap_untrusted(self.remote.description, f"mcp-tool:{self.name}")

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        arguments = args.model_dump(mode="json", exclude_none=True)
        if not self.server.trusted:
            ctx.require_approval(
                self.name,
                f"call {self.remote.name} on MCP server '{self.server.name}'",
                [ActionCategory.EXTERNAL],
                server=self.server.name,
                remote_tool=self.remote.name,
                arguments=arguments,
            )
        try:
            text, is_error = self.client.call_tool(self.remote.name, arguments)
        except (MCPError, TransportError, JsonRpcError) as exc:
            ctx.audit.record(
                category=EventCategory.TOOL_CALL,
                action=self.name,
                outcome=Outcome.FAILURE,
                tool=self.name,
                details={"server": self.server.name, "error": str(exc)[:1000]},
                session_id=ctx.session_id,
            )
            raise MCPToolError(f"{self.name}: {exc}") from exc
        ctx.audit.record(
            category=EventCategory.TOOL_CALL,
            action=self.name,
            outcome=Outcome.SUCCESS if not is_error else Outcome.FAILURE,
            tool=self.name,
            details={"server": self.server.name, "remote_tool": self.remote.name},
            session_id=ctx.session_id,
        )
        # A server reporting isError is a failed step, not a completed one: the agent loop
        # reads ``ok`` and adapts accordingly (AG-004).
        return ToolResult(
            ok=not is_error,
            output=text,
            data={
                "server": self.server.name,
                "tool": self.remote.name,
                "is_error": is_error,
                "trusted": self.server.trusted,
            },
        )


class MCPSession:
    """Owns the clients for the configured servers and their wrapped tools.

    A session is explicitly opened and closed, because each server is a child process. Use it
    as a context manager, or call :meth:`close` from a ``finally``.
    """

    def __init__(
        self, config: MCPConfig | None = None, *, workspace_root: str | None = None
    ) -> None:
        self.config = config if config is not None else load_mcp_config()
        self.workspace_root = workspace_root
        self.clients: dict[str, MCPClient] = {}
        self.tools: dict[str, list[MCPTool]] = {}
        self.errors: dict[str, str] = {}

    def __enter__(self) -> MCPSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def connect(self, name: str) -> list[MCPTool]:
        """Start one server and wrap its tools. Errors are recorded, not raised."""
        server = self.config.get(name)
        if name in self.tools:
            return self.tools[name]
        client = MCPClient(server)
        try:
            client.start(workspace_root=self.workspace_root)
            remote_tools = client.list_tools()
        except (MCPError, TransportError, JsonRpcError) as exc:
            client.close()
            self.errors[name] = str(exc)[:2000]
            return []
        wrapped: list[MCPTool] = []
        for remote in remote_tools:
            try:
                wrapped.append(MCPTool(server, remote, client))
            except MCPToolError as exc:
                # One unusable tool must not cost the whole server.
                self.errors[f"{name}/{remote.name}"] = str(exc)[:500]
        self.clients[name] = client
        self.tools[name] = wrapped
        return wrapped

    def connect_all(self) -> list[MCPTool]:
        tools: list[MCPTool] = []
        for server in self.config.enabled():
            tools.extend(self.connect(server.name))
        return tools

    def register_into(self, registry: ToolRegistry) -> list[str]:
        """Add every connected tool to ``registry`` under the ``mcp`` group (MCP-004)."""
        registered: list[str] = []
        for tools in self.tools.values():
            for tool in tools:
                try:
                    registry.register(tool, MCP_GROUP)
                except ValueError as exc:
                    # A name already taken: never silently replace an existing tool.
                    self.errors[tool.name] = str(exc)
                    continue
                registered.append(tool.name)
        return registered

    def catalogue(self) -> str:
        """A human-readable listing of what the servers offer, with their trust level."""
        lines: list[str] = []
        for name, tools in sorted(self.tools.items()):
            server = self.config.get(name)
            info = self.clients[name].info
            trust = "trusted" if server.trusted else "approval per call"
            lines.append(f"{name}  {info.render()}  [{trust}]  {len(tools)} tool(s)")
            lines += [f"    {t.name}  {t.remote.description[:120]}" for t in tools]
        for where, error in sorted(self.errors.items()):
            lines.append(f"{where}: ERROR {error.splitlines()[0][:200]}")
        return "\n".join(lines) or "(no MCP servers connected)"

    def close(self) -> None:
        for client in self.clients.values():
            client.close()
        self.clients.clear()
        self.tools.clear()


def connect_servers(
    registry: ToolRegistry,
    config: MCPConfig | None = None,
    *,
    workspace_root: str | None = None,
) -> MCPSession:
    """Convenience: connect every enabled server and register its tools (MCP-001, MCP-007)."""
    session = MCPSession(config, workspace_root=workspace_root)
    session.connect_all()
    session.register_into(registry)
    return session


def describe_for_model(tools: list[MCPTool]) -> str:
    """Tool descriptions for a planner prompt, fenced as the untrusted data they are."""
    if not tools:
        return ""
    body = "\n".join(f"- {t.name}: {t.remote.description[:300]}" for t in tools)
    return wrap_untrusted(body, "mcp-tool-descriptions")


MCP_TOOL_TYPES: tuple[type[Tool], ...] = (MCPTool,)


def is_mcp_tool(tool: Tool) -> bool:
    return isinstance(tool, MCPTool)


def remote_arguments(tool: Tool, raw: dict[str, Any]) -> dict[str, Any]:
    """Validate ``raw`` against the remote tool's schema without calling it (MCP-003)."""
    if not isinstance(tool, MCPTool):
        raise MCPToolError(f"{tool.name} is not an MCP tool")
    return tool.parse_args(raw).model_dump(mode="json", exclude_none=True)
