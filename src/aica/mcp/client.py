"""MCP client: handshake, tool discovery and tool calls (MCP-001, MCP-002).

The client speaks to one server over a :class:`~aica.mcp.protocol.Transport`. It owns the
request/response correlation and the MCP lifecycle; it does not decide what may be called -
that is policy, applied by the tool wrapper above it.

Everything a server says is **data**. Tool names, descriptions and results are third-party
content that will later be shown to a model, so they are length-bounded and redacted here,
and the names are namespaced by the wrapper so a server cannot present itself as a built-in
tool (SAFE-007).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from aica.mcp.config import ServerConfig
from aica.mcp.protocol import (
    JsonRpcError,
    StdioTransport,
    Transport,
    TransportError,
    TransportTimeout,
    notification,
    request,
)
from aica.safety.redaction import redact

PROTOCOL_VERSION = "2024-11-05"
CLIENT_NAME = "aica"
CLIENT_VERSION = "0.0.1"
MAX_DESCRIPTION_CHARS = 2000
MAX_RESULT_CHARS = 100_000
MAX_TOOLS = 200
MAX_UNSOLICITED = 50


class MCPError(RuntimeError):
    """The server could not be used."""


@dataclass(frozen=True)
class RemoteTool:
    """A tool as advertised by a server. ``name`` is the server's own, un-namespaced name."""

    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        return f"{self.name}: {self.description[:200]}"


@dataclass
class ServerInfo:
    name: str = ""
    version: str = ""
    protocol_version: str = ""
    capabilities: dict[str, Any] = field(default_factory=dict)

    def render(self) -> str:
        return f"{self.name or '(unnamed)'} {self.version} [MCP {self.protocol_version}]"


class MCPClient:
    """One connection to one MCP server. Use as a context manager."""

    def __init__(self, config: ServerConfig, transport: Transport | None = None) -> None:
        self.config = config
        self._transport = transport
        self._next_id = 1
        self.info = ServerInfo()
        self._tools: list[RemoteTool] | None = None
        self._started = False

    # ------------------------------------------------------------------ lifecycle
    def __enter__(self) -> MCPClient:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def start(self, workspace_root: str | None = None) -> ServerInfo:
        """Launch the server (if needed) and perform the MCP handshake."""
        if self._started:
            return self.info
        if self._transport is None:
            cwd = None
            if self.config.cwd and workspace_root:
                cwd = f"{workspace_root}/{self.config.cwd}"
            elif self.config.cwd:
                cwd = self.config.cwd
            self._transport = StdioTransport(
                self.config.argv(), env=self.config.environment(), cwd=cwd
            )
        try:
            result = self._call(
                "initialize",
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
                },
                timeout=self.config.startup_timeout_seconds,
            )
        except (TransportError, JsonRpcError) as exc:
            self.close()
            raise MCPError(f"MCP server {self.config.name!r} failed to initialize: {exc}") from exc

        server_info = result.get("serverInfo") if isinstance(result, dict) else {}
        server_info = server_info if isinstance(server_info, dict) else {}
        capabilities = result.get("capabilities") if isinstance(result, dict) else {}
        self.info = ServerInfo(
            name=str(server_info.get("name", ""))[:200],
            version=str(server_info.get("version", ""))[:100],
            protocol_version=str(result.get("protocolVersion", ""))[:50],
            capabilities=capabilities if isinstance(capabilities, dict) else {},
        )
        # The spec requires this notification before normal operation.
        self._notify("notifications/initialized")
        self._started = True
        return self.info

    def close(self) -> None:
        self._started = False
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    @property
    def alive(self) -> bool:
        return self._transport is not None and self._transport.alive

    # ------------------------------------------------------------------ MCP-002
    def list_tools(self, *, refresh: bool = False) -> list[RemoteTool]:
        """Discover the server's tools. Descriptions are bounded and redacted."""
        if self._tools is not None and not refresh:
            return self._tools
        if not self._started:
            self.start()
        result = self._call("tools/list", {}, timeout=self.config.call_timeout_seconds)
        raw = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(raw, list):
            raise MCPError(f"MCP server {self.config.name!r} returned no tool list")
        tools: list[RemoteTool] = []
        for entry in raw[:MAX_TOOLS]:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            schema = entry.get("inputSchema")
            tools.append(
                RemoteTool(
                    name=name.strip()[:128],
                    description=redact(str(entry.get("description") or "")).text[
                        :MAX_DESCRIPTION_CHARS
                    ],
                    input_schema=schema if isinstance(schema, dict) else {},
                )
            )
        self._tools = tools
        return tools

    def call_tool(self, name: str, arguments: dict[str, Any]) -> tuple[str, bool]:
        """Call a tool. Returns (text content, is_error).

        A server reports a tool-level failure with ``isError`` rather than a JSON-RPC error,
        and both must reach the caller as a failure - a tool that reports an error is not a
        step that succeeded.
        """
        if not self._started:
            self.start()
        result = self._call(
            "tools/call",
            {"name": name, "arguments": arguments},
            timeout=self.config.call_timeout_seconds,
        )
        if not isinstance(result, dict):
            raise MCPError(f"{self.config.name}/{name}: unusable result from the server")
        is_error = bool(result.get("isError", False))
        return _content_text(result.get("content")), is_error

    # ------------------------------------------------------------------ JSON-RPC
    def _call(self, method: str, params: dict[str, Any], *, timeout: float) -> Any:
        if self._transport is None:
            raise MCPError(f"MCP server {self.config.name!r} is not connected")
        request_id = self._next_id
        self._next_id += 1
        self._transport.send(request(method, params, request_id))
        deadline = time.monotonic() + timeout
        unsolicited = 0
        while True:
            remaining = max(deadline - time.monotonic(), 0.0)
            if remaining <= 0:
                raise TransportTimeout(f"{method}: no reply within {timeout:g}s")
            message = self._transport.receive(remaining)
            if message.get("id") != request_id:
                # A notification, a log, or a request from the server: MCP allows these to
                # arrive between a request and its response. Skip them, but not forever.
                unsolicited += 1
                if unsolicited > MAX_UNSOLICITED:
                    raise MCPError(
                        f"{method}: server sent {unsolicited} messages without answering"
                    )
                continue
            if "error" in message:
                error = message["error"]
                error = error if isinstance(error, dict) else {}
                raise JsonRpcError(
                    int(error.get("code", -1)),
                    redact(str(error.get("message", "unknown error"))).text[:1000],
                    error.get("data"),
                )
            return message.get("result")

    def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        if self._transport is None:
            return
        try:
            self._transport.send(notification(method, params))
        except TransportError:
            # A server that will not accept the notification will fail the next call with a
            # better message; losing a notification is not itself fatal.
            return


def _content_text(content: Any) -> str:
    """Flatten MCP content blocks into text, describing the parts that are not text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return redact(content).text[:MAX_RESULT_CHARS]
    if not isinstance(content, list):
        return redact(str(content)).text[:MAX_RESULT_CHARS]
    parts: list[str] = []
    for block in content:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, dict):
            kind = block.get("type")
            if kind == "text":
                parts.append(str(block.get("text", "")))
            elif kind == "image":
                parts.append(f"[image: {block.get('mimeType', 'unknown type')}]")
            elif kind == "resource":
                resource = block.get("resource")
                uri = resource.get("uri") if isinstance(resource, dict) else None
                parts.append(f"[resource: {uri or 'unknown'}]")
            else:
                parts.append(f"[{kind or 'unknown'} content]")
    return redact("\n".join(parts)).text[:MAX_RESULT_CHARS]
