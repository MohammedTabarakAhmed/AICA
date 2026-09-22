"""MCP server configuration (MCP-001, MCP-007).

An MCP server is a third-party program that this agent starts and then trusts for *tool
descriptions* - not for authority. Two rules follow, and both are enforced here rather than
left to the caller:

* **Servers are named in configuration.** The command line comes from ``config/mcp.toml``,
  never from a model or a tool argument. An agent can use the servers you approved; it cannot
  invent one.
* **The environment is allowlisted.** A server process receives only the variables named in
  its configuration, so it cannot read the credentials of unrelated services out of the
  parent environment (SAFE-006).

``trusted`` decides whether calls to the server pass the EXTERNAL approval gate. It defaults
to false: a server is someone else's code with side effects this project cannot see.
"""

from __future__ import annotations

import os
import shlex
import tomllib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

DEFAULT_MCP_PATH = Path("config/mcp.toml")
MAX_SERVERS = 32


class MCPConfigError(ValueError):
    """The MCP configuration is missing, malformed or unsafe."""


class ServerConfig(BaseModel):
    """One approved MCP server."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    command: str = Field(min_length=1, max_length=500)
    args: list[str] = Field(default_factory=list)
    cwd: str | None = None  # relative to the workspace root
    env: dict[str, str] = Field(
        default_factory=dict, description="literal values passed to the server process"
    )
    env_passthrough: list[str] = Field(
        default_factory=list, description="names of parent environment variables to forward"
    )
    # False means every call to this server passes the EXTERNAL approval gate.
    trusted: bool = False
    enabled: bool = True
    startup_timeout_seconds: float = Field(default=20.0, gt=0, le=300)
    call_timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    description: str = ""

    @field_validator("command")
    @classmethod
    def _no_shell_metacharacters(cls, value: str) -> str:
        """The command is executed with a fixed argv, never through a shell.

        Rejecting the metacharacters outright means a configuration that *expects* shell
        behaviour fails loudly instead of silently not doing what it looks like it does.
        """
        if any(ch in value for ch in ";|&<>`$\n"):
            raise ValueError(
                "the command must be a single executable without shell metacharacters; "
                "put arguments in args = [...]"
            )
        return value

    def argv(self) -> list[str]:
        return [self.command, *self.args]

    def render_command(self) -> str:
        return " ".join(shlex.quote(part) for part in self.argv())

    def environment(self) -> dict[str, str]:
        """The process environment: a minimal base, the allowlist, then literal values."""
        base: dict[str, str] = {}
        for name in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "USERPROFILE", "LANG"):
            value = os.environ.get(name)
            if value is not None:
                base[name] = value
        for name in self.env_passthrough:
            value = os.environ.get(name)
            if value is not None:
                base[name] = value
        base.update(self.env)
        return base


class MCPConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    servers: list[ServerConfig] = Field(default_factory=list)

    @field_validator("servers")
    @classmethod
    def _unique_and_bounded(cls, value: list[ServerConfig]) -> list[ServerConfig]:
        if len(value) > MAX_SERVERS:
            raise ValueError(f"too many servers ({len(value)}); the maximum is {MAX_SERVERS}")
        names = [s.name for s in value]
        duplicates = {n for n in names if names.count(n) > 1}
        if duplicates:
            raise ValueError(f"duplicate server names: {', '.join(sorted(duplicates))}")
        return value

    def enabled(self) -> list[ServerConfig]:
        return [s for s in self.servers if s.enabled]

    def get(self, name: str) -> ServerConfig:
        for server in self.servers:
            if server.name == name:
                if not server.enabled:
                    raise MCPConfigError(f"MCP server {name!r} is disabled in configuration")
                return server
        raise MCPConfigError(
            f"unknown MCP server {name!r}; configured: "
            + (", ".join(s.name for s in self.servers) or "none")
        )

    def names(self) -> list[str]:
        return [s.name for s in self.servers]


def load_mcp_config(path: str | Path | None = None) -> MCPConfig:
    """Load ``config/mcp.toml``. A missing file means no servers, not an error."""
    target = Path(path or os.environ.get("AICA_MCP_FILE") or DEFAULT_MCP_PATH)
    if not target.exists():
        return MCPConfig()
    try:
        raw = tomllib.loads(target.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise MCPConfigError(f"{target}: could not read MCP configuration: {exc}") from exc
    try:
        return MCPConfig.model_validate(raw)
    except ValidationError as exc:
        raise MCPConfigError(
            f"{target}: invalid MCP configuration: {exc.errors(include_url=False)}"
        ) from exc
