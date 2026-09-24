"""Tool registry with policy-controlled exposure (MCP-002, MCP-004, MCP-005)."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from aica.admin.controls import TargetKind
from aica.tools.base import Tool, ToolContext, ToolNotAllowed, ToolResult


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        self._groups: dict[str, str] = {}  # tool name -> policy group (filesystem, git, ...)

    def register(self, tool: Tool, group: str) -> None:
        if tool.name in self._tools:
            raise ValueError(f"duplicate tool {tool.name}")
        self._tools[tool.name] = tool
        self._groups[tool.name] = group

    def group_of(self, name: str) -> str:
        return self._groups[name]

    def is_mutating(self, name: str) -> bool:
        """Whether this tool changes state outside the agent (SEC-001's production gate)."""
        return type(self._tools[name]).mutating

    def denial_reason(self, name: str, ctx: ToolContext) -> str | None:
        """Why ``name`` may not be used here, or None when it may (SEC-001, SEC-002).

        Two layers, both narrowing: the coarse group allowlist from ``AutonomyLimits``,
        then the tool policy's allow/deny and its production denials. The deny list is
        evaluated inside ``ToolPolicy`` and wins over everything, so switching a tool off
        never depends on also remembering to remove it from an allowlist somewhere.
        """
        group = self._groups[name]
        # SEC-007 first: an operator switching something off during an incident must not
        # be overridden by anything, and must not have to wait for a restart. The control
        # plane is read here, on the call, rather than from a policy loaded at startup.
        if ctx.controls is not None:
            disabled = ctx.controls.is_disabled(TargetKind.TOOL, name, group)
            if disabled is not None:
                return disabled.describe()
        if group not in ctx.policy.autonomy.allowed_tools:
            return f"group {group!r} is not in autonomy.allowed_tools"
        return ctx.policy.tools.denial_reason(name, group, ctx.environment)

    def allowed(self, ctx: ToolContext) -> list[Tool]:
        return [t for n, t in self._tools.items() if self.denial_reason(n, ctx) is None]

    def schemas(self, ctx: ToolContext) -> list[dict[str, Any]]:
        return [t.schema() for t in self.allowed(ctx)]

    def get(self, name: str, ctx: ToolContext) -> Tool:
        tool = self._tools.get(name)
        if tool is None:
            raise KeyError(f"unknown tool {name!r}")
        reason = self.denial_reason(name, ctx)
        if reason is not None:
            raise ToolNotAllowed(f"tool {name!r} (group {self._groups[name]!r}): {reason}")
        return tool

    def call(self, name: str, raw_args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        return self.get(name, ctx).invoke(raw_args, ctx)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def clone(self) -> ToolRegistry:
        """A registry holding the same tools, safe to add to without affecting this one."""
        copy = ToolRegistry()
        copy._tools = dict(self._tools)
        copy._groups = dict(self._groups)
        return copy

    def subset(self, names: Iterable[str]) -> ToolRegistry:
        """A registry exposing only ``names`` - never more than this one already holds.

        A name this registry does not have is simply absent from the result: a caller
        describing a narrower agent (AG-008) may legitimately name a tool that this
        particular registry was not built with. Widening is impossible by construction.
        """
        wanted = set(names)
        copy = ToolRegistry()
        for name in sorted(wanted & set(self._tools)):
            copy.register(self._tools[name], self._groups[name])
        return copy
