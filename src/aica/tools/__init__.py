"""Baseline tool set (MCP-005): filesystem, git, shell, tests and repository retrieval."""

from aica.tools.base import (
    Tool,
    ToolArgumentError,
    ToolContext,
    ToolError,
    ToolNotAllowed,
    ToolResult,
)
from aica.tools.browser import BROWSER_TOOLS, SESSIONS, BrowserUnavailable
from aica.tools.database import DATABASE_TOOLS
from aica.tools.filesystem import FILESYSTEM_TOOLS, unified_diff
from aica.tools.git_tool import GIT_TOOLS
from aica.tools.rag_tool import RAG_TOOLS, format_results
from aica.tools.registry import ToolRegistry
from aica.tools.repository_tool import REPOSITORY_TOOLS
from aica.tools.shell import SHELL_TOOLS, ExecutionResult, build_environment, execute
from aica.tools.testing_tool import TESTING_TOOLS

_GROUPS: list[tuple[str, list[Tool]]] = [
    ("filesystem", FILESYSTEM_TOOLS),
    ("git", GIT_TOOLS),
    ("shell", SHELL_TOOLS),
    ("tests", TESTING_TOOLS),
    ("rag", RAG_TOOLS),
    ("browser", BROWSER_TOOLS),
    ("database", DATABASE_TOOLS),
    # INT-006. Off unless [autonomy].allowed_tools lists "repository": a third-party service.
    ("repository", REPOSITORY_TOOLS),
]


def default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    for group, tools in _GROUPS:
        for tool in tools:
            registry.register(tool, group)
    return registry


__all__ = [
    "BROWSER_TOOLS",
    "DATABASE_TOOLS",
    "FILESYSTEM_TOOLS",
    "GIT_TOOLS",
    "RAG_TOOLS",
    "REPOSITORY_TOOLS",
    "SESSIONS",
    "SHELL_TOOLS",
    "TESTING_TOOLS",
    "BrowserUnavailable",
    "ExecutionResult",
    "Tool",
    "ToolArgumentError",
    "ToolContext",
    "ToolError",
    "ToolNotAllowed",
    "ToolRegistry",
    "ToolResult",
    "build_environment",
    "default_registry",
    "execute",
    "format_results",
    "unified_diff",
]
