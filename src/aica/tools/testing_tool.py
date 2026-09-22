"""Testing tools (TEST-001..TEST-009)."""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from aica.testing.discovery import commands_for
from aica.testing.results import CheckStatus, analyze_failures, parse_output
from aica.tools.base import Tool, ToolContext, ToolError, ToolResult
from aica.tools.shell import RunCommand


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DiscoverTests(Tool):
    name: ClassVar[str] = "test.discover"
    description: ClassVar[str] = (
        "Discover the project's actual test/lint/typecheck commands from repository evidence."
    )

    class Args(_Args):
        kinds: list[str] = Field(default_factory=list)

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        cmds = commands_for(ctx.workspace.root, args.kinds or None)
        lines = [f"{c.kind}: {c.command}   [{c.framework}; {c.reason}]" for c in cmds]
        return ToolResult(
            output="\n".join(lines) or "(no test commands discovered)",
            data={
                "commands": [
                    {
                        "kind": c.kind,
                        "command": c.command,
                        "framework": c.framework,
                        "reason": c.reason,
                    }
                    for c in cmds
                ]
            },
        )


class RunTests(Tool):
    name: ClassVar[str] = "test.run"
    description: ClassVar[str] = (
        "Run tests and return a parsed outcome (counts, failures with locations, coverage). "
        "Either give an explicit command, or a kind to run the discovered command for that kind."
    )

    class Args(_Args):
        command: str | None = None
        kind: str = Field(default="unit", pattern="^(unit|integration|e2e|lint|typecheck|build)$")
        timeout_seconds: float = Field(default=900.0, gt=0, le=3600)

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        command = args.command
        if not command:
            candidates = commands_for(ctx.workspace.root, [args.kind])
            if not candidates:
                raise ToolError(f"no {args.kind} test command discovered; pass command explicitly")
            command = candidates[0].command
        shell = RunCommand()
        result = shell.invoke({"command": command, "timeout_seconds": args.timeout_seconds}, ctx)
        exit_code = result.data.get("exit_code")
        outcome = parse_output(
            args.kind,
            command,
            str(result.data.get("stdout", "")),
            str(result.data.get("stderr", "")),
            exit_code if isinstance(exit_code, int) else None,
            int(result.data.get("duration_ms", 0)),
        )
        if result.data.get("timed_out"):
            outcome.status = CheckStatus.ERROR
        analysis = analyze_failures(outcome)
        return ToolResult(
            ok=outcome.ok,
            output=outcome.summary() + ("\n\n" + analysis if not outcome.ok else ""),
            data={
                "kind": outcome.kind,
                "command": command,
                "status": outcome.status.value,
                "passed": outcome.passed,
                "failed": outcome.failed,
                "skipped": outcome.skipped,
                "exit_code": outcome.exit_code,
                "coverage_percent": outcome.coverage_percent,
                "failures": [
                    {"test": f.test, "location": f.location, "message": f.message}
                    for f in outcome.failures
                ],
                "analysis": analysis,
                "duration_ms": outcome.duration_ms,
            },
        )


TESTING_TOOLS: list[Tool] = [DiscoverTests(), RunTests()]
