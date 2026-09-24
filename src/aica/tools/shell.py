"""Controlled command execution (EXEC-001..EXEC-007).

Execution boundary for the MVP is: subprocess in the authorized workspace, with a
timeout, a controlled environment (only an allowlist of host variables plus task-scoped
overrides; no credentials by default), classification + approval before launch, and full
stdout/stderr/exit-code capture written to the audit log. Container/VM isolation is a
later hardening step recorded in the progress file.
"""

from __future__ import annotations

import os
import subprocess  # noqa: S404 - controlled execution is the purpose of this tool
import sys
import threading
import time
from dataclasses import dataclass
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from aica.audit import EventCategory, Outcome
from aica.policy import CancellationToken
from aica.safety.commands import Decision, categories_for, classify_command, decide
from aica.safety.redaction import redact
from aica.tools.base import Tool, ToolContext, ToolResult

# Host environment variables that are safe and useful to inherit. Credentials are not.
_INHERITED_ENV = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "COMSPEC",
    "WINDIR",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "LANG",
    "LC_ALL",
    "TERM",
    "SHELL",
    "PYTHONIOENCODING",
    "VIRTUAL_ENV",
    "JAVA_HOME",
    "GOPATH",
    "CARGO_HOME",
    "NVM_DIR",
    "NODE_PATH",
    "OS",
    "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS",
)
MAX_CAPTURE = 200_000


@dataclass(frozen=True)
class ExecutionResult:
    command: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool
    cancelled: bool

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.cancelled


def build_environment(overrides: dict[str, str] | None = None) -> dict[str, str]:
    """EXEC-004: controlled environment — allowlisted host vars + task-scoped overrides."""
    env = {k: v for k, v in os.environ.items() if k.upper() in _INHERITED_ENV}
    env["PYTHONUNBUFFERED"] = "1"
    env["AICA_SANDBOX"] = "1"
    for k, v in (overrides or {}).items():
        env[k] = v
    return env


def execute(
    command: str,
    cwd: str,
    *,
    timeout_seconds: float,
    env: dict[str, str] | None = None,
    cancel: CancellationToken | None = None,
) -> ExecutionResult:
    """Run ``command`` through the platform shell with timeout and cancellation."""
    started = time.monotonic()
    shell_cmd: list[str] | str
    if sys.platform == "win32":
        # Pass a single string: a list would go through list2cmdline, which re-quotes the
        # command and breaks any quoting the caller wrote. `/s` makes cmd strip exactly the
        # outer pair of quotes and take the rest literally.
        shell_cmd = f'cmd.exe /d /s /c "{command}"'
    else:
        shell_cmd = ["/bin/sh", "-c", command]
    proc = subprocess.Popen(  # noqa: S603 - command already classified and approval-gated
        shell_cmd,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    cancelled = False
    timed_out = False
    stop = threading.Event()

    def _watch_cancel() -> None:
        while not stop.wait(0.1):
            if cancel is not None and cancel.is_cancelled:
                proc.kill()
                return

    watcher = threading.Thread(target=_watch_cancel, daemon=True)
    watcher.start()
    try:
        out, err = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        timed_out = True
    finally:
        stop.set()
        watcher.join(timeout=1)
    if cancel is not None and cancel.is_cancelled:
        cancelled = True
    return ExecutionResult(
        command=command,
        exit_code=None if timed_out or cancelled else proc.returncode,
        stdout=out[-MAX_CAPTURE:],
        stderr=err[-MAX_CAPTURE:],
        duration_ms=int((time.monotonic() - started) * 1000),
        timed_out=timed_out,
        cancelled=cancelled,
    )


class RunCommand(Tool):
    name: ClassVar[str] = "shell.run"
    mutating: ClassVar[bool] = True
    description: ClassVar[str] = (
        "Run a shell command inside the workspace. Commands are classified; destructive, "
        "privileged, external and secret-touching commands require approval per policy."
    )

    class Args(BaseModel):
        model_config = ConfigDict(extra="forbid")

        command: str = Field(min_length=1, max_length=8000)
        cwd: str = "."
        timeout_seconds: float = Field(default=300.0, gt=0, le=3600)
        env: dict[str, str] = Field(
            default_factory=dict, description="task-scoped environment overrides"
        )

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        cwd = ctx.workspace.resolve(args.cwd).absolute
        if not cwd.is_dir():
            raise NotADirectoryError(args.cwd)
        classification = classify_command(args.command)
        decision = decide(classification, ctx.policy.approval, ctx.environment)
        cats = categories_for(classification, ctx.environment)
        if decision is Decision.BLOCK:
            ctx.audit.record(
                category=EventCategory.POLICY_DECISION,
                action=args.command,
                outcome=Outcome.BLOCKED,
                tool=self.name,
                details={
                    "class": classification.command_class.value,
                    "reasons": list(classification.reasons),
                },
            )
            raise PermissionError(f"command blocked by policy: {'; '.join(classification.reasons)}")
        if decision is Decision.REQUIRE_APPROVAL:
            ctx.require_approval(
                self.name,
                args.command,
                cats,
                classification=classification.command_class.value,
                reasons=", ".join(classification.reasons),
            )
        result = execute(
            args.command,
            str(cwd),
            timeout_seconds=min(args.timeout_seconds, float(ctx.policy.autonomy.max_seconds)),
            env=build_environment(args.env),
            cancel=ctx.cancel,
        )
        # EXEC-007: record command + outcome (redacted at the audit boundary).
        ctx.audit.record(
            category=EventCategory.COMMAND,
            action=args.command,
            outcome=Outcome.SUCCESS
            if result.ok
            else (Outcome.CANCELLED if result.cancelled else Outcome.FAILURE),
            tool=self.name,
            target=str(cwd.relative_to(ctx.workspace.root)) or ".",
            details={
                "class": classification.command_class.value,
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "stdout_tail": redact(result.stdout[-2000:]).text,
                "stderr_tail": redact(result.stderr[-2000:]).text,
            },
            duration_ms=result.duration_ms,
            session_id=ctx.session_id,
        )
        output = result.stdout
        if result.stderr:
            output += ("\n" if output else "") + "[stderr]\n" + result.stderr
        if result.timed_out:
            output += f"\n[timed out after {args.timeout_seconds:.0f}s; process killed]"
        if result.cancelled:
            output += "\n[cancelled]"
        return ToolResult(
            ok=result.ok,
            output=output,
            data={
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "cancelled": result.cancelled,
                "duration_ms": result.duration_ms,
                "class": classification.command_class.value,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
        )


SHELL_TOOLS: list[Tool] = [RunCommand()]
