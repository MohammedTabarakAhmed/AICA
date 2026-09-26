"""Controlled command execution (EXEC-001..EXEC-007).

Execution boundary for the MVP is: subprocess in the authorized workspace, with a
timeout, a controlled environment (only an allowlist of host variables plus task-scoped
overrides; no credentials by default), classification + approval before launch, and full
stdout/stderr/exit-code capture written to the audit log. Container/VM isolation is a
later hardening step recorded in the progress file.
"""

from __future__ import annotations

import os
import signal
import subprocess  # noqa: S404 - controlled execution is the purpose of this tool
import sys
import threading
import time
from dataclasses import dataclass, replace
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from aica.audit import EventCategory, Outcome
from aica.policy import CancellationToken
from aica.policy.models import ActionCategory
from aica.safety.commands import (
    CommandClass,
    Decision,
    categories_for,
    classify_command,
    decide,
)
from aica.safety.network import check_destinations
from aica.safety.redaction import redact
from aica.safety.secrets import SecretInjection, SecretStore
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
        # POSIX: its own process group, so a timeout or cancel can stop everything it started.
        start_new_session=sys.platform != "win32",
    )
    cancelled = False
    timed_out = False
    stop = threading.Event()

    def _watch_cancel() -> None:
        while not stop.wait(0.1):
            if cancel is not None and cancel.is_cancelled:
                _kill_tree(proc)
                return

    watcher = threading.Thread(target=_watch_cancel, daemon=True)
    watcher.start()
    try:
        out, err = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        timed_out = True
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:  # something outside the tree still holds the pipes
            out, err = "", ""

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


def _kill_tree(proc: subprocess.Popen[str]) -> None:
    """Stop the shell and everything it started (SAFE-008, AG-007).

    Killing only the shell leaves the command it ran alive - and holding the output pipes, so
    reading them waits for that command to finish on its own, whatever the timeout said.
    """
    try:
        if sys.platform == "win32":
            subprocess.run(  # noqa: S603 - fixed arguments, a pid we started
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],  # noqa: S607
                capture_output=True,
                timeout=15,
                check=False,
            )
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    proc.kill()


def _time_allowed(requested: float, ctx: ToolContext) -> float:
    """The command's timeout: what it asked for, within policy and what the run has left."""
    allowed = min(requested, float(ctx.policy.autonomy.max_seconds))
    if ctx.deadline is not None:
        allowed = min(allowed, max(ctx.deadline - time.monotonic(), 1.0))
    return allowed


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
        # SEC-004: secrets are NAMED, never supplied. A value passed as an argument would
        # already have travelled through the prompt, the plan and the session file before
        # any gate saw it; a name carries nothing.
        secrets: list[str] = Field(
            default_factory=list,
            max_length=10,
            description="names of policy-declared secrets to inject into the environment",
        )

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        cwd = ctx.workspace.resolve(args.cwd).absolute
        if not cwd.is_dir():
            raise NotADirectoryError(args.cwd)
        classification = classify_command(args.command)
        # SEC-003. A destination check before the approval gate, not instead of it:
        # approving "this command talks to the network" never meant approving where it
        # was going, and a host outside the allowlist is refused rather than offered for
        # approval. Only commands that actually invoke a network client are checked, and
        # one whose host cannot be read (``git push``) keeps the gate it already had.
        if classification.command_class is CommandClass.EXTERNAL:
            check = check_destinations(args.command, ctx.policy.network)
            if not check.ok:
                ctx.audit.record(
                    category=EventCategory.POLICY_DECISION,
                    action=args.command,
                    outcome=Outcome.BLOCKED,
                    tool=self.name,
                    details={"denied_hosts": list(check.denied), "rule": "SEC-003"},
                )
                raise PermissionError(f"{self.name}: {check.reason()}")
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
        injection = SecretInjection(env={}, names=())
        if args.secrets:
            # Resolution first: a name policy does not permit is refused before anyone is
            # asked to approve it, so the approval prompt only ever lists real secrets.
            injection = SecretStore(ctx.policy.secrets).prepare(args.secrets, self.name)
            ctx.require_approval(
                self.name,
                f"inject secret(s) {', '.join(injection.names)} into: {args.command}",
                [ActionCategory.SECRET_ACCESS],
                secrets=list(injection.names),  # names only; the values never leave the store
            )
        timeout = _time_allowed(args.timeout_seconds, ctx)
        result = execute(
            args.command,
            str(cwd),
            timeout_seconds=timeout,
            env=build_environment({**args.env, **injection.env}),
            cancel=ctx.cancel,
        )
        if injection.env:
            # A command handed a real credential will sometimes echo it back, and pattern
            # redaction only catches formats it recognises. The exact values are known
            # here, so they are removed literally before anything is captured or audited.
            result = replace(
                result,
                stdout=injection.scrub(result.stdout),
                stderr=injection.scrub(result.stderr),
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
            output += f"\n[timed out after {timeout:.0f}s; process killed]"
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
