"""JSON-RPC 2.0 over a child process's stdio (MCP-001 transport).

The MCP stdio transport is newline-delimited JSON-RPC: one JSON object per line on stdin and
stdout, with stderr reserved for the server's own logging. This module owns that framing and
the process lifecycle, and nothing above it needs to know either.

It is written defensively because the peer is someone else's program:

* every read has a deadline, so a server that stops answering cannot hang the agent;
* line length and total message size are capped, so a server cannot exhaust memory;
* a line that is not valid JSON is skipped rather than fatal - servers sometimes print
  banners to stdout - but a bounded number of them, so garbage cannot loop forever;
* the process is terminated, then killed, on close, and stderr is kept for diagnostics.

The design is deliberately transport-shaped: a network transport can implement the same
``send``/``receive``/``close`` surface without changing the client above it (Entry 019).
"""

from __future__ import annotations

import json
import subprocess  # noqa: S404 - fixed argv, shell=False, configured commands only
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Protocol

MAX_LINE_BYTES = 8 * 1024 * 1024
MAX_JUNK_LINES = 50
STDERR_KEEP_LINES = 200


class TransportError(RuntimeError):
    """The server could not be started, died, or spoke unusable JSON-RPC."""


class TransportTimeout(TransportError):
    """The server did not answer within the deadline."""


class JsonRpcError(RuntimeError):
    """The server returned a JSON-RPC error response."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.data = data


class Transport(Protocol):
    def send(self, message: dict[str, Any]) -> None: ...
    def receive(self, timeout: float) -> dict[str, Any]: ...
    def close(self) -> None: ...
    @property
    def alive(self) -> bool: ...


class StdioTransport:
    """Runs an MCP server as a child process and exchanges JSON-RPC lines with it."""

    def __init__(
        self,
        argv: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: str | Path | None = None,
    ) -> None:
        self.argv = argv
        self._stderr: deque[str] = deque(maxlen=STDERR_KEEP_LINES)
        try:
            self._process = subprocess.Popen(  # noqa: S603 - fixed argv, shell=False
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
                env=env,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except (OSError, ValueError) as exc:
            raise TransportError(f"could not start MCP server {argv[0]!r}: {exc}") from exc
        self._drain = threading.Thread(target=self._drain_stderr, daemon=True)
        self._drain.start()

    def _drain_stderr(self) -> None:
        """Keep the server's log without ever letting it block the pipe."""
        stream = self._process.stderr
        if stream is None:
            return
        try:
            for line in stream:
                self._stderr.append(line.rstrip("\n")[:2000])
        except (OSError, ValueError):
            return

    @property
    def alive(self) -> bool:
        return self._process.poll() is None

    @property
    def stderr_tail(self) -> str:
        return "\n".join(self._stderr)

    def send(self, message: dict[str, Any]) -> None:
        if not self.alive:
            raise TransportError(f"MCP server exited ({self._process.returncode}){self._why()}")
        stdin = self._process.stdin
        if stdin is None:  # pragma: no cover - only if Popen was built without a pipe
            raise TransportError("MCP server has no stdin")
        payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False)
        if len(payload.encode("utf-8")) > MAX_LINE_BYTES:
            raise TransportError("refusing to send a message larger than the line limit")
        try:
            stdin.write(payload + "\n")
            stdin.flush()
        except (OSError, ValueError) as exc:
            raise TransportError(f"could not write to the MCP server: {exc}{self._why()}") from exc

    def receive(self, timeout: float) -> dict[str, Any]:
        """Read the next JSON object. Non-JSON lines are skipped, within a bound."""
        stdout = self._process.stdout
        if stdout is None:  # pragma: no cover
            raise TransportError("MCP server has no stdout")
        deadline = time.monotonic() + timeout
        junk = 0
        while True:
            if time.monotonic() > deadline:
                raise TransportTimeout(f"no reply within {timeout:g}s{self._why()}")
            line = _read_line(stdout, deadline)
            if line is None:
                if not self.alive:
                    raise TransportError(
                        f"MCP server exited ({self._process.returncode}){self._why()}"
                    )
                raise TransportTimeout(f"no reply within {timeout:g}s{self._why()}")
            if not line.strip():
                continue
            if len(line.encode("utf-8", "replace")) > MAX_LINE_BYTES:
                raise TransportError("MCP server sent a message over the size limit")
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                junk += 1
                if junk > MAX_JUNK_LINES:
                    raise TransportError(
                        f"MCP server sent {junk} lines that were not JSON{self._why()}"
                    ) from None
                continue
            if not isinstance(message, dict):
                junk += 1
                continue
            return message

    def close(self) -> None:
        if self._process.poll() is None:
            for finish, wait in ((self._process.terminate, 5.0), (self._process.kill, 5.0)):
                try:
                    finish()
                    self._process.wait(timeout=wait)
                    break
                except (subprocess.TimeoutExpired, OSError):
                    continue
        for stream in (self._process.stdin, self._process.stdout, self._process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass

    def _why(self) -> str:
        tail = self.stderr_tail.strip()
        if not tail:
            return ""
        return "\nserver stderr:\n" + "\n".join(tail.splitlines()[-10:])


def _read_line(stream: Any, deadline: float) -> str | None:
    """Read one line, giving up at ``deadline``.

    ``readline`` on a pipe blocks, and there is no portable way to poll a pipe with a timeout
    on Windows, so the read runs on a worker thread and the caller stops waiting at the
    deadline. The thread is a daemon: if the server never answers, it dies with the process
    rather than keeping it alive.
    """
    result: list[str | None] = []

    def read() -> None:
        try:
            result.append(stream.readline())
        except (OSError, ValueError):
            result.append(None)

    worker = threading.Thread(target=read, daemon=True)
    worker.start()
    worker.join(timeout=max(deadline - time.monotonic(), 0.0))
    if worker.is_alive() or not result:
        return None
    line = result[0]
    return line if line else None


def request(method: str, params: dict[str, Any] | None, request_id: int) -> dict[str, Any]:
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


def notification(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        message["params"] = params
    return message
