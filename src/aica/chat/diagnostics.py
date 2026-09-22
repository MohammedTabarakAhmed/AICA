"""Debugging from logs, stack traces and error output (CHAT-004).

A log pasted by a user is untrusted data (SAFE-007) and usually far larger than the
useful part of it. This module turns raw log text into structure the assistant can act on:

1. parse stack frames / file:line references across Python, Node/TypeScript, Java and
   generic ``file:line:col`` compiler output;
2. keep only frames that point inside the authorized workspace (project frames), so
   library internals do not dominate the context;
3. extract the error type and message;
4. build retrieval queries from the implicated symbols and error text, so the repository
   context handed to the model is the code the log actually blames.

Nothing here calls a model; :meth:`aica.chat.assistant.CodingAssistant.debug` consumes it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from aica.safety.redaction import redact

MAX_LOG_CHARS = 40_000


@dataclass(frozen=True)
class LogFrame:
    """One ``file:line`` reference found in a log."""

    file: str
    line: int | None
    symbol: str | None = None
    source: str = ""  # the log line it came from
    project: bool = False  # inside the authorized workspace

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}" if self.line else self.file


@dataclass
class Diagnosis:
    """Structured view of a log (CHAT-004)."""

    error_type: str | None = None
    error_message: str | None = None
    frames: list[LogFrame] = field(default_factory=list)
    truncated: bool = False

    @property
    def project_frames(self) -> list[LogFrame]:
        return [f for f in self.frames if f.project]

    @property
    def culprit(self) -> LogFrame | None:
        """The deepest project frame - where a stack trace actually failed."""
        project = self.project_frames
        return project[-1] if project else (self.frames[-1] if self.frames else None)

    def queries(self) -> list[str]:
        """Retrieval queries: implicated symbols/files first, then the error text."""
        out: list[str] = []
        for frame in reversed(self.project_frames[-4:]):
            out.append(frame.symbol or Path(frame.file).stem)
        if self.error_message:
            out.append(self.error_message[:200])
        elif self.error_type:
            out.append(self.error_type)
        return list(dict.fromkeys(q for q in out if q))

    def render(self) -> str:
        lines: list[str] = []
        if self.error_type or self.error_message:
            lines.append(
                f"Error: {self.error_type or '(unknown)'}: {self.error_message or ''}".strip()
            )
        culprit = self.culprit
        if culprit is not None:
            where = f"{culprit.location}" + (f" in {culprit.symbol}" if culprit.symbol else "")
            lines.append(f"Most likely origin: {where}")
        if self.project_frames:
            lines.append("Project frames (outermost first):")
            lines.extend(
                f"  {f.location}" + (f" in {f.symbol}" if f.symbol else "")
                for f in self.project_frames
            )
        if not lines:
            lines.append("No file references or error lines were recognised in this log.")
        if self.truncated:
            lines.append(f"(log truncated to the last {MAX_LOG_CHARS} characters)")
        return "\n".join(lines)


# Python: '  File "path", line 12, in func'
_PY_FRAME = re.compile(r'^\s*File "(?P<file>[^"]+)", line (?P<line>\d+)(?:, in (?P<sym>\S+))?')
# Python exception line: 'ValueError: boom' (also 'pkg.mod.Error: boom')
_PY_ERROR = re.compile(
    r"^(?P<type>[A-Za-z_][\w.]*(?:Error|Exception|Warning|Exit))\s*:\s*(?P<msg>.*)$"
)
# Node/V8: '    at fn (/path/file.js:10:5)' or '    at /path/file.js:10:5'
_NODE_FRAME = re.compile(
    r"^\s*at\s+(?:(?P<sym>[\w$.<>\[\] ]+?)\s+\()?(?P<file>[^()\s]+?):(?P<line>\d+):(?P<col>\d+)\)?\s*$"
)
# Java: '\tat com.x.Y.method(Y.java:42)'
_JAVA_FRAME = re.compile(r"^\s*at\s+(?P<sym>[\w$.]+)\((?P<file>[\w$]+\.java):(?P<line>\d+)\)")
_JAVA_ERROR = re.compile(
    r"^(?:Exception in thread \"[^\"]+\" )?(?P<type>(?:[\w.]+\.)?[\w$]*(?:Exception|Error))(?:\s*:\s*(?P<msg>.*))?$"
)
# Compiler / linter style: 'src/app.ts:10:5 - error TS2322: ...' or 'file.py:3:1: E501 ...'
_GENERIC_FRAME = re.compile(
    r"^(?P<file>[\w./\\@+-]+\.[A-Za-z0-9]{1,6}):(?P<line>\d+)(?::(?P<col>\d+))?[:\s]"
)
# pytest short summary: 'FAILED tests/test_x.py::test_y - ValueError: boom'
_PYTEST_FAILED = re.compile(
    r"^(?:FAILED|ERROR)\s+(?P<file>[^\s:]+\.py)::(?P<sym>[\w:.\[\]-]+)(?:\s+-\s+(?P<msg>.*))?$"
)
# Fallback for exception classes that do not end in Error/Exception - a common convention
# (this project's own ``InvalidCommitMessage`` is one). Only used when no suffixed
# exception line appears anywhere in the log, because it also matches prose like "Note: x".
_LOOSE_ERROR = re.compile(
    r"^(?P<type>(?:[a-z_][\w]*\.)*[A-Z][A-Za-z0-9_]*[a-z][A-Za-z0-9_]*)\s*:\s*(?P<msg>\S.*)$"
)


def _relativize(raw_file: str, root: Path | None) -> tuple[str, bool]:
    """Return (display path, is_project). Absolute paths inside the root become relative."""
    cleaned = raw_file.strip().replace("\\", "/")
    if root is None:
        return cleaned, False
    candidate = Path(raw_file)
    try:
        if candidate.is_absolute():
            resolved = candidate.resolve()
            if resolved.is_relative_to(root):
                return resolved.relative_to(root).as_posix(), True
            return cleaned, False
    except (OSError, ValueError):
        return cleaned, False
    # Relative path: it is a project frame when it exists under the root.
    return cleaned, (root / cleaned).exists()


def parse_log(text: str, workspace_root: str | Path | None = None) -> Diagnosis:
    """Parse a log/stack trace into a :class:`Diagnosis` (CHAT-004).

    ``workspace_root`` marks which frames belong to the project. Secrets in the log are
    redacted before anything is stored (SAFE-006).
    """
    diag = Diagnosis()
    text = redact(text).text
    if len(text) > MAX_LOG_CHARS:
        # Keep the tail: the failure and its stack are at the end of a log.
        text = text[-MAX_LOG_CHARS:]
        diag.truncated = True
    root = Path(workspace_root).resolve() if workspace_root is not None else None

    strict = False  # a suffixed exception line beats any loose match
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        frame = _match_frame(line, root)
        if frame is not None:
            diag.frames.append(frame)
            continue
        if _match_error(line, diag):
            strict = True
        elif not strict:
            _match_loose_error(line, diag)
    _dedupe_frames(diag)
    return diag


def _match_frame(line: str, root: Path | None) -> LogFrame | None:
    for pattern in (_PY_FRAME, _NODE_FRAME, _JAVA_FRAME, _PYTEST_FAILED, _GENERIC_FRAME):
        m = pattern.match(line)
        if m is None:
            continue
        groups = m.groupdict()
        file_display, project = _relativize(groups["file"], root)
        raw_line = groups.get("line")
        return LogFrame(
            file=file_display,
            line=int(raw_line) if raw_line else None,
            symbol=(groups.get("sym") or None),
            source=line.strip()[:300],
            project=project,
        )
    return None


def _match_error(line: str, diag: Diagnosis) -> bool:
    stripped = line.strip()
    for pattern in (_PY_ERROR, _JAVA_ERROR):
        m = pattern.match(stripped)
        if m is None:
            continue
        # Last error line wins: the outermost exception of a chain is reported last.
        diag.error_type = m.group("type")
        diag.error_message = (m.groupdict().get("msg") or "").strip() or None
        return True
    return False


def _match_loose_error(line: str, diag: Diagnosis) -> None:
    """Record a non-suffixed exception class, e.g. ``pkg.mod.InvalidCommitMessage: ...``."""
    m = _LOOSE_ERROR.match(line.strip())
    if m is None:
        return
    diag.error_type = m.group("type")
    diag.error_message = (m.group("msg") or "").strip() or None


def _dedupe_frames(diag: Diagnosis) -> None:
    seen: set[tuple[str, int | None]] = set()
    unique: list[LogFrame] = []
    for frame in diag.frames:
        key = (frame.file, frame.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(frame)
    diag.frames = unique
