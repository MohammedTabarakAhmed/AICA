"""Audit sinks.

``JsonlAuditSink`` appends one redacted JSON object per line to a daily file. It is the
Phase 0 persistence baseline; ADM-007 audit search and ADM-009 retention are later phases
and will build on the same ``AuditEvent`` schema.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from aica.audit.events import AuditEvent

DEFAULT_AUDIT_DIR = Path(".aica/audit")


class AuditSink(Protocol):
    def write(self, event: AuditEvent) -> None: ...


class InMemoryAuditSink:
    """For tests and dry runs."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)


class JsonlAuditSink:
    def __init__(self, directory: str | os.PathLike[str] | None = None) -> None:
        env_dir = os.environ.get("AICA_AUDIT_DIR")
        self.directory = (
            Path(directory) if directory is not None else Path(env_dir or DEFAULT_AUDIT_DIR)
        )
        self.directory.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _file_for(self, event: AuditEvent) -> Path:
        return self.directory / f"audit-{event.timestamp.astimezone(UTC):%Y-%m-%d}.jsonl"

    def write(self, event: AuditEvent) -> None:
        line = event.to_json_line()
        with self._lock, self._file_for(event).open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def read_all(self) -> Iterator[AuditEvent]:
        for path in sorted(self.directory.glob("audit-*.jsonl")):
            with path.open(encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        yield AuditEvent.model_validate_json(line)


class AuditLog:
    """Facade that stamps actor/session context onto events."""

    def __init__(self, sink: AuditSink, actor: str, session_id: str | None = None) -> None:
        self.sink = sink
        self.actor = actor
        self.session_id = session_id

    def record(self, **fields: object) -> AuditEvent:
        # A caller passing None must not blank out the log's own context.
        if fields.get("actor") is None:
            fields["actor"] = self.actor
        if fields.get("session_id") is None:
            fields["session_id"] = self.session_id
        fields.setdefault("timestamp", datetime.now(UTC))
        event = AuditEvent.model_validate(fields)
        self.sink.write(event)
        return event
