import json
from pathlib import Path

from aica.audit import (
    AuditEvent,
    AuditLog,
    EventCategory,
    InMemoryAuditSink,
    JsonlAuditSink,
    Outcome,
)
from aica.safety import REDACTED


def test_event_redacts_arguments_and_details() -> None:
    e = AuditEvent(
        category=EventCategory.COMMAND,
        action="run: export TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        outcome=Outcome.SUCCESS,
        actor="dev@example.com",
        arguments={
            "command": "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz'",
            "api_key": "x" * 10,
        },
        details={"stdout": "AKIAIOSFODNN7EXAMPLE"},
    )
    assert "ghp_" not in e.action
    assert "abcdefghijklmnopqrstuvwxyz" not in str(e.arguments)
    assert e.arguments["api_key"] == REDACTED
    assert e.details["stdout"] == REDACTED
    assert e.event_id and e.timestamp.tzinfo is not None


def test_jsonl_sink_round_trip(tmp_path: Path) -> None:
    sink = JsonlAuditSink(tmp_path)
    log = AuditLog(sink, actor="dev", session_id="s1")
    e1 = log.record(
        category=EventCategory.TOOL_CALL,
        action="fs.read",
        outcome=Outcome.SUCCESS,
        tool="filesystem",
        target="README.md",
    )
    e2 = log.record(
        category=EventCategory.POLICY_DECISION,
        action="rm -rf build",
        outcome=Outcome.PENDING_APPROVAL,
    )
    files = list(tmp_path.glob("audit-*.jsonl"))
    assert len(files) == 1
    lines = files[0].read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["session_id"] == "s1"
    assert [e.event_id for e in sink.read_all()] == [e1.event_id, e2.event_id]


def test_audit_dir_from_env(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("AICA_AUDIT_DIR", str(tmp_path / "custom"))
    sink = JsonlAuditSink()
    assert sink.directory == tmp_path / "custom"
    assert sink.directory.is_dir()


def test_in_memory_sink() -> None:
    sink = InMemoryAuditSink()
    AuditLog(sink, actor="dev").record(
        category=EventCategory.TASK, action="start", outcome=Outcome.SUCCESS
    )
    assert len(sink.events) == 1 and sink.events[0].actor == "dev"
