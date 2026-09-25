"""Audit search, usage reporting and retention (ADM-007, ADM-006, ADM-009/SEC-005, API-015)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aica.admin.reporting import (
    AuditQuery,
    RetentionScope,
    apply_retention,
    iter_events,
    plan_retention,
    plan_workspace_retention,
    search,
    summarize,
)
from aica.audit import AuditEvent, EventCategory, JsonlAuditSink, Outcome
from aica.cli import main

fastapi_testclient = pytest.importorskip("fastapi.testclient", reason="the api extra is needed")
TestClient = fastapi_testclient.TestClient

TOKEN = "test-token-abcdefghijklmnop"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


def _event(**kwargs: object) -> AuditEvent:
    base: dict[str, object] = {
        "category": EventCategory.COMMAND,
        "action": "echo hello",
        "outcome": Outcome.SUCCESS,
        "actor": "alice",
        "timestamp": NOW,
    }
    base.update(kwargs)
    return AuditEvent.model_validate(base)


EVENTS = [
    _event(actor="alice", tool="shell.run", session_id="s1", duration_ms=100),
    _event(
        actor="bob",
        tool="fs.write",
        category=EventCategory.FILE_CHANGE,
        action="write src/app.py",
        session_id="s2",
        duration_ms=50,
    ),
    _event(
        actor="bob",
        tool="shell.run",
        outcome=Outcome.BLOCKED,
        action="rm -rf /",
        category=EventCategory.POLICY_DECISION,
        session_id="s2",
    ),
    _event(
        actor="alice",
        category=EventCategory.MODEL_CALL,
        action="chat",
        model="deepseek-chat",
        session_id="s1",
        duration_ms=800,
    ),
]


# ------------------------------------------------------------------ ADM-007 search
def test_search_with_no_filters_returns_everything_newest_first() -> None:
    results = search(EVENTS, AuditQuery())
    assert len(results) == len(EVENTS)
    assert results == sorted(results, key=lambda e: e.timestamp, reverse=True)


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        (AuditQuery(actor="alice"), 2),
        (AuditQuery(actor="bob"), 2),
        (AuditQuery(tool="shell.run"), 2),
        (AuditQuery(outcome=Outcome.BLOCKED), 1),
        (AuditQuery(category=EventCategory.MODEL_CALL), 1),
        (AuditQuery(model="deepseek-chat"), 1),
        (AuditQuery(session_id="s2"), 2),
        (AuditQuery(text="rm -rf"), 1),
        (AuditQuery(text="SRC/APP"), 1),  # case-insensitive
    ],
)
def test_each_filter_narrows_on_a_field_the_record_carries(
    query: AuditQuery, expected: int
) -> None:
    assert len(search(EVENTS, query)) == expected


def test_filters_combine_with_and() -> None:
    assert len(search(EVENTS, AuditQuery(actor="bob", tool="shell.run"))) == 1
    assert len(search(EVENTS, AuditQuery(actor="alice", outcome=Outcome.BLOCKED))) == 0


def test_a_time_window_excludes_events_outside_it() -> None:
    old = _event(timestamp=NOW - timedelta(days=10), actor="carol")
    events = [*EVENTS, old]
    assert len(search(events, AuditQuery(since=NOW - timedelta(days=1)))) == len(EVENTS)
    assert len(search(events, AuditQuery(until=NOW - timedelta(days=1)))) == 1


def test_search_respects_the_limit() -> None:
    assert len(search(EVENTS, AuditQuery(limit=2))) == 2


# ------------------------------------------------------------------ ADM-006 usage
def test_usage_aggregates_the_same_stream_the_search_reads() -> None:
    """Counted from the audit log itself, so the number shown is the one the record supports."""
    report = summarize(EVENTS)
    assert report.total == 4
    assert report.by_actor == {"alice": 2, "bob": 2}
    assert report.by_tool == {"shell.run": 2, "fs.write": 1}
    assert report.by_model == {"deepseek-chat": 1}
    assert report.sessions == 2
    assert report.blocked == 1
    assert report.duration_ms == 950


def test_usage_over_an_empty_window_says_so_rather_than_showing_zeroes() -> None:
    report = summarize(EVENTS, since=NOW + timedelta(days=1))
    assert report.total == 0
    assert "no activity recorded" in report.render()


def test_usage_renders_and_serialises() -> None:
    report = summarize(EVENTS)
    text = report.render()
    assert "alice" in text and "By actor" in text
    payload = json.loads(report.to_json())
    assert payload["total_events"] == 4 and payload["by_actor"]["bob"] == 2


# --------------------------------------------------- ADM-009 / SEC-005 retention
@pytest.fixture
def audit_dir(tmp_path: Path) -> Path:
    directory = tmp_path / ".aica" / "audit"
    directory.mkdir(parents=True)
    for day in ("2026-09-24", "2026-09-20", "2026-06-01"):
        (directory / f"audit-{day}.jsonl").write_text(
            _event().model_dump_json() + "\n", encoding="utf-8"
        )
    return directory


def test_retention_plans_by_whole_files_not_rows(audit_dir: Path) -> None:
    """Rewriting files to drop rows would leave a log someone edited in place."""
    # From 2026-09-24 a 3-day window keeps 09-24 and drops 09-20 and 06-01.
    plan = plan_retention(audit_dir, keep_days=3, now=NOW)
    assert [p.name for p in plan.remove] == ["audit-2026-06-01.jsonl", "audit-2026-09-20.jsonl"]
    assert [p.name for p in plan.keep] == ["audit-2026-09-24.jsonl"]
    assert plan.removed_bytes > 0


def test_retention_is_a_dry_run_until_applied(audit_dir: Path) -> None:
    plan = plan_retention(audit_dir, keep_days=3, now=NOW)
    assert len(list(audit_dir.glob("*.jsonl"))) == 3  # nothing removed by planning
    assert apply_retention(plan) == 2
    assert [p.name for p in audit_dir.glob("*.jsonl")] == ["audit-2026-09-24.jsonl"]


def test_retention_never_deletes_a_file_it_cannot_date(audit_dir: Path) -> None:
    (audit_dir / "audit-not-a-date.jsonl").write_text("{}\n", encoding="utf-8")
    plan = plan_retention(audit_dir, keep_days=1, now=NOW)
    assert "audit-not-a-date.jsonl" in [p.name for p in plan.keep]


def test_retention_rejects_a_zero_window(audit_dir: Path) -> None:
    with pytest.raises(ValueError, match="at least 1"):
        plan_retention(audit_dir, keep_days=0, now=NOW)


def test_retention_plan_renders_what_it_would_do(audit_dir: Path) -> None:
    plan = plan_retention(audit_dir, keep_days=3, now=NOW)
    assert "would remove" in plan.render(applied=False)
    assert "removed" in plan.render(applied=True)


# ------------------------------------------------------------------ reading files
def test_iter_events_skips_a_damaged_line_rather_than_stopping(audit_dir: Path) -> None:
    with (audit_dir / "audit-2026-09-24.jsonl").open("a", encoding="utf-8") as fh:
        fh.write("{ corrupted\n")
        fh.write(_event(actor="carol").model_dump_json() + "\n")
    actors = {e.actor for e in iter_events(audit_dir)}
    assert "carol" in actors


def test_iter_events_on_a_missing_directory_is_empty(tmp_path: Path) -> None:
    assert list(iter_events(tmp_path / "nope")) == []


# ------------------------------------------------------------------ CLI
@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "policy.toml").write_text(
        "version = 1\n[autonomy]\nmax_steps = 10\n[network]\nmode = 'deny'\n", encoding="utf-8"
    )
    sink = JsonlAuditSink(tmp_path / ".aica" / "audit")
    for event in EVENTS:
        sink.write(event)
    return tmp_path


def run(workspace: Path, *args: str) -> int:
    return main(
        ["-w", str(workspace), "--policy", str(workspace / "config" / "policy.toml"), *args]
    )


def test_cli_audit_search_filters(workspace: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(workspace, "audit", "--actor-filter", "bob") == 0
    out = capsys.readouterr().out
    assert "bob" in out and "alice" not in out


def test_cli_audit_reports_when_nothing_matches(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(workspace, "audit", "--actor-filter", "nobody") == 1
    assert "no matching audit events" in capsys.readouterr().out


def test_cli_audit_shows_attribution(workspace: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """NFR-004: every material action is attributable to actor and session."""
    run(workspace, "audit")
    out = capsys.readouterr().out
    assert "alice/s1" in out and "bob/s2" in out


def test_cli_usage_reports_by_actor(workspace: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(workspace, "usage", "--days", "3650", "--json") == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["by_actor"] == {"alice": 2, "bob": 2}
    assert payload["blocked"] == 1


def test_cli_retention_is_a_dry_run_by_default(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = len(list((workspace / ".aica" / "audit").glob("*.jsonl")))
    assert run(workspace, "retention", "--keep-days", "1") == 0
    assert "dry run" in capsys.readouterr().err
    assert len(list((workspace / ".aica" / "audit").glob("*.jsonl"))) == before


# ------------------------------------------------------------------ HTTP
@pytest.fixture
def client(workspace: Path) -> Iterator[TestClient]:
    from aica.api.app import ApiSettings, create_app

    app = create_app(
        ApiSettings(
            workspace=workspace,
            policy_file=str(workspace / "config" / "policy.toml"),
            token=TOKEN,
        )
    )
    with TestClient(app) as test_client:
        yield test_client


def test_http_audit_search_filters(client: TestClient) -> None:
    payload = client.get("/audit", params={"actor": "bob"}, headers=HEADERS).json()
    assert payload["count"] == 2
    assert {e["actor"] for e in payload["events"]} == {"bob"}


def test_http_audit_rejects_an_unknown_category(client: TestClient) -> None:
    assert client.get("/audit", params={"category": "wat"}, headers=HEADERS).status_code == 422


def test_http_usage_reports(client: TestClient) -> None:
    payload = client.get("/admin/usage", params={"days": 3650}, headers=HEADERS).json()
    assert payload["total_events"] == 4 and payload["sessions"] == 2


def test_http_retention_does_not_delete_without_apply(client: TestClient, workspace: Path) -> None:
    before = len(list((workspace / ".aica" / "audit").glob("*.jsonl")))
    payload = client.post("/admin/retention", json={"keep_days": 1}, headers=HEADERS).json()
    assert payload["applied"] is False
    assert len(list((workspace / ".aica" / "audit").glob("*.jsonl"))) == before


def test_http_retention_requires_a_token(client: TestClient) -> None:
    assert client.post("/admin/retention", json={"keep_days": 30}).status_code == 401
    assert client.get("/admin/usage").status_code == 401


# --------------------------------------------------- SEC-005 the other scopes
def test_retention_covers_sessions_and_source_derived_context(tmp_path: Path) -> None:
    """SEC-005 names sessions and source-derived context, not only the audit trail."""
    import os

    old = (NOW - timedelta(days=30)).timestamp()
    for relative in (".aica/sessions/s1.json", ".aica/index/chunks.db", ".aica/browser/shot.png"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x", encoding="utf-8")
        os.utime(path, (old, old))
    fresh = tmp_path / ".aica" / "sessions" / "s2.json"
    fresh.write_text("y", encoding="utf-8")

    plans = plan_workspace_retention(tmp_path, keep_days=7, now=NOW)
    by_scope: dict[str, list[str]] = {}
    for plan in plans:
        by_scope.setdefault(plan.scope.value, []).extend(p.name for p in plan.remove)
    assert by_scope["sessions"] == ["s1.json"]  # s2.json is fresh and kept
    assert sorted(by_scope["context"]) == ["chunks.db", "shot.png"]


def test_a_single_scope_does_not_touch_the_others(tmp_path: Path) -> None:
    """Deleting sessions should not force deleting the audit trail."""
    import os

    old = (NOW - timedelta(days=30)).timestamp()
    session = tmp_path / ".aica" / "sessions" / "s1.json"
    session.parent.mkdir(parents=True, exist_ok=True)
    session.write_text("x", encoding="utf-8")
    os.utime(session, (old, old))
    audit = tmp_path / ".aica" / "audit"
    audit.mkdir(parents=True, exist_ok=True)
    (audit / "audit-2026-06-01.jsonl").write_text("{}\n", encoding="utf-8")

    plans = plan_workspace_retention(tmp_path, 7, RetentionScope.SESSIONS, now=NOW)
    assert {p.scope for p in plans} == {RetentionScope.SESSIONS}
    for plan in plans:
        apply_retention(plan)
    assert (audit / "audit-2026-06-01.jsonl").exists()
    assert not session.exists()


def test_cli_retention_scope_is_reported_per_scope(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(workspace, "retention", "--keep-days", "1", "--scope", "audit") == 0
    out = capsys.readouterr().out
    assert "[audit]" in out and "[sessions]" not in out


def test_http_retention_reports_each_scope(client: TestClient) -> None:
    payload = client.post("/admin/retention", json={"keep_days": 1}, headers=HEADERS).json()
    assert {s["scope"] for s in payload["scopes"]} == {"audit", "sessions", "context"}
    assert payload["applied"] is False
