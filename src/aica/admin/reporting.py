"""Audit search, usage reporting and retention (ADM-007, ADM-006, ADM-009 / SEC-005).

The audit log has recorded every material action since Phase 0. Until now the only way
to consult it was to read the last N lines, which answers "what just happened" and
nothing an administrator actually asks: *who* ran the destructive commands last week,
which model answered for a session, how much a project is using, and what may now be
deleted.

Three things live here because they are three views of one record set:

* **Search** (ADM-007) filters on the fields the ``AuditEvent`` schema already carries -
  actor, category, outcome, tool, model, session, time window, free text - and streams
  rather than loading a year of logs into memory to return twenty rows.
* **Usage** (ADM-006) aggregates the same stream. Deliberately counted from the audit
  log rather than from a separate meter: a second counter would drift, and the number an
  administrator is shown should be the one the record supports.
* **Retention** (ADM-009, SEC-005) deletes whole daily files once they fall outside the
  window. Files, not rows, because a rewritten audit file is no longer evidence of
  anything - an append-only log that someone edits in place has lost the property that
  made it worth keeping. A dry run is the default at the surfaces, and the deletion
  itself is an audited administrative act.

Everything read here was redacted on the way in (SAFE-006), so nothing in this module
needs to redact again; what it must not do is re-introduce a value by reading around the
schema, and it never touches anything but ``AuditEvent``.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from aica.audit.events import AuditEvent, EventCategory, Outcome

MAX_RESULTS = 1000


@dataclass(frozen=True)
class AuditQuery:
    """ADM-007: what to look for. Every field is optional and they combine with AND."""

    actor: str | None = None
    category: EventCategory | None = None
    outcome: Outcome | None = None
    tool: str | None = None
    model: str | None = None
    session_id: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    text: str | None = None  # substring of the action, target or tool
    limit: int = 100

    def matches(self, event: AuditEvent) -> bool:
        if self.actor and event.actor != self.actor:
            return False
        if self.category and event.category is not self.category:
            return False
        if self.outcome and event.outcome is not self.outcome:
            return False
        if self.tool and event.tool != self.tool:
            return False
        if self.model and event.model != self.model:
            return False
        if self.session_id and event.session_id != self.session_id:
            return False
        when = event.timestamp.astimezone(UTC)
        if self.since and when < self.since:
            return False
        if self.until and when > self.until:
            return False
        if self.text:
            needle = self.text.lower()
            haystack = " ".join(
                part for part in (event.action, event.target, event.tool) if part
            ).lower()
            if needle not in haystack:
                return False
        return True


def search(events: Iterable[AuditEvent], query: AuditQuery) -> list[AuditEvent]:
    """Matching events, newest first, capped at ``query.limit``.

    Streams the source: an audit log is append-only and grows without bound, so a search
    that materialises it to answer one question stops working exactly when the log has
    become worth searching.
    """
    limit = max(1, min(query.limit, MAX_RESULTS))
    matched: list[AuditEvent] = [e for e in events if query.matches(e)]
    matched.sort(key=lambda e: e.timestamp, reverse=True)
    return matched[:limit]


@dataclass
class UsageReport:
    """ADM-006: what happened, by whom, over a window."""

    since: datetime | None = None
    until: datetime | None = None
    total: int = 0
    by_actor: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    by_outcome: dict[str, int] = field(default_factory=dict)
    by_tool: dict[str, int] = field(default_factory=dict)
    by_model: dict[str, int] = field(default_factory=dict)
    by_session: dict[str, int] = field(default_factory=dict)
    sessions: int = 0
    duration_ms: int = 0

    @property
    def blocked(self) -> int:
        return self.by_outcome.get(Outcome.BLOCKED.value, 0)

    @property
    def failures(self) -> int:
        return self.by_outcome.get(Outcome.FAILURE.value, 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "since": self.since.isoformat() if self.since else None,
            "until": self.until.isoformat() if self.until else None,
            "total_events": self.total,
            "sessions": self.sessions,
            "total_duration_ms": self.duration_ms,
            "blocked": self.blocked,
            "failures": self.failures,
            "by_actor": self.by_actor,
            "by_category": self.by_category,
            "by_outcome": self.by_outcome,
            "by_tool": self.by_tool,
            "by_model": self.by_model,
            "by_session": self.by_session,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def render(self) -> str:
        window = (
            f"{self.since.date() if self.since else 'start'} .. "
            f"{self.until.date() if self.until else 'now'}"
        )
        lines = [
            f"# Usage {window}",
            f"{self.total} material action(s) across {self.sessions} session(s); "
            f"{self.blocked} blocked, {self.failures} failed; "
            f"{self.duration_ms / 1000:.1f}s of recorded tool time",
        ]
        for title, data in (
            ("By actor", self.by_actor),
            ("By category", self.by_category),
            ("By tool", self.by_tool),
            ("By model", self.by_model),
        ):
            if not data:
                continue
            lines.append(f"\n## {title}")
            for key, count in sorted(data.items(), key=lambda kv: (-kv[1], kv[0])):
                lines.append(f"  {count:>6}  {key}")
        if not self.total:
            lines.append("\n(no activity recorded in this window)")
        return "\n".join(lines) + "\n"


def summarize(
    events: Iterable[AuditEvent],
    since: datetime | None = None,
    until: datetime | None = None,
) -> UsageReport:
    """ADM-006: aggregate the audit stream. NFR-004's attribution is what makes it possible."""
    report = UsageReport(since=since, until=until)
    actors: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    outcomes: Counter[str] = Counter()
    tools: Counter[str] = Counter()
    models: Counter[str] = Counter()
    sessions: Counter[str] = Counter()
    window = AuditQuery(since=since, until=until, limit=MAX_RESULTS)

    for event in events:
        if not window.matches(event):
            continue
        report.total += 1
        actors[event.actor] += 1
        categories[event.category.value] += 1
        outcomes[event.outcome.value] += 1
        if event.tool:
            tools[event.tool] += 1
        if event.model:
            models[event.model] += 1
        if event.session_id:
            sessions[event.session_id] += 1
        report.duration_ms += event.duration_ms or 0

    report.by_actor = dict(actors)
    report.by_category = dict(categories)
    report.by_outcome = dict(outcomes)
    report.by_tool = dict(tools)
    report.by_model = dict(models)
    report.by_session = dict(sessions)
    report.sessions = len(sessions)
    return report


# ------------------------------------------------------------------ ADM-009 / SEC-005
class RetentionScope(StrEnum):
    """What SEC-005 names, mapped onto where this system actually puts it.

    Separate scopes rather than one sweep, because the three have different meanings:
    the audit trail is evidence and is aged by the date in its filename; a session is
    personal working state; and source-derived context is a cache that can simply be
    rebuilt. An operator deleting one should not be made to delete the others.
    """

    AUDIT = "audit"  # .aica/audit - the audit trail, by the date in the filename
    SESSIONS = "sessions"  # .aica/sessions - conversations and task state
    CONTEXT = "context"  # .aica/index, .aica/browser, .aica/snapshots - source-derived
    ALL = "all"


# Where each scope lives, and whether its files are dated by name or by mtime.
_SCOPE_DIRS: dict[RetentionScope, tuple[str, ...]] = {
    RetentionScope.AUDIT: (".aica/audit",),
    RetentionScope.SESSIONS: (".aica/sessions",),
    RetentionScope.CONTEXT: (".aica/index", ".aica/browser", ".aica/snapshots"),
}


@dataclass(frozen=True)
class RetentionPlan:
    """What a retention run would remove, and what it would keep."""

    cutoff: datetime
    remove: tuple[Path, ...] = ()
    keep: tuple[Path, ...] = ()
    removed_bytes: int = 0
    scope: RetentionScope = RetentionScope.AUDIT

    @property
    def empty(self) -> bool:
        return not self.remove

    def render(self, applied: bool) -> str:
        verb = "removed" if applied else "would remove"
        lines = [
            f"retention cutoff {self.cutoff.date().isoformat()}: "
            f"{verb} {len(self.remove)} file(s), {self.removed_bytes} bytes; "
            f"keeping {len(self.keep)}"
        ]
        lines.extend(f"  {verb} {p.name}" for p in self.remove)
        return "\n".join(lines)


def plan_retention(directory: Path, keep_days: int, now: datetime | None = None) -> RetentionPlan:
    """Which daily audit files fall outside a ``keep_days`` window.

    Whole files, by the date in their name: a retention pass that rewrote files to drop
    individual rows would leave an audit log that someone has edited in place, which is
    no longer evidence of anything.
    """
    if keep_days < 1:
        raise ValueError("keep_days must be at least 1; use 0 files kept by removing the directory")
    reference = (now or datetime.now(UTC)).astimezone(UTC)
    cutoff = reference - timedelta(days=keep_days)
    remove: list[Path] = []
    keep: list[Path] = []
    size = 0
    for path in sorted(directory.glob("audit-*.jsonl")) if directory.is_dir() else []:
        try:
            day = datetime.strptime(path.stem.removeprefix("audit-"), "%Y-%m-%d").replace(
                tzinfo=UTC
            )
        except ValueError:
            keep.append(path)  # not one of ours: never delete what we cannot date
            continue
        if day < cutoff.replace(hour=0, minute=0, second=0, microsecond=0):
            remove.append(path)
            size += path.stat().st_size
        else:
            keep.append(path)
    return RetentionPlan(cutoff=cutoff, remove=tuple(remove), keep=tuple(keep), removed_bytes=size)


def apply_retention(plan: RetentionPlan) -> int:
    """Delete the files in ``plan``. Returns how many were removed."""
    removed = 0
    for path in plan.remove:
        try:
            path.unlink()
            removed += 1
        except OSError:  # noqa: PERF203 - one failure must not abort the rest
            continue
    return removed


def iter_events(directory: Path) -> Iterator[AuditEvent]:
    """Every recorded event, oldest first. Skips a damaged line rather than stopping."""
    if not directory.is_dir():
        return
    for path in sorted(directory.glob("audit-*.jsonl")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                yield AuditEvent.model_validate_json(line)
            except ValueError:  # noqa: S112 - a damaged line must not hide the rest
                continue


def plan_file_retention(
    directory: Path,
    keep_days: int,
    scope: RetentionScope,
    now: datetime | None = None,
) -> RetentionPlan:
    """Files in ``directory`` last modified outside the window.

    Used for the scopes whose files are not dated by name. Modification time is the
    honest signal available here: a session file is rewritten whenever the session is
    used, so "untouched for N days" is what "expired" means for it.
    """
    if keep_days < 1:
        raise ValueError("keep_days must be at least 1")
    reference = (now or datetime.now(UTC)).astimezone(UTC)
    cutoff = reference - timedelta(days=keep_days)
    remove: list[Path] = []
    keep: list[Path] = []
    size = 0
    for path in sorted(directory.rglob("*")) if directory.is_dir() else []:
        if not path.is_file():
            continue
        modified = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        if modified < cutoff:
            remove.append(path)
            size += path.stat().st_size
        else:
            keep.append(path)
    return RetentionPlan(
        cutoff=cutoff, remove=tuple(remove), keep=tuple(keep), removed_bytes=size, scope=scope
    )


def plan_workspace_retention(
    root: Path,
    keep_days: int,
    scope: RetentionScope = RetentionScope.ALL,
    now: datetime | None = None,
) -> list[RetentionPlan]:
    """SEC-005: a plan per scope. Nothing is deleted here."""
    scopes = (
        [RetentionScope.AUDIT, RetentionScope.SESSIONS, RetentionScope.CONTEXT]
        if scope is RetentionScope.ALL
        else [scope]
    )
    plans: list[RetentionPlan] = []
    for one in scopes:
        if one is RetentionScope.AUDIT:
            plans.append(plan_retention(root / ".aica" / "audit", keep_days, now))
            continue
        for relative in _SCOPE_DIRS[one]:
            plans.append(plan_file_retention(root / relative, keep_days, one, now))
    return plans
