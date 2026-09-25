"""Background agent tasks for the HTTP API (API-002, API-004, API-005, UX-006).

An HTTP request must not block for the length of an agent task, so a task runs on a worker
thread and the request returns its id. Everything else here follows from that:

* **Events are buffered per task**, so a client that connects to the stream late still sees
  what already happened rather than joining mid-run (API-003).
* **Cancel and pause are the same mechanism, with different intent.** Both stop the loop at
  the next step boundary through the existing ``CancellationToken``; pause additionally keeps
  the run state so it can be continued, which is exactly what ``AgentState`` already provides
  (API-005). Nothing new was invented for pause - it is cancellation plus the state that the
  loop already knows how to resume from.
* **Finished tasks are kept, bounded**, so a report can be fetched after the run ends without
  letting a long-lived server grow without limit.

The manager owns no policy. It runs ``AgentLoop``, which applies the workspace guard,
approval gates and audit exactly as it does from the CLI.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from aica.agent.events import AgentEvent, EventSink, EventType
from aica.agent.loop import AgentLoop, AgentState
from aica.chat.report import TaskReport
from aica.policy.budget import CancellationToken, RunBudget
from aica.review.acceptance import fingerprint
from aica.tools.base import ToolContext

MAX_EVENTS_PER_TASK = 5000
MAX_FINISHED_TASKS = 200
PAUSE_REASON = "paused by request"


class TaskState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    FINISHED = "finished"
    FAILED = "failed"


@dataclass
class TaskRecord:
    """One agent run. Shared between the worker thread and request handlers."""

    id: str
    session_id: str
    task: str
    state: TaskState = TaskState.QUEUED
    created: float = field(default_factory=time.time)
    finished: float | None = None
    report: TaskReport | None = None
    error: str | None = None
    agent_state: AgentState | None = None
    events: deque[AgentEvent] = field(default_factory=lambda: deque(maxlen=MAX_EVENTS_PER_TASK))
    token: CancellationToken = field(default_factory=CancellationToken)
    pause_requested: bool = False
    cleanup_error: str | None = None
    # CC-005. What each changed file looked like when the run ended, so a later reject or
    # partial accept can refuse to touch a file someone has edited since.
    final_fingerprints: dict[str, str] = field(default_factory=dict)
    # CC-005. path -> "accepted" | "rejected" | "partial"; a decision is final.
    decisions: dict[str, str] = field(default_factory=dict)
    _done: threading.Event = field(default_factory=threading.Event)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def active(self) -> bool:
        return self.state in {TaskState.QUEUED, TaskState.RUNNING}

    @property
    def resumable(self) -> bool:
        return self.state is TaskState.PAUSED and self.agent_state is not None

    def wait(self, timeout: float | None = None) -> bool:
        return self._done.wait(timeout)

    def summary(self) -> dict[str, Any]:
        report = self.report
        return {
            "task_id": self.id,
            "session_id": self.session_id,
            "task": self.task,
            "state": self.state.value,
            "created": self.created,
            "finished": self.finished,
            "outcome": report.outcome() if report else None,
            "succeeded": report.succeeded if report else None,
            "steps_used": report.steps_used if report else None,
            "events": len(self.events),
        }

    def detail(self) -> dict[str, Any]:
        data = self.summary()
        report = self.report
        if report is not None:
            data["report"] = {
                "outcome": report.outcome(),
                "succeeded": report.succeeded,
                "model": report.model,
                "verification": report.ledger.disclosure(),
                "changes": [
                    {"path": c.path, "action": c.action, "diff": c.diff} for c in report.changes
                ],
                "warnings": report.warnings,
                "unresolved": report.unresolved,
                "duration_ms": report.duration_ms,
                "rendered": report.render(),
            }
        if self.error:
            data["error"] = self.error
        if self.cleanup_error:
            data["cleanup_error"] = self.cleanup_error
        if self.agent_state is not None:
            data["plan"] = self.agent_state.plan.render()
        return data


class _RecordingSink:
    """Puts every event on the task's buffer and wakes anyone streaming it."""

    def __init__(self, record: TaskRecord, wakeup: threading.Event) -> None:
        self.record = record
        self.wakeup = wakeup

    def emit(self, event: AgentEvent) -> None:
        with self.record._lock:  # noqa: SLF001 - the record owns this lock for its own buffer
            self.record.events.append(event)
        self.wakeup.set()


class TaskManager:
    """Starts, tracks, cancels, pauses and resumes agent tasks."""

    def __init__(self) -> None:
        self._tasks: dict[str, TaskRecord] = {}
        self._wakeups: dict[str, threading.Event] = {}
        self._order: deque[str] = deque()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ API-002
    def start(
        self,
        loop: AgentLoop,
        task: str,
        ctx: ToolContext,
        *,
        session_id: str,
        budget: RunBudget | None = None,
        context: str = "",
        conventions: str = "",
        state: AgentState | None = None,
        on_finish: Callable[[], None] | None = None,
    ) -> TaskRecord:
        """Start a task on a worker thread.

        ``on_finish`` runs when the worker ends, however it ends. A caller that lends the
        task a resource - a repository index, say - closes it there, because the request
        that started the task has long since returned.
        """
        record = TaskRecord(id=uuid.uuid4().hex[:12], session_id=session_id, task=task)
        wakeup = threading.Event()
        with self._lock:
            self._tasks[record.id] = record
            self._wakeups[record.id] = wakeup
            self._order.append(record.id)
            self._evict_locked()

        ctx.cancel = record.token
        run_budget = budget or RunBudget(
            max_steps=ctx.policy.autonomy.max_steps,
            max_seconds=float(ctx.policy.autonomy.max_seconds),
            token=record.token,
        )
        run_budget.token = record.token
        loop.sink = _fan_in(loop.sink, _RecordingSink(record, wakeup))

        def run() -> None:
            record.state = TaskState.RUNNING
            try:
                report = loop.run(
                    task,
                    ctx,
                    budget=run_budget,
                    context=context,
                    conventions=conventions,
                    state=state,
                )
                record.report = report
                record.agent_state = loop.state
                record.final_fingerprints = _fingerprints(ctx.workspace.root, report)
                if record.pause_requested:
                    record.state = TaskState.PAUSED
                elif report.cancelled:
                    record.state = TaskState.CANCELLED
                else:
                    record.state = TaskState.FINISHED
            except Exception as exc:  # noqa: BLE001 - a worker thread must never die silently
                record.error = f"{type(exc).__name__}: {exc}"[:2000]
                record.agent_state = loop.state
                record.state = TaskState.FAILED
            finally:
                if on_finish is not None:
                    try:
                        on_finish()
                    except Exception as exc:  # noqa: BLE001 - cleanup must not hide the run
                        # Recorded on the task and surfaced by `detail()`: a cleanup that
                        # fails silently is how a resource leak survives a green test run.
                        record.cleanup_error = f"{type(exc).__name__}: {exc}"[:500]
                record.finished = time.time()
                record._done.set()  # noqa: SLF001
                wakeup.set()

        thread = threading.Thread(target=run, name=f"aica-task-{record.id}", daemon=True)
        thread.start()
        return record

    def _evict_locked(self) -> None:
        """Drop the oldest finished tasks once the retention limit is passed."""
        while len(self._order) > MAX_FINISHED_TASKS:
            for index, task_id in enumerate(self._order):
                record = self._tasks.get(task_id)
                if record is not None and not record.active:
                    del self._order[index]
                    self._tasks.pop(task_id, None)
                    self._wakeups.pop(task_id, None)
                    break
            else:
                return  # everything still running: keep them all

    # ------------------------------------------------------------------ lookup
    def get(self, task_id: str) -> TaskRecord | None:
        return self._tasks.get(task_id)

    def list(self, session_id: str | None = None) -> list[TaskRecord]:
        records = [self._tasks[i] for i in self._order if i in self._tasks]
        if session_id is not None:
            records = [r for r in records if r.session_id == session_id]
        return sorted(records, key=lambda r: r.created, reverse=True)

    # ------------------------------------------------------------------ API-004/005
    def cancel(self, task_id: str) -> bool:
        record = self.get(task_id)
        if record is None or not record.active:
            return False
        record.token.cancel("cancelled by request")
        return True

    def pause(self, task_id: str) -> bool:
        """UX-006/API-005: stop at the next step boundary, keeping the state to resume from."""
        record = self.get(task_id)
        if record is None or not record.active:
            return False
        record.pause_requested = True
        record.token.cancel(PAUSE_REASON)
        return True

    # ------------------------------------------------------------------ API-003
    def stream(self, task_id: str, *, timeout: float = 300.0) -> Iterator[AgentEvent]:
        """Yield the task's events, from the beginning, until it finishes.

        A client that connects after the run started still receives the buffered history
        first, so nothing is missed because of when the connection was made.
        """
        record = self.get(task_id)
        if record is None:
            return
        wakeup = self._wakeups.get(task_id)
        deadline = time.monotonic() + timeout
        sent = 0
        while True:
            with record._lock:  # noqa: SLF001
                pending = list(record.events)[sent:]
            for event in pending:
                sent += 1
                yield event
            if not record.active and sent >= len(record.events):
                return
            if time.monotonic() > deadline:
                return
            if wakeup is not None:
                wakeup.wait(timeout=0.25)
                wakeup.clear()
            else:  # pragma: no cover - a record always has a wakeup
                time.sleep(0.05)

    def shutdown(self, timeout: float = 5.0) -> None:
        for record in list(self._tasks.values()):
            if record.active:
                record.token.cancel("server shutting down")
        for record in list(self._tasks.values()):
            record.wait(timeout=timeout)


def _fingerprints(root: Path, report: TaskReport) -> dict[str, str]:
    out: dict[str, str] = {}
    for change in report.changes:
        target = root / change.path
        try:
            text: str | None = target.read_text(encoding="utf-8")
        except FileNotFoundError:
            text = None
        except (OSError, UnicodeDecodeError):
            continue  # not decidable here; the change stays visible, just not actionable
        out[change.path] = fingerprint(text)
    return out


def _fan_in(existing: EventSink, recorder: _RecordingSink) -> EventSink:
    """Keep whatever sink the caller configured and add the recorder alongside it."""
    from aica.agent.events import FanOutSink, NullSink

    if isinstance(existing, NullSink):
        return recorder
    return FanOutSink(existing, recorder)


def event_payload(event: AgentEvent) -> dict[str, Any]:
    """The JSON shape of an event on the wire (API-003)."""
    return {
        "type": event.type.value,
        "message": event.message,
        "step_id": event.step_id,
        "step_number": event.step_number,
        "total_steps": event.total_steps,
        "tool": event.tool,
        "status": event.status.value if event.status else None,
        "data": event.data,
        "timestamp": event.timestamp.isoformat(),
    }


TERMINAL_EVENTS = {EventType.TASK_FINISHED, EventType.CANCELLED}
