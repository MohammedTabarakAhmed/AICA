"""Agent event stream (UX-001, UX-002, UX-003; the payload for API-003 later).

The loop emits an event for everything a user needs to see while a task runs: the plan it
produced, the step it is on, each tool call starting/succeeding/failing, verification
results and the final outcome. A caller renders these however it likes - the CLI prints
them, a future web/IDE surface streams them.

Events are data, not control: nothing in the loop reads an event back to decide what to do,
so a broken or slow sink can never change what the agent does.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from aica.safety.redaction import redact


class EventType(StrEnum):
    TASK_STARTED = "task_started"
    PLAN_CREATED = "plan_created"
    PLAN_REVISED = "plan_revised"  # AG-004: the plan changed after an observation
    STEP_STARTED = "step_started"
    TOOL_CALLED = "tool_called"
    TOOL_SUCCEEDED = "tool_succeeded"
    TOOL_FAILED = "tool_failed"
    APPROVAL_REQUESTED = "approval_requested"
    OBSERVATION = "observation"  # what the agent concluded from a result
    VERIFICATION = "verification"
    PAUSED = "paused"
    RESUMED = "resumed"
    CANCELLED = "cancelled"
    TASK_FINISHED = "task_finished"


class StepStatus(StrEnum):
    """UX-003: the status a surface shows next to each step."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


class AgentEvent(BaseModel):
    """One thing that happened. Redacted at construction, so no sink can leak a secret."""

    model_config = ConfigDict(extra="forbid")

    type: EventType
    message: str = ""
    step_id: str | None = None
    step_number: int | None = None
    total_steps: int | None = None
    tool: str | None = None
    status: StepStatus | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def __init__(self, **kwargs: Any) -> None:
        if isinstance(kwargs.get("message"), str):
            kwargs["message"] = redact(kwargs["message"]).text
        super().__init__(**kwargs)

    def render(self) -> str:
        """One line, for a terminal (UX-001)."""
        where = ""
        if self.step_number is not None:
            total = f"/{self.total_steps}" if self.total_steps else ""
            where = f"[{self.step_number}{total}] "
        tool = f" ({self.tool})" if self.tool else ""
        return f"{where}{self.type.value}{tool}: {self.message}".rstrip(": ")


class EventSink(Protocol):
    def emit(self, event: AgentEvent) -> None: ...


class ListSink:
    """Collects events in memory - used by tests and by callers that render at the end."""

    def __init__(self) -> None:
        self.events: list[AgentEvent] = []

    def emit(self, event: AgentEvent) -> None:
        self.events.append(event)

    def of_type(self, *types: EventType) -> list[AgentEvent]:
        return [e for e in self.events if e.type in types]

    def render(self) -> str:
        return "\n".join(e.render() for e in self.events)


class CallbackSink:
    """Streams events to a callable as they happen (CLI printing, SSE later)."""

    def __init__(self, callback: Callable[[AgentEvent], None]) -> None:
        self._callback = callback

    def emit(self, event: AgentEvent) -> None:
        self._callback(event)


class NullSink:
    def emit(self, event: AgentEvent) -> None:
        return None


class FanOutSink:
    """Sends each event to several sinks.

    A sink is presentation, never control: if one raises (a closed socket, a full disk), the
    failure is recorded on ``errors`` for the caller to inspect and the remaining sinks still
    receive the event. The agent's own execution is never affected by it.
    """

    def __init__(self, *sinks: EventSink) -> None:
        self.sinks = list(sinks)
        self.errors: list[str] = []

    def emit(self, event: AgentEvent) -> None:
        for sink in self.sinks:
            try:
                sink.emit(event)
            except Exception as exc:  # noqa: BLE001 - a broken sink must not stop the agent
                self.errors.append(f"{type(sink).__name__}: {exc}")
