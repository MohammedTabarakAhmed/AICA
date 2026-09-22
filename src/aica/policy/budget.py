"""Run budget and cancellation.

AG-006 / AG-007 / SAFE-008 baseline: every autonomous loop consumes a ``RunBudget`` and
checks a ``CancellationToken`` before each step. Exceeding a bound or a cancel request
raises, so the loop cannot continue on its current path.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


class BudgetExceeded(RuntimeError):
    pass


class Cancelled(RuntimeError):
    pass


class CancellationToken:
    """Thread-safe stop flag (SAFE-008 emergency stop, AG-006 cancellation)."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._reason: str | None = None

    def cancel(self, reason: str = "cancelled") -> None:
        self._reason = reason
        self._event.set()

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str | None:
        return self._reason

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise Cancelled(self._reason or "cancelled")


@dataclass
class RunBudget:
    max_steps: int
    max_seconds: float
    token: CancellationToken = field(default_factory=CancellationToken)
    steps_used: int = 0
    started_at: float = field(default_factory=time.monotonic)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    @property
    def steps_remaining(self) -> int:
        return max(self.max_steps - self.steps_used, 0)

    def check(self) -> None:
        """Raise if the run may not continue. Call before every step."""
        self.token.raise_if_cancelled()
        if self.steps_used >= self.max_steps:
            raise BudgetExceeded(f"step limit reached ({self.max_steps})")
        if self.elapsed >= self.max_seconds:
            raise BudgetExceeded(f"time limit reached ({self.max_seconds:.0f}s)")

    def consume_step(self) -> int:
        """Check, then account for one step. Returns the 1-based step number."""
        self.check()
        self.steps_used += 1
        return self.steps_used
