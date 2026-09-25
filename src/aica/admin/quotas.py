"""Quota management (ADM-005).

BRD ADM-005 asks for limits "by user/project/team". Three decisions shape this:

* **Usage is counted from the audit log**, the same stream ADM-006 reports from. A
  separate meter would be faster and would drift, and then the number that stops someone
  working disagrees with the number an administrator is shown. One record, one answer.
* **A quota bounds a window, not a session.** ``AutonomyLimits`` already bounds a single
  run (AG-007); a quota is the orthogonal control - how much a principal may do in a day
  regardless of how many runs they split it across - so the two never overlap.
* **Exhaustion refuses; it does not queue or throttle.** A quota that silently slows work
  down is indistinguishable from a broken system, and one that queues turns a limit into
  a deadline nobody agreed to. Hitting a quota says so, names the limit and says when it
  resets.

A principal may be covered by several scopes (their own name, their team, the project);
the **most restrictive applicable limit wins**, so adding a team quota can only ever
tighten what a user may do, never loosen an individual limit.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from aica.audit.events import AuditEvent, EventCategory
from aica.policy.models import QuotaExceeded, QuotaLimit, QuotaPolicy, QuotaScope

# Re-exported: the schema lives with the rest of the policy schema, the counting and
# the verdict live here, and callers should not have to know which is which.
__all__ = [
    "QuotaExceeded",
    "QuotaLimit",
    "QuotaPolicy",
    "QuotaScope",
    "QuotaUsageRow",
    "QuotaVerdict",
    "Usage",
    "check",
    "measure",
    "report",
]


@dataclass(frozen=True)
class Usage:
    """What a principal has consumed inside one window."""

    actions: int = 0
    model_calls: int = 0
    commands: int = 0
    tool_seconds: int = 0


@dataclass(frozen=True)
class QuotaVerdict:
    """Whether the action may proceed, and why not."""

    allowed: bool
    limit: QuotaLimit | None = None
    measure: str = ""
    used: int = 0
    cap: int = 0
    resets_at: datetime | None = None

    def reason(self) -> str:
        if self.allowed or self.limit is None:
            return ""
        when = self.resets_at.isoformat(timespec="seconds") if self.resets_at else "the next window"
        return (
            f"quota exhausted: {self.measure} {self.used}/{self.cap} for "
            f"{self.limit.describe()}; resets at {when} (ADM-005)"
        )


def measure(events: Iterable[AuditEvent], principal: str, since: datetime) -> Usage:
    """Count what ``principal`` has used since ``since``, from the audit record."""
    actions = model_calls = commands = 0
    duration = 0
    for event in events:
        if event.actor != principal or event.timestamp.astimezone(UTC) < since:
            continue
        actions += 1
        if event.category is EventCategory.MODEL_CALL:
            model_calls += 1
        elif event.category is EventCategory.COMMAND:
            commands += 1
        duration += event.duration_ms or 0
    return Usage(
        actions=actions,
        model_calls=model_calls,
        commands=commands,
        tool_seconds=duration // 1000,
    )


_MEASURES: tuple[tuple[str, str], ...] = (
    ("actions", "max_actions"),
    ("model_calls", "max_model_calls"),
    ("commands", "max_commands"),
    ("tool_seconds", "max_tool_seconds"),
)


def check(
    policy: QuotaPolicy,
    principal: str,
    events: Iterable[AuditEvent],
    now: datetime | None = None,
) -> QuotaVerdict:
    """The verdict for ``principal``. The most restrictive applicable limit decides.

    Adding a team or project quota can therefore only ever tighten what a user may do;
    it can never raise an individual limit, which is the only direction that would be a
    surprise to whoever set the individual one.
    """
    if not policy.enabled:
        return QuotaVerdict(allowed=True)
    limits = policy.for_principal(principal)
    if not limits:
        return QuotaVerdict(allowed=True)
    reference = (now or datetime.now(UTC)).astimezone(UTC)
    # The stream is materialised once and re-counted per limit, because limits may have
    # different windows. Limits are few; the log is not.
    recorded = list(events)
    for limit in limits:
        since = reference - timedelta(days=limit.window_days)
        used = measure(recorded, principal, since)
        for attribute, field_name in _MEASURES:
            cap = getattr(limit, field_name)
            if cap is None:
                continue
            consumed = getattr(used, attribute)
            if consumed >= cap:
                return QuotaVerdict(
                    allowed=False,
                    limit=limit,
                    measure=attribute,
                    used=consumed,
                    cap=cap,
                    resets_at=since + timedelta(days=limit.window_days),
                )
    return QuotaVerdict(allowed=True)


@dataclass(frozen=True)
class QuotaUsageRow:
    """One applicable limit and what has been used against it."""

    limit: QuotaLimit
    used: dict[str, int]
    caps: dict[str, int]

    def describe(self) -> str:
        used = ", ".join(f"{k} {v}/{self.caps[k]}" for k, v in self.used.items())
        return f"{self.limit.describe()} | used: {used or '(nothing bounded)'}"

    def to_dict(self) -> dict[str, object]:
        return {
            "limit": self.limit.describe(),
            "scope": self.limit.scope.value,
            "window_days": self.limit.window_days,
            "used": dict(self.used),
            "caps": dict(self.caps),
        }


def report(
    policy: QuotaPolicy,
    principal: str,
    events: Iterable[AuditEvent],
    now: datetime | None = None,
) -> list[QuotaUsageRow]:
    """Every applicable limit with what is used against it - for ``aica usage``."""
    reference = (now or datetime.now(UTC)).astimezone(UTC)
    recorded = list(events)
    rows: list[QuotaUsageRow] = []
    for limit in policy.for_principal(principal):
        consumed = measure(recorded, principal, reference - timedelta(days=limit.window_days))
        bounded = [
            (attribute, field_name)
            for attribute, field_name in _MEASURES
            if getattr(limit, field_name) is not None
        ]
        rows.append(
            QuotaUsageRow(
                limit=limit,
                used={attribute: getattr(consumed, attribute) for attribute, _ in bounded},
                caps={attribute: getattr(limit, f) for attribute, f in bounded},
            )
        )
    return rows
