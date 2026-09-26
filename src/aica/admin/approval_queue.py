"""A durable approval queue (API-014, UX-008, SAFE-001/002).

Until identity existed there was nothing a queue could mean. A request-scoped approver
cannot hold state between HTTP requests, so the API refused a sensitive action with 409
and the client re-sent it with ``auto_approve`` - which is a workable contract for one
developer and not an approval workflow, because the same person decides and there is no
record of anyone having been asked.

With ADM-001 in place a queue is meaningful, and this is the smallest one that is
actually safe:

* **A pending request is a durable record, not a promise to run something later.** The
  queue stores what was asked and who decided; it never replays the action. Re-running is
  the client's job, and it still passes every gate again. A queue that executed on
  approval would be a second execution path with different guards from the first, which
  is precisely the thing the rest of this system refuses to have.
* **The requester may not decide their own request.** Enforced on the deciding principal
  against the recorded requester, the same shape as SEC-006, and not merely requested of
  the caller.
* **Deciding needs the approve permission** (ADM-001), so "approved" means approved by
  someone entitled to, not by whoever happened to be holding the CLI.
* **A decision is final.** Re-deciding a resolved request is refused rather than
  overwriting, because an audit trail where approvals can be edited afterwards answers no
  question anyone would ask it.

Entries expire: an approval nobody answered is not an approval, and a request that has
sat unanswered for days should not be waiting to authorise something whose context has
long since changed.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aica.admin.rbac import Permission, Principal
from aica.approvals import ApprovalRequest
from aica.audit.events import EventCategory, Outcome
from aica.audit.sink import AuditLog
from aica.policy.models import ActionCategory

QUEUE_FILE = "approvals.json"
DEFAULT_TTL_HOURS = 24
MAX_PENDING = 500

# HTTP tasks run on worker threads and may park requests concurrently; the queue is a
# read-modify-write of one file, so writes in this process are serialised.
_LOCK = threading.RLock()


class ApprovalError(RuntimeError):
    """The queue could not be read or written, or the request does not exist."""


class DecisionState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class PendingApproval(BaseModel):
    """One request awaiting a decision, or the record of a decided one."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    requested_by: str = Field(min_length=1, max_length=200)
    tool: str = Field(default="", max_length=100)
    action: str = Field(min_length=1, max_length=4000)
    categories: list[ActionCategory] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    requested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    state: DecisionState = DecisionState.PENDING
    decided_by: str | None = None
    decided_at: datetime | None = None
    note: str = Field(default="", max_length=1000)

    @property
    def resolved(self) -> bool:
        return self.state is not DecisionState.PENDING

    def is_expired(self, ttl_hours: int, now: datetime | None = None) -> bool:
        reference = (now or datetime.now(UTC)).astimezone(UTC)
        return not self.resolved and reference - self.requested_at > timedelta(hours=ttl_hours)

    def describe(self) -> str:
        """UX-008: the summary a surface shows. Categories first - they are the reason."""
        cats = ", ".join(c.value for c in self.categories) or "uncategorised"
        who = f"requested by {self.requested_by}"
        decided = f" | {self.state.value} by {self.decided_by}" if self.resolved else ""
        return f"[{cats}] {self.tool}: {self.action[:160]} ({who}{decided})"


class ApprovalQueue:
    """Durable pending approvals. Holds records; never executes anything."""

    def __init__(self, root: str | Path, ttl_hours: int = DEFAULT_TTL_HOURS) -> None:
        self.directory = Path(root) / ".aica" / "admin"
        self.ttl_hours = ttl_hours

    @property
    def path(self) -> Path:
        return self.directory / QUEUE_FILE

    # ------------------------------------------------------------------ reading
    def _read(self) -> list[PendingApproval]:
        if not self.path.is_file():
            return []
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ApprovalError(
                f"{self.path} exists but could not be read ({exc}); refusing to treat that "
                "as 'nothing is pending' (API-014)"
            ) from exc
        try:
            return [PendingApproval.model_validate(item) for item in raw.get("approvals", [])]
        except Exception as exc:  # pragma: no cover - pydantic message varies
            raise ApprovalError(f"{self.path} is not a valid approval queue: {exc}") from exc

    def all(self, now: datetime | None = None) -> list[PendingApproval]:
        """Every request, with expiry applied. Newest first."""
        entries = self._read()
        for entry in entries:
            if entry.is_expired(self.ttl_hours, now):
                entry.state = DecisionState.EXPIRED
        return sorted(entries, key=lambda e: e.requested_at, reverse=True)

    def pending(self, now: datetime | None = None) -> list[PendingApproval]:
        return [e for e in self.all(now) if e.state is DecisionState.PENDING]

    def get(self, request_id: str, now: datetime | None = None) -> PendingApproval:
        for entry in self.all(now):
            if entry.id == request_id:
                return entry
        raise ApprovalError(f"no approval request {request_id!r}")

    # ------------------------------------------------------------------ writing
    def submit(self, request: ApprovalRequest, requested_by: str) -> PendingApproval:
        """Record a request for a human to decide. Nothing runs as a result of this."""
        with _LOCK:
            return self._submit(request, requested_by)

    def _submit(self, request: ApprovalRequest, requested_by: str) -> PendingApproval:
        entries = [e for e in self._read() if not e.is_expired(self.ttl_hours)]
        if len(entries) >= MAX_PENDING:
            raise ApprovalError(
                f"the approval queue is full ({MAX_PENDING}); decide or expire some first"
            )
        entry = PendingApproval(
            requested_by=requested_by,
            tool=request.tool,
            action=request.action,
            categories=list(request.categories),
            details=dict(request.details),
        )
        self._write([*entries, entry])
        return entry

    def decide(
        self,
        request_id: str,
        principal: Principal,
        approved: bool,
        note: str = "",
        now: datetime | None = None,
    ) -> PendingApproval:
        """Record a decision. Raises rather than overwriting a resolved request."""
        principal.require(Permission.APPROVE, f"decide approval {request_id!r}")
        with _LOCK:
            return self._decide(request_id, principal, approved, note, now)

    def _decide(
        self,
        request_id: str,
        principal: Principal,
        approved: bool,
        note: str,
        now: datetime | None,
    ) -> PendingApproval:
        entries = self._read()
        target = next((e for e in entries if e.id == request_id), None)
        if target is None:
            raise ApprovalError(f"no approval request {request_id!r}")
        if target.is_expired(self.ttl_hours, now):
            raise ApprovalError(
                f"approval request {request_id!r} expired after {self.ttl_hours}h; "
                "an approval nobody answered is not an approval - re-request it"
            )
        if target.resolved:
            raise ApprovalError(
                f"approval request {request_id!r} is already {target.state.value} "
                f"(by {target.decided_by}); a decision is final"
            )
        # The same rule as SEC-006, checked against the recorded requester rather than
        # anything the caller says about themselves.
        principal.require_distinct_from(target.requested_by, "approval request")
        target.state = DecisionState.APPROVED if approved else DecisionState.REJECTED
        target.decided_by = principal.name
        target.decided_at = (now or datetime.now(UTC)).astimezone(UTC)
        target.note = note
        self._write(entries)
        return target

    def _write(self, entries: list[PendingApproval]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "approvals": [json.loads(e.model_dump_json()) for e in entries],
        }
        handle, temp = tempfile.mkstemp(dir=self.directory, suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            os.replace(temp, self.path)
        except OSError as exc:
            Path(temp).unlink(missing_ok=True)
            raise ApprovalError(f"could not write {self.path}: {exc}") from exc


def decide_and_record(
    queue: ApprovalQueue,
    request_id: str,
    principal: Principal,
    approved: bool,
    audit: AuditLog,
    note: str = "",
    via: str = "",
    **details: Any,
) -> PendingApproval:
    """Decide a request and audit the decision - the one path every surface uses.

    The API, the CLI and Slack (INT-004) all decide through here, so an approval given in
    a chat client is recorded exactly like one given at a terminal. A refused attempt is
    audited too: on a surface where anyone in a channel can press a button, who tried to
    approve something they were not entitled to is worth keeping.
    """
    context = {"via": via, **details} if via else dict(details)
    try:
        entry = queue.decide(request_id, principal, approved, note)
    except (PermissionError, ApprovalError) as exc:
        audit.record(
            category=EventCategory.APPROVAL,
            action=f"decision on {request_id} refused",
            outcome=Outcome.BLOCKED,
            details={"approved": approved, "reason": str(exc), **context},
        )
        raise
    audit.record(
        category=EventCategory.APPROVAL,
        action=f"decision on {request_id}: {entry.state.value}",
        outcome=Outcome.SUCCESS if approved else Outcome.PENDING_APPROVAL,
        details={
            "approved": approved,
            "note": note,
            "requested_by": entry.requested_by,
            "decided_by": entry.decided_by,
            **context,
        },
    )
    return entry


class QueueingApprover:
    """An ``Approver`` that parks the request for a human instead of answering it.

    The default ``DenyAllApprover`` is correct but unhelpful for an unattended run: the
    action is refused and the reason evaporates with the process. This records the
    request and *still* denies, so the run fails honestly and a human has something to
    decide afterwards. It never returns True - approving is a human act, and an approver
    that could say yes on its own would defeat the gate it implements.
    """

    def __init__(self, queue: ApprovalQueue, requested_by: str) -> None:
        self._queue = queue
        self._requested_by = requested_by
        self.submitted: list[PendingApproval] = []

    def approve(self, request: ApprovalRequest) -> bool:
        try:
            self.submitted.append(self._queue.submit(request, self._requested_by))
        except ApprovalError:
            # A queue that cannot be written must not turn a denial into an approval.
            pass
        return False
