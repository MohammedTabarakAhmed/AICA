"""One agent task per repository at a time (NFR-003, BRD section 8).

The BRD asks for concurrency-aware behaviour across multi-user, multi-repository and
long-running sessions. The hazard that matters is not throughput, it is two agents
editing the same working tree at once: each one's test run observes the other's
half-finished edits, each one's rollback undoes the other's work, and the report either
writes is a description of a tree nobody produced. So:

* **An agent task holds a lease on its repository** for the length of the run, and a
  second task on the same repository is *refused*, naming who holds it and until when.
  Refusing rather than waiting is deliberate: a queued agent task would start later
  against a tree that has changed underneath the plan it was given.
* **The lease is a file**, so it binds the CLI and the HTTP server alike, and two
  processes on one checkout see each other. A lock held only in memory would protect a
  server from itself and nothing else.
* **Other repositories are unaffected.** The lease lives in the repository's own
  ``.aica`` directory, so a second checkout - a worktree, a clone - is a separate
  repository with its own lease. That is the supported way for several people to run
  agents concurrently: one working tree each.
* **Mutating tool calls from outside the run are refused too** (checked in
  ``Tool.invoke``), otherwise ``POST /files`` could edit the tree mid-run and the lease
  would protect only against other *agents*.
* **A lease expires.** The run is bounded by ``RunBudget.max_seconds`` (AG-007), so the
  lease is taken for that plus a grace period; a crashed process cannot hold a repository
  forever. An expired lease is taken over under an exclusive takeover lock, so two
  processes racing to take a stale lease cannot both win.
* **Breaking a live lease is administrative** (ADM-001 ``administer``) and audited by the
  caller: it is the incident tool, not a routine one.
"""

from __future__ import annotations

import json
import os
import socket
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

LEASE_DIR = Path(".aica") / "locks"
LEASE_FILE = "agent.lease"
GRACE_SECONDS = 120
TAKEOVER_STALE_SECONDS = 30
# Windows refuses to delete or open a file another handle has open (a sharing violation,
# surfaced as PermissionError). These windows last microseconds, so they are retried
# briefly; if one persists, the caller is told the repository is busy, never that it is free.
SHARING_RETRIES = 50
SHARING_DELAY = 0.01


def _retrying[T](operation: Callable[[], T]) -> T:
    for _ in range(SHARING_RETRIES - 1):
        try:
            return operation()
        except PermissionError:
            time.sleep(SHARING_DELAY)
    return operation()


# A lease file that cannot be read is treated as held until it is at least this old, so a
# torn write never silently unlocks a repository while its writer may still be running.
UNREADABLE_STALE_AFTER = timedelta(days=1, seconds=GRACE_SECONDS)


class RepositoryBusy(RuntimeError):
    """Another agent task holds this repository (NFR-003)."""

    def __init__(self, lease: Lease | None, detail: str = "") -> None:
        self.lease = lease
        message = detail or (lease.describe() if lease else "repository is busy")
        super().__init__(
            f"repository busy: {message}. One agent task runs per working tree at a time; "
            "use a separate worktree or clone to work in parallel (NFR-003)"
        )


@dataclass(frozen=True)
class Lease:
    holder: str
    actor: str
    session_id: str
    task: str
    pid: int
    host: str
    acquired_at: datetime
    expires_at: datetime

    def expired(self, now: datetime | None = None) -> bool:
        return (now or datetime.now(UTC)) >= self.expires_at

    def describe(self) -> str:
        return (
            f"held by {self.actor} (session {self.session_id or '-'}, pid {self.pid} on "
            f"{self.host}) since {self.acquired_at.isoformat(timespec='seconds')}, until "
            f"{self.expires_at.isoformat(timespec='seconds')}: {self.task[:120]!r}"
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "holder": self.holder,
            "actor": self.actor,
            "session_id": self.session_id,
            "task": self.task,
            "pid": self.pid,
            "host": self.host,
            "acquired_at": self.acquired_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }

    def public(self) -> dict[str, Any]:
        """What a surface may show. The holder id is left out: it is what lets a context
        write through the lease, so it is a capability, not information."""
        data = self.to_json()
        del data["holder"]
        return data

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Lease:
        return cls(
            holder=str(data["holder"]),
            actor=str(data["actor"]),
            session_id=str(data.get("session_id", "")),
            task=str(data.get("task", "")),
            pid=int(data["pid"]),
            host=str(data.get("host", "")),
            acquired_at=datetime.fromisoformat(data["acquired_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
        )


class RepositoryLease:
    """The lease file for one repository root."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.path = self.root / LEASE_DIR / LEASE_FILE

    # ------------------------------------------------------------------ reading
    def _read(self) -> tuple[Lease | None, bool]:
        """(lease, readable). A missing file is (None, True)."""
        try:
            raw = _retrying(lambda: self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None, True
        except OSError:
            return None, False
        try:
            return Lease.from_json(json.loads(raw)), True
        except (ValueError, KeyError, TypeError):
            return None, False

    def current(self, now: datetime | None = None) -> Lease | None:
        """The live lease, or None when the repository is free.

        An unreadable lease file is reported as busy (``RepositoryBusy``) until it is old
        enough that no bounded run could still be behind it.
        """
        lease, readable = self._read()
        if not readable:
            if self._unreadable_is_stale(now):
                return None
            raise RepositoryBusy(None, f"lease file {self.path} is unreadable")
        if lease is None or lease.expired(now):
            return None
        return lease

    def _unreadable_is_stale(self, now: datetime | None) -> bool:
        try:
            mtime = datetime.fromtimestamp(self.path.stat().st_mtime, UTC)
        except FileNotFoundError:
            return True
        return (now or datetime.now(UTC)) - mtime > UNREADABLE_STALE_AFTER

    def check(self, holder: str | None) -> None:
        """Refuse unless the repository is free or leased to ``holder``."""
        lease = self.current()
        if lease is not None and lease.holder != holder:
            raise RepositoryBusy(lease)

    # ------------------------------------------------------------------ writing
    def acquire(
        self,
        *,
        actor: str,
        session_id: str = "",
        task: str = "",
        ttl_seconds: float,
        now: datetime | None = None,
    ) -> Lease:
        """Take the lease or raise ``RepositoryBusy``. Never waits."""
        moment = (now or datetime.now(UTC)).astimezone(UTC)
        lease = Lease(
            holder=uuid.uuid4().hex,
            actor=actor,
            session_id=session_id,
            task=task,
            pid=os.getpid(),
            host=socket.gethostname(),
            acquired_at=moment,
            expires_at=moment + timedelta(seconds=ttl_seconds + GRACE_SECONDS),
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self._create(lease):
            return lease
        existing = self.current(moment)  # raises for an unreadable, possibly live lease
        if existing is not None:
            raise RepositoryBusy(existing)
        # Stale. Taking it over is read-check-replace, so it runs under a short takeover
        # lock: without one, a second taker that also saw the stale lease could delete the
        # fresh lease the first taker had just written.
        takeover = self.path.with_name(f"{LEASE_FILE}.takeover")
        if not self._claim_takeover(takeover, moment):
            raise RepositoryBusy(None, "another process is taking over a stale lease")
        try:
            existing = self.current(moment)
            if existing is not None:
                raise RepositoryBusy(existing)
            try:
                _retrying(lambda: self.path.unlink(missing_ok=True))
            except PermissionError as exc:
                raise RepositoryBusy(None, f"stale lease {self.path} is locked: {exc}") from exc
            if self._create(lease):
                return lease
            raise RepositoryBusy(self.current(moment))
        finally:
            takeover.unlink(missing_ok=True)

    @staticmethod
    def _claim_takeover(takeover: Path, now: datetime) -> bool:
        for _ in range(2):
            try:
                os.close(os.open(takeover, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
                return True
            except FileExistsError:
                # A takeover is a few file operations; one older than this was abandoned
                # by a process that died mid-way.
                try:
                    age = now - datetime.fromtimestamp(takeover.stat().st_mtime, UTC)
                except FileNotFoundError:
                    continue
                if age <= timedelta(seconds=TAKEOVER_STALE_SECONDS):
                    return False
                takeover.unlink(missing_ok=True)
        return False

    def _create(self, lease: Lease) -> bool:
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            return False
        except PermissionError:
            # Windows: a lease another process is deleting still occupies the name.
            return False
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(lease.to_json(), fh)
        return True

    def release(self, lease: Lease) -> bool:
        """Remove the lease only if it is still ours - never someone's who took it over."""
        current, readable = self._read()
        if not readable or current is None or current.holder != lease.holder:
            return False
        _retrying(lambda: self.path.unlink(missing_ok=True))
        return True

    def force_release(self) -> Lease | None:
        """Break whatever lease exists. The caller checks ``administer`` and audits it."""
        lease, _ = self._read()
        _retrying(lambda: self.path.unlink(missing_ok=True))
        return lease
