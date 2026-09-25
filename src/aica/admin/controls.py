"""Immediate disable, and the change history behind it (SEC-007, ADM-003, ADM-004, ADM-010).

BRD section 16 asks for the "ability to disable a model, tool or integration
immediately". The policy file cannot provide that. Editing ``config/policy.toml`` is the
right way to express a standing rule, but it is the wrong instrument for an incident: it
needs an editor, a commit and - for the HTTP surface - a restart before anything changes,
and the thing being switched off is usually still running while all that happens.

So a disable is a separate, tiny piece of state that every enforcement point re-reads on
each call:

* **It takes effect on the next call**, with no restart and no reload, because the file
  is read at the moment of the check rather than folded into a loaded policy object.
* **It only ever subtracts.** There is no "enable" that grants something policy withholds;
  enabling only removes a disable this plane added. A control plane that could widen
  permissions would be a way around the policy file, which is the opposite of the point.
* **Every change is attributable** (ADM-010): who, when, why, and what it applied to,
  appended to a history that is never rewritten - so "why is this off?" is answerable
  months later, and so is "who turned it back on".
* **A failure to read it disables nothing silently.** A corrupt or unreadable controls
  file raises rather than being treated as "nothing is disabled", because the failure
  mode of guessing is that a thing someone switched off during an incident comes back.

``ADM-003``'s versioning/retirement and ``ADM-004``'s approval live in the model registry
and the policy file respectively; this is the immediate, operational half of both.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aica.admin.rbac import Permission, Principal, RbacPolicy
from aica.policy.models import ProjectPolicy

CONTROLS_FILE = "controls.json"
HISTORY_FILE = "history.jsonl"


class ControlError(RuntimeError):
    """The control state could not be read or written. Never silently ignored."""


class TargetKind(StrEnum):
    """What can be switched off. One per thing BRD section 16 names."""

    TOOL = "tool"  # a tool name or group: "shell.run", "database"
    MODEL = "model"  # a model name from the registry
    INTEGRATION = "integration"  # an MCP server, a database connection, a connector
    POLICY = "policy"  # ADM-008: the effective policy, identified by version + checksum


class Disabled(BaseModel):
    """One thing that is currently switched off."""

    model_config = ConfigDict(extra="forbid")

    kind: TargetKind
    name: str = Field(min_length=1, max_length=200)
    reason: str = Field(default="", max_length=1000)
    actor: str = Field(default="unknown", min_length=1, max_length=200)
    at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def key(self) -> str:
        return f"{self.kind.value}:{self.name}"

    def describe(self) -> str:
        when = self.at.isoformat(timespec="seconds")
        why = f": {self.reason}" if self.reason else ""
        return f"{self.kind.value} {self.name!r} disabled by {self.actor} at {when}{why}"


class ChangeRecord(BaseModel):
    """One administrative change (ADM-010). Append-only; never edited or removed."""

    model_config = ConfigDict(extra="forbid")

    at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    actor: str = "unknown"
    action: str  # "disable" | "enable" | "policy"
    kind: TargetKind
    name: str
    reason: str = ""

    def describe(self) -> str:
        when = self.at.isoformat(timespec="seconds")
        why = f" ({self.reason})" if self.reason else ""
        return f"{when}  {self.actor:<20} {self.action:<8} {self.kind.value} {self.name}{why}"


class ControlPlane:
    """Reads and writes the disable state. Cheap enough to consult on every call."""

    def __init__(
        self,
        root: str | Path,
        actor: str = "unknown",
        rbac: RbacPolicy | None = None,
        project: ProjectPolicy | None = None,
    ) -> None:
        self.directory = Path(root) / ".aica" / "admin"
        self.actor = actor
        # ADM-001/SEC-006. None = no role policy wired up, which behaves exactly as before.
        self.rbac = rbac or RbacPolicy()
        self.project = project or ProjectPolicy()  # ADM-002: owners administer

    @property
    def principal(self) -> Principal:
        return self.rbac.principal(self.actor, owner=self.project.is_owner(self.actor))

    @property
    def controls_path(self) -> Path:
        return self.directory / CONTROLS_FILE

    @property
    def history_path(self) -> Path:
        return self.directory / HISTORY_FILE

    # ------------------------------------------------------------------ reading
    def load(self) -> list[Disabled]:
        """Everything currently disabled. Raises on a file that exists but cannot be read."""
        path = self.controls_path
        if not path.is_file():
            return []
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ControlError(
                f"{path} exists but could not be read ({exc}); refusing to treat that as "
                "'nothing is disabled' (SEC-007)"
            ) from exc
        try:
            return [Disabled.model_validate(item) for item in raw.get("disabled", [])]
        except Exception as exc:  # pragma: no cover - pydantic message varies
            raise ControlError(f"{path} is not a valid control file: {exc}") from exc

    def is_disabled(self, kind: TargetKind, *names: str) -> Disabled | None:
        """The disable covering any of ``names``, or None.

        Several names because a tool is covered by its own name *or* its group: an
        operator switching off "database" during an incident means every database tool,
        and should not have to enumerate them.
        """
        wanted = {n for n in names if n}
        for entry in self.load():
            if entry.kind is kind and entry.name in wanted:
                return entry
        return None

    def history(self, limit: int | None = None) -> list[ChangeRecord]:
        """ADM-010: administrative changes, oldest first."""
        path = self.history_path
        if not path.is_file():
            return []
        records: list[ChangeRecord] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                records.append(ChangeRecord.model_validate_json(line))
            except ValueError:  # noqa: S112 - a damaged line must not hide the rest
                continue
        return records[-limit:] if limit else records

    # ------------------------------------------------------------------ writing
    def disable(self, kind: TargetKind, name: str, reason: str = "") -> Disabled:
        # ADM-001: administering is a role. Note there is no separation-of-duties check
        # on *disabling*: switching something off is the safe direction, and requiring a
        # second pair of eyes to stop a leaking model is how an incident gets longer.
        self.principal.require(Permission.ADMINISTER, f"disable {kind.value} {name!r}")
        entry = Disabled(kind=kind, name=name, reason=reason, actor=self.actor)
        current = [e for e in self.load() if e.key != entry.key]
        self._write([*current, entry])
        self._record("disable", kind, name, reason)
        return entry

    def enable(self, kind: TargetKind, name: str, reason: str = "") -> bool:
        """Remove a disable. Returns False when there was nothing to remove.

        This only ever undoes a disable made here - it cannot grant something the policy
        file withholds, so the control plane can never be used to get around policy.
        """
        self.principal.require(Permission.ADMINISTER, f"enable {kind.value} {name!r}")
        current = self.load()
        remaining = [e for e in current if not (e.kind is kind and e.name == name)]
        if len(remaining) == len(current):
            return False
        # SEC-006. Re-enabling is the direction that restores capability, so it is the
        # one that needs a second pair of eyes: the principal who switched a model or
        # tool off may not be the one who turns it back on. Checked against the recorded
        # disabler rather than anything in the request.
        disabler = next(e.actor for e in current if e.kind is kind and e.name == name)
        self.principal.require_distinct_from(disabler, f"{kind.value} re-enable")
        self._write(remaining)
        self._record("enable", kind, name, reason)
        return True

    def _write(self, entries: list[Disabled]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {
            "version": 1,
            "disabled": [json.loads(e.model_dump_json()) for e in entries],
        }
        # Written atomically: a half-written control file read mid-incident would be the
        # one moment this must not fail open.
        handle, temp = tempfile.mkstemp(dir=self.directory, suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            os.replace(temp, self.controls_path)
        except OSError as exc:
            Path(temp).unlink(missing_ok=True)
            raise ControlError(f"could not write {self.controls_path}: {exc}") from exc

    def _record(self, action: str, kind: TargetKind, name: str, reason: str) -> None:
        record = ChangeRecord(actor=self.actor, action=action, kind=kind, name=name, reason=reason)
        self.directory.mkdir(parents=True, exist_ok=True)
        with self.history_path.open("a", encoding="utf-8") as fh:
            fh.write(record.model_dump_json() + "\n")

    def __iter__(self) -> Iterator[Disabled]:
        return iter(self.load())

    # ------------------------------------------------------------------ ADM-008
    def record_policy_version(self, version: int, checksum: str) -> ChangeRecord | None:
        """Note the effective policy when it differs from the last one seen.

        Versioning by declaration alone does not work: a version number is bumped by
        whoever remembers to, so a change that forgot to bump it would be invisible. The
        checksum is what actually detects a change; the version is what a human cites.
        Recording both means an unbumped edit still shows up in the history, with the
        actor who was running when it first took effect.

        Returns the record written, or None when nothing changed.
        """
        name = f"v{version}+{checksum}"
        previous = [r for r in self.history() if r.kind is TargetKind.POLICY]
        if previous and previous[-1].name == name:
            return None
        record = ChangeRecord(
            actor=self.actor,
            action="policy",
            kind=TargetKind.POLICY,
            name=name,
            reason="effective policy changed" if previous else "effective policy first seen",
        )
        self.directory.mkdir(parents=True, exist_ok=True)
        with self.history_path.open("a", encoding="utf-8") as fh:
            fh.write(record.model_dump_json() + "\n")
        return record

    def policy_versions(self) -> list[ChangeRecord]:
        """ADM-008: every effective policy this workspace has seen, oldest first."""
        return [r for r in self.history() if r.kind is TargetKind.POLICY]
