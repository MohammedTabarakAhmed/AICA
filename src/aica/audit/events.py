"""Audit event schema (EXEC-007, DB-007, MCP-006, MM-012, ADM-007, BRD section 17 Auditability).

Every material action is attributable to user / session / agent / tool. Arguments and
details are redacted before they are stored (SAFE-006).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aica.safety.redaction import redact, redact_mapping


class EventCategory(StrEnum):
    COMMAND = "command"  # EXEC-007
    FILE_CHANGE = "file_change"  # FS-003/005/006
    GIT = "git"  # GIT-*
    TOOL_CALL = "tool_call"  # MCP-006
    MODEL_CALL = "model_call"  # MM-012
    DATABASE = "database"  # DB-007
    BROWSER = "browser"  # WEB-*
    POLICY_DECISION = "policy_decision"  # EXEC-006 / SAFE-001
    APPROVAL = "approval"  # SAFE-001/002
    SAFETY = "safety"  # SAFE-007 injection findings, redaction events
    TASK = "task"  # AG-005/006, session lifecycle
    ADMIN = "admin"  # ADM-*


class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    PENDING_APPROVAL = "pending_approval"
    CANCELLED = "cancelled"


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    category: EventCategory
    action: str = Field(min_length=1, max_length=200)
    outcome: Outcome
    actor: str = Field(min_length=1, max_length=200)  # user id / service principal
    session_id: str | None = None
    task_id: str | None = None
    agent: str | None = None  # agent / subagent name (AG-008)
    tool: str | None = None
    target: str | None = None  # path, repo, table, URL host ...
    model: str | None = None  # exact model/version when relevant (MM-012)
    arguments: dict[str, Any] = Field(default_factory=dict)
    details: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int | None = Field(default=None, ge=0)

    @field_validator("action", "target", "tool", "agent", "model")
    @classmethod
    def _redact_scalars(cls, value: str | None) -> str | None:
        return redact(value).text if value else value

    @field_validator("arguments", "details")
    @classmethod
    def _redact_mappings(cls, value: dict[str, Any]) -> dict[str, Any]:
        return redact_mapping(value)

    def to_json_line(self) -> str:
        return self.model_dump_json(exclude_none=True)
