"""Session persistence and context management (MEM-001..MEM-006, CHAT-005/006).

Sessions are JSON files under ``.aica/sessions``. Each records the messages, the exact
model/version used per turn, attachments and the tool/policy configuration needed to
reproduce or resume the session (MEM-006, MM-012).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from aica.models.base import ChatMessage, ModelAdapter
from aica.safety.injection import wrap_untrusted
from aica.safety.redaction import redact

DEFAULT_SESSION_DIR = Path(".aica/sessions")


class Attachment(BaseModel):
    """CHAT-006: task-scoped context. Content is untrusted and redacted on ingest."""

    model_config = ConfigDict(extra="forbid")

    name: str
    kind: str = "text"  # text | log | file
    content: str

    def as_context(self) -> str:
        return wrap_untrusted(self.content, f"attachment:{self.name}")


class Turn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str
    content: str
    model: str | None = None  # exact model/version that produced an assistant turn
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tokens: int = 0


class Session(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    title: str = ""
    workspace: str = "."
    created: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated: datetime = Field(default_factory=lambda: datetime.now(UTC))
    model_name: str | None = None
    policy_version: int = 1
    turns: list[Turn] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)
    summary: str = ""  # MEM-002 rolling summary of older turns
    task_state: dict[str, str] = Field(default_factory=dict)  # MEM-003 resumable state

    def add(self, role: str, content: str, model: str | None = None) -> Turn:
        turn = Turn(role=role, content=content, model=model, tokens=max(len(content) // 4, 1))
        self.turns.append(turn)
        self.updated = datetime.now(UTC)
        if not self.title and role == "user":
            self.title = content.strip().splitlines()[0][:80]
        return turn

    def reset_context(self, keep_summary: bool = False) -> None:
        """MEM-005: user-controlled clean context."""
        self.turns.clear()
        self.attachments.clear()
        if not keep_summary:
            self.summary = ""
        self.updated = datetime.now(UTC)

    def reproducibility(self) -> dict[str, str]:
        """MEM-006: what is needed to rerun this session comparably."""
        models = [t.model for t in self.turns if t.model]
        return {
            "session_id": self.session_id,
            "model_configured": self.model_name or "(default)",
            "models_used": ",".join(dict.fromkeys(models)) or "(none)",
            "policy_version": str(self.policy_version),
            "workspace": self.workspace,
            "turns": str(len(self.turns)),
        }


class SessionStore:
    def __init__(self, root: Path, directory: Path | None = None) -> None:
        self.dir = (directory or Path(root) / DEFAULT_SESSION_DIR).resolve()
        self.dir.mkdir(parents=True, exist_ok=True)

    def path_for(self, session_id: str) -> Path:
        return self.dir / f"{session_id}.json"

    def save(self, session: Session) -> Path:
        p = self.path_for(session.session_id)
        # Redact before persisting: sessions may quote logs or config (SAFE-006).
        data = json.loads(session.model_dump_json())
        p.write_text(redact(json.dumps(data, indent=1, default=str)).text, encoding="utf-8")
        return p

    def load(self, session_id: str) -> Session:
        p = self.path_for(session_id)
        if not p.exists():
            raise KeyError(f"unknown session {session_id}")
        return Session.model_validate_json(p.read_text(encoding="utf-8"))

    def list_sessions(self) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        for p in sorted(self.dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                s = Session.model_validate_json(p.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue
            out.append(
                {
                    "session_id": s.session_id,
                    "title": s.title or "(untitled)",
                    "updated": s.updated.isoformat(timespec="seconds"),
                    "turns": str(len(s.turns)),
                    "model": s.model_name or "(default)",
                }
            )
        return out

    def delete(self, session_id: str) -> bool:
        p = self.path_for(session_id)
        if p.exists():
            p.unlink()
            return True
        return False


def build_context(
    session: Session,
    system_prompt: str,
    *,
    max_turns: int = 20,
    retrieved: str | None = None,
) -> list[ChatMessage]:
    """Assemble the model context: system → summary → attachments → retrieval → recent turns.

    Retrieved repository content and attachments are fenced as untrusted data (SAFE-007).
    """
    messages = [ChatMessage(role="system", content=system_prompt)]
    if session.summary:
        messages.append(
            ChatMessage(
                role="system", content=f"Summary of earlier conversation:\n{session.summary}"
            )
        )
    for att in session.attachments:
        messages.append(ChatMessage(role="system", content=att.as_context()))
    if retrieved:
        messages.append(
            ChatMessage(role="system", content=wrap_untrusted(retrieved, "repository-retrieval"))
        )
    for turn in session.turns[-max_turns:]:
        role = turn.role if turn.role in {"system", "user", "assistant", "tool"} else "user"
        messages.append(ChatMessage(role=role, content=turn.content))  # type: ignore[arg-type]
    return messages


def summarize_if_needed(
    session: Session, summarizer: ModelAdapter, threshold: int = 24, keep: int = 8
) -> bool:
    """MEM-002: fold older turns into a rolling summary once the history grows."""
    if len(session.turns) <= threshold:
        return False
    old = session.turns[:-keep]
    transcript = "\n".join(f"{t.role}: {t.content}" for t in old)[:24_000]
    prompt = [
        ChatMessage(
            role="system",
            content="Summarize this development conversation. Keep decisions, file paths, commands, constraints and unresolved issues. Be concise and factual.",
        ),
        ChatMessage(role="user", content=transcript),
    ]
    response = summarizer.chat(prompt, temperature=0.0)
    session.summary = (session.summary + "\n" if session.summary else "") + response.content.strip()
    session.turns = session.turns[-keep:]
    return True
