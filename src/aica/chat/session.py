"""Session persistence and context management (MEM-001..MEM-006, CHAT-005/006).

Sessions are JSON files under ``.aica/sessions``. Each records the messages, the exact
model/version used per turn, attachments and the tool/policy configuration needed to
reproduce or resume the session (MEM-006, MM-012).
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from aica.admin.rbac import Permission, Principal
from aica.models.base import ChatMessage, ModelAdapter
from aica.safety.injection import wrap_untrusted
from aica.safety.redaction import redact

DEFAULT_SESSION_DIR = Path(".aica/sessions")
UPDATE_ATTEMPTS = 5

# Saves in this process are serialised; across processes the revision check catches it.
_SAVE_LOCK = threading.RLock()


class SessionConflict(RuntimeError):
    """NFR-003: the session changed on disk since this copy was loaded."""


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
    # NFR-003. Incremented by every save; a save of a copy older than what is on disk is
    # refused, so two writers cannot silently discard each other's turns or task state.
    revision: int = 0
    # NFR-003. The principal who created the session. None for sessions written before
    # ownership existed, which stay open to everyone rather than being locked out.
    owner: str | None = None

    def check_access(self, principal: Principal) -> None:
        """Refuse another principal's session while RBAC is enforced (NFR-003, ADM-001).

        An administrator may still open it - incident response needs to - but a peer may
        not continue, resume or overwrite someone else's working state.
        """
        if not principal.policy.enabled or self.owner is None or self.owner == principal.name:
            return
        principal.require(
            Permission.ADMINISTER, f"open session {self.session_id} of {self.owner!r}"
        )

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
        """Write atomically, refusing a copy older than the one on disk (NFR-003)."""
        p = self.path_for(session.session_id)
        with _SAVE_LOCK:
            on_disk = self._revision_on_disk(p)
            if on_disk > session.revision:
                raise SessionConflict(
                    f"session {session.session_id} was changed by another writer (revision "
                    f"{on_disk}, this copy {session.revision}); reload it and retry"
                )
            session.revision = on_disk + 1
            # Redact before persisting: sessions may quote logs or config (SAFE-006).
            data = json.loads(session.model_dump_json())
            text = redact(json.dumps(data, indent=1, default=str)).text
            handle, temp = tempfile.mkstemp(dir=self.dir, suffix=".tmp")
            try:
                with os.fdopen(handle, "w", encoding="utf-8") as fh:
                    fh.write(text)
                os.replace(temp, p)
            except BaseException:
                session.revision = on_disk
                Path(temp).unlink(missing_ok=True)
                raise
        return p

    def update(self, session: Session, change: Callable[[Session], None]) -> Session:
        """Apply ``change`` to the latest saved copy and save it, retrying on conflict.

        For a writer that held a session for a long time - an agent run - and must add its
        result without discarding whatever was saved meanwhile. Returns the saved copy.
        """
        latest = session
        for _ in range(UPDATE_ATTEMPTS):
            # Held across read-change-save, so writers in this process never race each
            # other; the retry is for a writer in another process.
            with _SAVE_LOCK:
                if self.path_for(session.session_id).exists():
                    latest = self.load(session.session_id)
                change(latest)
                try:
                    self.save(latest)
                    return latest
                except SessionConflict:
                    continue
        raise SessionConflict(
            f"session {session.session_id} kept changing; gave up after {UPDATE_ATTEMPTS} tries"
        )

    @staticmethod
    def _revision_on_disk(path: Path) -> int:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return 0
        except (OSError, ValueError):
            return 0  # an unreadable file is replaced, as it was before revisions existed
        value = raw.get("revision", 0) if isinstance(raw, dict) else 0
        return value if isinstance(value, int) else 0

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
