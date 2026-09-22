"""Model-generated, validated commit messages (GIT-006).

The model proposes; this module decides whether the proposal is acceptable. A message is
only returned when it passes :func:`validate_commit_message`; otherwise the deterministic
fallback built from the diff stat is used, so ``git.commit`` never receives an empty,
oversized or placeholder message.

Generation is advisory: nothing here commits. The caller passes the returned message to
``git.commit``, which still applies the protected-branch approval gate (GIT-007).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from aica.models.base import ChatMessage, ModelAdapter, ModelError
from aica.safety.injection import wrap_untrusted
from aica.safety.redaction import redact

SUBJECT_LIMIT = 72
BODY_LIMIT = 100
MAX_DIFF_CHARS = 24_000

COMMIT_SYSTEM = """You write Git commit messages for a professional engineering team.

Rules:
- First line: imperative mood, <= 72 characters, no trailing period ("Add retry to indexer",
  not "Added retry." or "This commit adds...").
- Then a blank line, then 1-5 short body lines explaining what changed and why.
- Describe only what the diff shows. Never invent a ticket number, author or rationale.
- No markdown headings, no code fences, no "Co-Authored-By" or other trailers.
- Output the message only."""

_PLACEHOLDER = re.compile(
    r"(?i)^(wip|update|updates|fix|fixes|changes?|misc|stuff|commit|asdf|test)\W*$"
)
_FENCE = re.compile(r"^```[\w-]*\s*|\s*```$")
_TRAILER = re.compile(r"(?im)^(co-authored-by|signed-off-by|generated with)\b.*$")


@dataclass(frozen=True)
class CommitMessage:
    subject: str
    body: str = ""
    model: str | None = None  # None = deterministic fallback, not model-generated

    @property
    def text(self) -> str:
        return f"{self.subject}\n\n{self.body}".strip() if self.body else self.subject

    @property
    def generated(self) -> bool:
        return self.model is not None


class InvalidCommitMessage(ValueError):
    """The proposed message violates the project's commit-message rules (GIT-006)."""


def validate_commit_message(text: str) -> CommitMessage:
    """Parse and check a commit message. Raises :class:`InvalidCommitMessage` when unusable."""
    cleaned = _TRAILER.sub("", _FENCE.sub("", text.strip())).strip()
    if not cleaned:
        raise InvalidCommitMessage("message is empty")
    lines = [line.rstrip() for line in cleaned.splitlines()]
    subject = lines[0].strip()
    if subject.startswith("#"):
        subject = subject.lstrip("# ").strip()
    if len(subject) < 8:
        raise InvalidCommitMessage(f"subject too short: {subject!r}")
    if len(subject) > SUBJECT_LIMIT:
        raise InvalidCommitMessage(f"subject exceeds {SUBJECT_LIMIT} characters ({len(subject)})")
    if subject.endswith("."):
        raise InvalidCommitMessage("subject must not end with a period")
    if _PLACEHOLDER.match(subject):
        raise InvalidCommitMessage(f"subject is a placeholder: {subject!r}")
    body_lines = [line for line in lines[1:] if line.strip()]
    for line in body_lines:
        if len(line) > BODY_LIMIT:
            raise InvalidCommitMessage(f"body line exceeds {BODY_LIMIT} characters")
    return CommitMessage(subject=subject, body="\n".join(body_lines))


def summarize_diff(diff: str) -> tuple[list[str], int, int]:
    """Return (changed paths, added lines, removed lines) from a unified diff."""
    paths: list[str] = []
    added = removed = 0
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            paths.append(line[6:].strip())
        elif line.startswith("--- a/") and not paths:
            continue
        elif line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return list(dict.fromkeys(p for p in paths if p and p != "/dev/null")), added, removed


def fallback_message(diff: str) -> CommitMessage:
    """Deterministic message from the diff stat - used when generation is unavailable."""
    paths, added, removed = summarize_diff(diff)
    if not paths:
        return CommitMessage(subject="Update working tree", body="")
    scope = Path(paths[0]).parent.as_posix()
    if len(paths) == 1:
        subject = f"Update {paths[0]}"
    elif scope and scope != ".":
        subject = f"Update {len(paths)} files in {scope}"
    else:
        subject = f"Update {len(paths)} files"
    subject = subject[:SUBJECT_LIMIT].rstrip()
    body = "\n".join(
        [
            f"Changed files ({len(paths)}): +{added}/-{removed} lines",
            *(f"- {p}" for p in paths[:10]),
        ]
    )
    return CommitMessage(subject=subject, body=body)


def generate_commit_message(
    adapter: ModelAdapter,
    diff: str,
    *,
    context: str = "",
    attempts: int = 2,
) -> CommitMessage:
    """GIT-006: ask the model for a commit message and accept it only if it validates.

    The diff is fenced as untrusted content: a diff may contain text that looks like
    instructions, and it must never be treated as any (SAFE-007).
    """
    if not diff.strip():
        raise InvalidCommitMessage("empty diff: nothing to describe")
    trimmed = redact(diff[:MAX_DIFF_CHARS]).text
    paths, added, removed = summarize_diff(diff)
    stat = f"{len(paths)} file(s), +{added}/-{removed} lines: {', '.join(paths[:10])}"
    user = (
        (f"Task context: {context}\n\n" if context.strip() else "")
        + f"Change statistics: {stat}\n\n"
        + wrap_untrusted(trimmed, "git-diff")
        + "\n\nWrite the commit message for this diff."
    )
    messages = [
        ChatMessage(role="system", content=COMMIT_SYSTEM),
        ChatMessage(role="user", content=user),
    ]
    last_error: InvalidCommitMessage | None = None
    for attempt in range(max(1, attempts)):
        response = adapter.chat(messages, temperature=0.2 if attempt == 0 else 0.0, max_tokens=300)
        try:
            candidate = validate_commit_message(redact(response.content).text)
        except InvalidCommitMessage as exc:
            last_error = exc
            messages = [
                *messages,
                ChatMessage(role="assistant", content=response.content),
                ChatMessage(
                    role="user",
                    content=f"That message was rejected: {exc}. Rewrite it following the rules.",
                ),
            ]
            continue
        return CommitMessage(subject=candidate.subject, body=candidate.body, model=response.model)
    raise InvalidCommitMessage(
        f"model did not produce a valid commit message after {attempts} attempt(s): {last_error}"
    )


def suggest_commit_message(
    adapter: ModelAdapter | None, diff: str, *, context: str = ""
) -> CommitMessage:
    """Best-effort GIT-006 entry point: generated when possible, deterministic otherwise.

    The fallback is marked (``generated`` is False) so a caller can tell the user that the
    message was not model-written rather than silently passing one off as the other.
    """
    if adapter is None:
        return fallback_message(diff)
    try:
        return generate_commit_message(adapter, diff, context=context)
    except (InvalidCommitMessage, ModelError):
        return fallback_message(diff)
