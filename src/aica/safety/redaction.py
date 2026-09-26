"""Secret redaction (SAFE-006, CC-007, CLAUDE.md section 7).

Applied to anything that leaves a trust boundary: audit records, logs, progress files,
error reports and model context. Pattern-based; tuned for low false negatives on the
credential formats most common in engineering workspaces.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

REDACTED = "[REDACTED]"

# (label, pattern). Patterns capture the whole secret; the label appears in the mask so
# reviewers can tell what kind of value was removed without seeing it.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private-key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    ),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "github-token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    ),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    # INT-004: Socket Mode app-level tokens (xapp-1-A0...-...), distinct from the xox* family.
    ("slack-app-token", re.compile(r"\bxapp-\d-[A-Za-z0-9-]{10,}\b")),
    ("openai-style-key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("url-credentials", re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s/@]+@")),
    (
        "assignment",
        re.compile(
            r"(?i)\b((?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret"
            r"|password|passwd|pwd|token|secret|private[_-]?key)\s*[:=]\s*[\"']?)([^\s\"',;]{6,})"
        ),
    ),
]


@dataclass(frozen=True)
class RedactionResult:
    text: str
    count: int
    kinds: tuple[str, ...]

    @property
    def redacted(self) -> bool:
        return self.count > 0


def redact(text: str) -> RedactionResult:
    if not text:
        return RedactionResult(text, 0, ())
    count = 0
    kinds: list[str] = []
    out = text
    for label, pattern in _PATTERNS:
        if label == "url-credentials":
            out, n = pattern.subn(lambda m: f"{m.group(1)}{REDACTED}@", out)
        elif label == "assignment":
            out, n = pattern.subn(lambda m: f"{m.group(1)}{REDACTED}", out)
        else:
            out, n = pattern.subn(f"{REDACTED}", out)
        if n:
            count += n
            kinds.append(label)
    return RedactionResult(out, count, tuple(kinds))


def redact_mapping(data: dict[str, object]) -> dict[str, object]:
    """Recursively redact string values (and secret-looking keys) in a JSON-like mapping."""
    sensitive_key = re.compile(
        r"(?i)(secret|token|password|passwd|api[_-]?key|private[_-]?key|credential)"
    )

    def _walk(value: object) -> object:
        if isinstance(value, str):
            return redact(value).text
        if isinstance(value, dict):
            return {
                k: (
                    REDACTED
                    if isinstance(k, str) and sensitive_key.search(k) and isinstance(v, str)
                    else _walk(v)
                )
                for k, v in value.items()
            }
        if isinstance(value, list | tuple):
            return [_walk(v) for v in value]
        return value

    result = _walk(data)
    assert isinstance(result, dict)
    return result
