"""Command classification and policy decision (EXEC-006, SECURITY_GUARDRAILS "Command Safety").

Commands are classified into read-only / development / privileged / destructive /
external before execution. Classification is conservative and pattern-based; anything
unrecognised is treated as ``DEVELOPMENT`` (allowed but audited), while matches for the
dangerous classes win over benign ones. The final decision comes from the approval policy.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from enum import StrEnum

from aica.policy.models import ActionCategory, ApprovalPolicy, Environment


class CommandClass(StrEnum):
    READ_ONLY = "read_only"
    DEVELOPMENT = "development"
    PRIVILEGED = "privileged"
    DESTRUCTIVE = "destructive"
    EXTERNAL = "external"


class Decision(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


# Ordered most-severe first. Each entry: (class, human reason, compiled regex on the
# normalised command string). Patterns are deliberately broad; false positives cost an
# approval prompt, false negatives cost data.
_RULES: list[tuple[CommandClass, str, re.Pattern[str]]] = [
    (
        CommandClass.DESTRUCTIVE,
        "recursive/forced delete",
        re.compile(r"\brm\s+(-[a-z]*[rf][a-z]*\s+)+", re.I),
    ),
    (
        CommandClass.DESTRUCTIVE,
        "Windows recursive delete",
        re.compile(r"\b(rmdir|rd)\s+/s\b|\bRemove-Item\b.*-Recurse", re.I),
    ),
    (
        CommandClass.DESTRUCTIVE,
        "git history/worktree destruction",
        re.compile(
            r"\bgit\s+(reset\s+--hard|clean\s+-[a-z]*[fx]|checkout\s+--\s|restore\s+(--source|\.)|branch\s+-D|push\s+.*(--force|-f\b|\+))",
            re.I,
        ),
    ),
    (
        CommandClass.DESTRUCTIVE,
        "destructive SQL",
        re.compile(r"\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA)\b|\bDELETE\s+FROM\b", re.I),
    ),
    (
        CommandClass.DESTRUCTIVE,
        "disk/format operation",
        re.compile(r"\b(mkfs|format|dd\s+if=|diskpart|fdisk)\b", re.I),
    ),
    (CommandClass.DESTRUCTIVE, "shred/overwrite", re.compile(r"\bshred\b|>\s*/dev/sd", re.I)),
    (
        CommandClass.PRIVILEGED,
        "privilege escalation",
        re.compile(r"\b(sudo|doas|runas|su)\b", re.I),
    ),
    (
        CommandClass.PRIVILEGED,
        "permission/ownership change",
        re.compile(r"\b(chmod|chown|icacls|takeown)\b", re.I),
    ),
    (
        CommandClass.PRIVILEGED,
        "service/system control",
        re.compile(
            r"\b(systemctl|service|sc\.exe|sc\s+(start|stop|delete)|shutdown|reboot|launchctl)\b",
            re.I,
        ),
    ),
    (
        CommandClass.PRIVILEGED,
        "package install to system",
        re.compile(
            r"\b(apt(-get)?|yum|dnf|brew|choco|winget)\s+(install|remove|uninstall)\b", re.I
        ),
    ),
    (
        CommandClass.PRIVILEGED,
        "registry/kernel modification",
        re.compile(r"\b(reg\s+(add|delete)|regedit|modprobe|sysctl\s+-w)\b", re.I),
    ),
    (
        CommandClass.EXTERNAL,
        "network transfer",
        re.compile(
            r"\b(curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|scp|rsync|ftp|sftp|ssh|nc|ncat|telnet)\b",
            re.I,
        ),
    ),
    (
        CommandClass.EXTERNAL,
        "push/publish/deploy",
        re.compile(
            r"\b(git\s+push|npm\s+publish|twine\s+upload|docker\s+push|kubectl\s+(apply|delete|rollout)|terraform\s+(apply|destroy)|helm\s+(install|upgrade|uninstall)|gh\s+(pr|release)\s+create)\b",
            re.I,
        ),
    ),
    (
        CommandClass.EXTERNAL,
        "remote package install",
        re.compile(
            r"\b(pip|pip3|uv)\s+install\b|\b(npm|pnpm|yarn)\s+(install|add|i)\b|\bcargo\s+(add|install)\b|\bgo\s+get\b",
            re.I,
        ),
    ),
    (
        CommandClass.READ_ONLY,
        "read-only inspection",
        re.compile(
            r"^\s*(ls|dir|cat|type|head|tail|less|more|pwd|echo|find|grep|rg|which|where|whoami|env|printenv|tree|wc|stat|file|du|df|git\s+(status|log|diff|show|branch|rev-parse|ls-files|blame|remote\s+-v)|python\s+--version|node\s+--version|npm\s+ls)\b",
            re.I,
        ),
    ),
]

_SECRET_FILE_ACCESS = re.compile(
    r"(^|[\s/\\\"'])(\.env(\.[\w-]+)?|id_rsa|id_ed25519|[\w.-]+\.(pem|key|p12|pfx))\b", re.I
)
_SHELL_CHAIN = re.compile(r"(\|\||&&|;|\|)")


@dataclass(frozen=True)
class CommandClassification:
    command: str
    command_class: CommandClass
    reasons: tuple[str, ...] = ()
    touches_secrets: bool = False
    segments: tuple[str, ...] = field(default_factory=tuple)


_SEVERITY = {
    CommandClass.DESTRUCTIVE: 4,
    CommandClass.PRIVILEGED: 3,
    CommandClass.EXTERNAL: 2,
    CommandClass.DEVELOPMENT: 1,
    CommandClass.READ_ONLY: 0,
}


def _split_segments(command: str) -> tuple[str, ...]:
    """Split on shell chaining so ``ls && rm -rf /`` is judged by its worst part."""
    parts = [p.strip() for p in _SHELL_CHAIN.split(command) if p and not _SHELL_CHAIN.fullmatch(p)]
    return tuple(p for p in parts if p)


def classify_command(command: str) -> CommandClassification:
    if not command or not command.strip():
        raise ValueError("empty command")
    segments = _split_segments(command)
    worst = CommandClass.READ_ONLY
    reasons: list[str] = []
    for seg in segments:
        matched = [(cls, reason) for cls, reason, pattern in _RULES if pattern.search(seg)]
        # A segment matching nothing is ordinary development work; a segment matching
        # several rules is judged by its most severe match.
        seg_class = max(
            (c for c, _ in matched), key=_SEVERITY.__getitem__, default=CommandClass.DEVELOPMENT
        )
        reasons.extend(r for c, r in matched if c is not CommandClass.READ_ONLY)
        if _SEVERITY[seg_class] > _SEVERITY[worst]:
            worst = seg_class
    touches_secrets = bool(_SECRET_FILE_ACCESS.search(command))
    if touches_secrets:
        reasons.append("references secret/credential file")
    return CommandClassification(
        command=command,
        command_class=worst,
        reasons=tuple(dict.fromkeys(reasons)),
        touches_secrets=touches_secrets,
        segments=segments,
    )


def categories_for(
    classification: CommandClassification, environment: Environment
) -> list[ActionCategory]:
    cats: list[ActionCategory] = []
    mapping = {
        CommandClass.DESTRUCTIVE: ActionCategory.DESTRUCTIVE,
        CommandClass.PRIVILEGED: ActionCategory.PRIVILEGED,
        CommandClass.EXTERNAL: ActionCategory.EXTERNAL,
    }
    if classification.command_class in mapping:
        cats.append(mapping[classification.command_class])
    if classification.touches_secrets:
        cats.append(ActionCategory.SECRET_ACCESS)
    if (
        environment is Environment.PRODUCTION
        and classification.command_class is not CommandClass.READ_ONLY
    ):
        cats.append(ActionCategory.PRODUCTION)
    return cats


def decide(
    classification: CommandClassification, approval: ApprovalPolicy, environment: Environment
) -> Decision:
    """Map a classification to allow / require_approval / block using the approval policy."""
    cats = categories_for(classification, environment)
    if any(approval.is_blocked(c) for c in cats):
        return Decision.BLOCK
    if any(approval.requires_approval(c) for c in cats):
        return Decision.REQUIRE_APPROVAL
    return Decision.ALLOW


def tokens(command: str) -> list[str]:
    """Best-effort tokenisation for display/audit; never used for execution decisions."""
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()
