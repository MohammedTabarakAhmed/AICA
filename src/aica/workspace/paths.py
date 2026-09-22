"""Authorized-workspace path guard (FS-001..FS-005, SECURITY_GUARDRAILS "Filesystem Safety").

Every filesystem tool resolves its target through ``WorkspaceGuard`` before touching
disk. Paths that escape the allowed directories (via ``..``, absolute paths or symlinks)
are rejected. Sensitive files are identified so reads can be routed through the
``secret_access`` approval category and writes to them can be refused.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path


class PathNotAuthorized(PermissionError):
    pass


_SENSITIVE_NAMES = re.compile(
    r"(?i)^(\.env(\..+)?|\.npmrc|\.pypirc|\.netrc|id_rsa|id_ed25519|id_ecdsa|.*\.(pem|key|p12|pfx|jks|keystore)"
    r"|credentials(\..+)?|secrets?(\..+)?|.*secret.*\.(json|ya?ml|toml))$"
)
_SENSITIVE_DIRS = {".git", ".ssh", ".aws", ".gnupg", ".venv", "node_modules"}


@dataclass(frozen=True)
class ResolvedPath:
    requested: str
    absolute: Path
    relative: Path  # relative to the workspace root
    sensitive: bool


class WorkspaceGuard:
    def __init__(
        self, root: str | os.PathLike[str], allowed_directories: list[str] | None = None
    ) -> None:
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise NotADirectoryError(str(self.root))
        dirs = allowed_directories or ["."]
        self.allowed: tuple[Path, ...] = tuple((self.root / d).resolve() for d in dirs)
        for d in self.allowed:
            if not d.is_relative_to(self.root):
                raise PathNotAuthorized(
                    f"allowed directory {d} is outside workspace root {self.root}"
                )

    def resolve(self, path: str | os.PathLike[str]) -> ResolvedPath:
        raw = Path(path)
        candidate = raw if raw.is_absolute() else self.root / raw
        # resolve() follows symlinks, so a link pointing outside the workspace is caught.
        absolute = candidate.resolve()
        if not any(absolute == d or absolute.is_relative_to(d) for d in self.allowed):
            raise PathNotAuthorized(f"{path!s} resolves outside the authorized workspace")
        relative = absolute.relative_to(self.root)
        return ResolvedPath(str(path), absolute, relative, self.is_sensitive(relative))

    def is_authorized(self, path: str | os.PathLike[str]) -> bool:
        try:
            self.resolve(path)
        except PathNotAuthorized:
            return False
        return True

    @staticmethod
    def is_sensitive(relative: Path) -> bool:
        parts = relative.parts
        if any(p in _SENSITIVE_DIRS for p in parts[:-1]):
            return True
        return bool(parts) and bool(_SENSITIVE_NAMES.match(parts[-1]))
