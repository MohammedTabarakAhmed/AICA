"""Git working-tree protection (GIT-010, GIT-003, GIT-007, SAFE-003).

Before the agent modifies files it must know whether the developer has uncommitted work
in the paths it is about to touch, and whether it is on a protected branch. This module
only *reads* Git state; it never runs mutating Git commands.
"""

from __future__ import annotations

import os
import subprocess  # noqa: S404 - git is invoked with fixed argv, no shell
from dataclasses import dataclass, field
from pathlib import Path

from aica.policy.models import GitPolicy


class GitError(RuntimeError):
    pass


class UserChangesPresent(PermissionError):
    """Raised when a target path has uncommitted developer changes (GIT-010).

    A ``PermissionError`` because it is a policy refusal, and every caller already treats
    those as one: the agent stops with a report, the API answers 409, the CLI exits cleanly.
    As a bare ``RuntimeError`` it escaped all three and crashed a live agent run.
    """

    def __init__(self, paths: list[str]) -> None:
        self.paths = paths
        super().__init__(
            "uncommitted developer changes present in: "
            + ", ".join(paths)
            + " - refusing to modify silently; commit, stash or explicitly authorize overwrite"
        )


class ProtectedBranch(PermissionError):
    """GIT-003/007: a policy refusal, for the same reason as ``UserChangesPresent``."""


@dataclass(frozen=True)
class WorkingTreeStatus:
    branch: str | None
    modified: tuple[str, ...] = ()
    staged: tuple[str, ...] = ()
    untracked: tuple[str, ...] = ()
    conflicted: tuple[str, ...] = ()

    @property
    def dirty_paths(self) -> frozenset[str]:
        return (
            frozenset(self.modified)
            | frozenset(self.staged)
            | frozenset(self.untracked)
            | frozenset(self.conflicted)
        )

    @property
    def is_clean(self) -> bool:
        return not self.dirty_paths


@dataclass
class GitGuard:
    repo_root: Path
    policy: GitPolicy = field(default_factory=GitPolicy)

    def __post_init__(self) -> None:
        self.repo_root = Path(self.repo_root).resolve()

    def _git(self, *args: str) -> str:
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, shell=False
                ["git", *args],  # noqa: S607 - git is resolved from PATH by design
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitError(f"git {' '.join(args)} failed: {exc}") from exc
        if proc.returncode != 0:
            raise GitError(f"git {' '.join(args)} exited {proc.returncode}: {proc.stderr.strip()}")
        return proc.stdout

    def is_repository(self) -> bool:
        try:
            return self._git("rev-parse", "--is-inside-work-tree").strip() == "true"
        except GitError:
            return False

    def current_branch(self) -> str | None:
        try:
            out = self._git("symbolic-ref", "--short", "-q", "HEAD").strip()
        except GitError:
            return None  # detached HEAD or unborn branch
        return out or None

    def status(self) -> WorkingTreeStatus:
        out = self._git("status", "--porcelain=v1", "-z", "--untracked-files=all")
        modified: list[str] = []
        staged: list[str] = []
        untracked: list[str] = []
        conflicted: list[str] = []
        entries = out.split("\0")
        i = 0
        while i < len(entries):
            entry = entries[i]
            i += 1
            if not entry:
                continue
            code, path = entry[:2], entry[3:]
            x, y = code[0], code[1]
            if x == "R" or x == "C":
                i += 1  # rename/copy carries the original path in the next record
            if code == "??":
                untracked.append(path)
            elif "U" in code or code in {"AA", "DD"}:
                conflicted.append(path)
            else:
                if x not in " ?":
                    staged.append(path)
                if y not in " ?":
                    modified.append(path)
        return WorkingTreeStatus(
            self.current_branch(),
            tuple(modified),
            tuple(staged),
            tuple(untracked),
            tuple(conflicted),
        )

    def _normalise(self, path: str | os.PathLike[str]) -> str:
        p = Path(path)
        absolute = (p if p.is_absolute() else self.repo_root / p).resolve()
        try:
            return absolute.relative_to(self.repo_root).as_posix()
        except ValueError:
            return absolute.as_posix()

    def conflicting_user_changes(self, targets: list[str | os.PathLike[str]]) -> list[str]:
        """Return the subset of ``targets`` that currently carry uncommitted changes."""
        status = self.status()
        wanted = {self._normalise(t) for t in targets}
        return sorted(
            p
            for p in status.dirty_paths
            if p in wanted or any(p.startswith(w + "/") for w in wanted)
        )

    def assert_safe_to_modify(
        self, targets: list[str | os.PathLike[str]], *, allow_dirty: bool = False
    ) -> None:
        """GIT-010: refuse to touch paths with uncommitted developer changes unless authorized."""
        if not self.is_repository():
            return  # nothing to protect against; caller should still snapshot (FS-007)
        if allow_dirty:
            return
        clashes = self.conflicting_user_changes(targets)
        if clashes:
            raise UserChangesPresent(clashes)

    def assert_not_protected_branch(self) -> None:
        """GIT-003 / GIT-007: changes must not be made directly on a protected branch."""
        branch = self.current_branch()
        if (
            branch is not None
            and self.policy.require_branch_for_changes
            and self.policy.is_protected(branch)
        ):
            raise ProtectedBranch(f"branch '{branch}' is protected; create a working branch first")
