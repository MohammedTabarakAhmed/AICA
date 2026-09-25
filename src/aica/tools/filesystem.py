"""Filesystem tools (FS-001..FS-007, GIT-010, SAFE-006).

All paths go through ``WorkspaceGuard``; every modification first checks ``GitGuard`` for
uncommitted developer changes and captures a snapshot for rollback; every material
modification returns a unified diff so it is reviewable (FS-006, UX-004).
"""

from __future__ import annotations

import difflib
import fnmatch
import hashlib
import os
from pathlib import Path
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from aica.policy.models import ActionCategory
from aica.tools.base import Tool, ToolContext, ToolError, ToolResult
from aica.workspace.snapshots import SnapshotStore

_IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".aica",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "dist",
    "build",
    "target",
}
MAX_READ_BYTES = 2_000_000


def unified_diff(before: str, after: str, path: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _snapshot_store(ctx: ToolContext) -> SnapshotStore:
    return SnapshotStore(ctx.workspace.root)


def _prepare_modification(
    ctx: ToolContext, tool: str, path: str, *, allow_dirty: bool
) -> tuple[Path, str]:
    """Shared pre-write checks: authorization, sensitivity, GIT-010, snapshot."""
    resolved = ctx.workspace.resolve(path)
    if resolved.sensitive:
        ctx.require_approval(
            tool,
            f"modify sensitive file {resolved.relative.as_posix()}",
            [ActionCategory.SECRET_ACCESS],
        )
    if ctx.git is not None and not _is_own_write(ctx, resolved.absolute):
        if allow_dirty:
            ctx.require_approval(
                tool,
                f"overwrite uncommitted developer changes in {resolved.relative.as_posix()}",
                [ActionCategory.DESTRUCTIVE],
            )
        ctx.git.assert_safe_to_modify([resolved.absolute], allow_dirty=allow_dirty)
    return resolved.absolute, resolved.relative.as_posix()


def _digest(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _is_own_write(ctx: ToolContext, path: Path) -> bool:
    """True when this run wrote ``path`` and nobody has changed it since (GIT-010)."""
    recorded = ctx.own_writes.get(path.as_posix())
    return recorded is not None and recorded == _digest(path)


def _record_own_write(ctx: ToolContext, path: Path) -> None:
    digest = _digest(path)
    if digest is None:
        ctx.own_writes.pop(path.as_posix(), None)
    else:
        ctx.own_writes[path.as_posix()] = digest


# ------------------------------------------------------------------ FS-001


class ListFiles(Tool):
    name: ClassVar[str] = "fs.list"
    description: ClassVar[str] = "List files and directories within the authorized workspace."

    class Args(_Args):
        path: str = "."
        recursive: bool = False
        pattern: str | None = Field(
            default=None, description="fnmatch glob applied to relative paths"
        )
        max_entries: int = Field(default=500, ge=1, le=10_000)

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        base = ctx.workspace.resolve(args.path).absolute
        if not base.is_dir():
            raise ToolError(f"{args.path} is not a directory")
        entries: list[str] = []
        if args.recursive:
            for dirpath, dirnames, filenames in os.walk(base):
                dirnames[:] = sorted(d for d in dirnames if d not in _IGNORED_DIRS)
                for fn in sorted(filenames):
                    rel = (Path(dirpath) / fn).relative_to(ctx.workspace.root).as_posix()
                    if args.pattern is None or fnmatch.fnmatch(rel, args.pattern):
                        entries.append(rel)
                    if len(entries) >= args.max_entries:
                        break
                if len(entries) >= args.max_entries:
                    break
        else:
            for child in sorted(base.iterdir(), key=lambda p: (p.is_file(), p.name)):
                if child.name in _IGNORED_DIRS:
                    continue
                rel = child.relative_to(ctx.workspace.root).as_posix()
                if args.pattern is None or fnmatch.fnmatch(rel, args.pattern):
                    entries.append(rel + ("/" if child.is_dir() else ""))
                if len(entries) >= args.max_entries:
                    break
        return ToolResult(
            output="\n".join(entries), data={"count": len(entries), "entries": entries}
        )


# ------------------------------------------------------------------ FS-002


class ReadFile(Tool):
    name: ClassVar[str] = "fs.read"
    description: ClassVar[str] = "Read a text file (optionally a line range) from the workspace."

    class Args(_Args):
        path: str
        start_line: int = Field(default=1, ge=1)
        end_line: int | None = Field(default=None, ge=1)

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        resolved = ctx.workspace.resolve(args.path)
        if resolved.sensitive:
            ctx.require_approval(
                self.name,
                f"read sensitive file {resolved.relative.as_posix()}",
                [ActionCategory.SECRET_ACCESS],
            )
        p = resolved.absolute
        if not p.is_file():
            raise ToolError(f"{args.path} is not a file")
        if p.stat().st_size > MAX_READ_BYTES:
            raise ToolError(f"{args.path} exceeds {MAX_READ_BYTES} bytes")
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        end = args.end_line or len(lines)
        selected = lines[args.start_line - 1 : end]
        return ToolResult(
            output="".join(selected),
            data={
                "path": resolved.relative.as_posix(),
                "total_lines": len(lines),
                "start_line": args.start_line,
                "end_line": min(end, len(lines)),
            },
        )


# ------------------------------------------------------------------ FS-003


class WriteFile(Tool):
    name: ClassVar[str] = "fs.write"
    mutating: ClassVar[bool] = True
    description: ClassVar[str] = "Create or overwrite a file. Returns a reviewable unified diff."

    class Args(_Args):
        path: str
        content: str
        allow_dirty: bool = Field(
            default=False,
            description="explicitly authorize overwriting uncommitted developer changes",
        )
        snapshot_id: str | None = None

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        absolute, rel = _prepare_modification(
            ctx, self.name, args.path, allow_dirty=args.allow_dirty
        )
        store = _snapshot_store(ctx)
        sid = args.snapshot_id or store.create(f"fs.write {rel}")
        store.capture(sid, absolute)
        existed = absolute.exists()
        before = absolute.read_text(encoding="utf-8", errors="replace") if existed else ""
        absolute.parent.mkdir(parents=True, exist_ok=True)
        absolute.write_text(args.content, encoding="utf-8", newline="\n")
        _record_own_write(ctx, absolute)
        diff = unified_diff(before, args.content, rel)
        return ToolResult(
            output=diff,
            data={"path": rel, "snapshot_id": sid, "created": not existed, "diff": diff},
        )


class EditFile(Tool):
    name: ClassVar[str] = "fs.edit"
    mutating: ClassVar[bool] = True
    description: ClassVar[str] = (
        "Replace an exact text span in a file (must match exactly once unless replace_all)."
    )

    class Args(_Args):
        path: str
        old_text: str = Field(min_length=1)
        new_text: str
        replace_all: bool = False
        allow_dirty: bool = False
        snapshot_id: str | None = None

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        absolute, rel = _prepare_modification(
            ctx, self.name, args.path, allow_dirty=args.allow_dirty
        )
        if not absolute.is_file():
            raise ToolError(f"{args.path} does not exist")
        before = absolute.read_text(encoding="utf-8", errors="replace")
        count = before.count(args.old_text)
        if count == 0:
            raise ToolError("old_text not found")
        if count > 1 and not args.replace_all:
            raise ToolError(f"old_text matches {count} times; make it unique or set replace_all")
        after = (
            before.replace(args.old_text, args.new_text)
            if args.replace_all
            else before.replace(args.old_text, args.new_text, 1)
        )
        store = _snapshot_store(ctx)
        sid = args.snapshot_id or store.create(f"fs.edit {rel}")
        store.capture(sid, absolute)
        absolute.write_text(after, encoding="utf-8", newline="\n")
        _record_own_write(ctx, absolute)
        diff = unified_diff(before, after, rel)
        return ToolResult(
            output=diff,
            data={
                "path": rel,
                "snapshot_id": sid,
                "replacements": count if args.replace_all else 1,
                "diff": diff,
            },
        )


# ------------------------------------------------------------------ FS-004


class MoveFile(Tool):
    name: ClassVar[str] = "fs.move"
    mutating: ClassVar[bool] = True
    description: ClassVar[str] = "Rename or move a file within the workspace."

    class Args(_Args):
        source: str
        destination: str
        allow_dirty: bool = False
        snapshot_id: str | None = None

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        src_abs, src_rel = _prepare_modification(
            ctx, self.name, args.source, allow_dirty=args.allow_dirty
        )
        dst_abs, dst_rel = _prepare_modification(
            ctx, self.name, args.destination, allow_dirty=args.allow_dirty
        )
        if not src_abs.exists():
            raise ToolError(f"{args.source} does not exist")
        if dst_abs.exists():
            raise ToolError(f"{args.destination} already exists")
        store = _snapshot_store(ctx)
        sid = args.snapshot_id or store.create(f"fs.move {src_rel} -> {dst_rel}")
        store.capture(sid, src_abs)
        store.capture(sid, dst_abs)
        dst_abs.parent.mkdir(parents=True, exist_ok=True)
        src_abs.rename(dst_abs)
        ctx.own_writes.pop(src_abs.as_posix(), None)
        _record_own_write(ctx, dst_abs)
        return ToolResult(
            output=f"moved {src_rel} -> {dst_rel}",
            data={"source": src_rel, "destination": dst_rel, "snapshot_id": sid},
        )


# ------------------------------------------------------------------ FS-005


class DeleteFile(Tool):
    name: ClassVar[str] = "fs.delete"
    mutating: ClassVar[bool] = True
    description: ClassVar[str] = (
        "Delete a file. Protected by the file_delete approval category and snapshotted first."
    )

    class Args(_Args):
        path: str
        allow_dirty: bool = False
        snapshot_id: str | None = None

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        absolute, rel = _prepare_modification(
            ctx, self.name, args.path, allow_dirty=args.allow_dirty
        )
        if not absolute.is_file():
            raise ToolError(f"{args.path} is not a file")
        ctx.require_approval(self.name, f"delete {rel}", [ActionCategory.FILE_DELETE], path=rel)
        store = _snapshot_store(ctx)
        sid = args.snapshot_id or store.create(f"fs.delete {rel}")
        store.capture(sid, absolute)
        absolute.unlink()
        ctx.own_writes.pop(absolute.as_posix(), None)
        return ToolResult(output=f"deleted {rel}", data={"path": rel, "snapshot_id": sid})


# ------------------------------------------------------------------ FS-006


class DiffFile(Tool):
    name: ClassVar[str] = "fs.diff"
    description: ClassVar[str] = (
        "Show the unified diff of a file against a snapshot (or against proposed content)."
    )

    class Args(_Args):
        path: str
        snapshot_id: str | None = None
        proposed_content: str | None = None

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        resolved = ctx.workspace.resolve(args.path)
        rel = resolved.relative.as_posix()
        current = (
            resolved.absolute.read_text(encoding="utf-8", errors="replace")
            if resolved.absolute.exists()
            else ""
        )
        if args.proposed_content is not None:
            diff = unified_diff(current, args.proposed_content, rel)
        elif args.snapshot_id:
            original = _snapshot_store(ctx).original_text(args.snapshot_id, rel) or ""
            diff = unified_diff(original, current, rel)
        else:
            raise ToolError("provide snapshot_id or proposed_content")
        return ToolResult(output=diff, data={"path": rel, "diff": diff, "changed": bool(diff)})


# ------------------------------------------------------------------ FS-007


class Snapshot(Tool):
    name: ClassVar[str] = "fs.snapshot"
    description: ClassVar[str] = (
        "Create a workspace snapshot id to group subsequent modifications for rollback."
    )

    class Args(_Args):
        label: str = ""
        paths: list[str] = Field(default_factory=list, description="files to capture immediately")

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        store = _snapshot_store(ctx)
        sid = store.create(args.label)
        for p in args.paths:
            store.capture(sid, ctx.workspace.resolve(p).absolute)
        return ToolResult(output=sid, data={"snapshot_id": sid, "captured": len(args.paths)})


class Rollback(Tool):
    name: ClassVar[str] = "fs.rollback"
    mutating: ClassVar[bool] = True
    description: ClassVar[str] = "Restore files from a snapshot (all files, or one path)."

    class Args(_Args):
        snapshot_id: str
        path: str | None = None

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        store = _snapshot_store(ctx)
        rel = ctx.workspace.resolve(args.path).relative.as_posix() if args.path else None
        # Rolling back overwrites the current state of those files; make sure they are all authorized.
        for entry in store.entries(args.snapshot_id):
            ctx.workspace.resolve(entry.relative)
        restored = store.rollback(args.snapshot_id, rel)
        return ToolResult(
            output="\n".join(restored), data={"snapshot_id": args.snapshot_id, "restored": restored}
        )


FILESYSTEM_TOOLS: list[Tool] = [
    ListFiles(),
    ReadFile(),
    WriteFile(),
    EditFile(),
    MoveFile(),
    DeleteFile(),
    DiffFile(),
    Snapshot(),
    Rollback(),
]
