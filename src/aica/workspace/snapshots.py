"""Workspace snapshots and rollback (FS-007, GIT-009 for uncommitted work).

Before the agent modifies or deletes a file, the original bytes are stored under a
snapshot id. A snapshot can be rolled back file-by-file or wholesale. Storage lives in the
workspace under ``.aica/snapshots`` (git-ignored) so it survives process restarts.
"""

from __future__ import annotations

import json
import shutil
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_MISSING = "__missing__"


@dataclass(frozen=True)
class SnapshotEntry:
    relative: str
    existed: bool


class SnapshotStore:
    def __init__(self, workspace_root: Path, directory: Path | None = None) -> None:
        self.root = Path(workspace_root).resolve()
        self.dir = (directory or self.root / ".aica" / "snapshots").resolve()
        self.dir.mkdir(parents=True, exist_ok=True)

    def create(self, label: str = "") -> str:
        sid = datetime.now(UTC).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:6]
        (self.dir / sid).mkdir()
        (self.dir / sid / "manifest.json").write_text(
            json.dumps({"label": label, "created": datetime.now(UTC).isoformat(), "files": {}}),
            encoding="utf-8",
        )
        return sid

    def _manifest(self, sid: str) -> dict[str, object]:
        p = self.dir / sid / "manifest.json"
        if not p.exists():
            raise KeyError(f"unknown snapshot {sid}")
        return json.loads(p.read_text(encoding="utf-8"))  # type: ignore[no-any-return]

    def _save_manifest(self, sid: str, manifest: dict[str, object]) -> None:
        (self.dir / sid / "manifest.json").write_text(
            json.dumps(manifest, indent=1), encoding="utf-8"
        )

    def capture(self, sid: str, absolute: Path) -> SnapshotEntry:
        """Record the current state of ``absolute`` (once per snapshot; first capture wins)."""
        relative = absolute.resolve().relative_to(self.root).as_posix()
        manifest = self._manifest(sid)
        files = manifest["files"]
        assert isinstance(files, dict)
        if relative in files:
            return SnapshotEntry(relative, files[relative] != _MISSING)
        if absolute.exists():
            blob = self.dir / sid / "blobs" / relative
            blob.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(absolute, blob)
            files[relative] = "blobs/" + relative
            existed = True
        else:
            files[relative] = _MISSING
            existed = False
        self._save_manifest(sid, manifest)
        return SnapshotEntry(relative, existed)

    def entries(self, sid: str) -> list[SnapshotEntry]:
        files = self._manifest(sid)["files"]
        assert isinstance(files, dict)
        return [SnapshotEntry(rel, ref != _MISSING) for rel, ref in files.items()]

    def original_text(self, sid: str, relative: str) -> str | None:
        files = self._manifest(sid)["files"]
        assert isinstance(files, dict)
        ref = files.get(relative)
        if ref is None or ref == _MISSING:
            return None
        text: str = (self.dir / sid / str(ref)).read_text(encoding="utf-8", errors="replace")
        return text

    def rollback(self, sid: str, relative: str | None = None) -> list[str]:
        """Restore files from the snapshot. Returns the paths restored/removed."""
        manifest = self._manifest(sid)
        files = manifest["files"]
        assert isinstance(files, dict)
        targets = [relative] if relative else list(files)
        restored: list[str] = []
        for rel in targets:
            ref = files.get(rel)
            if ref is None:
                raise KeyError(f"{rel} not in snapshot {sid}")
            dest = self.root / rel
            if ref == _MISSING:
                if dest.exists():
                    dest.unlink()
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(self.dir / sid / ref, dest)
            restored.append(rel)
        return restored

    def list_snapshots(self) -> list[str]:
        return sorted(p.name for p in self.dir.iterdir() if (p / "manifest.json").exists())
