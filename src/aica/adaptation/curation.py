"""Approved collection and versioned datasets (BRD 13).

The path from an agent run to a training example has three gates, each of which can only
narrow:

1. **Collection** needs ``[adaptation] collection_enabled`` and the ``administer``
   permission. Every run found is screened; one that fails the screen is recorded as
   *excluded* with its reasons and can never be approved - safety is not overridable by a
   reviewer, only by changing the run.
2. **Approval** is per trajectory, by a principal with ``approve``, and - with RBAC on - not
   by the developer whose run it was (the SEC-006 rule): a person is not the only judge of
   whether their own work becomes training data. Decisions are final.
3. **Dataset build** re-screens every approved trajectory against the policy *as it is
   now*, so tightening the exclusion list after approval still takes effect.

A dataset is content-addressed: its version is a digest of its examples and format, it is
written once and never modified, and ``verify_dataset`` recomputes the digest so a dataset
edited on disk is detected before anything trains on it or promotes from it.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from aica.adaptation.trajectories import Trajectory, extract, screen
from aica.admin.rbac import Permission, Principal
from aica.agent.plan import FILL_SYSTEM, PLANNER_SYSTEM
from aica.policy.models import Policy

ADAPTATION_DIR = Path(".aica") / "adaptation"
CANDIDATES_FILE = "candidates.json"
DATASET_FORMAT = "chat-sft-v2"

_LOCK = threading.RLock()


class AdaptationError(RuntimeError):
    """A BRD 13 step was refused or could not be completed."""


class CandidateState(StrEnum):
    EXCLUDED = "excluded"  # failed the screen; can never be approved
    PENDING = "pending"
    APPROVED = "approved"
    DECLINED = "declined"


def adaptation_dir(root: str | Path) -> Path:
    return Path(root).resolve() / ADAPTATION_DIR


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _atomic_write(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=1, ensure_ascii=False)
        os.replace(temp, path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        # Never read a damaged record as "nothing collected": that would let a rebuild
        # quietly drop every approval and every exclusion.
        raise AdaptationError(f"{path} could not be read: {exc}") from exc


# ------------------------------------------------------------------ candidates
class CandidateStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.path = adaptation_dir(self.root) / CANDIDATES_FILE

    def all(self) -> list[dict[str, Any]]:
        data = _read_json(self.path, {"candidates": []})
        return list(data.get("candidates", []))

    def _write(self, candidates: list[dict[str, Any]]) -> None:
        _atomic_write(self.path, {"version": 1, "candidates": candidates})

    def collect(self, policy: Policy, principal: Principal) -> dict[str, int]:
        """Screen every persisted agent run and record it as pending or excluded."""
        if not policy.adaptation.collection_enabled:
            raise AdaptationError(
                "trajectory collection is off; set [adaptation] collection_enabled = true "
                "in the policy file to allow it (BRD 13)"
            )
        principal.require(Permission.ADMINISTER, "collect training data")
        trajectories, unreadable = extract(self.root)
        with _LOCK:
            candidates = self.all()
            known = {c["id"] for c in candidates}
            added = excluded = 0
            for trajectory in trajectories:
                if trajectory.id in known:
                    continue
                verdict = screen(trajectory, policy.adaptation)
                state = CandidateState.PENDING if verdict.eligible else CandidateState.EXCLUDED
                candidates.append(
                    {
                        "id": trajectory.id,
                        "state": state.value,
                        "reasons": verdict.reasons,
                        "trajectory": trajectory.to_json(),
                        "collected_at": _now(),
                        "collected_by": principal.name,
                        "decided_by": None,
                        "decided_at": None,
                        "note": "",
                    }
                )
                known.add(trajectory.id)
                added += 1
                excluded += state is CandidateState.EXCLUDED
            self._write(candidates)
        return {
            "found": len(trajectories),
            "new": added,
            "excluded": excluded,
            "pending": added - excluded,
            "unreadable": len(unreadable),
        }

    def decide(
        self, candidate_id: str, principal: Principal, approve: bool, note: str = ""
    ) -> dict[str, Any]:
        principal.require(Permission.APPROVE, f"decide training candidate {candidate_id!r}")
        with _LOCK:
            candidates = self.all()
            target = next((c for c in candidates if c["id"] == candidate_id), None)
            if target is None:
                raise AdaptationError(f"no training candidate {candidate_id!r}")
            if target["state"] == CandidateState.EXCLUDED.value:
                raise AdaptationError(
                    f"{candidate_id} was excluded by the screen ("
                    + "; ".join(target["reasons"])
                    + "); an excluded run cannot be approved"
                )
            if target["state"] != CandidateState.PENDING.value:
                raise AdaptationError(
                    f"{candidate_id} is already {target['state']}; a decision is final"
                )
            owner = target["trajectory"].get("owner") or ""
            principal.require_distinct_from(owner, "training candidate")
            target["state"] = (
                CandidateState.APPROVED if approve else CandidateState.DECLINED
            ).value
            target["decided_by"] = principal.name
            target["decided_at"] = _now()
            target["note"] = note
            self._write(candidates)
            return target


# ------------------------------------------------------------------ datasets
@dataclass(frozen=True)
class DatasetManifest:
    version: str
    format: str
    examples: int
    trajectory_ids: list[str]
    excluded_at_build: dict[str, list[str]]
    exclude_paths: list[str]
    policy_checksum: str
    sha256: str
    created_at: str
    created_by: str

    def to_json(self) -> dict[str, Any]:
        return dict(self.__dict__)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> DatasetManifest:
        return cls(**data)


def examples_for(trajectory: Trajectory) -> list[dict[str, Any]]:
    """SFT examples in chat format, each exactly as the model was asked at the time.

    The first is the plan: the planner's prompt and the task, answered with the plan, where
    a deferred step shows only the arguments the plan gave. Each deferred step then adds one
    example: the request made once earlier steps had run, answered with the arguments that
    worked. A model trained on these learns to read before it writes, never to write content
    it has not seen.
    """
    steps: list[dict[str, Any]] = []
    for s in trajectory.steps:
        if s.deferred:
            steps.append(
                {
                    "intent": s.intent,
                    "tool": s.tool,
                    "arguments": s.planned_arguments,
                    "deferred": True,
                }
            )
        else:
            steps.append({"intent": s.intent, "tool": s.tool, "arguments": s.arguments})
    plan = {
        "summary": trajectory.summary,
        "steps": steps,
        "verification": sorted(trajectory.verification),
    }
    meta = {"trajectory": trajectory.id, "source_model": trajectory.model}
    examples: list[dict[str, Any]] = [
        {
            "messages": [
                {"role": "system", "content": PLANNER_SYSTEM},
                {"role": "user", "content": f"Task: {trajectory.task}"},
                {"role": "assistant", "content": json.dumps(plan, ensure_ascii=False)},
            ],
            "meta": {**meta, "kind": "plan"},
        }
    ]
    for s in trajectory.steps:
        if s.deferred and s.fill_prompt:
            examples.append(
                {
                    "messages": [
                        {"role": "system", "content": FILL_SYSTEM},
                        {"role": "user", "content": s.fill_prompt},
                        {
                            "role": "assistant",
                            "content": json.dumps({"arguments": s.arguments}, ensure_ascii=False),
                        },
                    ],
                    "meta": {**meta, "kind": "fill"},
                }
            )
    return examples


def datasets_dir(root: str | Path) -> Path:
    return adaptation_dir(root) / "datasets"


def build_dataset(root: str | Path, policy: Policy, principal: Principal) -> DatasetManifest:
    """Write a new immutable dataset from the approved candidates, re-screened now."""
    principal.require(Permission.ADMINISTER, "build a training dataset")
    approved = [
        c for c in CandidateStore(root).all() if c["state"] == CandidateState.APPROVED.value
    ]
    if not approved:
        raise AdaptationError("no approved training candidates to build a dataset from")
    lines: list[str] = []
    ids: list[str] = []
    dropped: dict[str, list[str]] = {}
    for candidate in sorted(approved, key=lambda c: c["id"]):
        trajectory = Trajectory.from_json(candidate["trajectory"])
        verdict = screen(trajectory, policy.adaptation)
        if not verdict.eligible:
            dropped[trajectory.id] = verdict.reasons
            continue
        lines += [
            json.dumps(example, sort_keys=True, ensure_ascii=False)
            for example in examples_for(trajectory)
        ]
        ids.append(trajectory.id)
    if not lines:
        raise AdaptationError(
            "every approved candidate fails the current screen: "
            + json.dumps(dropped, ensure_ascii=False)
        )
    body = "\n".join(lines) + "\n"
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    version = hashlib.sha256(f"{DATASET_FORMAT}\n{digest}".encode()).hexdigest()[:16]
    target = datasets_dir(root) / version
    if target.exists():
        # Same examples, same format: the same dataset. Verified, never rewritten.
        return verify_dataset(root, version)
    manifest = DatasetManifest(
        version=version,
        format=DATASET_FORMAT,
        examples=len(lines),
        trajectory_ids=ids,
        excluded_at_build=dropped,
        exclude_paths=list(policy.adaptation.exclude_paths),
        policy_checksum=policy.checksum(),
        sha256=digest,
        created_at=_now(),
        created_by=principal.name,
    )
    # Written into a staging directory and renamed into place, so a dataset directory either
    # exists complete or not at all.
    datasets_dir(root).mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(dir=datasets_dir(root), prefix=".staging-"))
    try:
        (staging / "train.jsonl").write_text(body, encoding="utf-8", newline="\n")
        (staging / "manifest.json").write_text(
            json.dumps(manifest.to_json(), indent=1, ensure_ascii=False), encoding="utf-8"
        )
        os.replace(staging, target)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return manifest


def verify_dataset(root: str | Path, version: str) -> DatasetManifest:
    """Load a dataset's manifest and prove its examples are the ones it was built with."""
    target = datasets_dir(root) / version
    manifest_path = target / "manifest.json"
    if not manifest_path.is_file():
        raise AdaptationError(f"no dataset {version!r}")
    manifest = DatasetManifest.from_json(_read_json(manifest_path, {}))
    try:
        body = (target / "train.jsonl").read_bytes()
    except OSError as exc:
        raise AdaptationError(f"dataset {version} has no readable train.jsonl: {exc}") from exc
    if hashlib.sha256(body).hexdigest() != manifest.sha256:
        raise AdaptationError(
            f"dataset {version} was modified after it was built; its examples no longer "
            "match the manifest, so nothing may train on or promote from it"
        )
    return manifest


def list_datasets(root: str | Path) -> list[DatasetManifest]:
    base = datasets_dir(root)
    if not base.is_dir():
        return []
    out: list[DatasetManifest] = []
    for entry in sorted(base.iterdir()):
        if entry.name.startswith("."):
            continue  # an interrupted build's staging directory, never a dataset
        manifest = entry / "manifest.json"
        if manifest.is_file():
            out.append(DatasetManifest.from_json(_read_json(manifest, {})))
    return sorted(out, key=lambda m: m.created_at, reverse=True)
