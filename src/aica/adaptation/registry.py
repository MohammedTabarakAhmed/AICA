"""Adapters: registered, evaluated, promoted, rolled back (BRD 13, MM-014).

Base models live in ``config/models.toml`` and are administered there (MM-001). Adapters
live here, separately, each pinned to the exact base model version it was trained on and
traceable to the dataset and configuration that produced it. The lifecycle:

``registered`` -> ``gate_passed`` / ``gate_failed`` -> ``promoted`` -> ``superseded`` or
``rolled_back``

* **Register** records an adapter a trainer produced: its job spec, dataset and base
  version, the digest of its files, and the id the serving endpoint exposes it under.
* **Evaluate** takes a golden-suite report (``aica eval run --out``) and applies two gates.
  The *quality* gate is EVAL-008's release gate, optionally against a baseline. The
  *security* gate is separate and stricter: the suite must contain security-tagged tasks
  and the adapter must pass every one - an adapter that is better on average and worse on
  security is not a candidate. The report must be *of this adapter* (its provenance names
  the base, the base version and the serving id), must come from a real model, and the
  dataset must still verify.
* **Promote** needs ``approve``, a passed gate, and - with RBAC on - a different principal
  from the one who registered it (SEC-006). It makes the gateway serve the adapter.
* **Roll back** returns the model to the previously promoted adapter, or to the bare base
  model when there was none. It is the incident tool and takes effect on the next call.

The gateway re-reads the active adapter on every call (``ActiveAdapters``), and refuses to
apply one whose base version no longer matches the registry: an adapter on the wrong
weights is a different, unevaluated model.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from aica.adaptation.curation import (
    AdaptationError,
    _atomic_write,
    _now,
    _read_json,
    adaptation_dir,
    verify_dataset,
)
from aica.adaptation.training import load_job
from aica.admin.rbac import Permission, Principal
from aica.evaluation.gates import GateError, ReleaseGate, evaluate_gate
from aica.evaluation.metrics import SuiteReport

REGISTRY_FILE = "adapters.json"
ACTIVE_FILE = "active.json"
SECURITY_TAG = "security"

_LOCK = threading.RLock()


class AdapterStatus(StrEnum):
    REGISTERED = "registered"
    GATE_PASSED = "gate_passed"
    GATE_FAILED = "gate_failed"
    PROMOTED = "promoted"
    SUPERSEDED = "superseded"
    ROLLED_BACK = "rolled_back"


def artifact_digest(directory: str | Path) -> str:
    """A digest over every file's relative path and bytes, in a stable order."""
    base = Path(directory)
    if not base.is_dir():
        raise AdaptationError(f"adapter artifact {base} is not a directory")
    files = sorted(p for p in base.rglob("*") if p.is_file())
    if not files:
        raise AdaptationError(f"adapter artifact {base} is empty")
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.relative_to(base).as_posix().encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def security_gate(report: SuiteReport) -> list[str]:
    """Failures of the security gate. Empty means passed."""
    security = [r for r in report.results if SECURITY_TAG in r.tags]
    if not security:
        return [f"the suite has no '{SECURITY_TAG}'-tagged tasks, so security was never measured"]
    failures = [r.task for r in security if not r.as_expected]
    out = [f"security task(s) failed: {', '.join(failures)}"] if failures else []
    if report.false_successes:
        out.append("the adapter claimed success it did not achieve on at least one task")
    return out


@dataclass(frozen=True)
class ActiveAdapter:
    adapter_id: str
    serving_id: str
    base_model: str
    base_version: str


class CandidateSource:
    """Serve one registered, not-yet-promoted adapter - for evaluating it (BRD 13).

    Every other model resolves as usual. This is how a candidate gets a golden-suite report
    of its own before anyone is asked to promote it.
    """

    def __init__(self, registry: AdapterRegistry, adapter_id: str) -> None:
        self._registry = registry
        record = registry.get(adapter_id)
        self.base_model: str = record["base_model"]
        self._candidate = ActiveAdapter(
            adapter_id=adapter_id,
            serving_id=record["serving_id"],
            base_model=record["base_model"],
            base_version=record["base_version"],
        )

    def active_for(self, base_model: str) -> ActiveAdapter | None:
        if base_model == self.base_model:
            return self._candidate
        return self._registry.active_for(base_model)


class AdapterRegistry:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.path = adaptation_dir(self.root) / REGISTRY_FILE
        self.active_path = adaptation_dir(self.root) / ACTIVE_FILE

    # ------------------------------------------------------------------ storage
    def all(self) -> list[dict[str, Any]]:
        return list(_read_json(self.path, {"adapters": []}).get("adapters", []))

    def get(self, adapter_id: str) -> dict[str, Any]:
        for record in self.all():
            if record["id"] == adapter_id:
                return record
        raise AdaptationError(f"no adapter {adapter_id!r}")

    def _save(self, adapters: list[dict[str, Any]]) -> None:
        _atomic_write(self.path, {"version": 1, "adapters": adapters})

    def _active(self) -> dict[str, Any]:
        data = _read_json(self.active_path, {"active": {}, "history": {}})
        data.setdefault("active", {})
        data.setdefault("history", {})
        return dict(data)

    @staticmethod
    def _event(record: dict[str, Any], actor: str, event: str, **detail: Any) -> None:
        record.setdefault("history", []).append(
            {"at": _now(), "actor": actor, "event": event, **detail}
        )

    # ------------------------------------------------------------------ register
    def register(
        self, config_version: str, serving_id: str, artifact: str | Path, principal: Principal
    ) -> dict[str, Any]:
        principal.require(Permission.ADMINISTER, "register an adapter")
        job = load_job(self.root, config_version)
        if job.get("produces") != "adapter":
            raise AdaptationError(
                "this job produces a new base model, not an adapter; register it in "
                "config/models.toml as a base model instead (BRD 13: keep them separate)"
            )
        verify_dataset(self.root, job["dataset"]["version"])
        digest = artifact_digest(artifact)
        with _LOCK:
            adapters = self.all()
            if any(a["artifact_sha256"] == digest for a in adapters):
                raise AdaptationError("these adapter files are already registered")
            name = job["config"]["name"]
            number = 1 + sum(1 for a in adapters if a["name"] == name)
            record: dict[str, Any] = {
                "id": f"{name}@{number}",
                "name": name,
                "number": number,
                "serving_id": serving_id,
                "base_model": job["base_model"]["name"],
                "base_version": job["base_model"]["version"],
                "dataset_version": job["dataset"]["version"],
                "config_version": config_version,
                "method": job["config"]["method"],
                "artifact_sha256": digest,
                "status": AdapterStatus.REGISTERED.value,
                "registered_by": principal.name,
                "registered_at": _now(),
                "evaluation": None,
                "history": [],
            }
            self._event(record, principal.name, "registered", artifact=str(artifact))
            adapters.append(record)
            self._save(adapters)
        return record

    # ------------------------------------------------------------------ evaluate
    def evaluate(
        self,
        adapter_id: str,
        candidate: str | Path,
        principal: Principal,
        baseline: str | Path | None = None,
        gate: ReleaseGate | None = None,
    ) -> dict[str, Any]:
        """Apply the quality and security gates to a report of this adapter."""
        principal.require(Permission.ADMINISTER, "record an adapter evaluation")
        with _LOCK:
            adapters = self.all()
            record = next((a for a in adapters if a["id"] == adapter_id), None)
            if record is None:
                raise AdaptationError(f"no adapter {adapter_id!r}")
            if record["status"] not in (
                AdapterStatus.REGISTERED.value,
                AdapterStatus.GATE_FAILED.value,
            ):
                raise AdaptationError(f"{adapter_id} is {record['status']}; it was already gated")
            report_bytes = Path(candidate).read_bytes()
            report = SuiteReport.load(candidate)
            p = report.provenance
            if p.model == "scripted":
                raise AdaptationError(
                    "the report came from the scripted adapter; it measures the harness, not "
                    "this adapter, and cannot be evidence for promoting it"
                )
            if (p.model, p.model_version, p.adapter) != (
                record["base_model"],
                record["base_version"],
                record["serving_id"],
            ):
                raise AdaptationError(
                    f"the report is of {p.label()}, not of {record['base_model']}@"
                    f"{record['base_version']}+{record['serving_id']}"
                )
            verify_dataset(self.root, record["dataset_version"])
            try:
                quality = evaluate_gate(
                    report, gate, SuiteReport.load(baseline) if baseline else None
                )
            except GateError as exc:
                raise AdaptationError(f"the quality gate could not be evaluated: {exc}") from exc
            security = security_gate(report)
            passed = quality.passed and not security
            record["evaluation"] = {
                "report": str(candidate),
                "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
                "baseline": str(baseline) if baseline else None,
                "suite": p.suite,
                "suite_checksum": p.suite_checksum,
                "quality_failures": quality.failures,
                "quality_notes": quality.notes,
                "security_failures": security,
                "passed": passed,
                "evaluated_by": principal.name,
                "evaluated_at": _now(),
            }
            record["status"] = (
                AdapterStatus.GATE_PASSED if passed else AdapterStatus.GATE_FAILED
            ).value
            self._event(record, principal.name, record["status"])
            self._save(adapters)
        return record

    # ------------------------------------------------------------------ promote / roll back
    def promote(
        self, adapter_id: str, principal: Principal, current_base_version: str
    ) -> dict[str, Any]:
        """Serve this adapter for its base model from the next call on."""
        principal.require(Permission.APPROVE, f"promote adapter {adapter_id!r}")
        with _LOCK:
            adapters = self.all()
            record = next((a for a in adapters if a["id"] == adapter_id), None)
            if record is None:
                raise AdaptationError(f"no adapter {adapter_id!r}")
            if record["status"] != AdapterStatus.GATE_PASSED.value:
                raise AdaptationError(
                    f"{adapter_id} is {record['status']}; only an adapter that passed both "
                    "gates may be promoted"
                )
            principal.require_distinct_from(record["registered_by"], "adapter")
            if current_base_version != record["base_version"]:
                raise AdaptationError(
                    f"{record['base_model']} is now at version {current_base_version}, but "
                    f"{adapter_id} was trained and evaluated on {record['base_version']}"
                )
            verify_dataset(self.root, record["dataset_version"])
            active = self._active()
            base = record["base_model"]
            previous = active["active"].get(base)
            for other in adapters:
                if other["id"] == previous:
                    other["status"] = AdapterStatus.SUPERSEDED.value
                    self._event(other, principal.name, "superseded", by=adapter_id)
            active["active"][base] = adapter_id
            active["history"].setdefault(base, []).append(adapter_id)
            record["status"] = AdapterStatus.PROMOTED.value
            self._event(record, principal.name, "promoted", replaced=previous)
            self._save(adapters)
            _atomic_write(self.active_path, active)
        return record

    def rollback(self, base_model: str, principal: Principal) -> str | None:
        """Return ``base_model`` to its previous adapter, or to no adapter. Returns the new one."""
        principal.require(Permission.APPROVE, f"roll back the adapter of {base_model!r}")
        with _LOCK:
            adapters = self.all()
            active = self._active()
            current = active["active"].get(base_model)
            if current is None:
                raise AdaptationError(f"{base_model} has no promoted adapter to roll back")
            history: list[str] = active["history"].get(base_model, [])
            if history and history[-1] == current:
                history.pop()
            restored = history[-1] if history else None
            for record in adapters:
                if record["id"] == current:
                    record["status"] = AdapterStatus.ROLLED_BACK.value
                    self._event(record, principal.name, "rolled_back", restored=restored)
                elif record["id"] == restored:
                    record["status"] = AdapterStatus.PROMOTED.value
                    self._event(record, principal.name, "restored", replaced=current)
            if restored is None:
                active["active"].pop(base_model, None)
            else:
                active["active"][base_model] = restored
            active["history"][base_model] = history
            self._save(adapters)
            _atomic_write(self.active_path, active)
        return restored

    def active_for(self, base_model: str) -> ActiveAdapter | None:
        adapter_id = self._active()["active"].get(base_model)
        if adapter_id is None:
            return None
        record = self.get(adapter_id)
        return ActiveAdapter(
            adapter_id=adapter_id,
            serving_id=record["serving_id"],
            base_model=record["base_model"],
            base_version=record["base_version"],
        )
