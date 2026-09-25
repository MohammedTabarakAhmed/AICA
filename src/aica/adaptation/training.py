"""Training configurations and job specifications: SFT and QLoRA-style adapters (BRD 13).

Training runs on GPU infrastructure, which is outside this product's scope (the BRD keeps
sizing and topology in a separate infrastructure document) and absent from a developer
machine. What belongs here is everything that decides *whether* and *what* to train:

* the configuration is validated against the model registry - the base model must exist,
  be ``approved`` (MM-001) and have an exact version, because an adapter is only valid for
  the precise weights it was trained on;
* the dataset must verify (its examples match its manifest) and be large enough to be
  worth training on (``min_training_examples``) - "where technically appropriate";
* full-weight fine-tuning is refused unless policy allows it, because it produces a new
  base model rather than an adapter and the BRD asks for the two to be kept separate;
* the configuration is content-addressed, so a job spec names exactly one dataset, one
  base model version and one set of hyperparameters, and the adapter it produces can be
  traced back to all three.

The output is a job spec for whatever trainer the organisation runs. Nothing here trains.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aica.adaptation.curation import (
    AdaptationError,
    _atomic_write,
    _read_json,
    adaptation_dir,
    datasets_dir,
    verify_dataset,
)
from aica.admin.rbac import Permission, Principal
from aica.models.base import ModelError
from aica.models.gateway import ModelGateway
from aica.policy.models import Policy


class Method(StrEnum):
    LORA = "lora"  # a low-rank adapter on full-precision base weights
    QLORA = "qlora"  # a low-rank adapter trained against a 4-bit quantised base
    FULL = "full"  # full-weight supervised fine-tuning: a new base model, not an adapter


class TrainingConfig(BaseModel):
    """Hyperparameters and inputs for one supervised fine-tuning run."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    base_model: str = Field(min_length=1, max_length=100)  # a name in config/models.toml
    dataset: str = Field(min_length=1, max_length=64)  # a dataset version
    method: Method = Method.QLORA
    epochs: int = Field(default=3, ge=1, le=100)
    learning_rate: float = Field(default=2e-4, gt=0, le=1)
    max_seq_length: int = Field(default=4096, ge=128, le=1_048_576)
    seed: int = 42
    # Adapter shape (ignored for FULL).
    lora_rank: int = Field(default=16, ge=1, le=1024)
    lora_alpha: int = Field(default=32, ge=1, le=4096)
    lora_dropout: float = Field(default=0.05, ge=0, lt=1)
    target_modules: list[str] = Field(
        default_factory=lambda: ["q_proj", "k_proj", "v_proj", "o_proj"]
    )
    quantization_bits: int | None = None

    @model_validator(mode="after")
    def _coherent(self) -> TrainingConfig:
        if self.method is Method.QLORA:
            if self.quantization_bits is None:
                self.quantization_bits = 4
            if self.quantization_bits != 4:
                raise ValueError("QLoRA trains against a 4-bit base; quantization_bits must be 4")
        elif self.quantization_bits is not None:
            raise ValueError(f"quantization_bits applies only to qlora, not {self.method.value}")
        if self.method is not Method.FULL and not self.target_modules:
            raise ValueError("an adapter needs at least one target module")
        return self

    @property
    def is_adapter(self) -> bool:
        return self.method is not Method.FULL

    def version(self) -> str:
        canonical = json.dumps(self.model_dump(mode="json"), sort_keys=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def jobs_dir(root: str | Path) -> Path:
    return adaptation_dir(root) / "jobs"


def plan_training(
    root: str | Path,
    config: TrainingConfig,
    policy: Policy,
    gateway: ModelGateway,
    principal: Principal,
) -> dict[str, Any]:
    """Validate a configuration and write its job spec. Returns the spec."""
    principal.require(Permission.ADMINISTER, "plan a training run")
    if config.method is Method.FULL and not policy.adaptation.allow_full_finetune:
        raise AdaptationError(
            "full fine-tuning produces a new base model, not an adapter; it is refused unless "
            "[adaptation] allow_full_finetune = true (BRD 13: keep base models and adapters "
            "separate)"
        )
    try:
        base = gateway.config_for(config.base_model)
    except ModelError as exc:
        raise AdaptationError(f"base model refused: {exc}") from exc
    if not base.exact_version:
        raise AdaptationError(
            f"base model {base.name!r} has the moving version {base.version!r}; an adapter is "
            "only valid for the exact weights it was trained on (MM-013)"
        )
    manifest = verify_dataset(root, config.dataset)
    minimum = policy.adaptation.min_training_examples
    if manifest.examples < minimum:
        raise AdaptationError(
            f"dataset {manifest.version} has {manifest.examples} example(s); at least "
            f"{minimum} are required before training is worthwhile "
            "([adaptation] min_training_examples)"
        )
    version = config.version()
    spec = {
        "job": f"{config.name}-{version}",
        "config_version": version,
        "config": config.model_dump(mode="json"),
        "base_model": {"name": base.name, "family": base.family, "version": base.version},
        "dataset": {
            "version": manifest.version,
            "sha256": manifest.sha256,
            "examples": manifest.examples,
            "format": manifest.format,
            "path": str(datasets_dir(root) / manifest.version / "train.jsonl"),
        },
        "produces": "adapter" if config.is_adapter else "base-model",
        "planned_by": principal.name,
        "policy_checksum": policy.checksum(),
    }
    target = jobs_dir(root) / f"{version}.json"
    if target.exists():
        existing = _read_json(target, {})
        if existing.get("config") != spec["config"]:  # pragma: no cover - a hash collision
            raise AdaptationError(f"job spec {target} exists with a different configuration")
        return dict(existing)
    _atomic_write(target, spec)
    return spec


def load_job(root: str | Path, config_version: str) -> dict[str, Any]:
    path = jobs_dir(root) / f"{config_version}.json"
    if not path.is_file():
        raise AdaptationError(f"no training job spec {config_version!r}")
    return dict(_read_json(path, {}))
