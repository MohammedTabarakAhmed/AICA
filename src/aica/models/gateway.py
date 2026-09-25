"""Model registry and gateway (MM-001, MM-002, MM-003, MM-005..008, MM-011, MM-014).

``config/models.toml`` is the approved-model registry: each entry carries a name, family,
exact version, context limit, declared capabilities and a policy status. The gateway turns an
entry into an adapter, and it is the only place that decides whether a model may be used at
all - the network policy on the provider host (SAFE-005), the approval status (MM-001) and the
enabled flag all apply here, before any request is built.

It never reads a credential itself: an entry names an environment variable and the adapter
reads it (SAFE-006). Adding GLM, Kimi, DeepSeek or a future provider is therefore a
configuration change, which is what MM-008 asks for.

Routing between several approved models, fallback and per-task rules live in
``aica.models.routing``; this module answers "may I use this one, and how".
"""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from aica.admin.controls import ControlPlane, TargetKind
from aica.models.base import Capability, ModelAdapter, ModelError, ModelInfo, ModelStatus
from aica.models.openai_compat import OpenAICompatibleAdapter, OpenAICompatibleConfig
from aica.models.routing import RoutingConfig
from aica.policy.models import NetworkPolicy

DEFAULT_MODELS_PATH = Path("config/models.toml")

# Version strings that mean "whatever is current today". Fine for an unpinned entry, and
# the whole problem for a pinned one: the same configuration would replay differently.
_FLOATING = re.compile(r"(?i)(^|[-_@/.])(latest|newest|stable|current|preview)($|[-_@/.])")


class ModelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    provider: str = Field(default="openai_compatible")
    family: str = Field(min_length=1)
    version: str = Field(min_length=1)
    base_url: str = Field(min_length=1)
    api_key_env: str | None = None
    context_window: int = Field(default=32_000, gt=0)
    capabilities: list[Capability] = Field(
        default_factory=lambda: [Capability.CHAT, Capability.STREAMING]
    )
    embedding_model: str | None = None
    timeout_seconds: float = Field(default=120.0, gt=0)
    enabled: bool = True
    # MM-001: where this model stands with whoever approves models here.
    status: ModelStatus = ModelStatus.APPROVED
    # MM-011: this exact served version, with no substitution by the router.
    pinned: bool = False
    # MM-014: an approved LoRA/domain adapter. Providers serve one under its own model id, so
    # it replaces the request's model field while ``version`` still records the base it sits on.
    adapter: str | None = None
    notes: str = ""

    @model_validator(mode="after")
    def _pin_is_reproducible(self) -> ModelConfig:
        if self.pinned and _FLOATING.search(self.version):
            raise ValueError(
                f"model {self.name!r} is pinned but its version {self.version!r} is a moving "
                "alias; a pin has to name an exact served version to be reproducible (MM-011)"
            )
        if self.adapter and self.status is not ModelStatus.APPROVED:
            raise ValueError(
                f"model {self.name!r} names adapter {self.adapter!r} but its status is "
                f"{self.status.value}; an adapter may only be served for an approved model"
            )
        return self

    @property
    def host(self) -> str:
        return urlparse(self.base_url).hostname or ""

    @property
    def exact_version(self) -> bool:
        """False for a moving alias such as ``latest``, which names different weights over time."""
        return not _FLOATING.search(self.version)

    @property
    def request_model(self) -> str:
        """What goes in the request's ``model`` field: the adapter when one is approved."""
        return self.adapter or self.version

    def info(self) -> ModelInfo:
        return ModelInfo(
            name=self.name,
            family=self.family,
            version=self.version,
            context_window=self.context_window,
            capabilities=list(self.capabilities),
            status=self.status,
            pinned=self.pinned,
            adapter=self.adapter,
        )


class ModelsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default: str | None = None
    models: list[ModelConfig] = Field(default_factory=list)
    routing: RoutingConfig = Field(default_factory=RoutingConfig)

    @model_validator(mode="after")
    def _names_unique_and_references_resolve(self) -> ModelsConfig:
        names = [m.name for m in self.models]
        duplicates = {n for n in names if names.count(n) > 1}
        if duplicates:
            raise ValueError(f"duplicate model name(s): {', '.join(sorted(duplicates))}")
        known = set(names)
        # A rule, fallback or default naming a model that does not exist is worth catching at
        # load time rather than at the moment someone needs a model and finds nothing there.
        referenced: dict[str, str] = {n: "routing.fallbacks" for n in self.routing.fallbacks}
        for rule in self.routing.rules:
            if rule.model:
                referenced[rule.model] = f"the {rule.task.value} routing rule"
            for name in rule.fallbacks:
                referenced.setdefault(name, f"the {rule.task.value} rule's fallbacks")
        if self.default:
            referenced.setdefault(self.default, "default")
        unknown = {n: where for n, where in referenced.items() if n not in known}
        if unknown:
            raise ValueError(
                "unknown model(s) referenced: "
                + "; ".join(f"{n} (in {where})" for n, where in sorted(unknown.items()))
            )
        return self


class ModelDisabled(PermissionError):
    """SEC-007: an administrator switched this model off. Not a configuration error."""


class NetworkDenied(PermissionError):
    pass


class ActiveAdapterSource(Protocol):
    """Where the gateway learns which promoted adapter to serve (BRD 13).

    Implemented by ``aica.adaptation.registry.AdapterRegistry``; declared here so the
    gateway does not import the adaptation package, which itself depends on the gateway.
    """

    def active_for(self, base_model: str) -> ActiveAdapterLike | None: ...


class ActiveAdapterLike(Protocol):
    @property
    def adapter_id(self) -> str: ...
    @property
    def serving_id(self) -> str: ...
    @property
    def base_version(self) -> str: ...


class ModelGateway:
    def __init__(
        self,
        config: ModelsConfig,
        network: NetworkPolicy,
        transport: httpx.BaseTransport | None = None,
        controls: ControlPlane | None = None,
        adapters: ActiveAdapterSource | None = None,
    ) -> None:
        self._config = config
        self._network = network
        self._transport = transport
        self._controls = controls  # SEC-007; None = no control plane wired up
        self._adapters = adapters  # BRD 13; None = no promoted adapters are applied
        self._cache: dict[str, ModelAdapter] = {}

    @classmethod
    def from_file(
        cls,
        network: NetworkPolicy,
        path: str | os.PathLike[str] | None = None,
        transport: httpx.BaseTransport | None = None,
        controls: ControlPlane | None = None,
        adapters: ActiveAdapterSource | None = None,
    ) -> ModelGateway:
        candidate = (
            Path(path)
            if path
            else Path(os.environ.get("AICA_MODELS_FILE", str(DEFAULT_MODELS_PATH)))
        )
        if not candidate.exists():
            return cls(ModelsConfig(), network, transport, controls, adapters)
        try:
            with candidate.open("rb") as fh:
                data = tomllib.load(fh)
            return cls(ModelsConfig.model_validate(data), network, transport, controls, adapters)
        except (tomllib.TOMLDecodeError, ValidationError) as exc:
            raise ModelError(f"invalid models file {candidate}: {exc}") from exc

    @property
    def routing(self) -> RoutingConfig:
        return self._config.routing

    def list_models(self, *, include_unusable: bool = False) -> list[ModelInfo]:
        """MM-001/MM-013: the registry as a user sees it."""
        return [
            m.info()
            for m in self._config.models
            if include_unusable or (m.enabled and m.status.usable)
        ]

    def default_name(self) -> str | None:
        """MM-003: the project default, or the first usable entry when none is set."""
        if self._config.default:
            return self._config.default
        usable = [m for m in self._config.models if m.enabled and m.status.usable]
        return usable[0].name if usable else None

    def config_for(self, name: str | None = None) -> ModelConfig:
        target = name or self.default_name()
        if not target:
            raise ModelError("no models configured (config/models.toml)")
        for m in self._config.models:
            if m.name == target:
                if not m.enabled:
                    raise ModelError(f"model {target!r} is disabled by configuration")
                if not m.status.usable:
                    # MM-001: approval status is a gate, not a label.
                    raise ModelError(
                        f"model {target!r} has status {m.status.value} and may not be used"
                        + (f" ({m.notes})" if m.notes else "")
                    )
                return m
        raise ModelError(
            f"unknown model {target!r}; configured: "
            + (", ".join(m.name for m in self._config.models) or "none")
        )

    def get(self, name: str | None = None) -> ModelAdapter:
        cfg = self.config_for(name)
        # SEC-007 / ADM-003. Checked before the cache on purpose: a model already built
        # for this process must stop being served the moment it is disabled, or
        # "immediately" would mean "after the next restart" for every long-running server.
        if self._controls is not None:
            disabled = self._controls.is_disabled(TargetKind.MODEL, cfg.name, cfg.family)
            if disabled is not None:
                raise ModelDisabled(disabled.describe())
        cfg = self._with_promoted_adapter(cfg)
        # Keyed by adapter too: a promotion or rollback must change what is served on the
        # next call, not whenever this process happens to restart.
        key = f"{cfg.name}+{cfg.adapter}" if cfg.adapter else cfg.name
        if key in self._cache:
            return self._cache[key]
        if not self._network.is_host_allowed(cfg.host):
            raise NetworkDenied(
                f"model endpoint host {cfg.host!r} is not allowed by network policy; "
                "add it to [network].allowed_hosts"
            )
        if cfg.provider != "openai_compatible":
            raise ModelError(f"unsupported provider {cfg.provider!r}")
        adapter = OpenAICompatibleAdapter(
            OpenAICompatibleConfig(
                base_url=cfg.base_url,
                model=cfg.request_model,
                api_key_env=cfg.api_key_env,
                timeout_seconds=cfg.timeout_seconds,
                embedding_model=cfg.embedding_model,
            ),
            cfg.info(),
            transport=self._transport,
        )
        self._cache[key] = adapter
        return adapter

    def effective_config(self, name: str | None = None) -> ModelConfig:
        """The entry as it would be served now, promoted adapter included (MM-012)."""
        return self._with_promoted_adapter(self.config_for(name))

    def _with_promoted_adapter(self, cfg: ModelConfig) -> ModelConfig:
        """Apply the adapter promoted for this model, re-read on every call (BRD 13)."""
        if self._adapters is None:
            return cfg
        active = self._adapters.active_for(cfg.name)
        if active is None:
            return cfg
        if active.base_version != cfg.version:
            # An adapter on weights it was not trained on is a different, unevaluated model.
            raise ModelError(
                f"adapter {active.adapter_id} was trained on {cfg.name} version "
                f"{active.base_version}, but the registry now serves {cfg.version}; roll it "
                "back or evaluate and promote an adapter for the new version"
            )
        if cfg.status is not ModelStatus.APPROVED:
            raise ModelError(
                f"adapter {active.adapter_id} is promoted for {cfg.name}, whose status is "
                f"{cfg.status.value}; an adapter may only be served for an approved model"
            )
        return cfg.model_copy(update={"adapter": active.serving_id})

    def register(self, name: str, adapter: ModelAdapter) -> None:
        """Inject a pre-built adapter (tests, fakes, future in-process providers)."""
        self._cache[name] = adapter
        if not any(m.name == name for m in self._config.models):
            info = adapter.info
            self._config.models.append(
                ModelConfig(
                    name=name,
                    provider="inprocess",
                    family=info.family,
                    version=info.version,
                    base_url="inprocess://local",
                    context_window=info.context_window,
                    capabilities=list(info.capabilities),
                )
            )
