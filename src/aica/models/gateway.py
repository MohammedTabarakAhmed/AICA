"""Model gateway: configuration-driven adapter construction.

Phase 1 scope is "one model" (BRD section 19 MVP). The configuration is already a list so
Release 1 (MM-001 registry, MM-002 selection, MM-005..007 families) extends it rather than
replacing it. The gateway enforces the network policy on the provider host (SAFE-005) and
never reads credentials itself — adapters pull them from the named environment variable.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aica.models.base import Capability, ModelAdapter, ModelError, ModelInfo
from aica.models.openai_compat import OpenAICompatibleAdapter, OpenAICompatibleConfig
from aica.policy.models import NetworkPolicy

DEFAULT_MODELS_PATH = Path("config/models.toml")


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

    @property
    def host(self) -> str:
        return urlparse(self.base_url).hostname or ""

    def info(self) -> ModelInfo:
        return ModelInfo(
            name=self.name,
            family=self.family,
            version=self.version,
            context_window=self.context_window,
            capabilities=list(self.capabilities),
        )


class ModelsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default: str | None = None
    models: list[ModelConfig] = Field(default_factory=list)


class NetworkDenied(PermissionError):
    pass


class ModelGateway:
    def __init__(
        self,
        config: ModelsConfig,
        network: NetworkPolicy,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._config = config
        self._network = network
        self._transport = transport
        self._cache: dict[str, ModelAdapter] = {}

    @classmethod
    def from_file(
        cls,
        network: NetworkPolicy,
        path: str | os.PathLike[str] | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> ModelGateway:
        candidate = (
            Path(path)
            if path
            else Path(os.environ.get("AICA_MODELS_FILE", str(DEFAULT_MODELS_PATH)))
        )
        if not candidate.exists():
            return cls(ModelsConfig(), network, transport)
        try:
            with candidate.open("rb") as fh:
                data = tomllib.load(fh)
            return cls(ModelsConfig.model_validate(data), network, transport)
        except (tomllib.TOMLDecodeError, ValidationError) as exc:
            raise ModelError(f"invalid models file {candidate}: {exc}") from exc

    def list_models(self) -> list[ModelInfo]:
        return [m.info() for m in self._config.models if m.enabled]

    def default_name(self) -> str | None:
        if self._config.default:
            return self._config.default
        enabled = [m for m in self._config.models if m.enabled]
        return enabled[0].name if enabled else None

    def config_for(self, name: str | None = None) -> ModelConfig:
        target = name or self.default_name()
        if not target:
            raise ModelError("no models configured (config/models.toml)")
        for m in self._config.models:
            if m.name == target:
                if not m.enabled:
                    raise ModelError(f"model {target!r} is disabled by configuration")
                return m
        raise ModelError(f"unknown model {target!r}")

    def get(self, name: str | None = None) -> ModelAdapter:
        cfg = self.config_for(name)
        if cfg.name in self._cache:
            return self._cache[cfg.name]
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
                model=cfg.version,
                api_key_env=cfg.api_key_env,
                timeout_seconds=cfg.timeout_seconds,
                embedding_model=cfg.embedding_model,
            ),
            cfg.info(),
            transport=self._transport,
        )
        self._cache[cfg.name] = adapter
        return adapter

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
