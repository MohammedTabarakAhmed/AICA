"""Approved repository connectors (INT-006).

The BRD asks for "Git-based enterprise repositories ... through approved connectors". The
shape follows the approved database connections (DB-001), for the same reasons:

* **A connector is selected by name.** A tool call can never supply a repository URL or a
  token, so a model cannot point the agent at a repository nobody approved.
* **A connector says what it permits** - ``read``, ``pull_request``, ``comment`` - so a
  read-only connector cannot open a pull request however the call is phrased.
* **Credentials are a SEC-004 secret name**, never a value. The token is read from the host
  environment at the moment of use, behind an audited SECRET_ACCESS approval.
* **The API host must pass the network policy** (SAFE-005), so approving a connector takes
  two deliberate edits, as approving a model does.

GitHub is the first provider. The provider is a field, so GitLab or Bitbucket are an added
client, not a change to the tools.
"""

from __future__ import annotations

import os
import tomllib
from enum import StrEnum
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

DEFAULT_REPOSITORIES_PATH = Path("config/repositories.toml")
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class RepositoryError(RuntimeError):
    """A connector is missing, disabled or misconfigured, or the provider refused a call."""


class ConnectorPermission(StrEnum):
    READ = "read"  # repository metadata, pull requests, issues
    PULL_REQUEST = "pull_request"  # open a pull request
    COMMENT = "comment"  # comment on a pull request or issue


class ConnectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, pattern=r"^[A-Za-z0-9_.-]+$")
    provider: Literal["github"] = "github"
    api_url: str = "https://api.github.com"
    # owner/name. Exactly one repository per connector: approving one is not approving an org.
    repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    # The name of a secret declared in config/policy.toml [[secrets.definitions]] (SEC-004).
    # None means anonymous access, which GitHub allows for public repositories, read only.
    secret: str | None = None
    permissions: list[ConnectorPermission] = Field(
        default_factory=lambda: [ConnectorPermission.READ]
    )
    enabled: bool = True
    description: str = ""

    @model_validator(mode="after")
    def _https_only(self) -> ConnectorConfig:
        url = urlparse(self.api_url)
        if url.scheme != "https" and not (url.scheme == "http" and url.hostname in _LOOPBACK):
            raise ValueError(
                f"connector {self.name!r}: api_url must be https (a token would otherwise "
                "travel in clear text); plain http is accepted only for loopback test servers"
            )
        return self

    @property
    def host(self) -> str:
        return urlparse(self.api_url).hostname or ""

    def permits(self, permission: ConnectorPermission) -> bool:
        return permission in self.permissions


class RepositoriesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default: str | None = None
    connectors: list[ConnectorConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def _names_are_unique(self) -> RepositoriesConfig:
        names = [c.name for c in self.connectors]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"duplicate connector names: {', '.join(duplicates)}")
        if self.default and self.default not in names:
            raise ValueError(f"default connector {self.default!r} is not defined")
        return self

    def get(self, name: str | None = None) -> ConnectorConfig:
        target = name or self.default
        if not target:
            raise RepositoryError(
                "no repository connector named and no default configured "
                "(config/repositories.toml, INT-006)"
            )
        for connector in self.connectors:
            if connector.name == target:
                if not connector.enabled:
                    raise RepositoryError(f"repository connector {target!r} is disabled")
                return connector
        known = ", ".join(c.name for c in self.connectors) or "(none)"
        raise RepositoryError(f"no approved repository connector {target!r}; approved: {known}")


def load_repositories(path: str | Path | None = None) -> RepositoriesConfig:
    """Load ``config/repositories.toml``. A missing file means no connectors, not an error."""
    target = Path(path or os.environ.get("AICA_REPOSITORIES_FILE") or DEFAULT_REPOSITORIES_PATH)
    if not target.exists():
        return RepositoriesConfig()
    try:
        raw = tomllib.loads(target.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise RepositoryError(f"{target}: could not read repository configuration: {exc}") from exc
    try:
        return RepositoriesConfig.model_validate(raw)
    except ValidationError as exc:
        raise RepositoryError(
            f"{target}: invalid repository configuration: {exc.errors(include_url=False)}"
        ) from exc
