"""Repository-provider integrations (INT-006)."""

from aica.integrations.github import GitHubClient
from aica.integrations.repositories import (
    DEFAULT_REPOSITORIES_PATH,
    ConnectorConfig,
    ConnectorPermission,
    RepositoriesConfig,
    RepositoryError,
    load_repositories,
)

__all__ = [
    "DEFAULT_REPOSITORIES_PATH",
    "ConnectorConfig",
    "ConnectorPermission",
    "GitHubClient",
    "RepositoriesConfig",
    "RepositoryError",
    "load_repositories",
]
