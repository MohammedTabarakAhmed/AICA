from __future__ import annotations

import os
import tomllib
from pathlib import Path

from pydantic import ValidationError

from aica.policy.models import Policy

DEFAULT_POLICY_PATH = Path("config/policy.toml")


class PolicyLoadError(RuntimeError):
    pass


def load_policy(path: str | os.PathLike[str] | None = None) -> Policy:
    """Load and validate the policy file.

    Resolution order: explicit ``path`` -> ``AICA_POLICY_FILE`` env var -> ``config/policy.toml``.
    A missing file yields the built-in defaults (deny network, approval for all sensitive
    categories). A present-but-invalid file is an error: policy must never silently degrade.
    """
    if path is not None:
        candidate = Path(path)
    else:
        candidate = Path(os.environ.get("AICA_POLICY_FILE", str(DEFAULT_POLICY_PATH)))
    if not candidate.exists():
        return Policy()
    try:
        with candidate.open("rb") as fh:
            data = tomllib.load(fh)
        return Policy.model_validate(data)
    except (tomllib.TOMLDecodeError, ValidationError) as exc:
        raise PolicyLoadError(f"invalid policy file {candidate}: {exc}") from exc
