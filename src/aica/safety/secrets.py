"""Controlled secret injection (SEC-004, BRD section 16).

Redaction (SAFE-006) removes secrets from what leaves the system. This is the other
half: how a secret legitimately *reaches* a command that needs one, without ever
existing as a value anyone or anything can pass around.

Four rules define it, and each exists because the obvious alternative fails:

* **A caller names a secret; it never supplies one.** ``shell.run`` takes
  ``secrets=["github_token"]``, not a value. A tool argument is model-writable and lands
  in prompts, plans, session files and audit records, so a design that lets a value
  travel as an argument has already lost the secret before any gate runs.
* **The name resolves through policy, not through the request.** Only secrets declared
  in ``config/policy.toml`` exist, and each declares which tools may receive it. A tool
  cannot reach a secret the operator did not point at it.
* **The value is read from the host environment at the moment of use** and is never
  stored, cached, logged, returned or written to a file by anything here.
* **Every injection is an audited SECRET_ACCESS approval**, recorded by *name*.

``scrub`` closes the last gap: a command handed a real credential will sometimes echo it
back, and pattern-based redaction only catches formats it recognises. Since the exact
values injected are known, they are removed from output literally.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from aica.policy.models import SecretPolicy
from aica.safety.redaction import REDACTED

# A secret's value must be long enough that scrubbing it cannot blank out ordinary text.
MIN_SCRUBBABLE = 6


class SecretError(PermissionError):
    """A secret was requested that policy does not define, or does not permit here."""


class SecretUnavailable(SecretError):
    """The secret is defined and permitted, but the environment does not hold it."""


@dataclass(frozen=True)
class SecretInjection:
    """What to add to a subprocess environment, and what to scrub from its output.

    ``values`` exists only for the lifetime of one tool call. Nothing persists it, and
    ``__repr__`` is overridden so a stray log line or an exception traceback that prints
    this object cannot leak what it holds.
    """

    env: dict[str, str]
    names: tuple[str, ...]

    @property
    def values(self) -> tuple[str, ...]:
        return tuple(self.env.values())

    def scrub(self, text: str) -> str:
        return scrub(text, self.values)

    def __repr__(self) -> str:  # pragma: no cover - defensive, but the point is it is safe
        return f"SecretInjection(names={self.names!r}, values=<{len(self.env)} redacted>)"


def scrub(text: str, values: tuple[str, ...] | list[str]) -> str:
    """Remove known secret values from ``text`` literally.

    Pattern-based redaction only catches credential *formats* it knows. When the exact
    value is known - as it is for anything this module injected - matching it literally
    is both cheaper and complete.
    """
    if not text:
        return text
    out = text
    for value in sorted({v for v in values if len(v) >= MIN_SCRUBBABLE}, key=len, reverse=True):
        out = out.replace(value, REDACTED)
        # A value split across a line break by a wrapping terminal still reads as the
        # secret to anyone looking; catch the common case of inserted whitespace.
        out = re.sub(re.escape(value).replace(r"\ ", r"\s+"), REDACTED, out)
    return out


class SecretStore:
    """Resolves declared secrets from the environment. Holds nothing between calls."""

    def __init__(self, policy: SecretPolicy, environ: dict[str, str] | None = None) -> None:
        self.policy = policy
        self._environ = environ  # None = read os.environ live, so a rotated value is seen

    def _value(self, var: str) -> str | None:
        source = self._environ if self._environ is not None else os.environ
        value = source.get(var)
        return value if value else None

    def describe(self) -> list[dict[str, object]]:
        """What is declared and whether it is currently available - never any value."""
        return [
            {
                "name": d.name,
                "env_var": d.env_var,
                "injected_as": d.target_var,
                "allowed_tools": list(d.allowed_tools),
                "available": self._value(d.env_var) is not None,
                "description": d.description,
            }
            for d in self.policy.definitions
        ]

    def prepare(self, names: list[str], tool: str) -> SecretInjection:
        """Resolve ``names`` for ``tool``. Raises rather than silently injecting nothing.

        A missing secret is an error, not an empty string: a command that runs with a
        blank credential fails somewhere far from here, in a way that looks like a bug in
        the command rather than a missing secret.
        """
        env: dict[str, str] = {}
        for name in names:
            definition = self.policy.get(name)
            if definition is None:
                raise SecretError(
                    f"no secret named {name!r} is declared in policy; "
                    f"declared: {', '.join(self.policy.names) or '(none)'} (SEC-004)"
                )
            if not definition.permits(tool):
                raise SecretError(
                    f"secret {name!r} may not be used by {tool!r} "
                    f"(allowed: {', '.join(definition.allowed_tools) or '(no tool)'}) (SEC-004)"
                )
            value = self._value(definition.env_var)
            if value is None:
                raise SecretUnavailable(
                    f"secret {name!r} is declared but {definition.env_var} is not set in the "
                    "environment; credentials are supplied by the environment only (SEC-004)"
                )
            env[definition.target_var] = value
        return SecretInjection(env=env, names=tuple(names))
