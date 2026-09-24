"""Network destination policy for execution tools (SEC-003, SAFE-005).

The browser tool has enforced a destination allowlist since WEB-001. Execution has not:
a command that reaches the network was *classified* as external and sent to the approval
gate, but nothing checked **where** it was going. So with one approval, or with the
external category approved for a run, `curl https://somewhere-else.example.com` left the
machine even though ``[network].allowed_hosts`` named one host. Approving "this command
talks to the network" is not the same as approving the destination, and treating them as
the same is what this module fixes.

What it does *not* do matters as much. Destinations are only checked for commands that
actually invoke a network client, so `echo https://example.com` is left alone; and a
command whose destination cannot be determined (``git push``, which resolves a remote
this module cannot see) is not guessed at - it keeps the approval gate it already had.
Claiming to enforce a destination this module cannot read would be worse than saying so.

Loopback is allowed, matching ``BrowserPolicy.allow_localhost``: reaching the project's
own dev server is the development case, and it does not leave the machine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aica.policy.models import NetworkPolicy

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})  # noqa: S104

# scheme://[user[:pass]@]host[:port]
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://(?:[^\s/@]+@)?([^\s/:?#\"']+)", re.I)
# scp/ssh/rsync style: [user@]host:path - only where a host is plausible.
_SSH_TARGET = re.compile(r"(?:^|\s)(?:[\w.-]+@)([A-Za-z0-9.-]+\.[A-Za-z]{2,}|[\w-]+):")
# A bare host argument to a client that takes one (ssh example.com, nc example.com 443).
_BARE_HOST = re.compile(
    r"\b(?:ssh|sftp|telnet|nc|ncat)\s+(?:-\S+\s+)*(?:[\w.-]+@)?([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b",
    re.I,
)


def is_local(host: str) -> bool:
    return host.lower().strip().strip("[]").split(":")[0] in LOCAL_HOSTS


def extract_destinations(command: str) -> list[str]:
    """Hosts this command would contact, as far as the text reveals them.

    Best effort and deliberately conservative: a host this cannot see is reported by its
    absence, not by a guess. The caller decides what to do when nothing is found.
    """
    hosts: list[str] = []
    for pattern in (_URL, _SSH_TARGET, _BARE_HOST):
        for match in pattern.finditer(command):
            host = match.group(1).strip().strip("[]").rstrip(".,;)")
            host = host.split(":")[0] if host.count(":") == 1 else host
            if host and host not in hosts:
                hosts.append(host.lower())
    return hosts


@dataclass(frozen=True)
class DestinationCheck:
    """The outcome of checking one command's destinations."""

    destinations: tuple[str, ...] = ()
    denied: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.denied

    @property
    def undetermined(self) -> bool:
        """True when the command reaches the network but named no host this could read."""
        return not self.destinations

    def reason(self) -> str:
        return (
            f"network policy denies {', '.join(self.denied)}; "
            "add the host to [network].allowed_hosts to permit it (SAFE-005, SEC-003)"
        )


def check_destinations(command: str, policy: NetworkPolicy) -> DestinationCheck:
    """Which of ``command``'s destinations the network policy refuses."""
    hosts = extract_destinations(command)
    denied = tuple(h for h in hosts if not is_local(h) and not policy.is_host_allowed(h))
    return DestinationCheck(destinations=tuple(hosts), denied=denied)
