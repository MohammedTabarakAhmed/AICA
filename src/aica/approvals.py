"""Human approval interface (SAFE-001, SAFE-002, UX-008).

Tools raise ``ApprovalRequired`` when policy demands a human decision. The caller (CLI,
web, agent runner) supplies an ``Approver``. The default is deny-all: nothing sensitive
can happen without an explicit approver being wired in.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from aica.policy.models import ActionCategory


@dataclass(frozen=True)
class ApprovalRequest:
    action: str  # human-readable proposed action (SAFE-002 shows the command/diff)
    categories: tuple[ActionCategory, ...]
    tool: str
    details: dict[str, object] = field(default_factory=dict)


class ApprovalRequired(PermissionError):
    def __init__(self, request: ApprovalRequest) -> None:
        self.request = request
        cats = ", ".join(c.value for c in request.categories)
        super().__init__(f"approval required for {request.tool}: {request.action} [{cats}]")


class Approver(Protocol):
    def approve(self, request: ApprovalRequest) -> bool: ...


class DenyAllApprover:
    def approve(self, request: ApprovalRequest) -> bool:
        return False


class AllowAllApprover:
    """For tests and explicitly authorized unattended runs only."""

    def approve(self, request: ApprovalRequest) -> bool:
        return True


class ScopedApprover:
    """Approves exactly the (tool, category) pairs a workflow was approved for; denies the rest.

    For unattended runs such as CI (INT-005). ``AllowAllApprover`` there would turn "this
    workflow may post a review comment" into "this workflow may do anything that asks", so
    the grant is written down per tool and per category, and every decision is kept.
    """

    def __init__(self, grants: dict[str, set[ActionCategory]]) -> None:
        self._grants = {tool: frozenset(cats) for tool, cats in grants.items()}
        self.requests: list[tuple[ApprovalRequest, bool]] = []

    def approve(self, request: ApprovalRequest) -> bool:
        granted = self._grants.get(request.tool, frozenset())
        decision = bool(request.categories) and set(request.categories) <= granted
        self.requests.append((request, decision))
        return decision


class CallbackApprover:
    def __init__(self, fn: Callable[[ApprovalRequest], bool]) -> None:
        self._fn = fn
        self.requests: list[ApprovalRequest] = []

    def approve(self, request: ApprovalRequest) -> bool:
        self.requests.append(request)
        return self._fn(request)


class ConsoleApprover:
    """Interactive y/N prompt; shows the full proposed action first (SAFE-002)."""

    def __init__(
        self, input_fn: Callable[[str], str] = input, print_fn: Callable[[str], None] = print
    ) -> None:
        self._input = input_fn
        self._print = print_fn

    def approve(self, request: ApprovalRequest) -> bool:
        self._print("\n=== APPROVAL REQUIRED ===")
        self._print(f"tool:       {request.tool}")
        self._print(f"categories: {', '.join(c.value for c in request.categories)}")
        self._print(f"action:     {request.action}")
        for k, v in request.details.items():
            self._print(f"{k}: {v}")
        try:
            answer = self._input("Approve? [y/N] ").strip().lower()
        except (EOFError, OSError):
            # No usable stdin (non-interactive run, captured output): deny rather than
            # crash. An unattended run must pass an explicit approver instead.
            self._print("(no interactive input available — denied)")
            return False
        return answer in {"y", "yes"}
