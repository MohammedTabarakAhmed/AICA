"""Tool framework (AGENTS.md "Tool Use"; MCP-002/003/004/006 baseline).

Every tool has: a name, a purpose, a pydantic argument schema (validated before execution),
a policy check (allowed-tools list, approval categories) and audit on every call. Tools
receive a ``ToolContext`` carrying the workspace guards, policy, approver and audit log so
they can never bypass them.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from pydantic import BaseModel, ConfigDict, ValidationError

from aica.admin.controls import ControlPlane
from aica.admin.quotas import QuotaExceeded
from aica.admin.quotas import check as quota_check
from aica.admin.rbac import Permission, Principal
from aica.admin.reporting import iter_events
from aica.approvals import ApprovalRequest, ApprovalRequired, Approver, DenyAllApprover
from aica.audit import AuditLog, EventCategory, InMemoryAuditSink, Outcome
from aica.policy import CancellationToken, Policy
from aica.policy.models import ActionCategory, Environment
from aica.workspace import GitGuard, WorkspaceGuard
from aica.workspace.lease import RepositoryBusy, RepositoryLease

if TYPE_CHECKING:
    from aica.rag.index import RepositoryIndex


class ToolError(RuntimeError):
    pass


class ToolArgumentError(ToolError):
    """MCP-003: malformed arguments are rejected before execution."""


class ToolNotAllowed(PermissionError):
    """MCP-004: tool disabled by policy."""


@dataclass
class ToolContext:
    workspace: WorkspaceGuard
    policy: Policy
    audit: AuditLog
    git: GitGuard | None = None
    approver: Approver = field(default_factory=DenyAllApprover)
    cancel: CancellationToken = field(default_factory=CancellationToken)
    session_id: str | None = None
    index: RepositoryIndex | None = None
    # Overrides config/databases.toml for a caller that keeps its databases elsewhere
    # (tests, or a project with several configurations). Never a DSN: a connection is always
    # selected by name from a configuration file (DB-001).
    databases_file: str | None = None
    # SEC-007. The control plane is re-read on every tool call rather than folded into
    # the loaded policy, so a disable takes effect on the next call with no restart.
    # None means no control plane is wired up for this context (tests, library use).
    controls: ControlPlane | None = None
    # ADM-001. Who is acting. None means identity is not wired up for this context, which
    # is the single-developer case; with RBAC disabled in policy a principal holds every
    # permission anyway, so adding identity never changes existing behaviour by itself.
    principal: Principal | None = None
    # ADM-005. Where the audit records this quota counts from live. None disables quota
    # enforcement for this context, which is the in-memory/test case.
    audit_directory: Path | None = None
    # NFR-003. The repository lease this context's run holds, if any. A mutating call is
    # refused while another holder leases the repository, so an edit from outside a
    # running agent task cannot land in the middle of it.
    lease_holder: str | None = None
    # GIT-010. What this run itself wrote: absolute path -> sha256 of the content it left.
    # A dirty file whose content still hashes to that value is the run's own change, and
    # the run may keep working on it; if anyone else touched it since, the hash differs and
    # the file is protected like any other developer change. Shared (not copied) with
    # subagents, whose context is a shallow ``replace`` of this one.
    own_writes: dict[str, str] = field(default_factory=dict)
    # AG-007. When the run this call belongs to must end (a ``time.monotonic()`` value). A
    # budget checked only between steps cannot stop one long step, so a command a step
    # runs is given no more time than the run has left. None: no run deadline.
    deadline: float | None = None
    # INT-006. Overrides config/repositories.toml, like ``databases_file``; a connector is
    # always selected by name from a configuration file, never supplied by a call.
    repositories_file: str | None = None
    # Test seam for the repository connector's HTTP client (an ``httpx.BaseTransport``).
    # None in real use: requests go to the connector's configured API host.
    http_transport: Any = None

    @classmethod
    def for_workspace(
        cls,
        root: str,
        policy: Policy | None = None,
        actor: str = "local-user",
        approver: Approver | None = None,
    ) -> ToolContext:
        policy = policy or Policy()
        ws = WorkspaceGuard(root, policy.autonomy.allowed_directories)
        git = GitGuard(ws.root, policy.git)
        return cls(
            workspace=ws,
            policy=policy,
            audit=AuditLog(InMemoryAuditSink(), actor=actor),
            git=git if git.is_repository() else None,
            approver=approver or DenyAllApprover(),
        )

    @property
    def environment(self) -> Environment:
        return self.policy.autonomy.environment

    @property
    def actor(self) -> Principal:
        """The acting principal. Falls back to the audit log's actor name (ADM-001)."""
        if self.principal is not None:
            return self.principal
        return self.policy.principal(self.audit.actor)

    def require_permission(self, permission: Permission, action: str) -> None:
        self.actor.require(permission, action)

    def check_quota(self, tool: str) -> None:
        """ADM-005: refuse when the acting principal has exhausted an applicable limit.

        Counted from the audit log, the same stream ADM-006 reports from, so the number
        that stops someone working is the number an administrator is shown. Exhaustion
        refuses rather than queueing or throttling: a quota that silently slows work is
        indistinguishable from a broken system.
        """
        policy = self.policy.quotas
        if not policy.enabled or self.audit_directory is None:
            return
        verdict = quota_check(policy, self.actor.name, iter_events(self.audit_directory))
        if verdict.allowed:
            return
        self.audit.record(
            category=EventCategory.POLICY_DECISION,
            action=f"{tool}: {verdict.measure} quota exhausted",
            outcome=Outcome.BLOCKED,
            tool=tool,
            details={"used": verdict.used, "cap": verdict.cap, "rule": "ADM-005"},
        )
        raise QuotaExceeded(f"{tool}: {verdict.reason()}")

    def require_approval(
        self, tool: str, action: str, categories: list[ActionCategory], **details: object
    ) -> None:
        """Apply approval policy for the given categories; raise if denied or blocked."""
        if (
            self.environment is Environment.PRODUCTION
            and ActionCategory.PRODUCTION not in categories
        ):
            categories = [*categories, ActionCategory.PRODUCTION]
        blocked = [c for c in categories if self.policy.approval.is_blocked(c)]
        if blocked:
            self.audit.record(
                category=EventCategory.POLICY_DECISION,
                action=action,
                outcome=Outcome.BLOCKED,
                tool=tool,
                details={"categories": [c.value for c in blocked]},
            )
            raise PermissionError(
                f"{tool}: action blocked by policy ({', '.join(c.value for c in blocked)})"
            )
        needed = [c for c in categories if self.policy.approval.requires_approval(c)]
        if not needed:
            return
        request = ApprovalRequest(
            action=action, categories=tuple(needed), tool=tool, details=dict(details)
        )
        # ADM-001: approving is a role, not a capability everyone running the agent has.
        # Checked before the approver is consulted, so a principal who cannot approve is
        # refused rather than being asked a question their answer would not count for.
        self.actor.require(Permission.APPROVE, f"approve {action!r}")
        approved = self.approver.approve(request)
        self.audit.record(
            category=EventCategory.APPROVAL,
            action=action,
            outcome=Outcome.SUCCESS if approved else Outcome.PENDING_APPROVAL,
            tool=tool,
            details={"categories": [c.value for c in needed], "approved": approved},
        )
        if not approved:
            raise ApprovalRequired(request)


class ToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool = True
    output: str = ""
    data: dict[str, Any] = {}


class Tool:
    """Base class. Subclasses set ``name``, ``description``, ``Args`` and implement ``run``."""

    name: ClassVar[str]
    description: ClassVar[str]
    Args: ClassVar[type[BaseModel]]
    # SEC-001: does running this tool change anything outside the agent's own memory?
    # Declared per tool because only the tool knows; ``invoke`` uses it to put every
    # mutating call behind the production approval gate, rather than relying on each
    # tool to remember. A tool that writes and leaves this False is the bug this
    # attribute exists to make visible.
    mutating: ClassVar[bool] = False

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        raise NotImplementedError

    def schema(self) -> dict[str, Any]:
        """MCP-002: discoverable input contract."""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.Args.model_json_schema(),
        }

    def parse_args(self, raw: dict[str, Any]) -> BaseModel:
        try:
            return self.Args.model_validate(raw)
        except ValidationError as exc:
            raise ToolArgumentError(
                f"{self.name}: invalid arguments: {exc.errors(include_url=False)}"
            ) from exc

    def invoke(self, raw: dict[str, Any], ctx: ToolContext) -> ToolResult:
        """Validate → policy → run → audit. The only entry point callers should use."""
        ctx.cancel.raise_if_cancelled()
        args = self.parse_args(raw)
        # SEC-001. A tool that changes something is gated in production even when nothing
        # about this particular call is otherwise sensitive: writing an ordinary file is
        # unremarkable in development and is exactly what an environment classification
        # exists to stop happening unattended against a live system. Tools that already
        # categorise the call add their own categories on top.
        if self.mutating and ctx.environment is Environment.PRODUCTION:
            ctx.require_approval(
                self.name,
                f"{self.name} in the production environment",
                [ActionCategory.PRODUCTION],
            )
        if self.mutating:
            try:
                RepositoryLease(ctx.workspace.root).check(ctx.lease_holder)
            except RepositoryBusy as exc:
                ctx.audit.record(
                    category=EventCategory.POLICY_DECISION,
                    action=f"{self.name}: repository leased by another task",
                    outcome=Outcome.BLOCKED,
                    tool=self.name,
                    details={"rule": "NFR-003", "reason": str(exc)[:500]},
                )
                raise
        ctx.check_quota(self.name)
        started = time.monotonic()
        try:
            result = self.run(args, ctx)
        except ApprovalRequired:
            raise
        except PermissionError as exc:
            self._audit(ctx, args, Outcome.BLOCKED, started, error=str(exc))
            raise
        except Exception as exc:
            self._audit(ctx, args, Outcome.FAILURE, started, error=str(exc))
            raise
        self._audit(
            ctx, args, Outcome.SUCCESS if result.ok else Outcome.FAILURE, started, data=result.data
        )
        return result

    def _audit(
        self,
        ctx: ToolContext,
        args: BaseModel,
        outcome: Outcome,
        started: float,
        error: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        details: dict[str, Any] = {}
        if error:
            details["error"] = error[:2000]
        if data:
            details["result"] = {
                k: v for k, v in data.items() if isinstance(v, str | int | float | bool)
            }
        ctx.audit.record(
            category=EventCategory.TOOL_CALL,
            action=self.name,
            outcome=outcome,
            tool=self.name,
            arguments=args.model_dump(mode="json"),
            details=details,
            duration_ms=int((time.monotonic() - started) * 1000),
            session_id=ctx.session_id,
        )
