"""Policy schema.

Operationalizes PROJECT_BRIEF "Bounded Autonomy" and BRD AG-007, SAFE-001, SAFE-005,
GIT-007 and section 16 (environment classification, tool allow/deny, network destination
policy). All fields are validated; an invalid policy file must fail loudly rather than
degrade to permissive defaults.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import TYPE_CHECKING, ClassVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

if TYPE_CHECKING:
    from aica.admin.rbac import Principal


class Environment(StrEnum):
    """BRD section 16: environment classification."""

    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class ActionCategory(StrEnum):
    """Sensitive-action categories that approval policy can reference (SAFE-001)."""

    DESTRUCTIVE = "destructive"  # rm -rf, git reset --hard, DROP TABLE ...
    PRIVILEGED = "privileged"  # sudo, chmod 777, service control ...
    EXTERNAL = "external"  # network side effects: curl POST, push, deploy ...
    PRODUCTION = "production"  # any action while environment == production
    FILE_DELETE = "file_delete"  # FS-005
    PROTECTED_BRANCH_COMMIT = "protected_branch_commit"  # GIT-007 / SAFE-003
    DATABASE_WRITE = "database_write"  # DB-005
    SECRET_ACCESS = "secret_access"  # noqa: S105 - category name, not a credential


class AutonomyLimits(BaseModel):
    """AG-007: maximum steps, time, tools, directories."""

    model_config = ConfigDict(extra="forbid")

    max_steps: int = Field(default=50, ge=1, le=10_000)
    max_seconds: int = Field(default=1800, ge=1, le=86_400)
    max_test_retries: int = Field(default=3, ge=0, le=50)  # TEST-006 bounded correction
    allowed_tools: list[str] = Field(
        default_factory=lambda: [
            "filesystem",
            "git",
            "shell",
            "tests",
            "rag",
            "browser",
            "database",
            # AG-008. Only ever exposes agent.delegate, and only for a run whose caller
            # asked for delegation; remove it here to forbid subagents outright.
            "agent",
        ]
    )
    allowed_directories: list[str] = Field(default_factory=lambda: ["."])
    environment: Environment = Environment.DEVELOPMENT

    @field_validator("allowed_tools", "allowed_directories")
    @classmethod
    def _non_empty_entries(cls, value: list[str]) -> list[str]:
        cleaned = [v.strip() for v in value]
        if any(not v for v in cleaned):
            raise ValueError("entries must be non-empty strings")
        return cleaned


class NetworkMode(StrEnum):
    DENY = "deny"
    ALLOWLIST = "allowlist"


class NetworkPolicy(BaseModel):
    """SAFE-005: external network access is deny-by-default and allowlisted."""

    model_config = ConfigDict(extra="forbid")

    mode: NetworkMode = NetworkMode.DENY
    allowed_hosts: list[str] = Field(default_factory=list)

    def is_host_allowed(self, host: str) -> bool:
        if self.mode is NetworkMode.DENY:
            return False
        host = host.lower().strip()
        for pattern in self.allowed_hosts:
            p = pattern.lower().strip()
            if p.startswith("*."):
                if host == p[2:] or host.endswith(p[1:]):
                    return True
            elif host == p:
                return True
        return False


class ApprovalPolicy(BaseModel):
    """SAFE-001: policy defines which action categories need approval or are blocked."""

    model_config = ConfigDict(extra="forbid")

    require_for: list[ActionCategory] = Field(
        default_factory=lambda: [
            ActionCategory.DESTRUCTIVE,
            ActionCategory.PRIVILEGED,
            ActionCategory.EXTERNAL,
            ActionCategory.PRODUCTION,
            ActionCategory.FILE_DELETE,
            ActionCategory.PROTECTED_BRANCH_COMMIT,
            ActionCategory.DATABASE_WRITE,
            ActionCategory.SECRET_ACCESS,
        ]
    )
    block: list[ActionCategory] = Field(default_factory=list)

    def requires_approval(self, category: ActionCategory) -> bool:
        return category in self.require_for

    def is_blocked(self, category: ActionCategory) -> bool:
        return category in self.block


class ToolPolicy(BaseModel):
    """SEC-002: tool allow/deny, and SEC-001's teeth for the environment classification.

    ``AutonomyLimits.allowed_tools`` is a *group* allowlist and stays the coarse control.
    This adds the two things BRD section 16 asks for that a group allowlist cannot express:

    * **A deny list that always wins.** Denying is not the absence of allowing: an operator
      switching one tool off must not have to know, or keep in step with, every list that
      might turn it back on. ``deny`` is therefore checked last and overrides everything,
      including ``allow`` and the group allowlist. It is also the mechanism SEC-007's
      immediate disable is built from.
    * **Per-tool granularity.** A group is the wrong unit when ``git.status`` is fine and
      ``git.clone`` is not. ``allow``, when non-empty, *narrows* within the groups already
      permitted - it can never widen them, so a policy file cannot grant itself a tool the
      group allowlist withholds.

    ``deny_in_production`` is what makes the environment classification enforceable rather
    than a label: the same policy file behaves differently once it says it is production.

    Patterns are an exact tool name (``git.clone``), a group name (``database``), or a
    prefix glob (``git.*``, ``db.w*``).
    """

    model_config = ConfigDict(extra="forbid")

    deny: list[str] = Field(default_factory=list)
    allow: list[str] = Field(default_factory=list)
    deny_in_production: list[str] = Field(default_factory=list)

    @field_validator("deny", "allow", "deny_in_production")
    @classmethod
    def _non_empty_patterns(cls, value: list[str]) -> list[str]:
        cleaned = [v.strip() for v in value]
        if any(not v for v in cleaned):
            raise ValueError("tool patterns must be non-empty strings")
        return cleaned

    @staticmethod
    def _matches(pattern: str, tool: str, group: str) -> bool:
        pattern = pattern.strip()
        if pattern.endswith("*"):
            return tool.startswith(pattern[:-1]) or group.startswith(pattern[:-1])
        return pattern == tool or pattern == group

    def denial_reason(
        self, tool: str, group: str, environment: Environment = Environment.DEVELOPMENT
    ) -> str | None:
        """Why this tool may not run, or None when this policy permits it.

        A reason rather than a bool: "not permitted by policy" leaves an operator guessing
        which of several lists stopped it, and that guess is usually wrong.
        """
        for pattern in self.deny:
            if self._matches(pattern, tool, group):
                return f"denied by policy (tools.deny matched {pattern!r})"
        if environment is Environment.PRODUCTION:
            for pattern in self.deny_in_production:
                if self._matches(pattern, tool, group):
                    return (
                        f"denied in the production environment "
                        f"(tools.deny_in_production matched {pattern!r})"
                    )
        if self.allow and not any(self._matches(p, tool, group) for p in self.allow):
            return "not in tools.allow, which narrows the permitted groups to a named set"
        return None


class SecretDefinition(BaseModel):
    """One secret the operator has declared (SEC-004)."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$")
    env_var: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    # Which tools may receive it. Empty means none: a secret nobody may use is the safe
    # reading of an operator who declared one and forgot to say where it goes.
    allowed_tools: list[str] = Field(default_factory=list)
    # The variable name the receiving process sees. Defaults to ``env_var``, but a tool
    # often expects a different name than the one the operator's machine uses.
    inject_as: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    description: str = Field(default="", max_length=500)

    @property
    def target_var(self) -> str:
        return self.inject_as or self.env_var

    def permits(self, tool: str) -> bool:
        return any(
            tool == pattern or (pattern.endswith("*") and tool.startswith(pattern[:-1]))
            for pattern in self.allowed_tools
        )


class SecretPolicy(BaseModel):
    """The declared secrets. Values are never here - only where to find them."""

    model_config = ConfigDict(extra="forbid")

    definitions: list[SecretDefinition] = Field(default_factory=list)

    @field_validator("definitions")
    @classmethod
    def _names_unique(cls, value: list[SecretDefinition]) -> list[SecretDefinition]:
        names = [d.name for d in value]
        duplicates = {n for n in names if names.count(n) > 1}
        if duplicates:
            raise ValueError(f"duplicate secret names: {', '.join(sorted(duplicates))}")
        return value

    def get(self, name: str) -> SecretDefinition | None:
        return next((d for d in self.definitions if d.name == name), None)

    @property
    def names(self) -> list[str]:
        return [d.name for d in self.definitions]


class QuotaExceeded(PermissionError):
    """ADM-005: the applicable limit for this window has been reached."""


class QuotaScope(StrEnum):
    """Who a limit applies to. ``PROJECT`` covers everyone in the workspace."""

    PRINCIPAL = "principal"
    TEAM = "team"
    PROJECT = "project"


class QuotaLimit(BaseModel):
    """One limit: a scope, who it names, and what it bounds per day."""

    model_config = ConfigDict(extra="forbid")

    scope: QuotaScope = QuotaScope.PRINCIPAL
    # The principal or team this names. Ignored (and may be empty) for PROJECT scope.
    name: str = Field(default="", max_length=200)
    # Members, for a team limit. A principal is in a team when named here.
    members: list[str] = Field(default_factory=list)
    window_days: int = Field(default=1, ge=1, le=365)

    max_actions: int | None = Field(default=None, ge=0)  # any audited material action
    max_model_calls: int | None = Field(default=None, ge=0)  # MODEL_CALL events
    max_commands: int | None = Field(default=None, ge=0)  # COMMAND events
    max_tool_seconds: int | None = Field(default=None, ge=0)  # recorded tool time

    @field_validator("name")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()

    def applies_to(self, principal: str) -> bool:
        if self.scope is QuotaScope.PROJECT:
            return True
        if self.scope is QuotaScope.TEAM:
            return principal in self.members
        return self.name == principal

    def describe(self) -> str:
        who = (
            "the project"
            if self.scope is QuotaScope.PROJECT
            else f"{self.scope.value} {self.name!r}"
        )
        bounds = ", ".join(
            f"{label}={value}"
            for label, value in (
                ("actions", self.max_actions),
                ("model_calls", self.max_model_calls),
                ("commands", self.max_commands),
                ("tool_seconds", self.max_tool_seconds),
            )
            if value is not None
        )
        return f"{who} per {self.window_days}d: {bounds or 'no bounds set'}"


class QuotaPolicy(BaseModel):
    """The configured limits (ADM-005). Empty means no quotas, which is the default."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    limits: list[QuotaLimit] = Field(default_factory=list)

    def for_principal(self, principal: str) -> list[QuotaLimit]:
        return [limit for limit in self.limits if limit.applies_to(principal)]


class Role(StrEnum):
    """The four roles ADM-001 needs. Ordered least to most capable."""

    VIEWER = "viewer"  # read the repository and the records
    DEVELOPER = "developer"  # run the agent: read, write, execute
    APPROVER = "approver"  # decide sensitive actions (SAFE-001)
    ADMIN = "admin"  # administer models, tools, policy and controls


class RoleBinding(BaseModel):
    """One principal and the roles assigned to them."""

    model_config = ConfigDict(extra="forbid")

    principal: str = Field(min_length=1, max_length=200)
    roles: list[Role] = Field(min_length=1)
    note: str = Field(default="", max_length=500)

    @field_validator("roles")
    @classmethod
    def _unique(cls, value: list[Role]) -> list[Role]:
        return list(dict.fromkeys(value))


class RbacPolicy(BaseModel):
    """Role assignments (ADM-001) and the separation-of-duties switch (SEC-006).

    ``enabled`` defaults to False so a single-developer workspace keeps working exactly
    as before. Turning it on is what makes a shared deployment enforce identity; leaving
    it off is an explicit local choice, not an accident, because nothing else changes.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    default_role: Role = Role.VIEWER  # what an unlisted principal gets: read-only
    separation_of_duties: bool = True  # SEC-006, meaningful only when enabled
    bindings: list[RoleBinding] = Field(default_factory=list)

    @field_validator("bindings")
    @classmethod
    def _principals_unique(cls, value: list[RoleBinding]) -> list[RoleBinding]:
        names = [b.principal for b in value]
        duplicates = {n for n in names if names.count(n) > 1}
        if duplicates:
            raise ValueError(
                f"a principal may appear once, with all their roles: {', '.join(sorted(duplicates))}"
            )
        return value

    def roles_for(self, principal: str) -> list[Role]:
        for binding in self.bindings:
            if binding.principal == principal:
                return list(binding.roles)
        return [self.default_role]

    def principal(self, name: str, owner: bool = False) -> Principal:
        # Imported here, not at module scope: this module is the policy *schema* and
        # must not depend on the packages that enforce it, or the enforcement layer
        # cannot import the schema it enforces.
        from aica.admin.rbac import Principal

        return Principal(name=name, roles=self.roles_for(name), policy=self, owner=owner)


class ProjectPolicy(BaseModel):
    """Who owns this repository and what it is (ADM-002).

    BRD ADM-002 asks that "repositories have owners, policies and approved tools". The
    policies and the approved tools are the rest of this file; what was missing is the
    owner, and an owner is only meaningful if it *does* something. So an owner holds the
    administer permission for this project without needing a separate role binding -
    which is the one place identity is derived rather than assigned, because an
    unowned-in-practice repository is how a policy file ends up with nobody able to
    change it during an incident.

    Owners still cannot approve agent actions: owning a repository and being entitled to
    wave through a destructive command are different things (see ADM-001).
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(default="", max_length=200)
    description: str = Field(default="", max_length=1000)
    repository: str = Field(default="", max_length=500)  # canonical URL or path
    owners: list[str] = Field(default_factory=list)

    @field_validator("owners")
    @classmethod
    def _non_empty_owners(cls, value: list[str]) -> list[str]:
        cleaned = [v.strip() for v in value]
        if any(not v for v in cleaned):
            raise ValueError("owner names must be non-empty strings")
        return list(dict.fromkeys(cleaned))

    def is_owner(self, principal: str) -> bool:
        return principal in self.owners

    def describe(self) -> str:
        who = ", ".join(self.owners) or "(no owner recorded)"
        return f"{self.name or '(unnamed project)'} owned by {who}"


class GitPolicy(BaseModel):
    """GIT-003 / GIT-007 / GIT-010."""

    model_config = ConfigDict(extra="forbid")

    protected_branches: list[str] = Field(default_factory=lambda: ["main", "master"])
    require_branch_for_changes: bool = True
    allow_force_push: bool = False

    def is_protected(self, branch: str) -> bool:
        return branch in self.protected_branches


class BrowserPolicy(BaseModel):
    """WEB-001 / WEB-006: which applications the browser tool may drive.

    The rule is the same shape as the network policy: loopback is the development case and is
    allowed by default; anything else must be allowlisted *and* passes through the EXTERNAL
    approval gate. A production environment classification adds the PRODUCTION gate on top
    (applied by ``ToolContext.require_approval``), so reaching a live system is never a
    silent side effect of a test run.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    engine: str = Field(default="chromium", pattern="^(chromium|firefox|webkit)$")
    headless: bool = True
    allow_localhost: bool = True  # 127.0.0.1 / localhost / ::1
    allowed_hosts: list[str] = Field(default_factory=list)  # same wildcard syntax as network
    max_seconds: float = Field(default=30.0, gt=0, le=600)
    screenshot_dir: str = ".aica/browser"

    # A dev server bound to 0.0.0.0 is routinely reached at that literal address, and doing so
    # still targets this machine - so it counts as local here. This is a URL the agent may
    # browse to, never an address anything binds to.
    _LOCAL_HOSTS: ClassVar[frozenset[str]] = frozenset(
        {"localhost", "127.0.0.1", "::1", "0.0.0.0"}  # noqa: S104
    )

    def is_local(self, host: str) -> bool:
        return host.lower().strip().strip("[]") in self._LOCAL_HOSTS

    def is_host_allowed(self, host: str) -> bool:
        """Local hosts follow ``allow_localhost``; everything else must be allowlisted."""
        host = host.lower().strip()
        if self.is_local(host):
            return self.allow_localhost
        for pattern in self.allowed_hosts:
            p = pattern.lower().strip()
            if p.startswith("*."):
                if host == p[2:] or host.endswith(p[1:]):
                    return True
            elif host == p:
                return True
        return False


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(default=1, ge=1)  # ADM-008 policy versioning hook
    autonomy: AutonomyLimits = Field(default_factory=AutonomyLimits)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    approval: ApprovalPolicy = Field(default_factory=ApprovalPolicy)
    git: GitPolicy = Field(default_factory=GitPolicy)
    browser: BrowserPolicy = Field(default_factory=BrowserPolicy)
    tools: ToolPolicy = Field(default_factory=ToolPolicy)  # SEC-002
    secrets: SecretPolicy = Field(default_factory=SecretPolicy)  # SEC-004
    rbac: RbacPolicy = Field(default_factory=RbacPolicy)  # ADM-001, SEC-006
    quotas: QuotaPolicy = Field(default_factory=QuotaPolicy)  # ADM-005
    project: ProjectPolicy = Field(default_factory=ProjectPolicy)  # ADM-002

    def principal(self, name: str) -> Principal:
        """The acting principal, with repository ownership applied (ADM-001, ADM-002).

        Every surface derives the actor through here rather than through ``rbac``
        directly, so an owner is never accidentally treated as an ordinary principal by
        whichever caller forgot to look at the project section.
        """
        return self.rbac.principal(name, owner=self.project.is_owner(name))

    def checksum(self) -> str:
        """A stable digest of the effective policy (ADM-008).

        Version numbers are declared by whoever edits the file and can be forgotten; a
        checksum cannot. Recording both means a change that did not bump the version is
        still visible as a change.
        """
        return hashlib.sha256(self.model_dump_json().encode("utf-8")).hexdigest()[:16]
