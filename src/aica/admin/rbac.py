"""Roles, permissions and separation of duties (ADM-001, SEC-006, SAFE-004).

Everything until now has been authorization without identity: a policy file said what
*the agent* may do, and whoever ran it inherited that. That is the right model for one
developer on one machine and the wrong one the moment a server is shared, because
"approved" then means "someone approved it" rather than "someone entitled to approve it
did".

This adds the missing half - who is asking - and keeps it deliberately small:

* **Four roles**, because the distinctions that matter operationally are read, change,
  approve and administer. More roles would be a permission system in its own right, and
  the BRD asks for role administration, not for a policy language.
* **Roles grant; they never override.** A principal's permissions are intersected with
  what policy already allows, never unioned. Giving someone the admin role cannot let
  them use a tool the policy file withholds, so identity can tighten the existing
  controls and can never be a way around them.
* **Approving is a separate role from changing.** ``DEVELOPER`` cannot approve; that is
  the whole point of an approval gate. An ``ADMIN`` administers but does not
  automatically approve agent actions either - the two are different jobs and merging
  them is how "four eyes" quietly becomes one pair.
* **Separation of duties is enforced on the actor, not requested of them** (SEC-006):
  when it is on, the principal who proposed a change may not be the one who confirms it,
  checked against the recorded proposer rather than trusted from the request.

An unknown principal gets ``default_role`` (viewer by default), so a misconfiguration
fails closed to read-only rather than open.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from aica.policy.models import RbacPolicy, Role, RoleBinding

# Re-exported: the schema lives with the rest of the policy schema, the
# behaviour lives here, and callers should not have to know which is which.
__all__ = [
    "NotPermitted",
    "Permission",
    "Principal",
    "RbacPolicy",
    "Role",
    "RoleBinding",
    "SeparationOfDuties",
]


class Permission(StrEnum):
    READ = "read"  # read-only tools, search, history
    WRITE = "write"  # mutating tools: edit, commit, run, database writes
    APPROVE = "approve"  # answer an approval request
    ADMINISTER = "administer"  # disable/enable, change controls, read the full audit


# What each role carries. Approving is deliberately *not* implied by administering:
# they are different jobs, and merging them turns four eyes into one pair.
_GRANTS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset({Permission.READ}),
    Role.DEVELOPER: frozenset({Permission.READ, Permission.WRITE}),
    Role.APPROVER: frozenset({Permission.READ, Permission.APPROVE}),
    Role.ADMIN: frozenset({Permission.READ, Permission.ADMINISTER}),
}


class NotPermitted(PermissionError):
    """The acting principal does not hold the permission this action needs (ADM-001)."""


class SeparationOfDuties(NotPermitted):
    """SEC-006: this principal may not confirm a change they proposed."""


class Principal(BaseModel):
    """Who is acting, and what that entitles them to."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    name: str = Field(min_length=1, max_length=200)
    roles: list[Role] = Field(default_factory=list)
    policy: RbacPolicy = Field(default_factory=RbacPolicy)
    # ADM-002: a repository owner administers it. Set by the caller that knows the
    # project; the default False keeps this type usable without one.
    owner: bool = False

    @property
    def permissions(self) -> frozenset[Permission]:
        """Every permission this principal holds.

        With RBAC off, everyone holds everything: this module must not change the
        behaviour of an existing single-developer workspace merely by being imported.
        """
        if not self.policy.enabled:
            return frozenset(Permission)
        granted: set[Permission] = set()
        for role in self.roles:
            granted |= _GRANTS[role]
        if self.owner:
            # ADM-002. Deliberately ADMINISTER only: owning a repository and being
            # entitled to wave through a destructive action are different things.
            granted.add(Permission.ADMINISTER)
        return frozenset(granted)

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions

    def require(self, permission: Permission, action: str) -> None:
        if self.can(permission):
            return
        held = ", ".join(sorted(r.value for r in self.roles)) or "(none)"
        raise NotPermitted(
            f"{self.name!r} may not {action}: it needs the {permission.value!r} permission "
            f"and holds the role(s) {held} (ADM-001)"
        )

    def require_distinct_from(self, proposer: str, action: str) -> None:
        """SEC-006: refuse when this principal proposed the change they are confirming."""
        if not (self.policy.enabled and self.policy.separation_of_duties):
            return
        if proposer and proposer == self.name:
            raise SeparationOfDuties(
                f"{self.name!r} proposed this {action} and may not also confirm it; "
                "a second principal must (SEC-006)"
            )

    def describe(self) -> str:
        roles = ", ".join(r.value for r in self.roles) or "(none)"
        state = "enforced" if self.policy.enabled else "not enforced"
        return f"{self.name} [{roles}] rbac:{state}"
