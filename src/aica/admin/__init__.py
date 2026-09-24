"""Administration and governance (BRD 7.16, ADM-*; and SEC-007's immediate disable).

The policy file expresses standing rules. This package is the operational half: the
things an administrator does *now*, without an editor, a commit or a restart.
"""

from aica.admin.controls import (
    ChangeRecord,
    ControlError,
    ControlPlane,
    Disabled,
    TargetKind,
)
from aica.admin.rbac import (
    NotPermitted,
    Permission,
    Principal,
    RbacPolicy,
    Role,
    RoleBinding,
    SeparationOfDuties,
)
from aica.admin.reporting import (
    AuditQuery,
    RetentionPlan,
    UsageReport,
    apply_retention,
    iter_events,
    plan_retention,
    search,
    summarize,
)

__all__ = [
    "AuditQuery",
    "ChangeRecord",
    "ControlError",
    "ControlPlane",
    "Disabled",
    "NotPermitted",
    "Permission",
    "Principal",
    "RbacPolicy",
    "RetentionPlan",
    "Role",
    "RoleBinding",
    "SeparationOfDuties",
    "TargetKind",
    "UsageReport",
    "apply_retention",
    "iter_events",
    "plan_retention",
    "search",
    "summarize",
]
