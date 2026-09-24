"""Roles, permissions and separation of duties (ADM-001, SEC-006)."""

from __future__ import annotations

from pathlib import Path

import pytest

from aica.admin import ControlPlane, TargetKind
from aica.admin.rbac import (
    NotPermitted,
    Permission,
    RbacPolicy,
    Role,
    RoleBinding,
    SeparationOfDuties,
)
from aica.approvals import AllowAllApprover
from aica.policy import AutonomyLimits, Policy
from aica.tools import ToolContext, default_registry
from aica.tools.base import ToolNotAllowed
from tests.test_tools_fs import make_ctx


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    return tmp_path


def _rbac(**roles: Role | list[Role]) -> RbacPolicy:
    bindings = [
        RoleBinding(principal=name, roles=value if isinstance(value, list) else [value])
        for name, value in roles.items()
    ]
    return RbacPolicy(enabled=True, bindings=bindings)


def _ctx(workspace: Path, actor: str, rbac: RbacPolicy) -> ToolContext:
    policy = Policy(rbac=rbac)
    ctx = make_ctx(workspace, policy, approver=AllowAllApprover())
    ctx.audit.actor = actor
    ctx.principal = rbac.principal(actor)
    return ctx


# ------------------------------------------------------------------ the grants
@pytest.mark.parametrize(
    ("role", "expected"),
    [
        (Role.VIEWER, {Permission.READ}),
        (Role.DEVELOPER, {Permission.READ, Permission.WRITE}),
        (Role.APPROVER, {Permission.READ, Permission.APPROVE}),
        (Role.ADMIN, {Permission.READ, Permission.ADMINISTER}),
    ],
)
def test_each_role_grants_what_it_says(role: Role, expected: set[Permission]) -> None:
    principal = _rbac(alice=role).principal("alice")
    assert principal.permissions == expected


def test_administering_does_not_imply_approving() -> None:
    """Two different jobs; merging them turns four eyes into one pair."""
    admin = _rbac(root=Role.ADMIN).principal("root")
    assert admin.can(Permission.ADMINISTER)
    assert not admin.can(Permission.APPROVE)


def test_roles_accumulate_when_a_principal_holds_several() -> None:
    both = _rbac(lead=[Role.DEVELOPER, Role.APPROVER]).principal("lead")
    assert both.can(Permission.WRITE) and both.can(Permission.APPROVE)
    assert not both.can(Permission.ADMINISTER)


def test_an_unknown_principal_falls_back_to_read_only() -> None:
    """A misconfiguration must fail closed, not open."""
    policy = RbacPolicy(enabled=True, bindings=[RoleBinding(principal="a", roles=[Role.ADMIN])])
    stranger = policy.principal("someone-else")
    assert stranger.permissions == {Permission.READ}


def test_rbac_disabled_grants_everything() -> None:
    """Importing this module must not change an existing single-developer workspace."""
    principal = RbacPolicy().principal("anyone")
    assert principal.permissions == frozenset(Permission)


def test_a_principal_may_be_bound_once() -> None:
    with pytest.raises(ValueError, match="may appear once"):
        RbacPolicy(
            bindings=[
                RoleBinding(principal="a", roles=[Role.VIEWER]),
                RoleBinding(principal="a", roles=[Role.ADMIN]),
            ]
        )


# ------------------------------------------------------------------ tool enforcement
def test_a_viewer_may_read_but_not_write(workspace: Path) -> None:
    ctx = _ctx(workspace, "vera", _rbac(vera=Role.VIEWER))
    reg = default_registry()
    assert reg.call("fs.read", {"path": "src/app.py"}, ctx).ok
    with pytest.raises(ToolNotAllowed, match="lacks the 'write' permission"):
        reg.call("fs.write", {"path": "src/new.py", "content": "y\n"}, ctx)


def test_a_developer_may_write(workspace: Path) -> None:
    ctx = _ctx(workspace, "dana", _rbac(dana=Role.DEVELOPER))
    assert default_registry().call("fs.write", {"path": "src/new.py", "content": "y = 2\n"}, ctx).ok


def test_roles_narrow_but_never_widen(workspace: Path) -> None:
    """An admin role cannot grant a tool the policy file withholds."""
    policy = Policy(
        autonomy=AutonomyLimits(allowed_tools=["filesystem"]),
        rbac=_rbac(root=[Role.ADMIN, Role.DEVELOPER]),
    )
    ctx = make_ctx(workspace, policy)
    ctx.principal = policy.rbac.principal("root")
    assert "not in autonomy.allowed_tools" in str(
        default_registry().denial_reason("shell.run", ctx)
    )


def test_a_viewer_is_not_offered_write_tools(workspace: Path) -> None:
    ctx = _ctx(workspace, "vera", _rbac(vera=Role.VIEWER))
    names = {t.name for t in default_registry().allowed(ctx)}
    assert "fs.read" in names
    assert "fs.write" not in names and "shell.run" not in names


# ------------------------------------------------------------------ approving
def test_a_developer_cannot_approve_their_own_sensitive_action(workspace: Path) -> None:
    """The whole point of an approval gate: the actor is not the approver."""
    (workspace / "src" / "doomed.py").write_text("x\n", encoding="utf-8")
    ctx = _ctx(workspace, "dana", _rbac(dana=Role.DEVELOPER))
    with pytest.raises(NotPermitted, match="'approve' permission"):
        default_registry().call("fs.delete", {"path": "src/doomed.py"}, ctx)
    assert (workspace / "src" / "doomed.py").exists()


def test_an_approver_who_can_also_write_may_proceed(workspace: Path) -> None:
    (workspace / "src" / "doomed.py").write_text("x\n", encoding="utf-8")
    ctx = _ctx(workspace, "lead", _rbac(lead=[Role.DEVELOPER, Role.APPROVER]))
    assert default_registry().call("fs.delete", {"path": "src/doomed.py"}, ctx).ok
    assert not (workspace / "src" / "doomed.py").exists()


# ------------------------------------------------------------------ SEC-006
def test_administering_requires_the_admin_role(workspace: Path) -> None:
    plane = ControlPlane(workspace, actor="dana", rbac=_rbac(dana=Role.DEVELOPER))
    with pytest.raises(NotPermitted, match="'administer' permission"):
        plane.disable(TargetKind.TOOL, "shell.run", "nope")


def test_the_principal_who_disabled_something_may_not_re_enable_it(workspace: Path) -> None:
    """SEC-006: re-enabling restores capability, so it is what needs the second pair of eyes."""
    rbac = _rbac(alice=Role.ADMIN, bob=Role.ADMIN)
    ControlPlane(workspace, actor="alice", rbac=rbac).disable(
        TargetKind.MODEL, "m1", "suspected leak"
    )
    with pytest.raises(SeparationOfDuties, match="may not also confirm it"):
        ControlPlane(workspace, actor="alice", rbac=rbac).enable(TargetKind.MODEL, "m1")
    # A different admin can.
    assert ControlPlane(workspace, actor="bob", rbac=rbac).enable(TargetKind.MODEL, "m1") is True


def test_disabling_never_needs_a_second_pair_of_eyes(workspace: Path) -> None:
    """Switching something off is the safe direction; gating it lengthens an incident."""
    rbac = _rbac(alice=Role.ADMIN)
    plane = ControlPlane(workspace, actor="alice", rbac=rbac)
    plane.disable(TargetKind.TOOL, "shell.run", "first")
    plane.disable(TargetKind.TOOL, "database", "second")  # same actor, no objection
    assert {e.name for e in plane.load()} == {"shell.run", "database"}


def test_separation_of_duties_can_be_turned_off(workspace: Path) -> None:
    rbac = RbacPolicy(
        enabled=True,
        separation_of_duties=False,
        bindings=[RoleBinding(principal="alice", roles=[Role.ADMIN])],
    )
    plane = ControlPlane(workspace, actor="alice", rbac=rbac)
    plane.disable(TargetKind.MODEL, "m1", "x")
    assert plane.enable(TargetKind.MODEL, "m1") is True


def test_separation_of_duties_is_inert_when_rbac_is_off(workspace: Path) -> None:
    plane = ControlPlane(workspace, actor="alice")
    plane.disable(TargetKind.MODEL, "m1", "x")
    assert plane.enable(TargetKind.MODEL, "m1") is True


def test_describe_states_whether_rbac_is_enforced() -> None:
    assert "rbac:enforced" in _rbac(a=Role.ADMIN).principal("a").describe()
    assert "rbac:not enforced" in RbacPolicy().principal("a").describe()
