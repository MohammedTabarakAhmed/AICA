import subprocess
from pathlib import Path

import pytest

from aica.approvals import AllowAllApprover, ApprovalRequired, CallbackApprover, DenyAllApprover
from aica.audit import AuditLog, EventCategory, InMemoryAuditSink, Outcome
from aica.policy import Policy
from aica.policy.models import ActionCategory, ApprovalPolicy, AutonomyLimits, Environment
from aica.tools import ToolContext, default_registry
from aica.tools.base import ToolArgumentError, ToolError, ToolNotAllowed
from aica.workspace import GitGuard, UserChangesPresent, WorkspaceGuard


def make_ctx(root: Path, policy: Policy | None = None, approver=None) -> ToolContext:  # type: ignore[no-untyped-def]
    policy = policy or Policy()
    ws = WorkspaceGuard(root, policy.autonomy.allowed_directories)
    git = GitGuard(ws.root, policy.git)
    return ToolContext(
        workspace=ws,
        policy=policy,
        audit=AuditLog(InMemoryAuditSink(), actor="tester", session_id="s1"),
        git=git if git.is_repository() else None,
        approver=approver or AllowAllApprover(),
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# demo\n", encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------- framework


def test_tool_schema_is_discoverable(workspace: Path) -> None:
    reg = default_registry()
    ctx = make_ctx(workspace)
    schemas = {s["name"]: s for s in reg.schemas(ctx)}
    assert "fs.read" in schemas
    assert schemas["fs.read"]["parameters"]["properties"]["path"]["type"] == "string"
    assert schemas["fs.read"]["description"]


def test_invalid_arguments_rejected_before_execution(workspace: Path) -> None:
    reg = default_registry()
    ctx = make_ctx(workspace)
    with pytest.raises(ToolArgumentError):
        reg.call("fs.read", {"path": 123}, ctx)
    with pytest.raises(ToolArgumentError):
        reg.call("fs.read", {"nope": "x"}, ctx)  # extra=forbid
    with pytest.raises(ToolArgumentError):
        reg.call("fs.write", {"path": "a.txt"}, ctx)  # missing content


def test_policy_disables_tool_group(workspace: Path) -> None:
    policy = Policy(autonomy=AutonomyLimits(allowed_tools=["filesystem"]))
    ctx = make_ctx(workspace, policy)
    reg = default_registry()
    reg.call("fs.list", {}, ctx)
    with pytest.raises(ToolNotAllowed):
        reg.call("shell.run", {"command": "echo hi"}, ctx)
    assert "shell.run" not in [t.name for t in reg.allowed(ctx)]


def test_every_call_is_audited(workspace: Path) -> None:
    ctx = make_ctx(workspace)
    reg = default_registry()
    reg.call("fs.read", {"path": "README.md"}, ctx)
    sink = ctx.audit.sink
    assert isinstance(sink, InMemoryAuditSink)
    evt = [e for e in sink.events if e.category is EventCategory.TOOL_CALL][-1]
    assert evt.tool == "fs.read" and evt.outcome is Outcome.SUCCESS
    assert evt.arguments["path"] == "README.md"
    assert evt.session_id == "s1"


def test_failure_is_audited(workspace: Path) -> None:
    ctx = make_ctx(workspace)
    with pytest.raises(ToolError):
        default_registry().call("fs.read", {"path": "missing.txt"}, ctx)
    sink = ctx.audit.sink
    assert isinstance(sink, InMemoryAuditSink)
    assert sink.events[-1].outcome in (Outcome.FAILURE, Outcome.BLOCKED)


# ---------------------------------------------------------------- filesystem


def test_list_and_read(workspace: Path) -> None:
    ctx = make_ctx(workspace)
    reg = default_registry()
    out = reg.call("fs.list", {"recursive": True}, ctx)
    assert "src/app.py" in out.data["entries"]
    read = reg.call("fs.read", {"path": "src/app.py"}, ctx)
    assert "def add" in read.output
    assert read.data["total_lines"] == 2


def test_read_line_range(workspace: Path) -> None:
    ctx = make_ctx(workspace)
    r = default_registry().call(
        "fs.read", {"path": "src/app.py", "start_line": 2, "end_line": 2}, ctx
    )
    assert r.output.strip() == "return a + b"


def test_path_escape_is_refused(workspace: Path) -> None:
    ctx = make_ctx(workspace)
    with pytest.raises(PermissionError):
        default_registry().call("fs.read", {"path": "../outside.txt"}, ctx)


def test_write_returns_diff_and_snapshot(workspace: Path) -> None:
    ctx = make_ctx(workspace)
    reg = default_registry()
    res = reg.call(
        "fs.write", {"path": "src/app.py", "content": "def add(a, b):\n    return a - b\n"}, ctx
    )
    assert "-    return a + b" in res.output and "+    return a - b" in res.output
    sid = res.data["snapshot_id"]
    assert (workspace / "src" / "app.py").read_text().endswith("a - b\n")
    roll = reg.call("fs.rollback", {"snapshot_id": sid}, ctx)
    assert "src/app.py" in roll.data["restored"]
    assert "a + b" in (workspace / "src" / "app.py").read_text()


def test_write_creates_new_file(workspace: Path) -> None:
    ctx = make_ctx(workspace)
    res = default_registry().call("fs.write", {"path": "src/new.py", "content": "x = 1\n"}, ctx)
    assert res.data["created"] is True
    assert (workspace / "src" / "new.py").exists()


def test_edit_requires_unique_match(workspace: Path) -> None:
    (workspace / "dup.txt").write_text("a\na\n", encoding="utf-8")
    ctx = make_ctx(workspace)
    reg = default_registry()
    with pytest.raises(Exception, match="matches 2 times"):
        reg.call("fs.edit", {"path": "dup.txt", "old_text": "a\n", "new_text": "b\n"}, ctx)
    res = reg.call(
        "fs.edit",
        {"path": "dup.txt", "old_text": "a\n", "new_text": "b\n", "replace_all": True},
        ctx,
    )
    assert res.data["replacements"] == 2
    with pytest.raises(Exception, match="not found"):
        reg.call("fs.edit", {"path": "dup.txt", "old_text": "zzz", "new_text": "y"}, ctx)


def test_delete_requires_approval(workspace: Path) -> None:
    ctx = make_ctx(workspace, approver=DenyAllApprover())
    reg = default_registry()
    with pytest.raises(ApprovalRequired) as exc:
        reg.call("fs.delete", {"path": "README.md"}, ctx)
    assert ActionCategory.FILE_DELETE in exc.value.request.categories
    assert (workspace / "README.md").exists()  # not deleted

    approver = CallbackApprover(lambda r: True)
    ctx2 = make_ctx(workspace, approver=approver)
    res = reg.call("fs.delete", {"path": "README.md"}, ctx2)
    assert not (workspace / "README.md").exists()
    assert approver.requests[0].tool == "fs.delete"
    # FS-007: deletion is recoverable.
    reg.call("fs.rollback", {"snapshot_id": res.data["snapshot_id"]}, ctx2)
    assert (workspace / "README.md").exists()


def test_blocked_category_cannot_be_approved(workspace: Path) -> None:
    policy = Policy(approval=ApprovalPolicy(block=[ActionCategory.FILE_DELETE]))
    ctx = make_ctx(workspace, policy, approver=AllowAllApprover())
    with pytest.raises(PermissionError, match="blocked by policy"):
        default_registry().call("fs.delete", {"path": "README.md"}, ctx)
    assert (workspace / "README.md").exists()


def test_sensitive_file_read_requires_approval(workspace: Path) -> None:
    (workspace / ".env").write_text("API_KEY=abc123456789\n", encoding="utf-8")
    ctx = make_ctx(workspace, approver=DenyAllApprover())
    with pytest.raises(ApprovalRequired) as exc:
        default_registry().call("fs.read", {"path": ".env"}, ctx)
    assert ActionCategory.SECRET_ACCESS in exc.value.request.categories


def test_move_file(workspace: Path) -> None:
    ctx = make_ctx(workspace)
    reg = default_registry()
    reg.call("fs.move", {"source": "src/app.py", "destination": "src/calc.py"}, ctx)
    assert (workspace / "src" / "calc.py").exists() and not (workspace / "src" / "app.py").exists()
    with pytest.raises(Exception, match="already exists"):
        reg.call("fs.move", {"source": "src/calc.py", "destination": "README.md"}, ctx)


def test_diff_against_proposed_content(workspace: Path) -> None:
    ctx = make_ctx(workspace)
    res = default_registry().call(
        "fs.diff", {"path": "README.md", "proposed_content": "# demo\nmore\n"}, ctx
    )
    assert res.data["changed"] and "+more" in res.output


def test_production_environment_escalates_write(workspace: Path) -> None:
    policy = Policy(autonomy=AutonomyLimits(environment=Environment.PRODUCTION))
    ctx = make_ctx(workspace, policy, approver=DenyAllApprover())
    with pytest.raises(ApprovalRequired) as exc:
        default_registry().call("fs.delete", {"path": "README.md"}, ctx)
    assert ActionCategory.PRODUCTION in exc.value.request.categories


# ---------------------------------------------------------------- GIT-010 through tools


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def git_workspace(workspace: Path) -> Path:
    _git(workspace, "init", "-q", "-b", "work")
    _git(workspace, "config", "user.email", "t@example.com")
    _git(workspace, "config", "user.name", "t")
    _git(workspace, "add", ".")
    _git(workspace, "commit", "-q", "-m", "init")
    return workspace


def test_write_refuses_to_clobber_uncommitted_user_changes(git_workspace: Path) -> None:
    (git_workspace / "src" / "app.py").write_text(
        "developer's work in progress\n", encoding="utf-8"
    )
    ctx = make_ctx(git_workspace)
    with pytest.raises(UserChangesPresent):
        default_registry().call(
            "fs.write", {"path": "src/app.py", "content": "agent version\n"}, ctx
        )
    assert "developer" in (git_workspace / "src" / "app.py").read_text()


def test_clobbering_is_possible_with_explicit_authorization(git_workspace: Path) -> None:
    (git_workspace / "src" / "app.py").write_text("developer's work\n", encoding="utf-8")
    approver = CallbackApprover(lambda r: True)
    ctx = make_ctx(git_workspace, approver=approver)
    default_registry().call(
        "fs.write", {"path": "src/app.py", "content": "agent version\n", "allow_dirty": True}, ctx
    )
    assert (git_workspace / "src" / "app.py").read_text() == "agent version\n"
    assert any(ActionCategory.DESTRUCTIVE in r.categories for r in approver.requests)


def test_clean_file_in_dirty_repo_is_still_writable(git_workspace: Path) -> None:
    (git_workspace / "src" / "app.py").write_text("dirty\n", encoding="utf-8")
    ctx = make_ctx(git_workspace)
    default_registry().call("fs.write", {"path": "README.md", "content": "# updated\n"}, ctx)
    assert (git_workspace / "README.md").read_text() == "# updated\n"
