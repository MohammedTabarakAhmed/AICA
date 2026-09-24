import subprocess
import sys
from pathlib import Path

import pytest

from aica.approvals import AllowAllApprover, ApprovalRequired, CallbackApprover, DenyAllApprover
from aica.audit import EventCategory, InMemoryAuditSink
from aica.policy import Policy
from aica.policy.models import ActionCategory, ApprovalPolicy, GitPolicy, NetworkMode, NetworkPolicy
from aica.tools import default_registry
from aica.tools.shell import build_environment, execute
from tests.test_tools_fs import make_ctx

ECHO = "echo hello"


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('hi')\n", encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------- EXEC


def test_read_only_command_runs_without_approval(ws: Path) -> None:
    ctx = make_ctx(ws, approver=DenyAllApprover())
    res = default_registry().call("shell.run", {"command": ECHO}, ctx)
    assert res.ok and "hello" in res.output
    assert res.data["exit_code"] == 0


def test_exit_code_and_stderr_captured(ws: Path) -> None:
    ctx = make_ctx(ws)
    code = "import sys; sys.stderr.write('boom'); sys.exit(3)"
    res = default_registry().call("shell.run", {"command": f'{sys.executable} -c "{code}"'}, ctx)
    assert res.data["exit_code"] == 3 and not res.ok
    assert "boom" in res.data["stderr"]


def test_destructive_command_requires_approval(ws: Path) -> None:
    ctx = make_ctx(ws, approver=DenyAllApprover())
    with pytest.raises(ApprovalRequired) as exc:
        default_registry().call("shell.run", {"command": "rm -rf src"}, ctx)
    assert ActionCategory.DESTRUCTIVE in exc.value.request.categories
    assert (ws / "src").exists()


def test_blocked_command_cannot_be_approved(ws: Path) -> None:
    policy = Policy(approval=ApprovalPolicy(block=[ActionCategory.DESTRUCTIVE]))
    ctx = make_ctx(ws, policy, approver=AllowAllApprover())
    with pytest.raises(PermissionError, match="blocked by policy"):
        default_registry().call("shell.run", {"command": "rm -rf /"}, ctx)


def test_approved_command_proceeds_and_is_audited(ws: Path) -> None:
    approver = CallbackApprover(lambda r: True)
    ctx = make_ctx(ws, approver=approver)
    default_registry().call("shell.run", {"command": "pip install requests --dry-run"}, ctx)
    assert approver.requests and ActionCategory.EXTERNAL in approver.requests[0].categories
    sink = ctx.audit.sink
    assert isinstance(sink, InMemoryAuditSink)
    assert any(e.category is EventCategory.COMMAND for e in sink.events)


def test_timeout_kills_process(ws: Path) -> None:
    ctx = make_ctx(ws)
    res = default_registry().call(
        "shell.run",
        {"command": f'{sys.executable} -c "import time; time.sleep(10)"', "timeout_seconds": 1.0},
        ctx,
    )
    assert res.data["timed_out"] is True and not res.ok


def test_cancellation_stops_running_command(ws: Path) -> None:
    ctx = make_ctx(ws)
    ctx.cancel.cancel("emergency stop")
    from aica.policy import Cancelled

    with pytest.raises(Cancelled):
        default_registry().call("shell.run", {"command": ECHO}, ctx)


def test_environment_is_controlled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECRET_TOKEN", "should-not-leak")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = build_environment({"TASK_VAR": "1"})
    assert "SECRET_TOKEN" not in env
    assert env["TASK_VAR"] == "1" and env["AICA_SANDBOX"] == "1" and "PATH" in env


def test_command_runs_in_workspace(ws: Path) -> None:
    ctx = make_ctx(ws)
    cmd = "cd" if sys.platform == "win32" else "pwd"
    res = default_registry().call("shell.run", {"command": cmd, "cwd": "src"}, ctx)
    assert "src" in res.output


def test_execute_helper_returns_structured_result(tmp_path: Path) -> None:
    r = execute(ECHO, str(tmp_path), timeout_seconds=30)
    assert r.ok and "hello" in r.stdout and r.exit_code == 0


# ---------------------------------------------------------------- GIT


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(ws: Path) -> Path:
    _git(ws, "init", "-q", "-b", "main")
    _git(ws, "config", "user.email", "t@example.com")
    _git(ws, "config", "user.name", "t")
    _git(ws, "add", ".")
    _git(ws, "commit", "-q", "-m", "init")
    return ws


def test_status_and_branches(repo: Path) -> None:
    ctx = make_ctx(repo)
    reg = default_registry()
    st = reg.call("git.status", {}, ctx)
    assert st.data["branch"] == "main" and st.data["clean"]
    br = reg.call("git.branches", {}, ctx)
    assert br.data["current"] == "main" and "main" in br.data["protected"]


def test_create_branch_and_commit(repo: Path) -> None:
    ctx = make_ctx(repo)
    reg = default_registry()
    reg.call("git.create_branch", {"name": "feature/x"}, ctx)
    (repo / "src" / "app.py").write_text("print('changed')\n", encoding="utf-8")
    diff = reg.call("git.diff", {}, ctx)
    assert diff.data["changed"]
    res = reg.call("git.commit", {"message": "change greeting"}, ctx)
    assert res.data["branch"] == "feature/x" and res.data["commit"]
    assert reg.call("git.status", {}, ctx).data["clean"]


def test_commit_to_protected_branch_requires_approval_with_diff(repo: Path) -> None:
    approver = CallbackApprover(lambda r: False)
    ctx = make_ctx(repo, approver=approver)
    (repo / "src" / "app.py").write_text("print('protected change')\n", encoding="utf-8")
    with pytest.raises(ApprovalRequired):
        default_registry().call("git.commit", {"message": "direct to main"}, ctx)
    req = approver.requests[0]
    assert ActionCategory.PROTECTED_BRANCH_COMMIT in req.categories
    assert "protected change" in str(req.details["diff"])  # SAFE-003: diff shown


def test_commit_nothing_is_an_error(repo: Path) -> None:
    ctx = make_ctx(repo)
    with pytest.raises(Exception, match="nothing to commit"):
        default_registry().call("git.commit", {"message": "empty"}, ctx)


def test_branch_name_is_validated(repo: Path) -> None:
    ctx = make_ctx(repo)
    from aica.tools.base import ToolArgumentError

    with pytest.raises(ToolArgumentError):
        default_registry().call("git.create_branch", {"name": "bad name; rm -rf /"}, ctx)


def test_switch_refuses_with_uncommitted_changes(repo: Path) -> None:
    ctx = make_ctx(repo)
    reg = default_registry()
    reg.call("git.create_branch", {"name": "other"}, ctx)
    (repo / "src" / "app.py").write_text("wip\n", encoding="utf-8")
    with pytest.raises(Exception, match="uncommitted changes"):
        reg.call("git.switch", {"name": "main"}, ctx)


def test_revert_undoes_a_commit(repo: Path) -> None:
    ctx = make_ctx(repo, Policy(git=GitPolicy(protected_branches=[])))
    reg = default_registry()
    (repo / "src" / "app.py").write_text("print('v2')\n", encoding="utf-8")
    sha = reg.call("git.commit", {"message": "bump to v2"}, ctx).data["commit"]
    reg.call("git.revert", {"commit": str(sha)}, ctx)
    assert "v2" not in (repo / "src" / "app.py").read_text()


def test_discard_requires_approval(repo: Path) -> None:
    ctx = make_ctx(repo, approver=DenyAllApprover())
    (repo / "src" / "app.py").write_text("wip\n", encoding="utf-8")
    with pytest.raises(ApprovalRequired):
        default_registry().call("git.discard", {"paths": ["src/app.py"]}, ctx)
    assert (repo / "src" / "app.py").read_text() == "wip\n"


def test_pr_content_generated(repo: Path) -> None:
    ctx = make_ctx(repo)
    reg = default_registry()
    reg.call("git.create_branch", {"name": "feature/pr"}, ctx)
    (repo / "src" / "app.py").write_text("print('pr')\n", encoding="utf-8")
    reg.call("git.commit", {"message": "add pr feature"}, ctx)
    res = reg.call("git.pr_content", {"base": "main", "tests_summary": "unit: 3 passed"}, ctx)
    assert "add pr feature" in res.data["body"]
    assert "unit: 3 passed" in res.data["body"]
    assert res.data["head"] == "feature/pr"


def test_clone_blocked_by_network_policy(repo: Path) -> None:
    policy = Policy(network=NetworkPolicy(mode=NetworkMode.ALLOWLIST, allowed_hosts=["github.com"]))
    ctx = make_ctx(repo, policy, approver=AllowAllApprover())
    with pytest.raises(PermissionError, match="network policy"):
        default_registry().call(
            "git.clone", {"url": "https://evil.example.com/x.git", "directory": "vendor"}, ctx
        )


def test_git_tools_require_repository(ws: Path) -> None:
    ctx = make_ctx(ws)  # not a git repo
    with pytest.raises(Exception, match="not a Git repository"):
        default_registry().call("git.status", {}, ctx)


def test_diff_include_untracked_emits_new_files_without_staging(repo: Path) -> None:
    """REV-001: a brand new file is invisible to `git diff` until it is staged.

    The diff is synthesised from the file's contents rather than by running `git add -N`,
    so answering a read-only question leaves the index untouched (GIT-010).
    """
    ctx = make_ctx(repo)
    reg = default_registry()
    (repo / "src" / "new_module.py").write_text("def added():\n    return 1\n", encoding="utf-8")

    without = reg.call("git.diff", {}, ctx)
    assert "new_module.py" not in without.output
    assert without.data["untracked_included"] == []

    result = reg.call("git.diff", {"include_untracked": True}, ctx)
    assert result.data["untracked_included"] == ["src/new_module.py"]
    assert "+++ b/src/new_module.py" in result.output
    assert "--- /dev/null" in result.output
    assert "+def added():" in result.output

    # Nothing was staged.
    staged = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert staged.strip() == ""


def test_diff_include_untracked_skips_binary_and_oversized_files(repo: Path) -> None:
    ctx = make_ctx(repo)
    (repo / "blob.bin").write_bytes(b"\x00\x01\x02\xff\xfe\xfd")
    (repo / "huge.txt").write_text("x" * 300_000, encoding="utf-8")
    result = default_registry().call("git.diff", {"include_untracked": True}, ctx)
    assert result.data["untracked_included"] == []


def test_diff_include_untracked_is_ignored_for_staged_and_base_diffs(repo: Path) -> None:
    """Untracked files have no meaning against the index or a ref, so they are not mixed in."""
    ctx = make_ctx(repo)
    (repo / "src" / "new_module.py").write_text("def added():\n    return 1\n", encoding="utf-8")
    staged = default_registry().call("git.diff", {"include_untracked": True, "staged": True}, ctx)
    assert staged.data["untracked_included"] == []
    assert "new_module.py" not in staged.output


def test_diff_include_untracked_respects_the_path_filter(repo: Path) -> None:
    ctx = make_ctx(repo)
    (repo / "src" / "inside.py").write_text("def a():\n    return 1\n", encoding="utf-8")
    (repo / "outside.py").write_text("def b():\n    return 2\n", encoding="utf-8")
    result = default_registry().call("git.diff", {"include_untracked": True, "path": "src"}, ctx)
    assert result.data["untracked_included"] == ["src/inside.py"]
