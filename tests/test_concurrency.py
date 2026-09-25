"""Concurrency-aware behaviour for multi-user, multi-repository sessions (NFR-003)."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aica.admin.rbac import NotPermitted, Role, RoleBinding
from aica.chat.session import Session, SessionConflict, SessionStore
from aica.cli import main
from aica.policy import Policy
from aica.policy.models import RbacPolicy
from aica.tools import ToolContext, default_registry
from aica.workspace.lease import LEASE_DIR, LEASE_FILE, RepositoryBusy, RepositoryLease

fastapi_testclient = pytest.importorskip("fastapi.testclient", reason="the api extra is needed")
TestClient = fastapi_testclient.TestClient

TOKEN = "test-token-abcdefghijklmnop"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "invoice.py").write_text("def total(x):\n    return sum(x)\n", "utf-8")
    (root / "config").mkdir()
    (root / "config" / "policy.toml").write_text(
        "version = 1\n[autonomy]\nmax_steps = 10\n[network]\nmode = 'deny'\n", encoding="utf-8"
    )
    return root


def _hold(root: Path, actor: str = "alice", ttl: float = 600) -> RepositoryLease:
    lease = RepositoryLease(root)
    lease.acquire(actor=actor, session_id="s1", task="refactor invoices", ttl_seconds=ttl)
    return lease


# ------------------------------------------------------------------ the lease
def test_a_second_task_on_the_same_repository_is_refused_and_told_who(workspace: Path) -> None:
    _hold(workspace)
    with pytest.raises(RepositoryBusy) as err:
        RepositoryLease(workspace).acquire(actor="bob", task="other", ttl_seconds=60)
    message = str(err.value)
    assert "alice" in message and "refactor invoices" in message and "worktree" in message


def test_release_frees_the_repository(workspace: Path) -> None:
    repository = RepositoryLease(workspace)
    lease = repository.acquire(actor="alice", ttl_seconds=60)
    assert repository.release(lease) is True
    assert repository.current() is None
    repository.acquire(actor="bob", ttl_seconds=60)  # does not raise


def test_release_never_removes_a_lease_someone_else_took_over(workspace: Path) -> None:
    repository = RepositoryLease(workspace)
    past = datetime.now(UTC) - timedelta(hours=2)
    stale = repository.acquire(actor="alice", ttl_seconds=1, now=past)
    fresh = repository.acquire(actor="bob", ttl_seconds=600)  # takes over the expired one
    assert repository.release(stale) is False
    current = repository.current()
    assert current is not None and current.holder == fresh.holder


def test_different_repositories_do_not_block_each_other(tmp_path: Path) -> None:
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    RepositoryLease(first).acquire(actor="alice", ttl_seconds=60)
    RepositoryLease(second).acquire(actor="bob", ttl_seconds=60)  # does not raise


def test_the_lease_expires_after_the_run_budget_and_grace(workspace: Path) -> None:
    repository = RepositoryLease(workspace)
    lease = repository.acquire(actor="alice", ttl_seconds=60)
    assert repository.current(lease.acquired_at + timedelta(seconds=61)) is not None
    assert repository.current(lease.expires_at) is None


def test_an_unreadable_lease_is_treated_as_held(workspace: Path) -> None:
    path = workspace / LEASE_DIR / LEASE_FILE
    path.parent.mkdir(parents=True)
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(RepositoryBusy, match="unreadable"):
        RepositoryLease(workspace).acquire(actor="bob", ttl_seconds=60)
    # ...until it is older than any bounded run could be.
    much_later = datetime.now(UTC) + timedelta(days=2)
    assert RepositoryLease(workspace).current(much_later) is None


def test_racing_threads_get_exactly_one_lease(workspace: Path) -> None:
    winners: list[str] = []
    barrier = threading.Barrier(12)

    def contend(name: str) -> None:
        barrier.wait()
        try:
            RepositoryLease(workspace).acquire(actor=name, ttl_seconds=60)
            winners.append(name)
        except RepositoryBusy:
            pass

    threads = [threading.Thread(target=contend, args=(f"u{i}",)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(winners) == 1


def test_racing_to_take_over_a_stale_lease_has_exactly_one_winner(workspace: Path) -> None:
    RepositoryLease(workspace).acquire(
        actor="crashed", ttl_seconds=1, now=datetime.now(UTC) - timedelta(hours=1)
    )
    winners: list[str] = []
    barrier = threading.Barrier(12)

    def contend(name: str) -> None:
        barrier.wait()
        try:
            RepositoryLease(workspace).acquire(actor=name, ttl_seconds=60)
            winners.append(name)
        except RepositoryBusy:
            pass

    threads = [threading.Thread(target=contend, args=(f"u{i}",)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(winners) == 1
    current = RepositoryLease(workspace).current()
    assert current is not None and current.actor == winners[0]


def test_a_lease_taken_by_another_process_is_seen_here(workspace: Path) -> None:
    """The point of a file lease: the CLI and a server are different processes."""
    script = (
        "import sys; from aica.workspace.lease import RepositoryLease;"
        "RepositoryLease(sys.argv[1]).acquire(actor='other-process', ttl_seconds=600)"
    )
    subprocess.run([sys.executable, "-c", script, str(workspace)], check=True, timeout=60)
    with pytest.raises(RepositoryBusy, match="other-process"):
        RepositoryLease(workspace).acquire(actor="here", ttl_seconds=60)


# ------------------------------------------------------------------ tool enforcement
def test_a_mutating_call_from_outside_the_run_is_refused_and_audited(workspace: Path) -> None:
    _hold(workspace)
    ctx = ToolContext.for_workspace(str(workspace))
    with pytest.raises(RepositoryBusy):
        default_registry().call("fs.write", {"path": "src/new.py", "content": "x = 1\n"}, ctx)
    assert not (workspace / "src" / "new.py").exists()
    blocked = [e for e in ctx.audit.sink.events if e.details.get("rule") == "NFR-003"]  # type: ignore[attr-defined]
    assert blocked and blocked[0].outcome.value == "blocked"


def test_a_read_only_call_is_unaffected_by_the_lease(workspace: Path) -> None:
    _hold(workspace)
    ctx = ToolContext.for_workspace(str(workspace))
    result = default_registry().call("fs.read", {"path": "src/invoice.py"}, ctx)
    assert "def total" in result.output


def test_the_holder_may_write(workspace: Path) -> None:
    repository = RepositoryLease(workspace)
    lease = repository.acquire(actor="alice", ttl_seconds=60)
    ctx = ToolContext.for_workspace(str(workspace))
    ctx.lease_holder = lease.holder
    default_registry().call("fs.write", {"path": "src/new.py", "content": "x = 1\n"}, ctx)
    assert (workspace / "src" / "new.py").read_text(encoding="utf-8") == "x = 1\n"


# ------------------------------------------------------------------ sessions
def test_saving_a_stale_copy_is_refused_rather_than_losing_a_turn(workspace: Path) -> None:
    store = SessionStore(workspace)
    session = Session(workspace=str(workspace))
    store.save(session)
    mine, theirs = store.load(session.session_id), store.load(session.session_id)
    theirs.add("user", "their turn")
    store.save(theirs)
    mine.add("user", "my turn")
    with pytest.raises(SessionConflict):
        store.save(mine)
    assert [t.content for t in store.load(session.session_id).turns] == ["their turn"]


def test_update_applies_the_change_to_the_latest_copy(workspace: Path) -> None:
    store = SessionStore(workspace)
    session = Session(workspace=str(workspace))
    store.save(session)
    stale = store.load(session.session_id)
    other = store.load(session.session_id)
    other.add("user", "saved meanwhile")
    store.save(other)
    store.update(stale, lambda latest: latest.add("assistant", "run result"))
    turns = [t.content for t in store.load(session.session_id).turns]
    assert turns == ["saved meanwhile", "run result"]


def test_concurrent_updates_all_survive(workspace: Path) -> None:
    store = SessionStore(workspace)
    session = Session(workspace=str(workspace))
    store.save(session)
    barrier = threading.Barrier(8)

    def append(i: int) -> None:
        barrier.wait()
        store.update(session.model_copy(), lambda latest: latest.add("user", f"turn {i}"))

    threads = [threading.Thread(target=append, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    saved = store.load(session.session_id)
    assert sorted(t.content for t in saved.turns) == sorted(f"turn {i}" for i in range(8))
    assert saved.revision == 9


def test_a_session_file_without_revision_or_owner_still_loads(workspace: Path) -> None:
    store = SessionStore(workspace)
    legacy = {"session_id": "legacy01", "workspace": str(workspace), "turns": []}
    store.path_for("legacy01").write_text(json.dumps(legacy), encoding="utf-8")
    loaded = store.load("legacy01")
    assert loaded.revision == 0 and loaded.owner is None
    store.save(loaded)  # and can be saved over


def _policy(**roles: Role) -> Policy:
    return Policy(
        rbac=RbacPolicy(
            enabled=True,
            bindings=[RoleBinding(principal=n, roles=[r]) for n, r in roles.items()],
        )
    )


def test_a_peer_may_not_open_another_users_session_with_rbac_on() -> None:
    policy = _policy(alice=Role.DEVELOPER, bob=Role.DEVELOPER, root=Role.ADMIN)
    session = Session(owner="alice")
    session.check_access(policy.principal("alice"))
    with pytest.raises(NotPermitted):
        session.check_access(policy.principal("bob"))
    session.check_access(policy.principal("root"))  # incident response still works


def test_ownership_is_inert_with_rbac_off_and_for_unowned_sessions() -> None:
    Session(owner="alice").check_access(Policy().principal("bob"))
    Session(owner=None).check_access(_policy(bob=Role.DEVELOPER).principal("bob"))


# ------------------------------------------------------------------ CLI
def run(workspace: Path, *args: str) -> int:
    return main(
        ["-w", str(workspace), "--policy", str(workspace / "config" / "policy.toml"), *args]
    )


WRITE_PLAN = json.dumps(
    {
        "summary": "add a module",
        "steps": [
            {
                "intent": "write it",
                "tool": "fs.write",
                "arguments": {"path": "src/added.py", "content": "VALUE = 1\n"},
            }
        ],
        "verification": [],
    }
)


def _scripted(monkeypatch: pytest.MonkeyPatch, plan: str = WRITE_PLAN) -> None:
    from aica import cli
    from aica.models.fake import ScriptedAdapter

    monkeypatch.setattr(
        cli, "_adapter", lambda args, ctx, task=None: (ScriptedAdapter([plan]), None)
    )


def test_cli_task_holds_the_lease_writes_and_releases_it(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scripted(monkeypatch)
    # Exit 1 is INCOMPLETE: the plan wrote a file and verified nothing, and TEST-009 does
    # not let that be called success. The write itself is what this test is about.
    assert run(workspace, "task", "add", "a", "module") == 1
    assert (workspace / "src" / "added.py").exists()  # the holder's own write was allowed
    assert RepositoryLease(workspace).current() is None  # and the lease was released


def test_cli_task_is_refused_while_another_task_holds_the_repository(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _scripted(monkeypatch)
    _hold(workspace)
    assert run(workspace, "task", "add", "a", "module") == 7
    assert "repository busy" in capsys.readouterr().err
    assert not (workspace / "src" / "added.py").exists()


def test_cli_new_sessions_are_owned_by_the_actor(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scripted(monkeypatch)
    assert run(workspace, "--actor", "carol", "task", "add", "a", "module") == 1
    (saved,) = SessionStore(workspace).list_sessions()
    assert SessionStore(workspace).load(saved["session_id"]).owner == "carol"


def test_cli_lease_status_and_break(workspace: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(workspace, "lease") == 0
    assert "free" in capsys.readouterr().out
    _hold(workspace)
    assert run(workspace, "lease") == 0
    status = capsys.readouterr().out
    assert "busy" in status and "alice" in status
    assert run(workspace, "lease", "--break") == 0
    assert "broken" in capsys.readouterr().out
    assert RepositoryLease(workspace).current() is None


def test_cli_breaking_a_lease_needs_administer(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (workspace / "config" / "policy.toml").write_text(
        "version = 1\n[autonomy]\nmax_steps = 10\n[network]\nmode = 'deny'\n"
        "[rbac]\nenabled = true\n[[rbac.bindings]]\nprincipal = 'dev'\nroles = ['developer']\n",
        encoding="utf-8",
    )
    _hold(workspace)
    assert run(workspace, "--actor", "dev", "lease", "--break") == 5
    assert RepositoryLease(workspace).current() is not None


# ------------------------------------------------------------------ HTTP
@pytest.fixture
def client(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    from aica.api.app import ApiSettings, create_app
    from aica.models.fake import ScriptedAdapter
    from aica.models.gateway import ModelGateway

    monkeypatch.setattr(
        ModelGateway, "get", lambda self, name=None: ScriptedAdapter([WRITE_PLAN], name="m")
    )
    app = create_app(
        ApiSettings(
            workspace=workspace,
            policy_file=str(workspace / "config" / "policy.toml"),
            token=TOKEN,
            actor="api-user",
        )
    )
    with TestClient(app) as test_client:
        yield test_client


def test_http_a_task_is_refused_while_the_repository_is_leased(
    client: TestClient, workspace: Path
) -> None:
    session_id = client.post("/sessions", json={}, headers=HEADERS).json()["session_id"]
    _hold(workspace)
    response = client.post(
        f"/sessions/{session_id}/tasks", json={"task": "add a module"}, headers=HEADERS
    )
    assert response.status_code == 409 and "repository busy" in response.json()["detail"]
    assert not (workspace / "src" / "added.py").exists()


def test_http_a_task_takes_and_releases_the_lease(client: TestClient, workspace: Path) -> None:
    session_id = client.post("/sessions", json={}, headers=HEADERS).json()["session_id"]
    started = client.post(
        f"/sessions/{session_id}/tasks", json={"task": "add a module"}, headers=HEADERS
    )
    assert started.status_code == 202, started.text
    task_id = started.json()["task_id"]
    client.app.state.manager.get(task_id).wait(timeout=30)  # type: ignore[attr-defined]
    assert (workspace / "src" / "added.py").exists()
    assert client.get("/admin/lease", headers=HEADERS).json()["busy"] is False


def test_http_a_file_edit_mid_run_is_refused(client: TestClient, workspace: Path) -> None:
    _hold(workspace)
    response = client.post(
        "/files",
        json={"tool": "fs.write", "arguments": {"path": "src/x.py", "content": "y = 2\n"}},
        headers=HEADERS,
    )
    assert response.status_code == 409
    assert not (workspace / "src" / "x.py").exists()


def test_http_lease_status_and_break(client: TestClient, workspace: Path) -> None:
    _hold(workspace)
    status = client.get("/admin/lease", headers=HEADERS).json()
    assert status["busy"] is True and status["lease"]["actor"] == "alice"
    broken = client.post("/admin/lease/break", headers=HEADERS).json()
    assert broken["broken"] is True
    assert client.get("/admin/lease", headers=HEADERS).json()["busy"] is False
    audit = client.get("/audit", params={"text": "lease broken"}, headers=HEADERS).json()
    assert audit["count"] >= 1


def test_http_sessions_are_owned_and_guarded_with_rbac_on(
    client: TestClient, workspace: Path
) -> None:
    session_id = client.post("/sessions", json={}, headers=HEADERS).json()["session_id"]
    assert SessionStore(workspace).load(session_id).owner == "api-user"
    # Hand the session to someone else, then turn RBAC on.
    store = SessionStore(workspace)
    session = store.load(session_id)
    session.owner = "alice"
    store.save(session)
    (workspace / "config" / "policy.toml").write_text(
        "version = 1\n[autonomy]\nmax_steps = 10\n[network]\nmode = 'deny'\n"
        "[rbac]\nenabled = true\n[[rbac.bindings]]\nprincipal = 'api-user'\n"
        "roles = ['developer']\n",
        encoding="utf-8",
    )
    response = client.post(
        f"/sessions/{session_id}/tasks", json={"task": "add a module"}, headers=HEADERS
    )
    assert response.status_code == 403


def test_http_never_publishes_the_holder_id(client: TestClient, workspace: Path) -> None:
    """The holder id lets a context write through the lease; it is not for display."""
    _hold(workspace)
    status = client.get("/admin/lease", headers=HEADERS).json()
    assert "holder" not in status["lease"]
    assert "holder" not in client.post("/admin/lease/break", headers=HEADERS).json()["lease"]
