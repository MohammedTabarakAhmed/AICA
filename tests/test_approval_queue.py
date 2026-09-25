"""The durable approval queue (API-014, UX-008, SEC-006)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aica.admin.approval_queue import (
    ApprovalError,
    ApprovalQueue,
    DecisionState,
    QueueingApprover,
)
from aica.admin.rbac import NotPermitted, Role, RoleBinding, SeparationOfDuties
from aica.approvals import ApprovalRequest
from aica.cli import main
from aica.policy import ActionCategory, Policy
from aica.policy.models import RbacPolicy

fastapi_testclient = pytest.importorskip("fastapi.testclient", reason="the api extra is needed")
TestClient = fastapi_testclient.TestClient

TOKEN = "test-token-abcdefghijklmnop"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

REQUEST = ApprovalRequest(
    action="rm -rf build/",
    categories=(ActionCategory.DESTRUCTIVE,),
    tool="shell.run",
    details={"cwd": "."},
)


def _rbac(**roles: Role) -> RbacPolicy:
    return RbacPolicy(
        enabled=True,
        bindings=[RoleBinding(principal=n, roles=[r]) for n, r in roles.items()],
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "policy.toml").write_text(
        "version = 1\n[autonomy]\nmax_steps = 10\n[network]\nmode = 'deny'\n", encoding="utf-8"
    )
    return tmp_path


# ------------------------------------------------------------------ the queue
def test_a_submitted_request_is_pending_and_runs_nothing(workspace: Path) -> None:
    queue = ApprovalQueue(workspace)
    entry = queue.submit(REQUEST, requested_by="dana")
    assert entry.state is DecisionState.PENDING
    assert entry.requested_by == "dana" and entry.tool == "shell.run"
    assert [e.id for e in queue.pending()] == [entry.id]


def test_an_approver_decides_and_the_record_is_kept(workspace: Path) -> None:
    queue = ApprovalQueue(workspace)
    entry = queue.submit(REQUEST, requested_by="dana")
    policy = Policy(rbac=_rbac(dana=Role.DEVELOPER, ava=Role.APPROVER))
    decided = queue.decide(entry.id, policy.principal("ava"), approved=True, note="fine")
    assert decided.state is DecisionState.APPROVED
    assert decided.decided_by == "ava" and decided.note == "fine"
    assert queue.pending() == []  # no longer waiting
    assert [e.state for e in queue.all()] == [DecisionState.APPROVED]


def test_the_requester_may_not_decide_their_own_request(workspace: Path) -> None:
    """SEC-006, checked against the recorded requester rather than trusted from the call."""
    queue = ApprovalQueue(workspace)
    entry = queue.submit(REQUEST, requested_by="dana")
    policy = Policy(rbac=_rbac(dana=Role.APPROVER))
    with pytest.raises(SeparationOfDuties, match="may not also confirm"):
        queue.decide(entry.id, policy.principal("dana"), approved=True)


def test_deciding_needs_the_approve_permission(workspace: Path) -> None:
    """ "Approved" must mean approved by someone entitled to, not by whoever ran the CLI."""
    queue = ApprovalQueue(workspace)
    entry = queue.submit(REQUEST, requested_by="dana")
    policy = Policy(rbac=_rbac(dana=Role.DEVELOPER, nina=Role.VIEWER))
    with pytest.raises(NotPermitted, match="'approve' permission"):
        queue.decide(entry.id, policy.principal("nina"), approved=True)


def test_a_decision_is_final(workspace: Path) -> None:
    """An audit trail whose approvals can be edited afterwards answers nothing."""
    queue = ApprovalQueue(workspace)
    entry = queue.submit(REQUEST, requested_by="dana")
    policy = Policy(rbac=_rbac(dana=Role.DEVELOPER, ava=Role.APPROVER, bo=Role.APPROVER))
    queue.decide(entry.id, policy.principal("ava"), approved=False)
    with pytest.raises(ApprovalError, match="already rejected"):
        queue.decide(entry.id, policy.principal("bo"), approved=True)


def test_an_unanswered_request_expires(workspace: Path) -> None:
    """An approval nobody answered is not an approval."""
    queue = ApprovalQueue(workspace, ttl_hours=1)
    entry = queue.submit(REQUEST, requested_by="dana")
    later = datetime.now(UTC) + timedelta(hours=2)
    assert queue.pending(now=later) == []
    assert queue.get(entry.id, now=later).state is DecisionState.EXPIRED


def test_an_expired_request_cannot_be_decided(workspace: Path) -> None:
    queue = ApprovalQueue(workspace, ttl_hours=1)
    entry = queue.submit(REQUEST, requested_by="dana")
    policy = Policy(rbac=_rbac(ava=Role.APPROVER))
    later = datetime.now(UTC) + timedelta(hours=2)
    with pytest.raises(ApprovalError, match="expired"):
        queue.decide(entry.id, policy.principal("ava"), approved=True, now=later)


def test_deciding_an_unknown_request_is_an_error(workspace: Path) -> None:
    policy = Policy(rbac=_rbac(ava=Role.APPROVER))
    with pytest.raises(ApprovalError, match="no approval request"):
        ApprovalQueue(workspace).decide("nope", policy.principal("ava"), approved=True)


def test_an_unreadable_queue_raises_rather_than_reporting_nothing_pending(
    workspace: Path,
) -> None:
    queue = ApprovalQueue(workspace)
    queue.submit(REQUEST, requested_by="dana")
    queue.path.write_text("{ broken", encoding="utf-8")
    with pytest.raises(ApprovalError, match="refusing to treat that as"):
        queue.pending()


def test_the_summary_leads_with_the_categories(workspace: Path) -> None:
    """UX-008: the category is the reason a human is being asked."""
    entry = ApprovalQueue(workspace).submit(REQUEST, requested_by="dana")
    assert entry.describe().startswith("[destructive]")
    assert "rm -rf build/" in entry.describe()


# ------------------------------------------------------------------ the approver
def test_the_queueing_approver_records_and_still_denies(workspace: Path) -> None:
    """Approving is a human act; an approver that could say yes defeats its own gate."""
    queue = ApprovalQueue(workspace)
    approver = QueueingApprover(queue, requested_by="agent")
    assert approver.approve(REQUEST) is False
    assert len(queue.pending()) == 1
    assert approver.submitted[0].requested_by == "agent"


def test_a_queue_that_cannot_be_written_still_denies(workspace: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    queue = ApprovalQueue(workspace)

    def boom(*_: object, **__: object) -> None:
        raise ApprovalError("disk full")

    monkeypatch.setattr(ApprovalQueue, "submit", boom)
    assert QueueingApprover(queue, requested_by="agent").approve(REQUEST) is False


# ------------------------------------------------------------------ CLI
def run(workspace: Path, *args: str) -> int:
    return main(
        ["-w", str(workspace), "--policy", str(workspace / "config" / "policy.toml"), *args]
    )


def test_cli_request_list_and_approve(workspace: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        run(
            workspace,
            "--actor",
            "dana",
            "approvals",
            "request",
            "rm -rf build",
            "--category",
            "destructive",
            "--tool",
            "shell.run",
        )
        == 0
    )
    request_id = capsys.readouterr().out.strip()

    assert run(workspace, "approvals", "list") == 0
    listing = capsys.readouterr().out
    assert "APPROVAL REQUEST(S)" in listing and "[destructive]" in listing

    assert run(workspace, "--actor", "ava", "approvals", "approve", request_id) == 0
    captured = capsys.readouterr()
    assert "approved by ava" in captured.out
    assert "nothing was run" in captured.err


def test_cli_list_says_so_when_empty(workspace: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(workspace, "approvals", "list") == 0
    assert "no approvals pending" in capsys.readouterr().out


def test_cli_reject_records_the_decision(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(workspace, "--actor", "dana", "approvals", "request", "drop", "table", "users")
    request_id = capsys.readouterr().out.strip()
    assert run(workspace, "--actor", "ava", "approvals", "reject", request_id, "--note", "no") == 0
    assert "rejected by ava" in capsys.readouterr().out


def test_cli_deciding_an_unknown_request_fails_cleanly(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(workspace, "approvals", "approve", "nosuchid") == 3
    assert "no approval request" in capsys.readouterr().err


# ------------------------------------------------------------------ HTTP
@pytest.fixture
def client(workspace: Path) -> Iterator[TestClient]:
    from aica.api.app import ApiSettings, create_app

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


def test_http_submit_list_and_decide(client: TestClient) -> None:
    created = client.post(
        "/approvals",
        json={"action": "rm -rf build", "tool": "shell.run", "categories": ["destructive"]},
        headers=HEADERS,
    )
    assert created.status_code == 201
    request_id = created.json()["id"]

    listed = client.get("/approvals", headers=HEADERS).json()
    assert listed["count"] == 1
    assert listed["summaries"][0].startswith("[destructive]")

    decided = client.post(
        f"/approvals/{request_id}", json={"approved": True, "note": "ok"}, headers=HEADERS
    )
    assert decided.status_code == 200
    assert decided.json()["state"] == "approved"
    assert client.get("/approvals", headers=HEADERS).json()["count"] == 0


def test_http_rejects_an_unknown_category(client: TestClient) -> None:
    response = client.post(
        "/approvals", json={"action": "x", "categories": ["nonsense"]}, headers=HEADERS
    )
    assert response.status_code == 422


def test_http_deciding_twice_is_refused(client: TestClient) -> None:
    request_id = client.post("/approvals", json={"action": "x"}, headers=HEADERS).json()["id"]
    first = client.post(f"/approvals/{request_id}", json={"approved": True}, headers=HEADERS)
    assert first.status_code == 200
    second = client.post(f"/approvals/{request_id}", json={"approved": False}, headers=HEADERS)
    assert second.status_code == 409


def test_http_approvals_require_a_token(client: TestClient) -> None:
    assert client.get("/approvals").status_code == 401
    assert client.post("/approvals", json={"action": "x"}).status_code == 401


def test_cli_an_action_with_dashes_is_accepted_after_the_separator(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A shell action is usually `rm -rf ...`; argparse reads `-rf` as an option without `--`."""
    code = run(workspace, "approvals", "request", "--tool", "shell.run", "--", "rm", "-rf", "build")
    assert code == 0
    capsys.readouterr()
    assert run(workspace, "approvals", "list") == 0
    assert "shell.run: rm -rf build" in capsys.readouterr().out
