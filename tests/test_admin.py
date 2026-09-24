"""Immediate disable and administrative history (SEC-007, ADM-003, ADM-004, ADM-010)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from aica.admin import ChangeRecord, ControlError, ControlPlane, TargetKind
from aica.cli import main
from aica.policy import Policy
from aica.tools import ToolContext, default_registry
from aica.tools.base import ToolNotAllowed
from tests.test_tools_fs import make_ctx

fastapi_testclient = pytest.importorskip("fastapi.testclient", reason="the api extra is needed")
TestClient = fastapi_testclient.TestClient

TOKEN = "test-token-abcdefghijklmnop"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "policy.toml").write_text(
        "version = 1\n[autonomy]\nmax_steps = 10\n[network]\nmode = 'deny'\n", encoding="utf-8"
    )
    return tmp_path


def _ctx(workspace: Path, actor: str = "admin") -> ToolContext:
    ctx = make_ctx(workspace, Policy())
    ctx.controls = ControlPlane(workspace, actor=actor)
    return ctx


# ------------------------------------------------------------------ the control plane
def test_disable_takes_effect_on_the_next_call_without_a_restart(workspace: Path) -> None:
    """The whole point: no policy edit, no reload, no restart."""
    ctx = _ctx(workspace)
    reg = default_registry()
    assert reg.call("fs.read", {"path": "src/app.py"}, ctx).ok

    ControlPlane(workspace, actor="oncall").disable(TargetKind.TOOL, "fs.read", "incident 4821")
    # Same context object, same registry - nothing was rebuilt.
    with pytest.raises(ToolNotAllowed, match="incident 4821"):
        reg.call("fs.read", {"path": "src/app.py"}, ctx)


def test_disabling_a_group_covers_every_tool_in_it(workspace: Path) -> None:
    """An operator switching off "database" should not have to enumerate five tools."""
    ctx = _ctx(workspace)
    ControlPlane(workspace).disable(TargetKind.TOOL, "database", "maintenance window")
    reg = default_registry()
    for tool in ("db.connections", "db.query", "db.execute"):
        assert reg.denial_reason(tool, ctx) is not None, tool
    assert reg.denial_reason("fs.read", ctx) is None


def test_enable_undoes_a_disable(workspace: Path) -> None:
    plane = ControlPlane(workspace, actor="oncall")
    plane.disable(TargetKind.TOOL, "shell.run", "incident")
    ctx = _ctx(workspace)
    assert default_registry().denial_reason("shell.run", ctx) is not None
    assert plane.enable(TargetKind.TOOL, "shell.run", "resolved") is True
    assert default_registry().denial_reason("shell.run", ctx) is None


def test_enable_cannot_grant_what_policy_withholds(workspace: Path) -> None:
    """The control plane only ever subtracts, or it would be a way around the policy file."""
    from aica.policy import AutonomyLimits

    policy = Policy(autonomy=AutonomyLimits(allowed_tools=["filesystem"]))
    ctx = make_ctx(workspace, policy)
    ctx.controls = ControlPlane(workspace)
    # Nothing was disabled, so there is nothing to enable ...
    assert ctx.controls.enable(TargetKind.TOOL, "shell.run") is False
    # ... and the policy denial stands regardless.
    assert "not in autonomy.allowed_tools" in str(
        default_registry().denial_reason("shell.run", ctx)
    )


def test_enable_reports_when_there_was_nothing_to_undo(workspace: Path) -> None:
    assert ControlPlane(workspace).enable(TargetKind.TOOL, "fs.read") is False


def test_disabled_tools_are_absent_from_the_advertised_list(workspace: Path) -> None:
    ctx = _ctx(workspace)
    ControlPlane(workspace).disable(TargetKind.TOOL, "shell.run", "incident")
    assert "shell.run" not in {t.name for t in default_registry().allowed(ctx)}


def test_a_second_disable_of_the_same_target_replaces_the_first(workspace: Path) -> None:
    plane = ControlPlane(workspace, actor="a")
    plane.disable(TargetKind.TOOL, "shell.run", "first")
    plane.disable(TargetKind.TOOL, "shell.run", "second")
    entries = [e for e in plane.load() if e.name == "shell.run"]
    assert len(entries) == 1 and entries[0].reason == "second"


def test_an_unreadable_control_file_raises_rather_than_disabling_nothing(
    workspace: Path,
) -> None:
    """Guessing "nothing is disabled" would bring back a thing switched off in an incident."""
    plane = ControlPlane(workspace)
    plane.disable(TargetKind.TOOL, "shell.run", "incident")
    plane.controls_path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(ControlError, match="refusing to treat that as"):
        plane.load()


def test_no_control_file_means_nothing_is_disabled(workspace: Path) -> None:
    assert ControlPlane(workspace).load() == []


# ------------------------------------------------------------------ ADM-010 history
def test_every_change_is_attributable(workspace: Path) -> None:
    ControlPlane(workspace, actor="alice").disable(TargetKind.MODEL, "m1", "suspected leak")
    ControlPlane(workspace, actor="bob").enable(TargetKind.MODEL, "m1", "cleared")
    history = ControlPlane(workspace).history()
    assert [(r.actor, r.action, r.name) for r in history] == [
        ("alice", "disable", "m1"),
        ("bob", "enable", "m1"),
    ]
    assert "suspected leak" in history[0].describe()


def test_history_is_append_only_and_survives_a_damaged_line(workspace: Path) -> None:
    plane = ControlPlane(workspace, actor="alice")
    plane.disable(TargetKind.TOOL, "shell.run", "one")
    with plane.history_path.open("a", encoding="utf-8") as fh:
        fh.write("{ corrupted\n")
    plane.disable(TargetKind.TOOL, "fs.write", "two")
    records = plane.history()
    assert [r.name for r in records] == ["shell.run", "fs.write"]


def test_history_records_round_trip(workspace: Path) -> None:
    ControlPlane(workspace, actor="alice").disable(TargetKind.INTEGRATION, "mcp-echo", "x")
    line = ControlPlane(workspace).history_path.read_text(encoding="utf-8").strip()
    assert ChangeRecord.model_validate_json(line).kind is TargetKind.INTEGRATION


# ------------------------------------------------------------------ models (ADM-003)
def test_a_disabled_model_stops_being_served_even_when_already_built(workspace: Path) -> None:
    """Checked before the cache, or "immediately" would mean "after the next restart"."""
    from aica.models.fake import ScriptedAdapter
    from aica.models.gateway import ModelDisabled, ModelGateway, ModelsConfig
    from aica.policy import NetworkPolicy

    plane = ControlPlane(workspace, actor="oncall")
    gateway = ModelGateway(config=ModelsConfig(), network=NetworkPolicy(), controls=plane)
    gateway.register("m1", ScriptedAdapter(name="m1"))
    assert gateway.get("m1") is not None  # built and cached

    plane.disable(TargetKind.MODEL, "m1", "provider incident")
    with pytest.raises(ModelDisabled, match="provider incident"):
        gateway.get("m1")


# ------------------------------------------------------------------ CLI
def run(workspace: Path, *args: str) -> int:
    return main(
        ["-w", str(workspace), "--policy", str(workspace / "config" / "policy.toml"), *args]
    )


def test_cli_disable_status_and_history(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        run(
            workspace,
            "--actor",
            "oncall",
            "admin",
            "disable",
            "tool",
            "shell.run",
            "--reason",
            "incident 4821",
        )
        == 0
    )
    assert "in effect from the next call" in capsys.readouterr().err

    assert run(workspace, "admin", "status") == 0
    assert "shell.run" in capsys.readouterr().out

    assert run(workspace, "admin", "history") == 0
    history = capsys.readouterr().out
    assert "oncall" in history and "disable" in history and "incident 4821" in history


def test_cli_enable_reports_when_nothing_was_disabled(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(workspace, "admin", "enable", "tool", "fs.read") == 1
    assert "was not disabled" in capsys.readouterr().err


def test_cli_status_says_so_when_nothing_is_disabled(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(workspace, "admin", "status") == 0
    assert "nothing is disabled" in capsys.readouterr().out


def test_cli_disabled_tool_is_refused_by_a_later_command(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """End to end through the real CLI: disable, then try to use it."""
    run(workspace, "admin", "disable", "tool", "shell", "--reason", "incident")
    capsys.readouterr()
    # 4 is `aica run`'s existing "refused" code, shared with approval denial.
    assert run(workspace, "run", "echo", "hello") == 4
    assert "disabled by" in capsys.readouterr().err


# ------------------------------------------------------------------ HTTP
@pytest.fixture
def client(workspace: Path) -> Iterator[TestClient]:
    from aica.api.app import ApiSettings, create_app

    app = create_app(
        ApiSettings(
            workspace=workspace,
            policy_file=str(workspace / "config" / "policy.toml"),
            token=TOKEN,
            actor="api-admin",
        )
    )
    with TestClient(app) as test_client:
        yield test_client


def test_admin_endpoints_require_a_token(client: TestClient) -> None:
    assert client.get("/admin/controls").status_code == 401
    assert client.post("/admin/controls", json={"kind": "tool", "name": "x"}).status_code == 401


def test_http_disable_then_the_tool_is_refused(client: TestClient, workspace: Path) -> None:
    response = client.post(
        "/admin/controls",
        json={"kind": "tool", "name": "shell", "reason": "incident 99"},
        headers=HEADERS,
    )
    assert response.status_code == 200 and response.json()["changed"] is True

    listed = client.get("/admin/controls", headers=HEADERS).json()["disabled"]
    assert [e["name"] for e in listed] == ["shell"]

    refused = client.post(
        "/commands",
        json={"tool": "shell.run", "arguments": {"command": "echo hi"}},
        headers=HEADERS,
    )
    assert refused.status_code in {403, 409}
    assert "incident 99" in refused.text


def test_http_enable_and_history(client: TestClient) -> None:
    client.post(
        "/admin/controls", json={"kind": "model", "name": "m1", "reason": "leak"}, headers=HEADERS
    )
    undo = client.post(
        "/admin/controls",
        json={"kind": "model", "name": "m1", "disabled": False, "reason": "cleared"},
        headers=HEADERS,
    )
    assert undo.json()["changed"] is True

    history = client.get("/admin/history", headers=HEADERS).json()["changes"]
    assert [h["action"] for h in history] == ["disable", "enable"]
    assert all(h["actor"] == "api-admin" for h in history)


def test_http_rejects_an_unknown_target_kind(client: TestClient) -> None:
    response = client.post(
        "/admin/controls", json={"kind": "spaceship", "name": "x"}, headers=HEADERS
    )
    assert response.status_code == 422


def test_http_reports_an_unreadable_control_file_rather_than_an_empty_list(
    client: TestClient, workspace: Path
) -> None:
    plane = ControlPlane(workspace)
    plane.disable(TargetKind.TOOL, "shell", "incident")
    plane.controls_path.write_text("{ broken", encoding="utf-8")
    assert client.get("/admin/controls", headers=HEADERS).status_code == 500


def test_control_file_is_written_atomically(workspace: Path) -> None:
    """A half-written control file read mid-incident is the one thing that must not happen."""
    plane = ControlPlane(workspace)
    plane.disable(TargetKind.TOOL, "shell.run", "incident")
    payload = json.loads(plane.controls_path.read_text(encoding="utf-8"))
    assert payload["version"] == 1 and len(payload["disabled"]) == 1
    assert list(plane.directory.glob("*.tmp")) == []
