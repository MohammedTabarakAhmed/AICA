"""Network destination policy and controlled secret injection (SEC-003, SEC-004)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from aica.approvals import AllowAllApprover, ApprovalRequired, DenyAllApprover
from aica.policy import NetworkMode, NetworkPolicy, Policy
from aica.policy.models import SecretDefinition, SecretPolicy
from aica.safety.network import check_destinations, extract_destinations
from aica.safety.secrets import SecretError, SecretStore, SecretUnavailable, scrub
from aica.tools import default_registry
from aica.tools.base import ToolArgumentError
from tests.test_tools_fs import make_ctx

WINDOWS = sys.platform == "win32"
ECHO_TOKEN = "echo %DEPLOY_TOKEN%" if WINDOWS else "echo $DEPLOY_TOKEN"


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    return tmp_path


def _net(*hosts: str) -> Policy:
    return Policy(network=NetworkPolicy(mode=NetworkMode.ALLOWLIST, allowed_hosts=list(hosts)))


# ------------------------------------------- SEC-003 network destinations for execution
def test_execution_refuses_a_destination_outside_the_allowlist(workspace: Path) -> None:
    """Approving "this command talks to the network" never meant approving where to."""
    ctx = make_ctx(workspace, _net("api.deepseek.com"), approver=AllowAllApprover())
    with pytest.raises(PermissionError, match="network policy denies evil.example.com"):
        default_registry().call("shell.run", {"command": "curl https://evil.example.com/x"}, ctx)


def test_execution_accepts_an_allowlisted_destination() -> None:
    policy = _net("api.deepseek.com")
    assert check_destinations("curl https://api.deepseek.com/v1", policy.network).ok


def test_execution_allows_loopback_without_an_allowlist_entry() -> None:
    """Reaching the project's own dev server is the development case; it never leaves the box."""
    policy = Policy(network=NetworkPolicy(mode=NetworkMode.DENY))
    for command in (
        "curl http://127.0.0.1:3000/health",
        "curl http://localhost:8000/",
        "wget http://[::1]:9000/x",
    ):
        assert check_destinations(command, policy.network).ok, command


def test_a_command_whose_destination_cannot_be_read_keeps_its_approval_gate() -> None:
    """`git push` resolves a remote this cannot see; guessing would be worse than the gate."""
    check = check_destinations("git push origin main", _net().network)
    assert check.ok and check.undetermined


def test_destination_check_ignores_commands_that_do_not_reach_the_network(
    workspace: Path,
) -> None:
    """A URL inside an echo is text, not a destination."""
    ctx = make_ctx(workspace, _net(), approver=DenyAllApprover())
    result = default_registry().call("shell.run", {"command": "echo https://example.com"}, ctx)
    assert result.ok and "example.com" in result.output


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("curl https://a.example.com/p?q=1", ["a.example.com"]),
        ("curl -u user:pw https://b.example.com", ["b.example.com"]),
        ("scp f user@c.example.com:/tmp", ["c.example.com"]),
        ("ssh admin@d.example.com", ["d.example.com"]),
        ("git push origin main", []),
    ],
)
def test_destination_extraction(command: str, expected: list[str]) -> None:
    assert extract_destinations(command) == expected


def test_denied_destination_is_audited(workspace: Path) -> None:
    ctx = make_ctx(workspace, _net("ok.example.com"), approver=AllowAllApprover())
    with pytest.raises(PermissionError):
        default_registry().call("shell.run", {"command": "curl https://bad.example.com"}, ctx)
    events = [e for e in ctx.audit.sink.events if e.outcome.value == "blocked"]  # type: ignore[attr-defined]
    assert any(e.details.get("rule") == "SEC-003" for e in events)


# -------------------------------------------------- SEC-004 controlled secret injection
def _with_secret() -> Policy:
    return Policy(
        secrets=SecretPolicy(
            definitions=[
                SecretDefinition(
                    name="deploy_token", env_var="DEPLOY_TOKEN", allowed_tools=["shell.run"]
                )
            ]
        )
    )


def test_a_secret_is_named_never_supplied(workspace: Path) -> None:
    """A value passed as an argument would leak before any gate ran, so there is no way to."""
    ctx = make_ctx(workspace, _with_secret())
    with pytest.raises(ToolArgumentError):
        default_registry().call(
            "shell.run", {"command": "echo hi", "secrets": [{"value": "s3cret"}]}, ctx
        )


def test_undeclared_secret_is_refused() -> None:
    store = SecretStore(SecretPolicy(), environ={"ANY": "x"})
    with pytest.raises(SecretError, match="no secret named"):
        store.prepare(["nope"], "shell.run")


def test_a_secret_cannot_reach_a_tool_policy_did_not_point_it_at() -> None:
    policy = SecretPolicy(
        definitions=[SecretDefinition(name="t", env_var="T", allowed_tools=["db.execute"])]
    )
    store = SecretStore(policy, environ={"T": "value-1234"})
    with pytest.raises(SecretError, match="may not be used by"):
        store.prepare(["t"], "shell.run")
    assert store.prepare(["t"], "db.execute").env == {"T": "value-1234"}


def test_a_declared_but_unset_secret_fails_loudly_rather_than_injecting_nothing() -> None:
    """A blank credential fails far away, looking like a bug in the command."""
    policy = SecretPolicy(
        definitions=[SecretDefinition(name="t", env_var="T", allowed_tools=["shell.run"])]
    )
    with pytest.raises(SecretUnavailable, match="not set in the environment"):
        SecretStore(policy, environ={}).prepare(["t"], "shell.run")


def test_secret_is_injected_under_the_name_the_tool_expects() -> None:
    policy = SecretPolicy(
        definitions=[
            SecretDefinition(
                name="gh",
                env_var="MY_LOCAL_PAT",
                inject_as="GITHUB_TOKEN",
                allowed_tools=["shell.*"],
            )
        ]
    )
    injection = SecretStore(policy, environ={"MY_LOCAL_PAT": "ghp_abcdef123456"}).prepare(
        ["gh"], "shell.run"
    )
    assert injection.env == {"GITHUB_TOKEN": "ghp_abcdef123456"}


def test_injection_repr_does_not_leak_the_value() -> None:
    policy = SecretPolicy(
        definitions=[SecretDefinition(name="t", env_var="T", allowed_tools=["shell.run"])]
    )
    injection = SecretStore(policy, environ={"T": "super-secret-value"}).prepare(["t"], "shell.run")
    assert "super-secret-value" not in repr(injection)
    assert "redacted" in repr(injection)


def test_describe_reports_availability_but_never_a_value() -> None:
    policy = SecretPolicy(
        definitions=[
            SecretDefinition(name="a", env_var="A", allowed_tools=["shell.run"]),
            SecretDefinition(name="b", env_var="B", allowed_tools=["shell.run"]),
        ]
    )
    described = SecretStore(policy, environ={"A": "value-here"}).describe()
    assert [d["available"] for d in described] == [True, False]
    assert "value-here" not in str(described)


def test_scrub_removes_an_echoed_secret_from_output() -> None:
    assert scrub("token is abcdef123456 ok", ["abcdef123456"]) == "token is [REDACTED] ok"
    # Too short to scrub safely: blanking it would eat ordinary text.
    assert scrub("the id is abc", ["abc"]) == "the id is abc"


def test_shell_injects_the_secret_and_scrubs_it_from_the_output(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: the command sees the value, and nothing that comes back does."""
    monkeypatch.setenv("DEPLOY_TOKEN", "tok-abcdef123456")
    ctx = make_ctx(workspace, _with_secret(), approver=AllowAllApprover())
    result = default_registry().call(
        "shell.run", {"command": ECHO_TOKEN, "secrets": ["deploy_token"]}, ctx
    )
    assert result.ok
    assert "tok-abcdef123456" not in result.output
    assert "[REDACTED]" in result.output


def test_a_command_without_the_secret_does_not_receive_it(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The host variable is not inherited: only a named, approved injection delivers it."""
    monkeypatch.setenv("DEPLOY_TOKEN", "tok-abcdef123456")
    ctx = make_ctx(workspace, _with_secret(), approver=AllowAllApprover())
    result = default_registry().call("shell.run", {"command": ECHO_TOKEN}, ctx)
    assert "tok-abcdef123456" not in result.output


def test_secret_injection_requires_approval(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DEPLOY_TOKEN", "tok-abcdef123456")
    ctx = make_ctx(workspace, _with_secret(), approver=DenyAllApprover())
    with pytest.raises(ApprovalRequired):
        default_registry().call(
            "shell.run", {"command": "echo hi", "secrets": ["deploy_token"]}, ctx
        )


def test_audit_records_the_secret_by_name_only(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DEPLOY_TOKEN", "tok-abcdef123456")
    ctx = make_ctx(workspace, _with_secret(), approver=AllowAllApprover())
    default_registry().call("shell.run", {"command": ECHO_TOKEN, "secrets": ["deploy_token"]}, ctx)
    dumped = "\n".join(e.model_dump_json() for e in ctx.audit.sink.events)  # type: ignore[attr-defined]
    assert "deploy_token" in dumped  # the name is recorded
    assert "tok-abcdef123456" not in dumped  # the value is not


def test_duplicate_secret_names_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate secret names"):
        SecretPolicy(
            definitions=[
                SecretDefinition(name="a", env_var="A"),
                SecretDefinition(name="a", env_var="B"),
            ]
        )


def test_a_secret_with_no_allowed_tools_reaches_nothing() -> None:
    """An operator who declared a secret and forgot where it goes gets the safe reading."""
    policy = SecretPolicy(definitions=[SecretDefinition(name="a", env_var="A")])
    with pytest.raises(SecretError, match="no tool"):
        SecretStore(policy, environ={"A": "value-1234"}).prepare(["a"], "shell.run")
