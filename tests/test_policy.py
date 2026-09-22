import time
from pathlib import Path

import pytest

from aica.policy import (
    ActionCategory,
    BudgetExceeded,
    Cancelled,
    Environment,
    NetworkMode,
    NetworkPolicy,
    Policy,
    PolicyLoadError,
    RunBudget,
    load_policy,
)


def test_defaults_are_secure() -> None:
    p = Policy()
    assert p.network.mode is NetworkMode.DENY
    assert not p.network.is_host_allowed("example.com")
    assert p.approval.requires_approval(ActionCategory.DESTRUCTIVE)
    assert p.approval.requires_approval(ActionCategory.SECRET_ACCESS)
    assert p.git.is_protected("main") and not p.git.allow_force_push
    assert p.autonomy.environment is Environment.DEVELOPMENT


def test_repo_policy_file_loads() -> None:
    p = load_policy(Path(__file__).resolve().parents[1] / "config" / "policy.toml")
    assert p.version == 1
    assert p.autonomy.max_steps == 50


def test_repo_policy_never_opens_the_network_implicitly() -> None:
    """SAFE-005 as an invariant rather than a literal.

    This file's `[network]` mode legitimately changes - it became `allowlist` when
    api.deepseek.com was approved - so asserting `DENY` would only record which day the test
    was written. What must never change is that nothing is reachable unless it is named: an
    allowlist has to be non-empty and free of wildcards, because `*` would be deny-by-default
    in name only.
    """
    p = load_policy(Path(__file__).resolve().parents[1] / "config" / "policy.toml")
    assert p.network.mode in {NetworkMode.DENY, NetworkMode.ALLOWLIST}
    if p.network.mode is NetworkMode.DENY:
        assert not p.network.is_host_allowed("api.deepseek.com")
        return
    assert p.network.allowed_hosts, "allowlist mode with an empty list would allow nothing"
    assert all(host.strip() not in {"*", "*.*", ""} for host in p.network.allowed_hosts)
    assert not p.network.is_host_allowed("not-listed.example.com")


def test_missing_file_yields_defaults(tmp_path: Path) -> None:
    assert load_policy(tmp_path / "nope.toml") == Policy()


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    f = tmp_path / "policy.toml"
    f.write_text("[autonomy]\nmax_steps = 5\nallow_everything = true\n", encoding="utf-8")
    with pytest.raises(PolicyLoadError):
        load_policy(f)


def test_out_of_range_is_rejected(tmp_path: Path) -> None:
    f = tmp_path / "policy.toml"
    f.write_text("[autonomy]\nmax_steps = 0\n", encoding="utf-8")
    with pytest.raises(PolicyLoadError):
        load_policy(f)


def test_env_var_selects_policy_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = tmp_path / "p.toml"
    f.write_text("[autonomy]\nmax_steps = 7\n", encoding="utf-8")
    monkeypatch.setenv("AICA_POLICY_FILE", str(f))
    assert load_policy().autonomy.max_steps == 7


def test_network_allowlist_matching() -> None:
    n = NetworkPolicy(
        mode=NetworkMode.ALLOWLIST, allowed_hosts=["api.example.com", "*.internal.corp"]
    )
    assert n.is_host_allowed("api.example.com")
    assert n.is_host_allowed("API.EXAMPLE.COM")
    assert n.is_host_allowed("git.internal.corp")
    assert n.is_host_allowed("internal.corp")
    assert not n.is_host_allowed("evil.com")
    assert not n.is_host_allowed("notinternal.corp")


def test_budget_step_limit() -> None:
    b = RunBudget(max_steps=2, max_seconds=60)
    assert b.consume_step() == 1
    assert b.consume_step() == 2
    with pytest.raises(BudgetExceeded):
        b.consume_step()
    assert b.steps_remaining == 0


def test_budget_time_limit() -> None:
    b = RunBudget(max_steps=100, max_seconds=0.01)
    time.sleep(0.02)
    with pytest.raises(BudgetExceeded):
        b.check()


def test_cancellation_stops_loop() -> None:
    b = RunBudget(max_steps=100, max_seconds=60)
    b.consume_step()
    b.token.cancel("emergency stop")
    assert b.token.is_cancelled
    with pytest.raises(Cancelled, match="emergency stop"):
        b.consume_step()
    assert b.steps_used == 1  # the cancelled step was not consumed
