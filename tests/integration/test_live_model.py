"""The model layer against a real provider (MM-002/003/008/012, NFR-001).

Everything else in this suite verifies model behaviour against a scripted adapter, which
proves the code around the model but not that the HTTP adapter, the credential handling, the
network policy and the streaming parser work against a real endpoint.

This module closes that gap and is **skipped unless a credential is configured**, so the suite
stays runnable offline and in CI:

    set DEEPSEEK_API_KEY=...            (or the variable named in config/models.toml)
    set AICA_TEST_LIVE_MODEL=1          (an explicit opt-in: these calls cost money)

To verify a model other than the default, name it and the variable holding its key:

    set AICA_TEST_LIVE_MODEL_NAME=glm-4.7-flash

The variable holding the key is read from that model's ``api_key_env`` in config/models.toml
(``AICA_TEST_LIVE_MODEL_KEY_ENV`` still overrides it). A model with no ``api_key_env`` - the
local Ollama entry - needs only the opt-in and a running server:

    set AICA_TEST_LIVE_MODEL_NAME=qwen2.5-coder-7b

The opt-in is separate from the key on purpose: a key may be present in the environment for
other reasons, and a test run should never spend someone's credit by accident. Prompts are
tiny and `max_tokens` is capped, so a full run costs a fraction of a cent.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aica.models.base import Capability, ChatMessage, ModelError
from aica.models.gateway import ModelGateway
from aica.policy import load_policy
from aica.policy.models import NetworkMode, NetworkPolicy

pytestmark = pytest.mark.integration

LIVE = os.environ.get("AICA_TEST_LIVE_MODEL") == "1"
MODEL = os.environ.get("AICA_TEST_LIVE_MODEL_NAME") or None  # None: the configured default
MODELS_FILE = "config/models.toml"
POLICY_FILE = "config/policy.toml"
# Only read the registry once opted in, so an offline run does no work here at all.
KEY_ENV = os.environ.get("AICA_TEST_LIVE_MODEL_KEY_ENV") or (
    ModelGateway.from_file(NetworkPolicy(), MODELS_FILE).config_for(MODEL).api_key_env
    if LIVE
    else None
)

if not LIVE or (KEY_ENV and not os.environ.get(KEY_ENV)):  # pragma: no cover - normal skip
    needs = f"set {KEY_ENV} and " if KEY_ENV else ""
    pytest.skip(
        f"{needs}set AICA_TEST_LIVE_MODEL=1 to verify against a real provider",
        allow_module_level=True,
    )


@pytest.fixture(scope="module")
def adapter():  # type: ignore[no-untyped-def]
    policy = load_policy(POLICY_FILE)
    gateway = ModelGateway.from_file(policy.network, MODELS_FILE)
    return gateway.get(MODEL)


# ---------------------------------------------------------------- MM-003/012


def test_a_real_chat_call_answers_and_reports_its_model(adapter) -> None:  # type: ignore[no-untyped-def]
    """MM-003/MM-012: a real completion, and the exact served model recorded with it."""
    response = adapter.chat(
        [
            ChatMessage(role="system", content="Answer with one word only."),
            ChatMessage(role="user", content="What is 21 plus 21? Reply with the number only."),
        ],
        temperature=0.0,
        max_tokens=16,
    )
    assert "42" in response.content
    assert response.model, "the served model id must be recorded (MM-012)"
    assert response.finish_reason


def test_streaming_yields_progressive_chunks(adapter) -> None:  # type: ignore[no-untyped-def]
    """NFR-001: progressive output from a real endpoint, not one buffered reply."""
    chunks = list(
        adapter.stream(
            [ChatMessage(role="user", content="Count from 1 to 5, separated by spaces.")],
            temperature=0.0,
            max_tokens=40,
        )
    )
    assert len(chunks) > 1, "a streamed reply should arrive in more than one chunk"
    text = "".join(c.delta for c in chunks)
    assert "1" in text and "5" in text
    assert chunks[-1].done is True
    assert any(c.model for c in chunks)


def test_capabilities_are_reported(adapter) -> None:  # type: ignore[no-untyped-def]
    """MM-013: what the configured model says it can do."""
    info = adapter.info
    assert info.name and info.version
    assert info.supports(Capability.CHAT)
    assert info.context_window > 0


# ---------------------------------------------------------------- the agent, for real


def test_the_planner_produces_a_usable_plan_from_a_real_model(tmp_path: Path) -> None:
    """AG-002 against a real model: the JSON plan protocol has to survive a real reply."""
    from aica.agent.plan import Planner
    from aica.approvals import DenyAllApprover
    from aica.audit import AuditLog, InMemoryAuditSink
    from aica.policy import Policy
    from aica.tools import ToolContext, default_registry
    from aica.workspace import WorkspaceGuard

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "calc.py").write_text(
        "def divide(a, b):\n    return a / b\n", encoding="utf-8"
    )
    policy = Policy()
    ctx = ToolContext(
        workspace=WorkspaceGuard(tmp_path, policy.autonomy.allowed_directories),
        policy=policy,
        audit=AuditLog(InMemoryAuditSink(), actor="live-model-test"),
        approver=DenyAllApprover(),
    )
    gateway = ModelGateway.from_file(load_policy(POLICY_FILE).network, MODELS_FILE)
    plan = Planner(gateway.get(MODEL), default_registry()).create(
        "read src/calc.py and report whether divide guards against a zero divisor", ctx
    )
    assert plan.steps, "a real model must produce at least one step"
    assert all(s.tool for s in plan.steps)
    assert plan.model, "the plan records which model produced it"


# ---------------------------------------------------------------- SAFE-005


def test_network_policy_still_blocks_an_unlisted_host() -> None:
    """The allowlist is what permits the call, and it permits only what it lists."""
    from aica.models.gateway import ModelsConfig

    config = ModelsConfig.model_validate(
        {
            "default": "elsewhere",
            "models": [
                {
                    "name": "elsewhere",
                    "family": "test",
                    "version": "x",
                    "base_url": "https://not-allowed.example.com",
                }
            ],
        }
    )
    gateway = ModelGateway(
        config, NetworkPolicy(mode=NetworkMode.ALLOWLIST, allowed_hosts=["api.deepseek.com"])
    )
    with pytest.raises((PermissionError, ModelError), match="(?i)not allowed|policy"):
        gateway.get("elsewhere")
