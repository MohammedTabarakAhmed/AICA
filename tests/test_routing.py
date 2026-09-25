"""Model registry, routing, fallback and pinning (MM-001..MM-014).

The provider calls here go through a real ``httpx`` transport that returns real HTTP
responses - 503s, malformed bodies, SSE streams that die halfway - so the fallback behaviour
is exercised against the same code path a live endpoint would take, without a network.

The properties that matter most are the negative ones: fallback must not trigger on a model
that answers *badly*, a pinned model must never be silently substituted, a model that cannot
do the work must not be routed to it, and a stream must not switch models once the caller has
started reading the answer.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from aica.audit import AuditLog, EventCategory, InMemoryAuditSink, Outcome
from aica.models.base import (
    Capability,
    ChatMessage,
    ModelError,
    ModelStatus,
    ModelUnavailable,
)
from aica.models.gateway import ModelConfig, ModelGateway, ModelsConfig, NetworkDenied
from aica.models.routing import (
    ModelRouter,
    RoutingConfig,
    RoutingError,
    RoutingRule,
    TaskKind,
)
from aica.policy.models import NetworkMode, NetworkPolicy

ALL_CAPS = [Capability.CHAT, Capability.STREAMING, Capability.TOOLS, Capability.EMBEDDINGS]
HOSTS = {"primary": "https://primary.example.com", "backup": "https://backup.example.com"}


def model(
    name: str,
    *,
    host: str = "primary",
    capabilities: list[Capability] | None = None,
    context_window: int = 128_000,
    status: ModelStatus = ModelStatus.APPROVED,
    enabled: bool = True,
    pinned: bool = False,
    version: str | None = None,
    adapter: str | None = None,
    api_key_env: str | None = None,
) -> ModelConfig:
    return ModelConfig(
        name=name,
        family="test",
        version=version or f"{name}-0001",
        base_url=HOSTS.get(host, host),
        capabilities=capabilities if capabilities is not None else list(ALL_CAPS),
        context_window=context_window,
        status=status,
        enabled=enabled,
        pinned=pinned,
        adapter=adapter,
        api_key_env=api_key_env,
        embedding_model="embed-1",
    )


def network() -> NetworkPolicy:
    return NetworkPolicy(
        mode=NetworkMode.ALLOWLIST,
        allowed_hosts=["primary.example.com", "backup.example.com"],
    )


def gateway(
    *models: ModelConfig,
    default: str | None = None,
    routing: RoutingConfig | None = None,
    handler: Any = None,
    policy: NetworkPolicy | None = None,
) -> ModelGateway:
    config = ModelsConfig(
        default=default or (models[0].name if models else None),
        models=list(models),
        routing=routing or RoutingConfig(),
    )
    transport = httpx.MockTransport(handler) if handler else None
    return ModelGateway(config, policy or network(), transport)


def router(gw: ModelGateway, audit: AuditLog | None = None) -> ModelRouter:
    return ModelRouter(gw, gw.routing, audit=audit, session_id="s1")


def audit_log() -> AuditLog:
    return AuditLog(InMemoryAuditSink(), actor="router-test")


def events(log: AuditLog) -> list[Any]:
    return [e for e in log.sink.events if e.category is EventCategory.MODEL_CALL]  # type: ignore[attr-defined]


# ---------------------------------------------------------------- MM-001 the registry


def test_the_registry_exposes_name_family_version_context_and_capabilities() -> None:
    """MM-001/MM-013: everything a user or a router needs in order to choose."""
    info = gateway(model("m1")).list_models()[0]
    assert (info.name, info.family, info.version) == ("m1", "test", "m1-0001")
    assert info.context_window == 128_000
    assert info.supports(Capability.CHAT) and not info.supports(Capability.FIM)
    assert info.status is ModelStatus.APPROVED
    assert "m1-0001" in info.describe() and "chat" in info.describe()


@pytest.mark.parametrize("status", [ModelStatus.PENDING, ModelStatus.BLOCKED])
def test_an_unapproved_model_may_not_be_used(status: ModelStatus) -> None:
    """MM-001: approval status is a gate, not a label."""
    gw = gateway(model("m1", status=status))
    with pytest.raises(ModelError, match=status.value):
        gw.config_for("m1")
    assert gw.list_models() == []
    assert gw.list_models(include_unusable=True)[0].status is status


def test_a_deprecated_model_still_works_by_name_but_is_never_routed_to() -> None:
    """An existing pin keeps working while nothing new drifts onto a deprecated model."""
    gw = gateway(
        model("old", status=ModelStatus.DEPRECATED),
        model("new"),
        default="new",
    )
    assert gw.config_for("old").name == "old"  # explicit selection still allowed
    selection = router(gw).select(TaskKind.CHAT)
    assert selection.name == "new"
    assert "old" not in selection.candidates


def test_a_disabled_model_is_refused() -> None:
    with pytest.raises(ModelError, match="disabled"):
        gateway(model("m1", enabled=False)).config_for("m1")


def test_duplicate_model_names_are_rejected() -> None:
    with pytest.raises(Exception, match="duplicate model name"):
        ModelsConfig(models=[model("m1"), model("m1")])


def test_an_unknown_model_is_named_with_what_is_configured() -> None:
    with pytest.raises(ModelError, match="unknown model 'nope'.*m1"):
        gateway(model("m1")).config_for("nope")


@pytest.mark.parametrize(
    "routing",
    [
        RoutingConfig(fallbacks=["ghost"]),
        RoutingConfig(rules=[RoutingRule(task=TaskKind.CHAT, model="ghost")]),
        RoutingConfig(rules=[RoutingRule(task=TaskKind.CHAT, model="m1", fallbacks=["ghost"])]),
    ],
)
def test_routing_may_not_reference_a_model_that_does_not_exist(routing: RoutingConfig) -> None:
    """Caught at load time, not when someone finally needs a model and finds nothing."""
    with pytest.raises(Exception, match="unknown model"):
        ModelsConfig(default="m1", models=[model("m1")], routing=routing)


def test_a_default_that_does_not_exist_is_rejected() -> None:
    with pytest.raises(Exception, match="unknown model"):
        ModelsConfig(default="ghost", models=[model("m1")])


# ---------------------------------------------------------------- MM-011 pinning


@pytest.mark.parametrize("version", ["model-latest", "chat-preview", "v1-stable", "current"])
def test_a_pinned_model_may_not_name_a_moving_alias(version: str) -> None:
    """MM-011: a pin that can change meaning tomorrow is not reproducible."""
    with pytest.raises(Exception, match="moving alias"):
        model("m1", pinned=True, version=version)


def test_a_pin_on_an_exact_version_is_accepted() -> None:
    config = model("m1", pinned=True, version="deepseek-chat-20250714")
    assert config.pinned and config.info().pinned
    assert "pinned" in config.info().describe()


def test_a_pinned_model_is_never_substituted() -> None:
    """MM-011 beats MM-010: this exact version or an error, never a quiet stand-in."""
    gw = gateway(
        model("pinned-one", pinned=True, version="exact-20250101"),
        model("other", host="backup"),
        default="pinned-one",
        routing=RoutingConfig(fallbacks=["other"]),
    )
    selection = router(gw).select(TaskKind.CHAT, requested="pinned-one")
    assert selection.candidates == ["pinned-one"]
    assert selection.fallbacks == []


def test_an_unpinned_request_still_gets_the_fallback_chain() -> None:
    gw = gateway(
        model("first"),
        model("second", host="backup"),
        default="first",
        routing=RoutingConfig(fallbacks=["second"]),
    )
    selection = router(gw).select(TaskKind.CHAT, requested="first")
    assert selection.candidates == ["first", "second"]
    assert "requested by name" in selection.reason


# ---------------------------------------------------------------- MM-014 adapters


def test_an_approved_adapter_is_what_the_request_asks_for() -> None:
    """MM-014: the LoRA is served under its own id; the base version stays on record."""
    config = model("tuned", adapter="sql-lora-v3", version="base-20250101")
    assert config.request_model == "sql-lora-v3"
    assert config.info().version == "base-20250101"
    assert config.info().adapter == "sql-lora-v3"
    assert "adapter sql-lora-v3" in config.info().describe()


def test_an_adapter_needs_an_approved_base_model() -> None:
    with pytest.raises(Exception, match="adapter"):
        model("tuned", adapter="sql-lora-v3", status=ModelStatus.PENDING)


def test_without_an_adapter_the_request_names_the_version() -> None:
    assert model("m1").request_model == "m1-0001"


# ---------------------------------------------------------------- MM-004 / MM-009 routing


def test_a_rule_routes_a_task_to_its_model() -> None:
    gw = gateway(
        model("generalist"),
        model("reviewer", host="backup"),
        default="generalist",
        routing=RoutingConfig(rules=[RoutingRule(task=TaskKind.REVIEW, model="reviewer")]),
    )
    assert router(gw).select(TaskKind.REVIEW).name == "reviewer"
    assert router(gw).select(TaskKind.CODING).name == "generalist"  # no rule -> default


def test_without_a_rule_the_project_default_is_used() -> None:
    gw = gateway(model("a"), model("b", host="backup"), default="b")
    selection = router(gw).select(TaskKind.GENERAL)
    assert selection.name == "b"
    assert "default" in selection.reason


def test_a_named_model_beats_the_rule() -> None:
    """MM-002: manual selection is respected, not treated as a hint."""
    gw = gateway(
        model("routed"),
        model("asked-for", host="backup"),
        default="routed",
        routing=RoutingConfig(rules=[RoutingRule(task=TaskKind.CHAT, model="routed")]),
    )
    assert router(gw).select(TaskKind.CHAT, requested="asked-for").name == "asked-for"


def test_a_model_that_cannot_do_the_work_is_not_routed_to_it() -> None:
    """Chat needs streaming; a model without it is rejected with the reason, not attempted."""
    gw = gateway(
        model("no-stream", capabilities=[Capability.CHAT]),
        model("streams", host="backup"),
        default="no-stream",
        routing=RoutingConfig(fallbacks=["streams"]),
    )
    selection = router(gw).select(TaskKind.CHAT)
    assert selection.name == "streams"
    assert "streaming" in selection.rejected["no-stream"]


def test_embedding_work_needs_an_embedding_model() -> None:
    gw = gateway(model("chat-only", capabilities=[Capability.CHAT, Capability.STREAMING]))
    with pytest.raises(RoutingError, match="embeddings"):
        router(gw).select(TaskKind.EMBEDDINGS)


def test_a_rule_can_demand_a_minimum_context() -> None:
    gw = gateway(
        model("small", context_window=8_000),
        model("large", host="backup", context_window=200_000),
        default="small",
        routing=RoutingConfig(
            rules=[
                RoutingRule(task=TaskKind.PLANNING, min_context=32_000, fallbacks=["large"]),
            ]
        ),
    )
    selection = router(gw).select(TaskKind.PLANNING)
    assert selection.name == "large"
    assert "context window 8000 < 32000" in selection.rejected["small"]


def test_a_caller_can_demand_a_minimum_context() -> None:
    gw = gateway(model("small", context_window=8_000))
    with pytest.raises(RoutingError, match="context window"):
        router(gw).select(TaskKind.CODING, min_context=64_000)


def test_a_rule_can_demand_an_extra_capability() -> None:
    gw = gateway(
        model("no-tools", capabilities=[Capability.CHAT, Capability.STREAMING]),
        routing=RoutingConfig(
            rules=[RoutingRule(task=TaskKind.CODING, require=[Capability.TOOLS])]
        ),
    )
    with pytest.raises(RoutingError, match="tools"):
        router(gw).select(TaskKind.CODING)


def test_two_rules_for_one_task_are_rejected() -> None:
    with pytest.raises(Exception, match="more than one routing rule"):
        RoutingConfig(
            rules=[
                RoutingRule(task=TaskKind.CHAT, model="a"),
                RoutingRule(task=TaskKind.CHAT, model="b"),
            ]
        )


def test_a_rule_that_says_nothing_is_rejected() -> None:
    with pytest.raises(Exception, match="says nothing"):
        RoutingRule(task=TaskKind.CHAT)


def test_a_candidate_named_twice_is_tried_once() -> None:
    gw = gateway(
        model("a"),
        model("b", host="backup"),
        default="a",
        routing=RoutingConfig(
            rules=[RoutingRule(task=TaskKind.CHAT, model="a", fallbacks=["b", "a"])],
            fallbacks=["b"],
        ),
    )
    assert router(gw).select(TaskKind.CHAT).candidates == ["a", "b"]


def test_with_nothing_configured_the_router_says_so() -> None:
    with pytest.raises(RoutingError, match="no approved model"):
        router(gateway()).select(TaskKind.CHAT)


# ---------------------------------------------------------------- MM-012 recording


def test_the_route_is_recorded_with_the_exact_version() -> None:
    log = audit_log()
    gw = gateway(model("m1", version="m1-20250714"), model("m2", host="backup"), default="m1")
    router(gw, log).select(TaskKind.PLANNING)
    recorded = events(log)
    assert recorded and recorded[0].model == "m1@m1-20250714"
    assert recorded[0].details["task"] == "planning"
    assert recorded[0].session_id == "s1"


def test_a_refusal_to_route_is_recorded_too() -> None:
    log = audit_log()
    with pytest.raises(RoutingError):
        router(gateway(model("m1", capabilities=[Capability.CHAT])), log).select(
            TaskKind.EMBEDDINGS
        )
    assert events(log)[0].outcome is Outcome.FAILURE


# ---------------------------------------------------------------- MM-010 fallback


def responder(behaviour: dict[str, Any]) -> Any:
    """A transport whose answer depends on which host the request went to."""

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host.split(".")[0]
        action = behaviour[host]
        if isinstance(action, int):
            return httpx.Response(action, json={"error": f"HTTP {action}"})
        if isinstance(action, httpx.Response):
            return action
        if callable(action):
            return action(request)
        if "embeddings" in request.url.path:
            return httpx.Response(200, json={"data": [{"index": 0, "embedding": [0.5, 0.25]}]})
        if "chat/completions" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "model": f"{action}-served",
                    "choices": [{"message": {"content": action}, "finish_reason": "stop"}],
                },
            )
        return httpx.Response(
            200, json={"model": action, "choices": [{"text": action, "finish_reason": "stop"}]}
        )

    return handler


def two_models(handler: Any, **kwargs: Any) -> ModelGateway:
    return gateway(
        model("primary"),
        model("backup", host="backup"),
        default="primary",
        routing=RoutingConfig(fallbacks=["backup"]),
        handler=handler,
        **kwargs,
    )


def test_an_unavailable_model_falls_back_to_the_next_one() -> None:
    """MM-010: a 503 from the first model is answered by the second."""
    log = audit_log()
    gw = two_models(responder({"primary": 503, "backup": "second"}))
    adapter = router(gw, log).get(TaskKind.CHAT)

    response = adapter.chat([ChatMessage(role="user", content="hi")])
    assert response.content == "second"
    assert adapter.last_used == "backup"  # type: ignore[attr-defined]
    assert adapter.attempts == ["primary", "backup"]  # type: ignore[attr-defined]

    outcomes = [(e.model, e.outcome) for e in events(log)]
    assert ("primary@primary-0001", Outcome.FAILURE) in outcomes
    assert ("backup@backup-0001", Outcome.SUCCESS) in outcomes


@pytest.mark.parametrize("code", [500, 502, 503, 429, 408])
def test_every_unavailability_code_triggers_the_fallback(code: int) -> None:
    gw = two_models(responder({"primary": code, "backup": "second"}))
    adapter = router(gw).get(TaskKind.CHAT)
    assert adapter.chat([ChatMessage(role="user", content="hi")]).content == "second"


def test_a_transport_failure_triggers_the_fallback() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    gw = two_models(responder({"primary": refuse, "backup": "second"}))
    assert (
        router(gw).get(TaskKind.CHAT).chat([ChatMessage(role="user", content="hi")]).content
        == "second"
    )


def test_a_bad_request_does_not_fall_back() -> None:
    """A 400 is this system's fault, not an outage. Falling back would hide it."""
    gw = two_models(responder({"primary": 400, "backup": "second"}))
    adapter = router(gw).get(TaskKind.CHAT)
    with pytest.raises(ModelError, match="HTTP 400"):
        adapter.chat([ChatMessage(role="user", content="hi")])
    assert adapter.attempts == ["primary"]  # type: ignore[attr-defined]


def test_a_malformed_answer_does_not_fall_back() -> None:
    """A model that answers badly is a bug to see, not a reason for a second opinion."""
    gw = two_models(
        responder({"primary": httpx.Response(200, json={"nonsense": True}), "backup": "second"})
    )
    with pytest.raises(ModelError, match="malformed"):
        router(gw).get(TaskKind.CHAT).chat([ChatMessage(role="user", content="hi")])


def test_when_everything_is_unavailable_the_error_names_each_attempt() -> None:
    gw = two_models(responder({"primary": 503, "backup": 500}))
    with pytest.raises(ModelUnavailable, match="primary.*backup") as exc:
        router(gw).get(TaskKind.CHAT).chat([ChatMessage(role="user", content="hi")])
    assert "2 tried" in str(exc.value)


def test_completion_and_embeddings_fall_back_too() -> None:
    gw = two_models(responder({"primary": 503, "backup": "second"}))
    routed = router(gw)
    assert routed.get(TaskKind.COMPLETION).complete("def f(", ")").content == "second"
    assert routed.get(TaskKind.EMBEDDINGS).embed(["a"]) == [[0.5, 0.25]]


def test_the_reported_model_is_the_one_asked_for_not_whoever_answered() -> None:
    """``info`` must not change under the caller mid-run; the response says who answered."""
    gw = two_models(responder({"primary": 503, "backup": "second"}))
    adapter = router(gw).get(TaskKind.CHAT)
    response = adapter.chat([ChatMessage(role="user", content="hi")])
    assert adapter.info.name == "primary"
    assert response.model == "second-served"  # MM-012: the exact model that answered


# ---------------------------------------------------------------- streaming


def sse(*chunks: str) -> httpx.Response:
    body = "".join(
        f'data: {{"model":"m","choices":[{{"delta":{{"content":"{c}"}}}}]}}\n\n' for c in chunks
    )
    return httpx.Response(
        200, text=body + "data: [DONE]\n\n", headers={"Content-Type": "text/event-stream"}
    )


def test_a_stream_falls_back_before_the_first_chunk() -> None:
    gw = two_models(responder({"primary": 503, "backup": lambda r: sse("he", "llo")}))
    adapter = router(gw).get(TaskKind.CHAT)
    chunks = list(adapter.stream([ChatMessage(role="user", content="hi")]))
    assert "".join(c.delta for c in chunks) == "hello"
    assert adapter.last_used == "backup"  # type: ignore[attr-defined]


def test_a_stream_does_not_switch_models_once_it_has_started() -> None:
    """Splicing two models' answers together would be worse than an honest failure."""

    def dies_midway(request: httpx.Request) -> httpx.Response:
        def body() -> Iterator[bytes]:
            yield b'data: {"model":"m","choices":[{"delta":{"content":"partial"}}]}\n\n'
            raise httpx.ReadError("connection dropped", request=request)

        return httpx.Response(200, content=body(), headers={"Content-Type": "text/event-stream"})

    gw = two_models(responder({"primary": dies_midway, "backup": lambda r: sse("whole")}))
    adapter = router(gw).get(TaskKind.CHAT)
    stream = adapter.stream([ChatMessage(role="user", content="hi")])
    assert next(stream).delta == "partial"
    with pytest.raises(Exception, match="(?i)dropped|read"):
        list(stream)
    # The backup was never tried: the caller already had part of the first model's answer.
    assert adapter.attempts == ["primary"]  # type: ignore[attr-defined]


def test_an_empty_answer_is_not_papered_over_with_another_model() -> None:
    def empty(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="", headers={"Content-Type": "text/event-stream"})

    gw = two_models(responder({"primary": empty, "backup": lambda r: sse("hi")}))
    adapter = router(gw).get(TaskKind.CHAT)
    # An empty stream still yields the adapter's terminal chunk, so there is nothing to
    # fall back from - the caller gets an empty answer from the primary, not a silent swap.
    chunks = list(adapter.stream([ChatMessage(role="user", content="x")]))
    assert [c.delta for c in chunks] == [""]
    assert adapter.last_used == "primary"  # type: ignore[attr-defined]


# ---------------------------------------------------------------- selection-time refusals


def test_a_model_whose_credential_is_missing_is_skipped_at_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A key that is not configured here makes that model unusable on this machine."""
    monkeypatch.delenv("AICA_TEST_MISSING_KEY", raising=False)
    gw = gateway(
        model("needs-key", api_key_env="AICA_TEST_MISSING_KEY"),
        model("no-key-needed", host="backup"),
        default="needs-key",
        routing=RoutingConfig(fallbacks=["no-key-needed"]),
        handler=responder({"primary": 200, "backup": "second"}),
    )
    selection = router(gw).select(TaskKind.CHAT)
    assert selection.name == "no-key-needed"
    assert "AICA_TEST_MISSING_KEY" in selection.rejected["needs-key"]


def test_a_single_candidate_reports_its_own_problem(monkeypatch: pytest.MonkeyPatch) -> None:
    """With nowhere to fall back to, the caller sees the real error, not a routing summary."""
    monkeypatch.delenv("AICA_TEST_MISSING_KEY", raising=False)
    gw = gateway(model("needs-key", api_key_env="AICA_TEST_MISSING_KEY"))
    with pytest.raises(ModelError, match="AICA_TEST_MISSING_KEY is not set"):
        router(gw).select(TaskKind.CHAT)


def test_an_endpoint_the_network_policy_refuses_is_not_used() -> None:
    """SAFE-005 still decides, and the error says which host and where to add it."""
    gw = gateway(
        model("elsewhere", host="https://not-listed.example.com"),
        policy=NetworkPolicy(mode=NetworkMode.ALLOWLIST, allowed_hosts=["primary.example.com"]),
    )
    with pytest.raises(NetworkDenied, match="not-listed.example.com"):
        router(gw).select(TaskKind.CHAT)


def test_every_candidate_denied_is_reported_as_a_routing_failure() -> None:
    gw = gateway(
        model("one", host="https://a.example.com"),
        model("two", host="https://b.example.com"),
        default="one",
        routing=RoutingConfig(fallbacks=["two"]),
        policy=NetworkPolicy(mode=NetworkMode.DENY),
    )
    with pytest.raises(RoutingError, match="one.*two"):
        router(gw).select(TaskKind.CHAT)


# ---------------------------------------------------------------- the shipped registry


def test_the_repository_registry_is_valid_and_declares_its_families() -> None:
    """MM-005/006/007: GLM, Kimi and DeepSeek are all configured, by configuration alone."""
    gw = ModelGateway.from_file(NetworkPolicy(), "config/models.toml")
    families = {i.family for i in gw.list_models(include_unusable=True)}
    assert {"deepseek", "glm", "kimi"} <= families
    # Only what is approved and deployed is usable today.
    assert [i.name for i in gw.list_models()] == ["deepseek-chat", "glm-4.7-flash"]
    assert gw.default_name() == "deepseek-chat"
    # And the routing rules in that file resolve to models that exist.
    assert gw.routing.rule_for(TaskKind.PLANNING) is not None


# ---------------------------------------------------------------- the remaining edges


def test_a_selection_describes_itself_with_its_chain() -> None:
    gw = two_models(responder({"primary": 200, "backup": "second"}))
    text = router(gw).select(TaskKind.CHAT).describe()
    assert "chat: primary (primary-0001)" in text
    assert "fallback: backup" in text


def test_a_fallback_chain_cannot_be_empty() -> None:
    from aica.models.routing import FallbackAdapter

    with pytest.raises(RoutingError, match="at least one model"):
        FallbackAdapter([], model("m1").info())


def test_the_chain_reports_its_members_in_order() -> None:
    gw = two_models(responder({"primary": 200, "backup": "second"}))
    assert router(gw).get(TaskKind.CHAT).names == ["primary", "backup"]  # type: ignore[attr-defined]


def test_a_fallback_naming_a_disabled_model_is_rejected_with_the_reason() -> None:
    gw = gateway(
        model("live"),
        model("shelved", host="backup", enabled=False),
        default="live",
        routing=RoutingConfig(fallbacks=["shelved"]),
    )
    selection = router(gw).select(TaskKind.CHAT)
    assert selection.candidates == ["live"]
    assert "disabled" in selection.rejected["shelved"]


def test_asking_for_a_model_that_does_not_exist_is_an_error() -> None:
    gw = gateway(model("m1"))
    with pytest.raises(RoutingError, match="unknown model 'ghost'"):
        router(gw).select(TaskKind.CHAT, requested="ghost")


class _Silent:
    """An adapter whose stream ends without yielding anything at all."""

    def __init__(self, info: Any) -> None:
        self._info = info

    @property
    def info(self) -> Any:
        return self._info

    def chat(self, messages: Any, **kwargs: Any) -> Any:
        raise ModelUnavailable("silent")

    def stream(self, messages: Any, **kwargs: Any) -> Iterator[Any]:
        return iter(())

    def complete(self, prefix: str, suffix: str = "", **kwargs: Any) -> Any:
        raise ModelUnavailable("silent")

    def embed(self, texts: list[str]) -> list[list[float]]:
        raise ModelUnavailable("silent")


def test_a_stream_that_yields_nothing_falls_back() -> None:
    """Nothing reached the caller, so switching models still produces one coherent answer."""
    gw = two_models(responder({"primary": 200, "backup": lambda r: sse("hello")}))
    gw.register("primary", _Silent(model("primary").info()))
    adapter = router(gw).get(TaskKind.CHAT)
    chunks = list(adapter.stream([ChatMessage(role="user", content="hi")]))
    assert "".join(c.delta for c in chunks) == "hello"
    assert adapter.last_used == "backup"  # type: ignore[attr-defined]


def test_when_every_model_is_silent_each_call_path_says_so() -> None:
    gw = two_models(responder({"primary": 200, "backup": 200}))
    gw.register("primary", _Silent(model("primary").info()))
    gw.register("backup", _Silent(model("backup").info()))
    routed = router(gw)
    with pytest.raises(ModelUnavailable, match="2 tried"):
        list(routed.get(TaskKind.CHAT).stream([ChatMessage(role="user", content="x")]))
    with pytest.raises(ModelUnavailable, match="2 tried"):
        routed.get(TaskKind.COMPLETION).complete("def f(")
    with pytest.raises(ModelUnavailable, match="2 tried"):
        routed.get(TaskKind.EMBEDDINGS).embed(["a"])
