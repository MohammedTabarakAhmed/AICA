import json

import httpx
import pytest

from aica.models import (
    Capability,
    ChatMessage,
    ModelConfig,
    ModelError,
    ModelGateway,
    ModelsConfig,
    ModelUnavailable,
    NetworkDenied,
    OpenAICompatibleAdapter,
    OpenAICompatibleConfig,
    ScriptedAdapter,
)
from aica.models.base import ModelInfo
from aica.policy.models import NetworkMode, NetworkPolicy

INFO = ModelInfo(
    name="test-model",
    family="deepseek",
    version="deepseek-chat",
    context_window=1000,
    capabilities=[Capability.CHAT, Capability.STREAMING, Capability.EMBEDDINGS],
)


def _adapter(handler, info=INFO, **kwargs):  # type: ignore[no-untyped-def]
    cfg = OpenAICompatibleConfig(
        base_url="https://api.example.com", model="deepseek-chat", **kwargs
    )
    return OpenAICompatibleAdapter(cfg, info, transport=httpx.MockTransport(handler))


def test_chat_parses_response_and_records_model() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content)["messages"][0]["content"] == "hi"
        return httpx.Response(
            200,
            json={
                "model": "deepseek-chat-0711",
                "choices": [{"message": {"content": "hello"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 1},
            },
        )

    r = _adapter(handler).chat([ChatMessage(role="user", content="hi")])
    assert r.content == "hello"
    assert r.model == "deepseek-chat-0711"  # MM-012 exact version
    assert r.usage.prompt_tokens == 3


def test_streaming_yields_deltas_then_done() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = (
            'data: {"model":"m","choices":[{"delta":{"content":"he"}}]}\n\n'
            'data: {"model":"m","choices":[{"delta":{"content":"llo"}}]}\n\n'
            'data: {"model":"m","choices":[{"delta":{},"finish_reason":"stop"}]}\n\n'
            "data: [DONE]\n\n"
        )
        return httpx.Response(200, text=body, headers={"Content-Type": "text/event-stream"})

    chunks = list(_adapter(handler).stream([ChatMessage(role="user", content="x")]))
    assert "".join(c.delta for c in chunks) == "hello"
    assert chunks[-1].done


def test_server_errors_map_to_model_unavailable() -> None:
    for status in (500, 503, 429):
        with pytest.raises(ModelUnavailable):
            _adapter(lambda r, s=status: httpx.Response(s, text="nope")).chat(
                [ChatMessage(role="user", content="x")]
            )


def test_client_error_is_model_error() -> None:
    with pytest.raises(ModelError, match="HTTP 400"):
        _adapter(lambda r: httpx.Response(400, text="bad")).chat(
            [ChatMessage(role="user", content="x")]
        )


def test_transport_failure_is_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(ModelUnavailable):
        _adapter(handler).chat([ChatMessage(role="user", content="x")])


def test_missing_credential_env_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TEST_KEY", raising=False)
    with pytest.raises(ModelError, match="TEST_KEY"):
        _adapter(lambda r: httpx.Response(200, json={}), api_key_env="TEST_KEY")


def test_credential_is_sent_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_KEY", "secret-value")
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization", "")
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    _adapter(handler, api_key_env="TEST_KEY").chat([ChatMessage(role="user", content="x")])
    assert seen["auth"] == "Bearer secret-value"


def test_completion_falls_back_to_chat_without_fim() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/chat/completions")
        return httpx.Response(200, json={"choices": [{"message": {"content": "    return a + b"}}]})

    r = _adapter(handler).complete("def add(a, b):\n", "\n")
    assert r.content.strip() == "return a + b"


def test_completion_uses_fim_endpoint_when_supported() -> None:
    info = INFO.model_copy(update={"capabilities": [Capability.CHAT, Capability.FIM]})

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/completions") and not request.url.path.endswith(
            "/chat/completions"
        )
        return httpx.Response(200, json={"choices": [{"text": "x = 1"}]})

    assert _adapter(handler, info=info).complete("pre", "suf").content == "x = 1"


def test_embeddings_are_ordered_by_index() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {"index": 1, "embedding": [0.0, 1.0]},
                    {"index": 0, "embedding": [1.0, 0.0]},
                ]
            },
        )

    vecs = _adapter(handler, embedding_model="emb").embed(["a", "b"])
    assert vecs == [[1.0, 0.0], [0.0, 1.0]]


# ---------------------------------------------------------------- gateway


def _cfg(host: str = "api.example.com") -> ModelsConfig:
    return ModelsConfig(
        default="m1",
        models=[
            ModelConfig(
                name="m1", family="deepseek", version="deepseek-chat", base_url=f"https://{host}"
            ),
            ModelConfig(
                name="m2",
                family="glm",
                version="glm-4",
                base_url="https://glm.example.com",
                enabled=False,
            ),
        ],
    )


def test_gateway_enforces_network_policy() -> None:
    denied = ModelGateway(_cfg(), NetworkPolicy())  # deny-by-default
    with pytest.raises(NetworkDenied):
        denied.get()
    allowed = ModelGateway(
        _cfg(), NetworkPolicy(mode=NetworkMode.ALLOWLIST, allowed_hosts=["api.example.com"])
    )
    assert allowed.get().info.name == "m1"


def test_gateway_lists_only_enabled_and_respects_default() -> None:
    gw = ModelGateway(
        _cfg(), NetworkPolicy(mode=NetworkMode.ALLOWLIST, allowed_hosts=["api.example.com"])
    )
    assert [m.name for m in gw.list_models()] == ["m1"]
    assert gw.default_name() == "m1"
    with pytest.raises(ModelError, match="disabled"):
        gw.get("m2")
    with pytest.raises(ModelError, match="unknown model"):
        gw.get("nope")


def test_gateway_accepts_injected_adapter() -> None:
    gw = ModelGateway(ModelsConfig(), NetworkPolicy())
    gw.register("fake", ScriptedAdapter(["hi"]))
    assert gw.get("fake").chat([ChatMessage(role="user", content="x")]).content == "hi"
    assert "fake" in [m.name for m in gw.list_models()]


def test_repo_models_file_is_valid() -> None:
    gw = ModelGateway.from_file(NetworkPolicy(), "config/models.toml")
    names = [m.name for m in gw.list_models()]
    assert gw.default_name() == "deepseek-chat"
    assert "deepseek-chat" in names  # MM-007 DeepSeek is first-class
    assert "glm-4.7-flash" in names  # MM-005 GLM, approved 2026-09-25
    assert "qwen2.5-coder-7b" in names  # local Ollama, approved 2026-09-25
    assert "kimi" not in names  # disabled until approved


def test_a_model_without_a_key_sends_no_authorization_header() -> None:
    """A local server (Ollama) takes no credential; the adapter must not invent one."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "42"}}]})

    assert _adapter(handler).chat([ChatMessage(role="user", content="x")]).content == "42"
    assert "authorization" not in {k.lower() for k in seen[0].headers}


def test_scripted_adapter_embeddings_are_normalized() -> None:
    vecs = ScriptedAdapter().embed(["alpha beta", "alpha beta"])
    assert vecs[0] == vecs[1]
    assert abs(sum(v * v for v in vecs[0]) - 1.0) < 1e-6


# ---------------------------------------------------------------- provider options and retries


def test_extra_body_is_sent_but_cannot_replace_the_adapters_fields() -> None:
    """GLM's thinking switch reaches the provider; the model and messages stay the adapter's."""
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "42"}}]})

    adapter = _adapter(handler, extra_body={"thinking": {"type": "disabled"}})
    assert adapter.chat([ChatMessage(role="user", content="x")]).content == "42"
    assert seen[0]["thinking"] == {"type": "disabled"}
    assert seen[0]["model"] == "deepseek-chat"

    with pytest.raises(ValueError, match="model"):
        _adapter(handler, extra_body={"model": "something-else"})
    with pytest.raises(ValueError, match="extra_body"):
        ModelConfig(
            name="m",
            family="glm",
            version="v",
            base_url="https://api.example.com",
            extra_body={"messages": []},
        )


def test_overloaded_provider_is_retried_then_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 429 "overloaded" is retried with backoff; the call succeeds without the router."""
    waits: list[float] = []
    monkeypatch.setattr(OpenAICompatibleAdapter, "_sleep", staticmethod(waits.append))
    replies = iter(
        [
            httpx.Response(429, json={"error": {"code": "1305", "message": "overloaded"}}),
            httpx.Response(503, text="busy", headers={"Retry-After": "7"}),
            httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]}),
        ]
    )
    adapter = _adapter(lambda r: next(replies), max_retries=3)
    assert adapter.chat([ChatMessage(role="user", content="x")]).content == "ok"
    assert waits == [2.0, 7.0]  # exponential by default, Retry-After when the provider says


def test_retries_are_bounded_and_the_providers_reason_is_kept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    waits: list[float] = []
    monkeypatch.setattr(OpenAICompatibleAdapter, "_sleep", staticmethod(waits.append))
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            429,
            json={"error": {"message": "overloaded", "key": "sk-abcdefghijklmnopqrstuvwxyz0123"}},
            headers={"Retry-After": "600"},
        )

    with pytest.raises(ModelUnavailable) as err:
        _adapter(handler, max_retries=2).chat([ChatMessage(role="user", content="x")])
    assert calls == 3
    assert waits == [30.0, 30.0]  # a provider cannot park the agent for ten minutes
    message = str(err.value)
    assert "after 3 attempts" in message and "overloaded" in message
    assert "sk-abcdefghijklmnopqrstuvwxyz0123" not in message  # SAFE-006: redacted


def test_no_retries_by_default_so_the_router_fails_over_promptly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        OpenAICompatibleAdapter, "_sleep", staticmethod(lambda s: pytest.fail("slept"))
    )
    with pytest.raises(ModelUnavailable, match="HTTP 429: nope"):
        _adapter(lambda r: httpx.Response(429, text="nope")).chat(
            [ChatMessage(role="user", content="x")]
        )


def test_a_timeout_is_retried_like_an_overload(monkeypatch: pytest.MonkeyPatch) -> None:
    """A free tier that goes quiet for the whole timeout is retried, within the same bound."""
    waits: list[float] = []
    monkeypatch.setattr(OpenAICompatibleAdapter, "_sleep", staticmethod(waits.append))
    outcomes = iter([True, False])

    def handler(request: httpx.Request) -> httpx.Response:
        if next(outcomes):
            raise httpx.ReadTimeout("timed out", request=request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    adapter = _adapter(handler, max_retries=1)
    assert adapter.chat([ChatMessage(role="user", content="x")]).content == "ok"
    assert waits == [2.0]

    def always(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    with pytest.raises(ModelUnavailable, match="ReadTimeout"):
        _adapter(always, max_retries=1).chat([ChatMessage(role="user", content="x")])
