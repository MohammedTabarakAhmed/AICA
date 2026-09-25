"""OpenAI-compatible HTTP adapter.

GLM (Zhipu), Kimi (Moonshot) and DeepSeek all expose OpenAI-compatible chat-completions
APIs, as do vLLM / llama.cpp / Ollama style self-hosted servers. One adapter therefore
covers the MVP "one model" and the Release-1 families (MM-005..007) by configuration.

Credentials come only from environment variables (SAFE-006); the endpoint host must pass
the network policy (SAFE-005) — enforced by ``ModelGateway`` before the adapter is built.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

from aica.models.base import (
    Capability,
    ChatMessage,
    ModelError,
    ModelInfo,
    ModelResponse,
    ModelUnavailable,
    StreamChunk,
    Usage,
)
from aica.safety.redaction import redact

# Fields the adapter owns. ``extra_body`` may add provider options but never replace these,
# so configuration cannot change which model is called or what it is sent.
_RESERVED = frozenset({"model", "messages", "stream", "prompt", "suffix"})
_RETRY_CAP_SECONDS = 30.0


@dataclass(frozen=True)
class OpenAICompatibleConfig:
    base_url: str
    model: str
    api_key_env: str | None = None
    timeout_seconds: float = 120.0
    embedding_model: str | None = None
    # Provider-specific request fields, e.g. GLM's {"thinking": {"type": "disabled"}}.
    extra_body: Mapping[str, Any] = field(default_factory=dict)
    # Retries of a 429/5xx/408 before the model is reported unavailable. Zero leaves failover
    # to the router (MM-010); a shared free tier that answers "overloaded" needs a few.
    max_retries: int = 0

    def __post_init__(self) -> None:
        clash = _RESERVED & set(self.extra_body)
        if clash:
            raise ValueError(f"extra_body may not set {sorted(clash)}")
        if self.max_retries < 0:
            raise ValueError("max_retries must be >= 0")


class OpenAICompatibleAdapter:
    # Indirection so tests can observe the backoff without waiting for it.
    _sleep = staticmethod(time.sleep)

    def __init__(
        self,
        config: OpenAICompatibleConfig,
        info: ModelInfo,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._config = config
        self._info = info
        headers = {"Content-Type": "application/json"}
        if config.api_key_env:
            key = os.environ.get(config.api_key_env)
            if not key:
                raise ModelError(
                    f"environment variable {config.api_key_env} is not set; "
                    "credentials are injected via environment only"
                )
            headers["Authorization"] = f"Bearer {key}"
        self._client = httpx.Client(
            base_url=config.base_url.rstrip("/"),
            headers=headers,
            timeout=config.timeout_seconds,
            transport=transport,
        )

    @property
    def info(self) -> ModelInfo:
        return self._info

    # ------------------------------------------------------------------ helpers
    def _post(
        self, path: str, payload: dict[str, object], *, stream: bool = False
    ) -> httpx.Response:
        body = {**self._config.extra_body, **payload}
        attempt = 0
        while True:
            try:
                req = self._client.build_request("POST", path, json=body)
                resp = self._client.send(req, stream=stream)
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                # Nothing was received, so sending again cannot duplicate an answer.
                if attempt < self._config.max_retries:
                    self._sleep(2.0 * (2**attempt))
                    attempt += 1
                    continue
                raise ModelUnavailable(
                    f"{self._info.name}: {exc.__class__.__name__}: {exc}"
                ) from exc
            except httpx.HTTPError as exc:
                raise ModelUnavailable(
                    f"{self._info.name}: {exc.__class__.__name__}: {exc}"
                ) from exc
            if resp.status_code >= 500 or resp.status_code in (408, 429):
                detail = self._error_text(resp)
                if attempt < self._config.max_retries:
                    self._sleep(self._backoff(resp, attempt))
                    attempt += 1
                    continue
                tries = f" after {attempt + 1} attempts" if attempt else ""
                raise ModelUnavailable(f"{self._info.name}: HTTP {resp.status_code}{tries}{detail}")
            if resp.status_code >= 400:
                raise ModelError(
                    f"{self._info.name}: HTTP {resp.status_code}{self._error_text(resp)}"
                )
            return resp

    @staticmethod
    def _error_text(resp: httpx.Response) -> str:
        """The provider's own explanation, redacted and short: "HTTP 429" alone cannot tell
        "overloaded, try again" from "quota exhausted"."""
        try:
            text = resp.read().decode("utf-8", "replace").strip()[:300]
        finally:
            resp.close()
        return f": {redact(text).text}" if text else ""

    @staticmethod
    def _backoff(resp: httpx.Response, attempt: int) -> float:
        """Honour Retry-After when the provider sends seconds; otherwise 2s, 4s, 8s... capped."""
        header = resp.headers.get("retry-after", "")
        try:
            wait = float(header)
        except ValueError:
            wait = 2.0 * (2**attempt)
        return max(0.0, min(wait, _RETRY_CAP_SECONDS))

    @staticmethod
    def _messages(messages: list[ChatMessage]) -> list[dict[str, str]]:
        out = []
        for m in messages:
            d = {"role": m.role, "content": m.content}
            if m.name:
                d["name"] = m.name
            out.append(d)
        return out

    # ---------------------------------------------------------------- protocol
    def chat(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> ModelResponse:
        payload: dict[str, object] = {
            "model": self._config.model,
            "messages": self._messages(messages),
            "temperature": temperature,
            "stream": False,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens
        data = self._post("/chat/completions", payload).json()
        try:
            choice = data["choices"][0]
            usage = data.get("usage") or {}
            return ModelResponse(
                content=choice["message"].get("content") or "",
                model=str(data.get("model") or self._config.model),
                finish_reason=choice.get("finish_reason"),
                usage=Usage(
                    prompt_tokens=int(usage.get("prompt_tokens", 0)),
                    completion_tokens=int(usage.get("completion_tokens", 0)),
                ),
            )
        except (KeyError, IndexError, TypeError) as exc:
            raise ModelError(f"{self._info.name}: malformed response: {exc}") from exc

    def stream(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> Iterator[StreamChunk]:
        payload: dict[str, object] = {
            "model": self._config.model,
            "messages": self._messages(messages),
            "temperature": temperature,
            "stream": True,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens
        resp = self._post("/chat/completions", payload, stream=True)
        model = self._config.model
        try:
            for line in resp.iter_lines():
                if not line.startswith("data:"):
                    continue
                body = line[5:].strip()
                if body == "[DONE]":
                    break
                try:
                    data = json.loads(body)
                except json.JSONDecodeError:
                    continue
                model = str(data.get("model") or model)
                for choice in data.get("choices", []):
                    delta = (choice.get("delta") or {}).get("content") or ""
                    finish = choice.get("finish_reason")
                    if delta or finish:
                        yield StreamChunk(
                            delta=delta, model=model, finish_reason=finish, done=bool(finish)
                        )
        finally:
            resp.close()
        yield StreamChunk(delta="", model=model, done=True)

    def complete(self, prefix: str, suffix: str = "", *, max_tokens: int = 256) -> ModelResponse:
        if self._info.supports(Capability.FIM):
            payload: dict[str, object] = {
                "model": self._config.model,
                "prompt": prefix,
                "suffix": suffix or None,
                "max_tokens": max_tokens,
                "temperature": 0.0,
            }
            data = self._post("/completions", payload).json()
            try:
                choice = data["choices"][0]
                return ModelResponse(
                    content=choice.get("text") or "",
                    model=str(data.get("model") or self._config.model),
                    finish_reason=choice.get("finish_reason"),
                )
            except (KeyError, IndexError, TypeError) as exc:
                raise ModelError(f"{self._info.name}: malformed completion: {exc}") from exc
        # Fallback: emulate FIM through chat for models without a completions endpoint.
        messages = [
            ChatMessage(
                role="system",
                content=(
                    "You are a code completion engine. Output only the code that belongs at "
                    "the cursor between PREFIX and SUFFIX. No explanations, no fences."
                ),
            ),
            ChatMessage(role="user", content=f"PREFIX:\n{prefix}\nSUFFIX:\n{suffix}\nCOMPLETION:"),
        ]
        return self.chat(messages, temperature=0.0, max_tokens=max_tokens)

    def embed(self, texts: list[str]) -> list[list[float]]:
        model = self._config.embedding_model
        if not model:
            raise ModelError(f"{self._info.name}: no embedding model configured")
        data = self._post("/embeddings", {"model": model, "input": texts}).json()
        try:
            items = sorted(data["data"], key=lambda d: int(d.get("index", 0)))
            return [[float(x) for x in item["embedding"]] for item in items]
        except (KeyError, TypeError, ValueError) as exc:
            raise ModelError(f"{self._info.name}: malformed embeddings: {exc}") from exc

    def close(self) -> None:
        self._client.close()
