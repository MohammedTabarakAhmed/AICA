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
from collections.abc import Iterator
from dataclasses import dataclass

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


@dataclass(frozen=True)
class OpenAICompatibleConfig:
    base_url: str
    model: str
    api_key_env: str | None = None
    timeout_seconds: float = 120.0
    embedding_model: str | None = None


class OpenAICompatibleAdapter:
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
        try:
            req = self._client.build_request("POST", path, json=payload)
            resp = self._client.send(req, stream=stream)
        except httpx.HTTPError as exc:
            raise ModelUnavailable(f"{self._info.name}: {exc.__class__.__name__}: {exc}") from exc
        if resp.status_code >= 500 or resp.status_code in (408, 429):
            resp.close()
            raise ModelUnavailable(f"{self._info.name}: HTTP {resp.status_code}")
        if resp.status_code >= 400:
            body = resp.read().decode("utf-8", "replace")[:500]
            resp.close()
            raise ModelError(f"{self._info.name}: HTTP {resp.status_code}: {body}")
        return resp

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
