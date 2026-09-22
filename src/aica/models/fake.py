"""Scripted adapter for tests, dry runs and evaluation harnesses."""

from __future__ import annotations

import hashlib
import math
from collections import deque
from collections.abc import Callable, Iterator

from aica.models.base import Capability, ChatMessage, ModelInfo, ModelResponse, StreamChunk

Responder = Callable[[list[ChatMessage]], str]


class ScriptedAdapter:
    def __init__(
        self,
        responses: list[str] | None = None,
        responder: Responder | None = None,
        name: str = "scripted-model",
        dims: int = 64,
    ) -> None:
        self._queue: deque[str] = deque(responses or [])
        self._responder = responder
        self._dims = dims
        self.calls: list[list[ChatMessage]] = []
        self._info = ModelInfo(
            name=name,
            family="test",
            version=f"{name}-v0",
            context_window=32_000,
            capabilities=[
                Capability.CHAT,
                Capability.STREAMING,
                Capability.FIM,
                Capability.EMBEDDINGS,
            ],
        )

    @property
    def info(self) -> ModelInfo:
        return self._info

    def _next(self, messages: list[ChatMessage]) -> str:
        self.calls.append(list(messages))
        if self._queue:
            return self._queue.popleft()
        if self._responder:
            return self._responder(messages)
        return "OK"

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> ModelResponse:
        return ModelResponse(
            content=self._next(messages), model=self._info.version, finish_reason="stop"
        )

    def stream(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> Iterator[StreamChunk]:
        text = self._next(messages)
        for word in text.split(" "):
            yield StreamChunk(delta=word + " ", model=self._info.version)
        yield StreamChunk(delta="", model=self._info.version, done=True, finish_reason="stop")

    def complete(self, prefix: str, suffix: str = "", *, max_tokens: int = 256) -> ModelResponse:
        return self.chat([ChatMessage(role="user", content=prefix + "\x00" + suffix)])

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Deterministic feature-hashing embedding; adequate for tests only."""
        out: list[list[float]] = []
        for text in texts:
            vec = [0.0] * self._dims
            for tok in text.lower().split():
                h = int(hashlib.blake2b(tok.encode(), digest_size=4).hexdigest(), 16)
                vec[h % self._dims] += 1.0
            norm = math.sqrt(sum(v * v for v in vec)) or 1.0
            out.append([v / norm for v in vec])
        return out
