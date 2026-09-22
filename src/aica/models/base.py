"""Model adapter abstraction (MM-008).

The agent core talks only to ``ModelAdapter``. Concrete adapters (OpenAI-compatible HTTP,
scripted fakes, future providers) plug in behind it, so GLM / Kimi / DeepSeek / future
models never require agent-core changes. Every response carries the exact model id that
produced it so it can be recorded (MM-012, MEM-006, EVAL-009).
"""

from __future__ import annotations

from collections.abc import Iterator
from enum import StrEnum
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

Role = Literal["system", "user", "assistant", "tool"]


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Role
    content: str
    name: str | None = None


class Capability(StrEnum):
    CHAT = "chat"
    STREAMING = "streaming"
    TOOLS = "tools"
    STRUCTURED_OUTPUT = "structured_output"
    FIM = "fim"  # fill-in-the-middle completion
    EMBEDDINGS = "embeddings"


class ModelInfo(BaseModel):
    """MM-013: capability information exposed to users and routers."""

    model_config = ConfigDict(extra="forbid")

    name: str
    family: str  # glm | kimi | deepseek | ...
    version: str  # exact served version / model id
    context_window: int = Field(gt=0)
    capabilities: list[Capability] = Field(default_factory=list)

    def supports(self, cap: Capability) -> bool:
        return cap in self.capabilities


class Usage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt_tokens: int = 0
    completion_tokens: int = 0


class ModelResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str
    model: str  # exact model/version that answered (MM-012)
    finish_reason: str | None = None
    usage: Usage = Field(default_factory=Usage)


class StreamChunk(BaseModel):
    model_config = ConfigDict(extra="forbid")

    delta: str
    model: str
    done: bool = False
    finish_reason: str | None = None


class ModelError(RuntimeError):
    pass


class ModelUnavailable(ModelError):
    """Raised when the provider cannot be reached or refuses (MM-010 fallback trigger)."""


class ModelAdapter(Protocol):
    @property
    def info(self) -> ModelInfo: ...

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> ModelResponse: ...

    def stream(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> Iterator[StreamChunk]: ...

    def complete(self, prefix: str, suffix: str = "", *, max_tokens: int = 256) -> ModelResponse:
        """Fill-in-the-middle style completion for CC-001/CC-002."""
        ...

    def embed(self, texts: list[str]) -> list[list[float]]: ...
