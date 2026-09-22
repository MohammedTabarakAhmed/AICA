"""Embedding providers for semantic search (RAG-003).

``HashingEmbedder`` is a dependency-free, deterministic feature-hashing embedding over
identifier tokens, sub-tokens and bigrams. It gives usable "meaning-ish" retrieval for
code (shared vocabulary, split camelCase/snake_case) without a model and is the MVP
default. ``AdapterEmbedder`` delegates to a model adapter's ``/embeddings`` endpoint and
is the intended production path once an embedding model is approved.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol

from aica.models.base import ModelAdapter

_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_STOP = {
    "the",
    "a",
    "an",
    "of",
    "to",
    "in",
    "is",
    "and",
    "or",
    "for",
    "self",
    "this",
    "return",
    "def",
    "class",
    "import",
    "from",
    "if",
    "else",
    "None",
    "true",
    "false",
    "null",
}


def tokenize(text: str) -> list[str]:
    """Identifier-aware tokenizer shared by lexical and hashing-semantic search."""
    out: list[str] = []
    for tok in _TOKEN.findall(text):
        low = tok.lower()
        if low in _STOP and len(low) < 5:
            continue
        out.append(low)
        parts = [p for p in re.split(r"_+", tok) if p]
        if len(parts) > 1:
            out.extend(p.lower() for p in parts)
        for part in parts:
            sub = [s for s in _CAMEL.split(part) if s]
            if len(sub) > 1:
                out.extend(s.lower() for s in sub)
    return out


class Embedder(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def dims(self) -> int: ...

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class HashingEmbedder:
    def __init__(self, dims: int = 512) -> None:
        self._dims = dims

    @property
    def name(self) -> str:
        return f"hashing-{self._dims}"

    @property
    def dims(self) -> int:
        return self._dims

    def _bucket(self, key: str) -> tuple[int, float]:
        h = hashlib.blake2b(key.encode("utf-8"), digest_size=8).digest()
        idx = int.from_bytes(h[:4], "big") % self._dims
        sign = 1.0 if h[4] & 1 else -1.0
        return idx, sign

    def embed(self, texts: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for text in texts:
            vec = [0.0] * self._dims
            toks = tokenize(text)
            for i, tok in enumerate(toks):
                idx, sign = self._bucket(tok)
                vec[idx] += sign
                if i + 1 < len(toks):
                    idx2, sign2 = self._bucket(tok + " " + toks[i + 1])
                    vec[idx2] += 0.5 * sign2
            norm = math.sqrt(sum(v * v for v in vec)) or 1.0
            out.append([v / norm for v in vec])
        return out


class AdapterEmbedder:
    def __init__(self, adapter: ModelAdapter, dims: int, name: str | None = None) -> None:
        self._adapter = adapter
        self._dims = dims
        self._name = name or f"{adapter.info.name}-embeddings"

    @property
    def name(self) -> str:
        return self._name

    @property
    def dims(self) -> int:
        return self._dims

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors = self._adapter.embed(texts)
        return [_normalize(v) for v in vectors]


def _normalize(v: list[float]) -> list[float]:
    norm = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / norm for x in v]


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b, strict=False))
