"""Embedding providers. All produce 384-dimensional vectors to match knowledge_chunks.embedding."""
from __future__ import annotations

import math
from typing import Protocol

import httpx

from .config import settings

DIMENSIONS = 384


class EmbeddingNotConfigured(RuntimeError):
    pass


class Embedder(Protocol):
    model_id: str

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class OpenAIEmbedder:
    def __init__(self) -> None:
        if not settings.openai_api_key:
            raise EmbeddingNotConfigured("OPENAI_API_KEY is not set")
        self.model = settings.openai_embedding_model
        # The stored model id includes the dimension so vectors from different setups never mix.
        self.model_id = f"openai/{self.model}@{DIMENSIONS}"
        self.http = httpx.Client(base_url=settings.openai_base_url, timeout=60,
                                 headers={"Authorization": f"Bearer {settings.openai_api_key}"})

    def embed(self, texts: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for i in range(0, len(texts), 64):
            batch = [t[:8000] for t in texts[i:i + 64]]
            r = self.http.post("/embeddings", json={"model": self.model, "input": batch, "dimensions": DIMENSIONS})
            if r.status_code >= 400:
                raise RuntimeError(f"OpenAI embeddings request failed ({r.status_code}): {r.text[:300]}")
            data = sorted(r.json()["data"], key=lambda d: d["index"])
            out.extend(d["embedding"] for d in data)
        return out


class LocalEmbedder:
    """Runs BAAI/bge-small-en-v1.5 on CPU via fastembed (pip install -r requirements-local.txt)."""

    def __init__(self) -> None:
        try:
            from fastembed import TextEmbedding
        except ImportError as exc:
            raise EmbeddingNotConfigured("EMBEDDING_PROVIDER=local needs `pip install fastembed`") from exc
        self.model_id = f"local/{settings.local_embedding_model}@{DIMENSIONS}"
        self._model = TextEmbedding(settings.local_embedding_model)

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors = []
        for v in self._model.embed(texts):
            v = [float(x) for x in v]
            norm = math.sqrt(sum(x * x for x in v)) or 1.0
            vectors.append([x / norm for x in v])
        return vectors


_embedder: Embedder | None = None


def get_embedder() -> Embedder:
    """Return the configured embedder or raise EmbeddingNotConfigured. Never falls back silently."""
    global _embedder
    if _embedder is not None:
        return _embedder
    provider = settings.resolved_embedding_provider
    if provider == "openai":
        _embedder = OpenAIEmbedder()
    elif provider == "local":
        _embedder = LocalEmbedder()
    else:
        raise EmbeddingNotConfigured("No embedding provider configured (set OPENAI_API_KEY or EMBEDDING_PROVIDER=local)")
    return _embedder


def to_pgvector(v: list[float]) -> str:
    return "[" + ",".join(f"{x:.6f}" for x in v) + "]"
