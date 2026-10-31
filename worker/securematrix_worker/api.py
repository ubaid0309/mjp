"""HTTP API used by the web app for knowledge-base search and grounded Q&A.

Every request must carry the user's Supabase access token; it is validated with
Supabase Auth before anything else happens.
"""
from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import rag
from .config import VERSION, settings
from .embeddings import EmbeddingNotConfigured
from .semgrep_runner import semgrep_version
from .supa import client

log = logging.getLogger("securematrix.api")

app = FastAPI(title="SecureMatrix worker API", version=VERSION, docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_methods=["GET", "POST"],
                   allow_headers=["Authorization", "Content-Type"])

INSUFFICIENT = "The knowledge base does not contain enough evidence to answer this question."


def current_user(authorization: str = Header(default="")) -> dict:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Missing access token")
    user = client().user_from_token(authorization[7:])
    if not user:
        raise HTTPException(401, "Invalid or expired session")
    return user


class SearchRequest(BaseModel):
    query: str = Field(min_length=3, max_length=2000)
    top_k: int = Field(default=6, ge=1, le=20)
    cwe_ids: list[str] | None = None


class AskRequest(BaseModel):
    question: str = Field(min_length=5, max_length=2000)


_semgrep_version: str | None = None


@app.get("/health")
def health() -> dict:
    global _semgrep_version
    _semgrep_version = _semgrep_version or semgrep_version()
    try:
        model = rag.get_embedder().model_id
    except EmbeddingNotConfigured:
        model = None
    return {"status": "ok", "version": VERSION, "semgrep_version": _semgrep_version,
            "embedding_model": model, "llm_configured": settings.llm_configured,
            "llm_model": settings.openai_chat_model if settings.llm_configured else None}


def _search(query: str, top_k: int, cwe_ids: list[str] | None) -> tuple[list[dict], str, float]:
    try:
        rows, model = rag.semantic_search(client(), query, top_k=top_k * 3, cwe_ids=cwe_ids)
    except EmbeddingNotConfigured as exc:
        raise HTTPException(503, f"Semantic search unavailable: {exc}") from exc
    threshold = rag.min_similarity(model)
    # Keep the best chunk per document, then the top_k documents.
    best: dict[str, dict] = {}
    for r in rows:
        if r["document_id"] not in best or r["similarity"] > best[r["document_id"]]["similarity"]:
            best[r["document_id"]] = r
    ranked = sorted(best.values(), key=lambda r: -r["similarity"])[:top_k]
    for r in ranked:
        r["above_threshold"] = r["similarity"] >= threshold
    return ranked, model, threshold


@app.post("/api/rag/search")
def search(req: SearchRequest, _user: dict = Depends(current_user)) -> dict:
    results, model, threshold = _search(req.query, req.top_k, req.cwe_ids)
    return {"mode": "semantic", "model": model, "min_similarity": threshold, "results": results,
            "evidence_sufficient": any(r["above_threshold"] for r in results)}


@app.post("/api/rag/ask")
def ask(req: AskRequest, _user: dict = Depends(current_user)) -> dict:
    results, model, threshold = _search(req.question, 5, None)
    evidence = [r for r in results if r["above_threshold"]]
    base = {"model": model, "min_similarity": threshold, "sources": results}
    if not evidence:
        return {**base, "answer": INSUFFICIENT, "grounded": False, "llm_configured": settings.llm_configured}
    try:
        out = rag.grounded_answer(req.question, evidence)
    except Exception as exc:  # noqa: BLE001
        log.exception("LLM call failed")
        raise HTTPException(502, "The language model request failed; retrieved sources are still shown") from exc
    return {**base, "sources": evidence, "answer": out.get("answer"), "grounded": out.get("answer") is not None,
            "llm_configured": out["llm_configured"], "llm_model": out.get("model")}
