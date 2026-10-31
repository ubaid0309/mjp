"""Knowledge-base import, chunking, indexing and retrieval (the RAG part of SecureMatrix)."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
import os
from dataclasses import dataclass
from pathlib import Path

import httpx

from .config import KNOWLEDGE_DIR, settings
from .embeddings import EmbeddingNotConfigured, get_embedder, to_pgvector
from .supa import Supa

log = logging.getLogger("securematrix.rag")

CHUNK_CHAR_LIMIT = 1600
CHUNK_OVERLAP = 200


def min_similarity(model_id: str) -> float:
    """Below this cosine similarity a match is not treated as evidence. Different models
    have very different similarity ranges, so the threshold depends on the model."""
    env = os.getenv("RAG_MIN_SIMILARITY")
    if env:
        return float(env)
    return 0.62 if model_id.startswith("local/") else 0.30


# -- Import -------------------------------------------------------------------
DOC_FIELDS = ["slug", "cwe_id", "title", "cwe_name", "category", "severity_default", "languages", "description",
              "prerequisites", "impact", "detection_patterns", "remediation", "vulnerable_example",
              "secure_example", "cve_examples", "references"]


def load_entries(directory: Path = KNOWLEDGE_DIR / "entries") -> list[dict]:
    entries = []
    for path in sorted(directory.glob("*.json")):
        entries.extend(json.loads(path.read_text(encoding="utf-8")))
    return entries


def import_entries(db: Supa, entries: list[dict], source: str = "seed") -> int:
    rows = []
    for e in entries:
        row = {k: e.get(k) for k in DOC_FIELDS}
        row["owasp_top10"] = e.get("owasp_top10_2021", [])
        row["owasp_api"] = e.get("owasp_api_2023", [])
        row["source"] = source
        rows.append(row)
    db.insert_many("knowledge_documents", rows, chunk=100, upsert_on="slug")
    return len(rows)


# -- Chunking -----------------------------------------------------------------
def _bullets(items: list[str]) -> str:
    return "\n".join(f"- {i}" for i in items or [])


def _code(example: dict | None) -> str:
    if not example:
        return ""
    return f"```{example.get('language', '')}\n{example.get('code', '')}\n```"


def build_chunks(doc: dict) -> list[dict]:
    """Split one knowledge document into section chunks. Each chunk repeats the CWE and title
    so it still makes sense on its own when retrieved."""
    head = f"{doc.get('cwe_id') or ''} {doc['title']} ({doc.get('category', '')})".strip()
    owasp = ", ".join((doc.get("owasp_top10") or []) + (doc.get("owasp_api") or []))
    sections = [
        ("overview", f"{head}\nCWE name: {doc.get('cwe_name') or '-'}\nOWASP: {owasp or '-'}\n\n{doc['description']}\n\n"
                     f"Attack prerequisites:\n{_bullets(doc.get('prerequisites'))}\n\nImpact:\n{_bullets(doc.get('impact'))}"),
        ("detection", f"{head} - how to detect it\n{_bullets(doc.get('detection_patterns'))}\n\n"
                      f"Vulnerable example:\n{_code(doc.get('vulnerable_example'))}"),
        ("remediation", f"{head} - remediation\n{_bullets(doc.get('remediation'))}\n\n"
                        f"Secure example:\n{_code(doc.get('secure_example'))}"),
    ]
    chunks = []
    for section, text in sections:
        start = 0
        while start < len(text):
            # Continuation pieces repeat the header so every chunk names its CWE.
            prefix = "" if start == 0 else f"{head} ({section}, continued)\n"
            piece = prefix + text[start:start + CHUNK_CHAR_LIMIT - len(prefix)]
            chunks.append({"section": section, "content": piece, "token_estimate": len(piece) // 4})
            if start + CHUNK_CHAR_LIMIT - len(prefix) >= len(text):
                break
            start += CHUNK_CHAR_LIMIT - len(prefix) - CHUNK_OVERLAP
    for i, c in enumerate(chunks):
        c["chunk_index"] = i
    return chunks


# -- Indexing -----------------------------------------------------------------
def index_pending(db: Supa, limit: int = 50) -> dict:
    """Embed documents that are pending, stale, or embedded with a different model."""
    try:
        embedder = get_embedder()
    except EmbeddingNotConfigured as exc:
        return {"indexed": 0, "skipped": str(exc)}
    model_id = embedder.model_id
    docs = db.select("knowledge_documents", {
        "select": "*",
        "or": f'(index_status.in.(pending,stale),embedding_model.is.null,embedding_model.neq."{model_id}")',
        "index_status": "neq.indexing",
        "limit": str(limit),
    })
    done = failed = 0
    for doc in docs:
        db.update("knowledge_documents", {"id": doc["id"]}, {"index_status": "indexing"})
        try:
            chunks = build_chunks(doc)
            vectors = embedder.embed([c["content"] for c in chunks])
            db.delete("knowledge_chunks", {"document_id": f"eq.{doc['id']}"})
            db.insert("knowledge_chunks", [
                {**c, "document_id": doc["id"], "embedding": to_pgvector(v), "embedding_model": model_id}
                for c, v in zip(chunks, vectors)
            ])
            db.update("knowledge_documents", {"id": doc["id"]}, {
                "index_status": "indexed", "index_error": None, "indexed_at": datetime.now(timezone.utc).isoformat(),
                "embedding_model": model_id, "chunk_count": len(chunks),
            })
            done += 1
        except Exception as exc:  # noqa: BLE001 - recorded on the document, worker keeps going
            log.exception("indexing %s failed", doc["slug"])
            db.update("knowledge_documents", {"id": doc["id"]},
                      {"index_status": "failed", "index_error": str(exc)[:500]})
            failed += 1
    return {"indexed": done, "failed": failed, "model": model_id}


# -- Retrieval ----------------------------------------------------------------
@dataclass
class Retrieved:
    document_id: str
    chunk_id: str | None
    slug: str
    cwe_id: str | None
    title: str
    section: str | None
    content: str | None
    similarity: float | None
    match_type: str


def semantic_search(db: Supa, query: str, top_k: int = 8, cwe_ids: list[str] | None = None,
                    min_sim: float = 0.0) -> tuple[list[dict], str]:
    embedder = get_embedder()
    vec = embedder.embed([query])[0]
    rows = db.rpc("match_knowledge_chunks", {
        "p_query_embedding": to_pgvector(vec),
        "p_embedding_model": embedder.model_id,
        "p_match_count": top_k,
        "p_min_similarity": min_sim,
        "p_cwe_ids": cwe_ids,
    })
    return rows, embedder.model_id


class FindingRetriever:
    """Retrieves knowledge for findings. Exact CWE matches come from metadata; semantic matches
    come from pgvector. If embeddings are unavailable, CWE matches still work and the result says so."""

    def __init__(self, db: Supa) -> None:
        self.db = db
        self._docs_by_cwe: dict[str, dict] | None = None
        self._cache: dict[str, tuple[list[Retrieved], str]] = {}
        try:
            self.model_id: str | None = get_embedder().model_id
        except EmbeddingNotConfigured:
            self.model_id = None

    def docs_by_cwe(self) -> dict[str, dict]:
        if self._docs_by_cwe is None:
            rows = self.db.select_all("knowledge_documents", {
                "select": "id,slug,cwe_id,title,category", "is_enabled": "is.true", "cwe_id": "not.is.null"})
            self._docs_by_cwe = {r["cwe_id"]: r for r in rows}
        return self._docs_by_cwe

    def for_finding(self, title: str, message: str, cwes: list[str], snippet: str, rule_key: str,
                    max_docs: int = 4) -> tuple[list[Retrieved], str]:
        """Returns (references, evidence_status) with status matched | insufficient | unavailable."""
        cache_key = f"{rule_key}|{','.join(cwes)}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        by_doc: dict[str, Retrieved] = {}
        for cwe in cwes:
            d = self.docs_by_cwe().get(cwe)
            if d:
                by_doc[d["id"]] = Retrieved(d["id"], None, d["slug"], d["cwe_id"], d["title"], None, None, None, "cwe_exact")

        status = "unavailable"
        if self.model_id:
            query = f"{title}. {', '.join(cwes)}. {message}\nCode:\n{snippet[:600]}"
            try:
                rows, _ = semantic_search(self.db, query, top_k=12, min_sim=min_similarity(self.model_id))
                for r in rows:
                    existing = by_doc.get(r["document_id"])
                    if existing and existing.match_type in ("cwe_exact", "cwe_and_semantic"):
                        if existing.similarity is None or r["similarity"] > existing.similarity:
                            existing.similarity, existing.chunk_id = r["similarity"], r["chunk_id"]
                            existing.section, existing.content = r["section"], r["content"]
                            existing.match_type = "cwe_and_semantic"
                    elif not existing:
                        by_doc[r["document_id"]] = Retrieved(r["document_id"], r["chunk_id"], r["slug"], r["cwe_id"],
                                                             r["title"], r["section"], r["content"], r["similarity"], "semantic")
                status = "matched" if by_doc else "insufficient"
            except Exception:  # noqa: BLE001 - retrieval failure must not fail the scan
                log.exception("semantic retrieval failed")
                status = "matched" if by_doc else "unavailable"
        elif by_doc:
            status = "matched"

        order = {"cwe_and_semantic": 0, "cwe_exact": 1, "semantic": 2}
        refs = sorted(by_doc.values(), key=lambda r: (order[r.match_type], -(r.similarity or 0)))[:max_docs]
        self._cache[cache_key] = (refs, status)
        return refs, status


# -- Grounded answers ---------------------------------------------------------
SYSTEM_PROMPT = """You are the SecureMatrix security assistant.
Answer ONLY from the numbered knowledge-base excerpts provided. Cite excerpts as [1], [2].
If the excerpts do not contain enough information to answer, reply exactly:
"The knowledge base does not contain enough evidence to answer this question."
Do not invent CVE identifiers, CVSS scores, library versions or URLs. Be concise and practical."""


def grounded_answer(question: str, contexts: list[dict]) -> dict:
    if not settings.llm_configured:
        return {"answer": None, "llm_configured": False}
    numbered = "\n\n".join(f"[{i + 1}] ({c['cwe_id'] or c['slug']} - {c['section']})\n{c['content']}"
                           for i, c in enumerate(contexts))
    r = httpx.post(f"{settings.openai_base_url}/chat/completions", timeout=90,
                   headers={"Authorization": f"Bearer {settings.openai_api_key}"},
                   json={"model": settings.openai_chat_model, "temperature": 0.1,
                         "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                                      {"role": "user", "content": f"Knowledge-base excerpts:\n{numbered}\n\nQuestion: {question}"}]})
    if r.status_code >= 400:
        raise RuntimeError(f"LLM request failed ({r.status_code})")
    return {"answer": r.json()["choices"][0]["message"]["content"], "llm_configured": True,
            "model": settings.openai_chat_model}
