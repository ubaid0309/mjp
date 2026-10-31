"""SecureMatrix worker CLI.

    python -m securematrix_worker run          # job loop + KB indexer + HTTP API
    python -m securematrix_worker kb-import    # load knowledge/entries/*.json into the database
    python -m securematrix_worker kb-index     # embed pending/stale knowledge documents now
"""
from __future__ import annotations

import argparse
import logging
import platform
import threading
import time

from .config import VERSION, settings
from .supa import client


def _heartbeat(db) -> None:
    from .embeddings import EmbeddingNotConfigured, get_embedder
    from .semgrep_runner import semgrep_version
    try:
        model = get_embedder().model_id
    except EmbeddingNotConfigured:
        model = None
    db.insert("worker_status", {
        "worker_id": settings.worker_id, "hostname": platform.node(), "version": VERSION,
        "semgrep_version": semgrep_version(), "embedding_provider": settings.resolved_embedding_provider,
        "embedding_model": model, "llm_provider": "openai" if settings.llm_configured else None,
        "llm_model": settings.openai_chat_model if settings.llm_configured else None,
        "capabilities": {"semgrep": semgrep_version() is not None, "embeddings": model is not None,
                         "llm": settings.llm_configured, "api_port": settings.api_port},
        "last_heartbeat_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, upsert_on="worker_id")


def job_loop() -> None:
    from .pipeline import ScanRun
    from .rag import index_pending
    log = logging.getLogger("securematrix.worker")
    db = client()
    last_beat = last_index = 0.0
    while True:
        try:
            now = time.monotonic()
            if now - last_beat > 30:
                _heartbeat(db)
                last_beat = now
            if now - last_index > 30:
                res = index_pending(db)
                if res.get("indexed") or res.get("failed"):
                    log.info("knowledge indexing: %s", res)
                last_index = now
            jobs = db.rpc("claim_next_scan_job", {"p_worker_id": settings.worker_id})
            if jobs:
                log.info("claimed scan %s", jobs[0]["id"])
                ScanRun(db, jobs[0]).run()
                continue
        except Exception:  # noqa: BLE001 - keep the worker alive; errors are logged
            log.exception("worker loop error")
        time.sleep(settings.poll_seconds)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(prog="securematrix_worker")
    parser.add_argument("command", choices=["run", "kb-import", "kb-index"])
    args = parser.parse_args()

    if args.command == "kb-import":
        from .rag import import_entries, load_entries
        n = import_entries(client(), load_entries())
        print(f"Imported {n} knowledge documents. Run `kb-index` (or start the worker) to embed them.")
    elif args.command == "kb-index":
        from .rag import index_pending
        total = 0
        while True:
            res = index_pending(client())
            print(res)
            if not res.get("indexed"):
                break
            total += res["indexed"]
        print(f"Indexed {total} documents")
    else:
        import uvicorn
        from .api import app
        threading.Thread(target=job_loop, daemon=True, name="job-loop").start()
        uvicorn.run(app, host="0.0.0.0", port=settings.api_port, log_level="warning")


if __name__ == "__main__":
    main()
