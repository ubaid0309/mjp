"""SecureMatrix worker CLI.

    python -m securematrix_worker run          # job loop + KB indexer + HTTP API
    python -m securematrix_worker kb-import    # load knowledge/entries/*.json into the database
    python -m securematrix_worker kb-index     # embed pending/stale knowledge documents now
    python -m securematrix_worker migrate      # apply supabase/migrations using DATABASE_URL
    python -m securematrix_worker create-admin # confirmed admin from SM_ADMIN_EMAIL / SM_ADMIN_PASSWORD
    python -m securematrix_worker bootstrap    # all of the above in order, then doctor
    python -m securematrix_worker doctor       # check that every part is configured and working
"""
from __future__ import annotations

import argparse
import logging
import os
import platform
import sys
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


def _kb_index() -> int:
    from .rag import index_pending
    total = 0
    while True:
        res = index_pending(client())
        if res.get("skipped"):
            print(f"  Skipped embedding: {res['skipped']}")
            return total
        total += res.get("indexed", 0)
        if res.get("failed"):
            print(f"  {res['failed']} documents failed to index (see index_error on the Knowledge base page)")
        if not res.get("indexed"):
            return total
        print(f"  embedded {total} documents so far with {res['model']}")


def _step(title: str) -> None:
    print(f"\n== {title}")


def bootstrap() -> int:
    from . import admin
    from .rag import import_entries, load_entries

    _step("Database migrations")
    if os.getenv("DATABASE_URL"):
        applied = admin.migrate(os.environ["DATABASE_URL"])
        print(f"  applied: {', '.join(applied)}" if applied else "  already up to date")
        admin.wait_for_api_schema(client())
    else:
        print("  DATABASE_URL not set, skipping (apply supabase/migrations in the SQL editor instead)")

    _step("Administrator account")
    email, password = os.getenv("SM_ADMIN_EMAIL", ""), os.getenv("SM_ADMIN_PASSWORD", "")
    if email and password:
        print(f"  {email}: {admin.create_admin(client(), email, password, os.getenv('SM_ADMIN_NAME', ''))}")
    else:
        print("  not requested; the first account registered in the app becomes admin")

    _step("Knowledge base")
    print(f"  imported {import_entries(client(), load_entries())} documents")
    print(f"  embedded {_kb_index()} documents")

    _step("Health check")
    ok = admin.print_checks(admin.doctor(client()))
    return 0 if ok else 1


def main() -> None:
    logging.basicConfig(level=logging.INFO if "run" in sys.argv else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(prog="securematrix_worker")
    parser.add_argument("command", choices=["run", "kb-import", "kb-index", "migrate", "create-admin", "bootstrap", "doctor"])
    parser.add_argument("--api", help="doctor: also check the worker API at this URL")
    args = parser.parse_args()

    from .admin import SetupError
    try:
        if args.command == "bootstrap":
            sys.exit(bootstrap())
        if args.command == "migrate":
            from .admin import migrate
            applied = migrate(os.getenv("DATABASE_URL", ""))
            print(f"Applied: {', '.join(applied)}" if applied else "Database already up to date")
            return
        if args.command == "create-admin":
            from .admin import create_admin
            email, password = os.getenv("SM_ADMIN_EMAIL", ""), os.getenv("SM_ADMIN_PASSWORD", "")
            if not email or not password:
                raise SetupError("Set SM_ADMIN_EMAIL and SM_ADMIN_PASSWORD")
            print(f"{email}: {create_admin(client(), email, password, os.getenv('SM_ADMIN_NAME', ''))}")
            return
        if args.command == "doctor":
            from .admin import doctor, print_checks
            print("SecureMatrix health check")
            sys.exit(0 if print_checks(doctor(client(), args.api)) else 1)
    except SetupError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:  # noqa: BLE001 - setup commands should end with a readable message, not a traceback
        if args.command in ("run", "kb-import", "kb-index"):
            raise
        print(f"\nERROR: {type(exc).__name__}: {str(exc)[:400]}", file=sys.stderr)
        sys.exit(2)

    if args.command == "kb-import":
        from .rag import import_entries, load_entries
        n = import_entries(client(), load_entries())
        print(f"Imported {n} knowledge documents. Run `kb-index` (or start the worker) to embed them.")
    elif args.command == "kb-index":
        print(f"Indexed {_kb_index()} documents")
    else:
        import uvicorn
        from .api import app
        threading.Thread(target=job_loop, daemon=True, name="job-loop").start()
        uvicorn.run(app, host="0.0.0.0", port=settings.api_port, log_level="warning")


if __name__ == "__main__":
    main()
