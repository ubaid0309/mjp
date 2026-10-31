"""Setup and diagnostics: database migrations, first admin account, and the `doctor` health check.

These run from the setup scripts (setup.bat / setup.sh) so a fresh Supabase project can be prepared
without pasting SQL into the dashboard.
"""
from __future__ import annotations

import os
from pathlib import Path

import httpx

from .config import ROOT, settings
from .supa import Supa, SupabaseError

MIGRATIONS_DIR = Path(os.getenv("SM_MIGRATIONS_DIR", ROOT.parent / "supabase" / "migrations"))


class SetupError(RuntimeError):
    pass


# -- Migrations -----------------------------------------------------------------
def migrate(database_url: str) -> list[str]:
    """Apply supabase/migrations/*.sql in order, each in its own transaction, recording what ran.
    Safe to re-run: applied files are skipped."""
    import psycopg

    if not database_url:
        raise SetupError("DATABASE_URL is not set. Copy the Session pooler connection string from "
                         "Supabase: Project > Connect > Session pooler, and put your database password in it.")
    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    if not files:
        raise SetupError(f"No migration files found in {MIGRATIONS_DIR}")
    try:
        conn = psycopg.connect(database_url, connect_timeout=15, prepare_threshold=None)
    except psycopg.OperationalError as exc:
        raise SetupError(f"Could not connect to the database: {str(exc).strip().splitlines()[0]}. "
                         "Check the password in DATABASE_URL and use the Session pooler address (port 5432).") from exc

    applied_now: list[str] = []
    with conn:
        with conn.cursor() as cur:
            cur.execute("create schema if not exists securematrix_meta")
            cur.execute("revoke all on schema securematrix_meta from public")
            cur.execute("create table if not exists securematrix_meta.migrations "
                        "(name text primary key, applied_at timestamptz not null default now())")
            cur.execute("select name from securematrix_meta.migrations")
            done = {r[0] for r in cur.fetchall()}
            # The schema may have been created by hand in the SQL editor before this runner existed.
            cur.execute("select to_regclass('public.scan_jobs') is not null")
            if not done and cur.fetchone()[0]:
                cur.execute("select to_regprocedure('public.worker_upsert_findings(uuid,jsonb)') is not null")
                manual_all = cur.fetchone()[0]
                baseline = [f.name for f in files] if manual_all else [f.name for f in files[:2]]
                for name in baseline:
                    cur.execute("insert into securematrix_meta.migrations (name) values (%s)", (name,))
                done = set(baseline)
        conn.commit()

        for f in files:
            if f.name in done:
                continue
            try:
                with conn.transaction():
                    with conn.cursor() as cur:
                        cur.execute(f.read_text(encoding="utf-8"))
                        cur.execute("insert into securematrix_meta.migrations (name) values (%s)", (f.name,))
            except psycopg.Error as exc:
                raise SetupError(f"Migration {f.name} failed: {str(exc).strip().splitlines()[0]}") from exc
            applied_now.append(f.name)
        # Ask the Supabase REST layer to pick up the new tables and functions.
        conn.execute("notify pgrst, 'reload schema'")
        conn.commit()
    return applied_now


def wait_for_api_schema(db: Supa, timeout_s: int = 60) -> None:
    """PostgREST reloads its schema cache asynchronously after migrations; wait until it sees our tables."""
    import time
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            db.select("profiles", {"select": "id", "limit": "1"})
            db.rpc("get_scan_summary", {"p_scan_job_id": "00000000-0000-0000-0000-000000000000"})
            return
        except SupabaseError as exc:
            if time.monotonic() > deadline:
                raise SetupError(f"The Supabase API does not see the SecureMatrix tables yet ({str(exc)[:120]}). "
                                 "Wait a minute and run setup again.") from exc
            time.sleep(2)


# -- First administrator ------------------------------------------------------------
def create_admin(db: Supa, email: str, password: str, full_name: str = "") -> str:
    """Create a confirmed user (no confirmation email needed) and make sure it has the admin role.
    If the user already exists it is only promoted."""
    if len(password) < 8:
        raise SetupError("Admin password must be at least 8 characters.")
    r = db.http.post("/auth/v1/admin/users", json={
        "email": email, "password": password, "email_confirm": True, "user_metadata": {"full_name": full_name}})
    if r.status_code in (200, 201):
        outcome = "created"
    elif r.status_code == 422 or "already" in r.text.lower():
        outcome = "already existed"
    else:
        raise SetupError(f"Could not create the admin user ({r.status_code}): {r.text[:200]}")
    rows = db.select("profiles", {"email": f"eq.{email}", "select": "id,role"})
    if not rows:
        raise SetupError("The user exists but has no profile row; were the migrations applied before the user was created?")
    if rows[0]["role"] != "admin":
        db.update("profiles", {"id": rows[0]["id"]}, {"role": "admin"})
    return outcome


# -- Doctor ---------------------------------------------------------------------------
def doctor(db: Supa, api_url: str | None = None) -> list[tuple[str, bool | None, str]]:
    """Return (check, ok, detail). ok=None means optional/not configured."""
    from .embeddings import EmbeddingNotConfigured, get_embedder
    from .semgrep_runner import semgrep_version

    checks: list[tuple[str, bool | None, str]] = []

    def add(name, ok, detail):
        checks.append((name, ok, detail))

    try:
        db.select("scan_jobs", {"select": "id", "limit": "1"})
        add("Database schema", True, "SecureMatrix tables are present")
    except SupabaseError as exc:
        if "401" in str(exc) or "Invalid API key" in str(exc):
            add("Database schema", False, "Supabase rejected the service role key (SUPABASE_SERVICE_ROLE_KEY)")
        else:
            add("Database schema", False, "Tables not found: run the migrations (setup does this automatically)")
        return checks
    except httpx.HTTPError as exc:
        add("Supabase reachable", False, f"Cannot reach {settings.supabase_url}: {exc}")
        return checks

    try:
        buckets = {b["id"] for b in db._check(db.http.get("/storage/v1/bucket"))}
        missing = {"project-uploads", "reports"} - buckets
        add("Private storage buckets", not missing, "project-uploads and reports exist" if not missing else f"missing: {', '.join(missing)}")
    except Exception as exc:  # noqa: BLE001
        add("Private storage buckets", False, str(exc)[:150])

    admins = db.select("profiles", {"role": "eq.admin", "select": "email"})
    add("Administrator account", bool(admins), admins[0]["email"] if admins else "none yet: register in the app (first account becomes admin)")

    docs = db.select_all("knowledge_documents", {"select": "index_status,embedding_model"})
    indexed = sum(1 for d in docs if d["index_status"] == "indexed")
    add("Knowledge base loaded", len(docs) >= 100, f"{len(docs)} documents")

    version = semgrep_version()
    add("Semgrep scanner", bool(version), f"version {version}" if version else f"not runnable at {settings.semgrep_bin}")
    try:
        r = httpx.get(f"{settings.semgrep_registry_url}/p/secrets", timeout=20, follow_redirects=True)
        add("Semgrep registry (optional)", r.status_code == 200, "registry rule packs downloadable" if r.status_code == 200
            else f"HTTP {r.status_code}; bundled rules will still run")
    except httpx.HTTPError:
        add("Semgrep registry (optional)", None, "unreachable; scans use the bundled rules only")

    try:
        emb = get_embedder()
        emb.embed(["sql injection"])
        add("Embedding provider", True, emb.model_id)
        current = sum(1 for d in docs if d["index_status"] == "indexed" and d["embedding_model"] == emb.model_id)
        add("Knowledge base indexed", current == len(docs) and current > 0, f"{current}/{len(docs)} documents embedded with {emb.model_id}")
    except EmbeddingNotConfigured as exc:
        add("Embedding provider", None, f"{exc}. Retrieval falls back to exact CWE matches.")
        add("Knowledge base indexed", None, f"{indexed}/{len(docs)} (needs an embedding provider)")
    except Exception as exc:  # noqa: BLE001
        add("Embedding provider", False, f"configured but failing: {str(exc)[:160]}")

    if settings.llm_configured:
        try:
            r = httpx.post(f"{settings.openai_base_url}/chat/completions", timeout=30,
                           headers={"Authorization": f"Bearer {settings.openai_api_key}"},
                           json={"model": settings.openai_chat_model, "max_tokens": 1,
                                 "messages": [{"role": "user", "content": "ping"}]})
            add("Language model", r.status_code == 200, settings.openai_chat_model if r.status_code == 200
                else f"{settings.openai_chat_model}: HTTP {r.status_code} {r.text[:120]}")
        except httpx.HTTPError as exc:
            add("Language model", False, str(exc)[:150])
    else:
        add("Language model", None, "OPENAI_API_KEY not set; AI explanations disabled")

    if api_url:
        try:
            r = httpx.get(f"{api_url}/health", timeout=5)
            add("Worker API", r.status_code == 200, f"{api_url} is up")
        except httpx.HTTPError:
            add("Worker API", False, f"{api_url} not reachable; is the worker running?")
    return checks


def print_checks(checks: list[tuple[str, bool | None, str]]) -> bool:
    ok_all = True
    for name, ok, detail in checks:
        mark = "[ OK ]" if ok else "[WARN]" if ok is None else "[FAIL]"
        ok_all = ok_all and ok is not False
        print(f"  {mark} {name:<28} {detail}")
    return ok_all
