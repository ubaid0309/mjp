# SecureMatrix – Vulnerability and Threat Management Platform

SecureMatrix analyses uploaded source code with a real static-analysis engine (Semgrep), stores every finding with its
evidence, explains each one using a Retrieval-Augmented Generation (RAG) security knowledge base of 116 CWE weakness
classes, scores and prioritises it, and tracks it through a remediation lifecycle.

Final-year BE Computer Engineering major project. The full roadmap is in [`docs/PLAN.md`](docs/PLAN.md); architecture and workflow figures for the report and paper are in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Status (review 1: about 35% of the full scope)

| Module | State |
|---|---|
| Auth (Supabase email/password, first user becomes admin) | Working |
| Database schema: 18 tables, RLS on all, private storage buckets, RPCs | Working |
| ZIP upload, secure extraction, file discovery, exclusions, limits | Working |
| Batched Semgrep scanning with real progress, cancellation, coverage report | Working |
| Normalisation, cross-rule deduplication, stable fingerprints, secret redaction | Working |
| Knowledge base: 116 unique CWE records, chunked, embedded in pgvector | Working |
| RAG: per-finding retrieval (CWE match + vector similarity), semantic search, grounded Q&A | Working |
| Risk scoring (transparent, explained per finding) | Working |
| Dashboard, projects, scan progress/results, vulnerability explorer, finding detail, KB admin, settings | Working |
| Finding lifecycle (status transitions enforced in the database), notes, audit history | Working |
| JSON report export, CSV findings export | Working |
| Remediation patches, fix verification re-scan, PDF reports, threat analysis, team assignment | Planned (pages explain scope, nothing is simulated) |

## Architecture

```
 Browser (React + TS + Vite + Tailwind)
   |  supabase-js (anon key, RLS)                 |  HTTPS + user JWT
   v                                              v
 Supabase                                   SecureMatrix worker (Python, Docker)
   Auth  ─ Postgres + pgvector ─ Storage  <──  service-role key
            ^  scan_jobs queue                  ├─ job loop: claim_next_scan_job (FOR UPDATE SKIP LOCKED)
            └───────────────────────────────────┤    extract -> discover -> Semgrep batches -> dedupe
                                                │    -> RAG retrieval -> risk score -> persist
                                                ├─ KB indexer: chunks + embeddings for pending/stale docs
                                                └─ API: /api/rag/search, /api/rag/ask (JWT verified)
                                                        │
                                                OpenAI embeddings / chat (optional, server-side only)
```

Why a worker and not Edge Functions: Semgrep is a native binary and scans can run for minutes, which Edge Functions
are not built for. Every user-facing write that matters (queueing a scan, cancelling, changing a finding's status,
re-indexing) goes through a `SECURITY DEFINER` RPC that validates permissions and input.

Key rules enforced by the database, not just the UI:
- A finding can only become `resolved` when `verification_status = 'verified_resolved'` (check constraint).
- Accepting a risk requires a written justification.
- Users see only projects they are members of; the knowledge base is editable by admins only.
- Uploads must live under `<user id>/<project id>/` in the private `project-uploads` bucket.

## Repository layout

```
supabase/migrations/   schema, RLS, RPCs, storage buckets
worker/                Python worker: scan pipeline, RAG, API, bundled Semgrep rules, tests, Dockerfile
knowledge/entries/     the 116-record knowledge base (JSON) + validate.py
web/                   React frontend
demo/                  intentionally vulnerable ByteMart project (+ ready-made zip) and its secure reference
docs/PLAN.md           phased implementation plan
```

## Quick start on Windows (about 10 minutes)

You need: a free Supabase project, Docker Desktop (setup offers to install it), and optionally an OpenAI API key.

1. **Create the Supabase project** at https://supabase.com/dashboard (any region near you). Keep the database
   password you choose; you need it in step 3.
2. **Double-click `setup.bat`** in the project folder. It installs Node.js/Docker Desktop with `winget` if they are
   missing, then asks for:

   | Prompt | Where to find it in Supabase |
   |---|---|
   | Project URL | Project Settings > API (or Data API): `https://<ref>.supabase.co` |
   | anon / publishable key | Project Settings > API Keys: `anon` (legacy) or `publishable` |
   | service_role / secret key | Same page: `service_role` (legacy) or a `secret` key. Keep it private |
   | Database connection string | **Connect** button (top bar) > **Session pooler** > URI. Replace `[YOUR-PASSWORD]` |
   | OpenAI API key | platform.openai.com > API keys (optional) |
   | Admin email and password | Anything you like; this becomes the app's administrator, already confirmed |

   Setup then builds the worker (with Semgrep), applies the database migrations, creates the admin account, loads
   and embeds the 116-record knowledge base, installs the web app, runs a health check and opens
   http://localhost:5173.
3. **Sign in** and upload `demo\bytemart-vulnerable.zip` from **New scan**.

Every day after that:

| File | What it does |
|---|---|
| `start.bat` | Starts the worker and web app, opens the browser |
| `stop.bat` | Stops both |
| `check.bat` | Health check: database, storage, admin, knowledge base, Semgrep, OpenAI, worker API |
| `setup.bat` | Safe to re-run (e.g. to add the OpenAI key later); finished steps are skipped |

Without Docker: `setup.bat -Native` uses a local Python 3.10+ instead. Docker is recommended because Semgrep's
native Windows support is limited.

If the database step fails (for example a wrong password), you can instead paste the three files from
`supabase/migrations/` into the Supabase **SQL Editor** in order and leave the connection string empty.

### Manual setup (any OS)

1. Apply `supabase/migrations/*.sql` in order (SQL Editor, or `npx supabase db push` after `npx supabase link`).
2. Worker: copy `worker/.env.example` to `worker/.env`, fill it in, then
   `docker compose up --build -d worker` and
   `docker compose run --rm worker python -m securematrix_worker bootstrap`
   (set `SM_ADMIN_EMAIL` / `SM_ADMIN_PASSWORD` and pass them with `-e` to create a confirmed admin).
3. Web: copy `web/.env.example` to `web/.env.local`, fill it in, then `npm ci` and `npm run dev` in `web/`.

Worker commands: `run`, `bootstrap`, `migrate`, `create-admin`, `kb-import`, `kb-index`, `doctor`.

## Environment variables

| Where | Variable | Purpose |
|---|---|---|
| web | `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY` | Public Supabase settings (RLS protects data) |
| web | `VITE_WORKER_API_URL` | Worker API, default `http://localhost:8787` |
| worker | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | Required. The service key never leaves the worker |
| worker | `DATABASE_URL` | Only for `migrate`/`bootstrap`: Supabase Session pooler connection string |
| worker | `OPENAI_API_KEY` | Embeddings + grounded explanations |
| worker | `OPENAI_CHAT_MODEL` | Chat model for explanations (default `gpt-4o-mini`) |
| worker | `EMBEDDING_PROVIDER` | `openai`, `local` (bge-small on CPU, build with `LOCAL_EMBEDDINGS=true`) or `none` |
| worker | `SM_MAX_ARCHIVE_MB`, `SM_MAX_UNCOMPRESSED_MB`, `SEMGREP_JOBS`, `SM_CORS_ORIGINS` | Limits and tuning |

If no embedding provider is configured, scans still attach knowledge by exact CWE match and the UI says so;
nothing is faked. Changing the embedding model re-indexes the knowledge base automatically, because every
vector stores the model that produced it and retrieval only compares vectors from the same model.

## How the pipeline works

1. **Extract**: the archive is streamed from private storage. Any absolute path, `..` segment, symlink or encrypted
   entry rejects the whole archive; entry count, total size and compression ratio are limited (zip bombs); sizes are
   enforced while streaming.
2. **Discover**: files are classified by language; dependency/build folders (`node_modules`, `vendor`, `dist`, ...),
   lock files, binaries and oversized files are recorded as excluded with a reason.
3. **Scan**: Semgrep runs in batches (default 200 files) with the bundled SecureMatrix rules (53 rules) and selected
   registry packs. Each batch updates progress and checks for cancellation and the time limit. A pack that cannot be
   downloaded is reported as unavailable in the coverage section.
4. **Deduplicate**: results on the same line for the same CWE are merged across rules. The fingerprint ignores line
   numbers, so a finding keeps its identity when code moves; a resolved finding that reappears is reopened.
5. **Retrieve**: each finding gets knowledge references by exact CWE match and pgvector cosine similarity; below
   the evidence threshold it is marked "insufficient evidence".
6. **Score**: `100 x severity x exploitability x exposure x confidence`, with every factor and its reason stored.
   It is an internal prioritisation score, never presented as CVSS.

## Tests

```bash
cd worker
pip install -r requirements-dev.txt     # plus semgrep for the rule tests
python -m pytest -q
```

49 tests cover archive safety (traversal, symlinks, zip bombs, limits, exclusions), CWE/OWASP parsing, severity
mapping, secret redaction, deduplication and fingerprint stability, risk scoring, knowledge-base integrity
(100+ unique CWEs, required categories) and chunking, and that the bundled rules detect each vulnerability in the
demo project without flagging the parameterised query. `python knowledge/validate.py` validates the knowledge base.

## Local development without Supabase Cloud

`npx supabase start` runs the whole stack in Docker and applies the migrations. Use the printed API URL and keys in
`web/.env.local` and `worker/.env`; set `EMBEDDING_PROVIDER=local` to work without an OpenAI key.

## Known limitations

- Static analysis finds code patterns; it cannot prove exploitability. Findings are marked "needs manual review"
  unless the rule confidence is high.
- Authorization logic flaws such as IDOR are mostly invisible to pattern rules (see `order_detail` in the demo).
- No dependency (SCA) scanning yet; repository URL import, incremental scans, patching, verification re-scans,
  threat modelling and PDF reports are in later phases.
- The worker API is plain HTTP on localhost for development; put it behind HTTPS for any shared deployment.
