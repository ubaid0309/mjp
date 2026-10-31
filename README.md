# SecureMatrix – Vulnerability and Threat Management Platform

SecureMatrix analyses uploaded source code with a real static-analysis engine (Semgrep), stores every finding with its
evidence, explains each one using a Retrieval-Augmented Generation (RAG) security knowledge base of 116 CWE weakness
classes, scores and prioritises it, and tracks it through a remediation lifecycle.

Final-year BE Computer Engineering major project. The full roadmap is in [`docs/PLAN.md`](docs/PLAN.md).

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

## Setup on Windows with Supabase Cloud

Prerequisites: Node.js 20+, Docker Desktop, a free Supabase project, and optionally an OpenAI API key.

### 1. Database

1. Create a project at supabase.com. From **Project settings > API** copy the project URL, the `anon`/publishable key
   and the `service_role`/secret key.
2. Open **SQL Editor** and run the three files in `supabase/migrations/` in order (`...0100_core_schema.sql`,
   `...0200_functions_and_rls.sql`, `...0300_worker_rpcs.sql`).
   With the Supabase CLI you can instead run `npx supabase link --project-ref <ref>` then `npx supabase db push`.
3. For a quick demo, turn off **Authentication > Providers > Email > Confirm email**, or confirm accounts by email.

### 2. Worker

```powershell
copy worker\.env.example worker\.env      # fill SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, OPENAI_API_KEY
docker compose up --build -d worker
docker compose run --rm worker python -m securematrix_worker kb-import
```

`kb-import` loads the 116 knowledge documents. The running worker embeds them within about 30 seconds
(OpenAI `text-embedding-3-small`, 384 dimensions); watch progress on the Knowledge base page.
Check `http://localhost:8787/health`: it reports the Semgrep version, embedding model and whether the LLM is configured.

### 3. Web app

```powershell
cd web
copy .env.example .env.local              # fill VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY
npm install
npm run dev                               # http://localhost:5173
```

Register (the first account becomes admin), open **New scan** and upload `demo/bytemart-vulnerable.zip`.

## Environment variables

| Where | Variable | Purpose |
|---|---|---|
| web | `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY` | Public Supabase settings (RLS protects data) |
| web | `VITE_WORKER_API_URL` | Worker API, default `http://localhost:8787` |
| worker | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | Required. The service key never leaves the worker |
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
