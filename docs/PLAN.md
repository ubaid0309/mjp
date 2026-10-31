# SecureMatrix — Implementation Plan

This is the working plan for the project. Each phase ends with something that runs end to end; nothing in the UI shows data that was not produced by the backend.

## Architecture decisions

| Concern | Decision | Why |
|---|---|---|
| Database, auth, storage | Supabase (cloud for the demo; local CLI stack for development) | Postgres + pgvector + RLS + private buckets in one place |
| Long-running scans | Python worker (`worker/`), runs in Docker on Windows | Semgrep is a native binary and scans can run for minutes, which rules out Edge Functions for this part |
| Job queue | `scan_jobs` table, claimed with `FOR UPDATE SKIP LOCKED` through a service-role-only RPC | No extra infrastructure; several workers can run safely |
| Static analysis | Semgrep CE: registry packs + SecureMatrix's own bundled rules | Real scanner; bundled rules keep working offline and the scan record says which rule sets actually ran |
| Embeddings | OpenAI `text-embedding-3-small` at 384 dimensions (local `bge-small-en-v1.5` as an optional fallback) | Every chunk records the model it was embedded with; retrieval only compares vectors from the same model |
| Generation | OpenAI chat model, configurable, used only after retrieval | Grounded on retrieved chunks + scanner evidence; labelled as AI-generated and unverified |
| User mutations | Security-definer RPCs (status change, cancel scan, comments) | RLS can't restrict columns, so this stops a user from editing severity or fingerprints |
| Lifecycle rule | DB trigger rejects `resolved` unless a verification re-scan set `verification_status = verified_resolved` | A suggested fix can never mark itself resolved |

## Phases

### Phase 1: Foundation and core scan pipeline (the 30–40% review)
1. Schema for all 14 required tables plus supporting tables (`project_members`, `scan_job_events`, `finding_knowledge_refs`, `worker_status`), RLS on every table, private storage buckets, RPCs.
2. Auth (email/password); the first registered user becomes admin.
3. Knowledge base: 100+ unique CWE-keyed records (CWE, OWASP Top 10 2021, OWASP API 2023, impact, prerequisites, detection patterns, remediation, examples, references, verified CVEs only). Import + chunk + embed + pgvector index.
4. Worker: safe ZIP extraction (path traversal, symlinks, zip bombs, size/count limits), file discovery and classification, batched Semgrep runs with real progress, cancellation, normalisation, deduplication, secret redaction, CWE/OWASP mapping, risk scoring, RAG retrieval per finding.
5. Frontend: login/register, dashboard (live metrics), projects, new scan upload, scan progress and results, vulnerability explorer with filters, finding detail (evidence, RAG references, KB remediation guidance, lifecycle status), knowledge-base admin (search, filters, counts, index status, add/edit/disable, re-index), scan history, settings/system status.
6. A deliberately vulnerable demo project with secure counterparts.

### Phase 2: Remediation and verification
- Grounded remediation suggestions (root cause, patch/diff, side effects, references), approval flow, patch history, rollback.
- Verification re-scan of the patched copy, so the original upload is never modified; statuses: verified / still detected / partial / failed / manual review.
- Lifecycle extras: assignments, comments, due dates, risk acceptance with justification, overdue tracking.

### Phase 3: Threat analysis and reporting
- Attack-surface extraction (routes, entry points, config), STRIDE scenarios linked to findings and labelled as *inferred*.
- PDF + JSON reports (coverage, methodology, limitations, RAG references).
- Configurable risk weights in Settings.

### Phase 4: Scale and polish
- Incremental re-scan by file hash, repository URL import, extra scanners (e.g. dependency audit), analytics, automated test suite for the full workflow, deployment guide.

## Honesty rules
- No fake progress: progress is `batches_done / batches_total` written by the worker.
- If Semgrep, the embedding provider or the LLM isn't configured, the UI says so; it never invents a result.
- Internal scores are labelled "SecureMatrix risk score", never CVSS.
- Findings carry their source: `scanner_confirmed` vs `ai_potential`; KB text is shown as "retrieved knowledge"; fixes are "unverified" until a re-scan confirms them.
