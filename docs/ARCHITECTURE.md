# SecureMatrix: architecture and workflow

Figures for reports, slides and the research paper. Every figure exists as SVG (vector, use this in Word/LaTeX)
and PNG (3x resolution) in [`docs/diagrams/`](diagrams/). Solid elements are implemented; dashed elements are planned.

| Fig. | File | Shows |
|---|---|---|
| 1 | `01-system-architecture` | Components, trust boundaries and how they communicate |
| 2 | `02-end-to-end-workflow` | The workflow from upload to verified fix |
| 3 | `03-scan-pipeline` | What the worker does for one scan job |
| 4 | `04-rag-pipeline` | Knowledge indexing and retrieval-augmented generation |
| 5 | `05-scan-sequence` | Message sequence between all actors during a scan |
| 6 | `06-finding-lifecycle` | Finding states and allowed transitions |
| 7 | `07-data-model` | Core database entities and relationships |

---

## Fig. 1: System architecture

*Caption: SecureMatrix architecture. The browser talks to Supabase directly under Row Level Security; a separate
worker runs long scans and the RAG API with a service-role key that never reaches the client.*

SecureMatrix has four tiers:

1. **Presentation layer.** A React + TypeScript single-page application. It holds only the public (anon) Supabase
   key, so every read it makes is filtered by Row Level Security (RLS) to the projects the user belongs to.
2. **Supabase platform.** Auth issues JWT sessions; PostgREST exposes tables and remote procedures (RPC); PostgreSQL
   with the pgvector extension stores both relational data and 384-dimensional embeddings; Storage keeps uploaded
   archives in a private bucket under `<user id>/<project id>/`. State-changing operations that need validation
   (queueing a scan, changing a finding's status, re-indexing) are `SECURITY DEFINER` functions, so a client cannot
   write fields such as severity or fingerprint directly.
3. **SecureMatrix worker.** A Python service in a Docker container with four parts: a job loop that claims queued
   scans with `FOR UPDATE SKIP LOCKED` (several workers can run safely), the scan pipeline, the knowledge indexer,
   and a FastAPI RAG API used by the browser for semantic search and grounded Q&A. The API verifies the user's JWT
   with Supabase Auth on every request.
4. **External services.** Semgrep CE performs static analysis; OpenAI provides embeddings
   (text-embedding-3-small, reduced to 384 dimensions) and the chat model used only for grounded answers.

Design choice: scanning runs in a worker rather than in serverless Edge Functions because Semgrep is a native binary
and a large project can take minutes, beyond typical function time limits.

## Fig. 2: End-to-end workflow

*Caption: SecureMatrix workflow. Steps up to triage are implemented; remediation, verification re-scan and threat
analysis (dashed) are planned.*

Upload → private storage and job queue → safe extraction → batched static analysis → normalisation and
deduplication → RAG retrieval → risk scoring → persisted findings → review and triage. The planned loop adds a
patch proposal, explicit user approval, application to a copy of the code (the original upload is never modified)
and a verification re-scan; only that re-scan can mark a finding resolved.

## Fig. 3: Scan pipeline

*Caption: Stages executed by the worker for one scan job, grouped into ingestion, batched analysis, and
enrichment/persistence.*

- **Ingest.** The archive is streamed with a size limit. The whole archive is rejected if any entry has an absolute
  path, a `..` segment, a symbolic link or encryption, or if limits on entry count, total expanded size or
  compression ratio (zip bombs) are exceeded. Sizes are enforced while writing, not trusted from ZIP headers.
  Dependency folders (`node_modules`, `vendor`, ...), build output, lock files, binaries and oversized files are
  recorded with a reason but not analysed.
- **Batched analysis.** Files are split into batches (default 200). Before each batch the worker checks the cancel
  flag and the time limit; after each batch it records `batches_done` and a heartbeat, which is what the progress
  bar shows (no simulated progress). Rule sets that cannot be loaded are listed as unavailable in the coverage report.
- **Enrich and persist.** Results are normalised (CWE, OWASP 2021, severity, confidence), secrets are redacted from
  snippets, duplicates across rules are merged, knowledge is retrieved, risk is scored, and findings are upserted:
  a fingerprint that ignores line numbers lets a finding keep its identity across scans, and a resolved finding
  that reappears is reopened automatically.

## Fig. 4: RAG pipeline

*Caption: Retrieval-augmented generation in SecureMatrix. (A) The 116-record CWE knowledge base is chunked and
embedded into pgvector. (B) Findings and questions retrieve evidence by exact CWE match and cosine similarity; below
the threshold the system reports insufficient evidence instead of generating an answer.*

- **Knowledge base.** 116 records, one per CWE weakness class (no duplicates), each with OWASP Top 10 2021 and OWASP
  API Security 2023 mappings, description, attack prerequisites, impact, detection patterns, remediation, vulnerable
  and secure code examples, verified CVE examples where well established, and references.
- **Chunking.** Each record becomes section chunks (overview, detection, remediation) of at most 1,600 characters.
  Every chunk repeats the CWE ID and title so it is self-describing when retrieved alone.
- **Embedding.** Each vector stores the model that produced it; retrieval only compares vectors from the same
  model, and changing the model triggers re-indexing. Editing a document marks it stale and it is re-embedded.
- **Hybrid retrieval.** Exact CWE metadata matches are combined with top-k cosine similarity (HNSW index).
- **Evidence threshold.** Matches below a model-specific similarity threshold (0.30 for OpenAI
  text-embedding-3-small at 384 dimensions) are not treated as evidence. In testing, security queries scored
  0.35-0.60 and unrelated queries 0.14-0.28.
- **Grounded generation.** The language model receives only numbered excerpts and must cite them; if the excerpts
  are insufficient it must answer with a fixed "not enough evidence" sentence. Answers are labelled AI-generated.

## Fig. 5: Scan sequence

*Caption: Interaction sequence for one scan, from sign-in to a grounded explanation of a finding.*

Note steps 7 (`create_scan_job` validates the storage path and clamps scan settings server-side), 9
(`claim_next_scan_job` with row locking), 13-16 (per-batch cancellation check and progress) and 26 (JWT
verification before any RAG call).

## Fig. 6 and Table 1: Finding lifecycle

*Caption: Finding lifecycle. Transitions are enforced by the database; "Resolved" can only be reached through a
verification re-scan.*

| From | Allowed next states |
|---|---|
| New | Triaged, In progress, Fix proposed, Accepted risk |
| Triaged | In progress, Fix proposed, Accepted risk |
| In progress | Triaged, Fix proposed, Accepted risk |
| Fix proposed | In progress, Fix applied |
| Fix applied | Verification pending, In progress |
| Verification pending | In progress (still detected); Resolved (verifier only) |
| Resolved | Triaged, In progress (reopen; automatic when a scan detects it again) |
| Accepted risk | Triaged (acceptance revoked) |

Two database constraints back this up: `status = resolved` requires `verification_status = verified_resolved`, and
`status = accepted_risk` requires a justification of at least 10 characters. Every change is written to the audit log.

## Fig. 7: Data model

*Caption: Core entities (simplified). All 18 tables have Row Level Security enabled.*

`projects` own `scan_jobs`; a scan produces raw `scan_results` that are merged into persistent `vulnerabilities`
(unique per project and fingerprint). Findings cite `knowledge_documents` through `finding_knowledge_refs`, which
record the match type and similarity, making every explanation traceable to its source.

---

## Risk score (sm-risk-v1)

`risk = 100 x S x E x X x C`, rounded to one decimal, where

| Factor | Values |
|---|---|
| S, severity | critical 0.95, high 0.75, medium 0.50, low 0.25, info 0.05 |
| E, exploitability | 1.0 for directly exploitable classes (e.g. CWE-78, 89, 22, 502, 918); 0.8 for classes needing extra conditions (e.g. CWE-79, 352, 327); 0.65 other mapped CWEs; 0.6 unmapped |
| X, exposure | 1.0 entry points (routes, controllers, handlers); 0.9 configuration; 0.8 other code; 0.4 tests and examples |
| C, confidence | high 1.0, medium 0.85, low 0.7 |

Priority: P1 >= 65, P2 >= 40, P3 >= 15, otherwise P4. The factors and reasons are stored with each finding. This is an
internal prioritisation score and is not presented as CVSS.

## Measured results (Phase 1)

| Measure | Result |
|---|---|
| Knowledge base | 116 records, 116 unique CWE IDs, 23 categories, 0 validation errors |
| Bundled Semgrep rules | 53 (Python, JavaScript/TypeScript, PHP, Java, secrets, configuration) |
| Demo project (ByteMart, 10 source files, 5 languages) | 54 raw results merged into 48 findings (20 critical, 13 high, 15 medium); dependency folder correctly excluded |
| Scan time for the demo project | 7-16 seconds end to end (16 s including registry rule download and OpenAI embeddings) |
| Knowledge evidence | 48 of 48 findings matched (CWE + vector retrieval with OpenAI embeddings) |
| Example retrieval | SQL injection finding: CWE-89 at similarity 0.80; path traversal: CWE-22 at 0.76 |
| Automated tests | 49 passing (archive safety, deduplication, redaction, risk score, knowledge base integrity, rule detection) |
| Known false positive | SSRF taint rule on the secure reference version (an allow-list check is invisible to the rule) |

## Regenerating the figures

- Figures 1, 3, 4, 6: edit `docs/diagrams/src/build.py`, then run `python3 docs/diagrams/src/build.py`.
- Figures 2, 5, 7: edit the `.mmd` files (Mermaid), then render with
  `npx @mermaid-js/mermaid-cli -i <file>.mmd -o <file>.svg -c docs/diagrams/mermaid-config.json -b white`.
  They can also be pasted into https://mermaid.live.
- PNGs: `node docs/diagrams/src/render.cjs` (needs Playwright) or export from the SVG in any editor.
