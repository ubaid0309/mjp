-- SecureMatrix core schema
-- Tables, constraints and indexes. Row Level Security lives in the next migration.

create extension if not exists vector with schema extensions;

-- ---------------------------------------------------------------------------
-- Users and projects
-- ---------------------------------------------------------------------------

create table public.profiles (
  id          uuid primary key references auth.users (id) on delete cascade,
  email       text,
  full_name   text check (char_length(full_name) <= 120),
  role        text not null default 'analyst' check (role in ('admin', 'analyst', 'viewer')),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table public.projects (
  id               uuid primary key default gen_random_uuid(),
  owner_id         uuid not null references public.profiles (id) on delete cascade,
  name             text not null check (char_length(btrim(name)) between 2 and 100),
  description      text check (char_length(description) <= 2000),
  primary_language text check (char_length(primary_language) <= 40),
  source_type      text not null default 'zip' check (source_type in ('zip', 'repository')),
  repository_url   text check (repository_url is null or repository_url ~ '^https://[^\s]+$'),
  scan_settings    jsonb not null default '{}'::jsonb,
  is_demo          boolean not null default false,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now()
);
create index projects_owner_idx on public.projects (owner_id);

create table public.project_members (
  project_id  uuid not null references public.projects (id) on delete cascade,
  user_id     uuid not null references public.profiles (id) on delete cascade,
  role        text not null default 'viewer' check (role in ('owner', 'maintainer', 'viewer')),
  added_at    timestamptz not null default now(),
  primary key (project_id, user_id)
);
create index project_members_user_idx on public.project_members (user_id);

-- ---------------------------------------------------------------------------
-- Scans
-- ---------------------------------------------------------------------------

create table public.scan_jobs (
  id                 uuid primary key default gen_random_uuid(),
  project_id         uuid not null references public.projects (id) on delete cascade,
  created_by         uuid references public.profiles (id) on delete set null,
  scan_type          text not null default 'full' check (scan_type in ('full', 'incremental', 'verification')),
  parent_scan_id     uuid references public.scan_jobs (id) on delete set null,
  status             text not null default 'queued'
                     check (status in ('queued', 'running', 'completed', 'failed', 'cancelled')),
  stage              text not null default 'queued'
                     check (stage in ('queued', 'extracting', 'discovering', 'scanning', 'deduplicating',
                                      'enriching', 'scoring', 'finalizing', 'done')),
  archive_path       text,
  archive_size_bytes bigint check (archive_size_bytes >= 0),
  archive_sha256     text,
  config             jsonb not null default '{}'::jsonb,
  files_total        integer not null default 0 check (files_total >= 0),
  files_scanned      integer not null default 0 check (files_scanned >= 0),
  files_excluded     integer not null default 0 check (files_excluded >= 0),
  batches_total      integer not null default 0 check (batches_total >= 0),
  batches_done       integer not null default 0 check (batches_done >= 0),
  findings_total     integer not null default 0 check (findings_total >= 0),
  coverage           jsonb not null default '{}'::jsonb,
  error_message      text,
  cancel_requested   boolean not null default false,
  worker_id          text,
  attempts           integer not null default 0,
  heartbeat_at       timestamptz,
  queued_at          timestamptz not null default now(),
  started_at         timestamptz,
  finished_at        timestamptz,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now(),
  check (batches_done <= batches_total)
);
create index scan_jobs_project_idx on public.scan_jobs (project_id, created_at desc);
create index scan_jobs_queue_idx on public.scan_jobs (queued_at) where status = 'queued';

create table public.scan_job_events (
  id           bigint generated always as identity primary key,
  scan_job_id  uuid not null references public.scan_jobs (id) on delete cascade,
  stage        text not null,
  level        text not null default 'info' check (level in ('info', 'warning', 'error')),
  message      text not null check (char_length(message) <= 2000),
  created_at   timestamptz not null default now()
);
create index scan_job_events_job_idx on public.scan_job_events (scan_job_id, id);

create table public.project_files_metadata (
  id               uuid primary key default gen_random_uuid(),
  project_id       uuid not null references public.projects (id) on delete cascade,
  scan_job_id      uuid not null references public.scan_jobs (id) on delete cascade,
  path             text not null check (char_length(path) <= 1024),
  language         text,
  size_bytes       bigint not null default 0,
  line_count       integer,
  sha256           text,
  status           text not null check (status in ('queued', 'scanned', 'excluded', 'failed')),
  exclusion_reason text,
  created_at       timestamptz not null default now(),
  unique (scan_job_id, path)
);
create index project_files_project_idx on public.project_files_metadata (project_id);

-- ---------------------------------------------------------------------------
-- Knowledge base (RAG)
-- ---------------------------------------------------------------------------

create table public.knowledge_documents (
  id                 uuid primary key default gen_random_uuid(),
  slug               text not null unique check (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
  cwe_id             text unique check (cwe_id ~ '^CWE-[0-9]+$'),
  title              text not null check (char_length(title) between 3 and 200),
  cwe_name           text,
  category           text not null,
  owasp_top10        text[] not null default '{}',
  owasp_api          text[] not null default '{}',
  severity_default   text not null default 'medium'
                     check (severity_default in ('critical', 'high', 'medium', 'low', 'info')),
  languages          text[] not null default '{}',
  description        text not null,
  prerequisites      text[] not null default '{}',
  impact             text[] not null default '{}',
  detection_patterns text[] not null default '{}',
  remediation        text[] not null default '{}',
  vulnerable_example jsonb,
  secure_example     jsonb,
  cve_examples       jsonb not null default '[]'::jsonb,
  "references"       jsonb not null default '[]'::jsonb,
  source             text not null default 'manual' check (source in ('seed', 'manual', 'import')),
  is_enabled         boolean not null default true,
  version            integer not null default 1,
  content_hash       text,
  index_status       text not null default 'pending'
                     check (index_status in ('pending', 'indexing', 'indexed', 'failed', 'stale')),
  index_error        text,
  indexed_at         timestamptz,
  embedding_model    text,
  chunk_count        integer not null default 0,
  search_tsv         tsvector,
  created_by         uuid references public.profiles (id) on delete set null,
  updated_by         uuid references public.profiles (id) on delete set null,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now()
);
create index knowledge_documents_category_idx on public.knowledge_documents (category);
create index knowledge_documents_tsv_idx on public.knowledge_documents using gin (search_tsv);
create index knowledge_documents_index_status_idx on public.knowledge_documents (index_status);

-- 384 dimensions: OpenAI text-embedding-3-small with dimensions=384, or local bge-small-en-v1.5.
-- embedding_model is stored per chunk; retrieval only compares vectors from the same model.
create table public.knowledge_chunks (
  id              uuid primary key default gen_random_uuid(),
  document_id     uuid not null references public.knowledge_documents (id) on delete cascade,
  chunk_index     integer not null check (chunk_index >= 0),
  section         text not null,
  content         text not null,
  token_estimate  integer not null default 0,
  embedding       extensions.vector(384),
  embedding_model text,
  created_at      timestamptz not null default now(),
  unique (document_id, chunk_index)
);
create index knowledge_chunks_embedding_idx on public.knowledge_chunks
  using hnsw (embedding extensions.vector_cosine_ops);
create index knowledge_chunks_model_idx on public.knowledge_chunks (embedding_model);

-- ---------------------------------------------------------------------------
-- Findings
-- ---------------------------------------------------------------------------

create table public.vulnerabilities (
  id                         uuid primary key default gen_random_uuid(),
  ref_no                     bigint generated always as identity unique,
  project_id                 uuid not null references public.projects (id) on delete cascade,
  fingerprint                text not null,
  title                      text not null,
  description                text,
  category                   text,
  severity                   text not null check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  confidence                 text not null default 'medium' check (confidence in ('high', 'medium', 'low')),
  source                     text not null default 'scanner_confirmed'
                             check (source in ('scanner_confirmed', 'ai_potential')),
  detection_method           text not null,
  rule_ids                   text[] not null default '{}',
  cwe_ids                    text[] not null default '{}',
  owasp_top10                text[] not null default '{}',
  language                   text,
  file_path                  text not null,
  start_line                 integer check (start_line >= 0),
  end_line                   integer check (end_line >= 0),
  snippet                    text,
  requires_manual_review     boolean not null default true,
  risk_score                 numeric(5, 1) check (risk_score between 0 and 100),
  risk_rationale             jsonb not null default '{}'::jsonb,
  priority                   text check (priority in ('P1', 'P2', 'P3', 'P4')),
  status                     text not null default 'new'
                             check (status in ('new', 'triaged', 'in_progress', 'fix_proposed', 'fix_applied',
                                               'verification_pending', 'resolved', 'accepted_risk')),
  verification_status        text not null default 'not_started'
                             check (verification_status in ('not_started', 'pending', 'verified_resolved',
                                    'still_detected', 'partially_resolved', 'verification_failed', 'manual_review')),
  kb_evidence_status         text not null default 'pending'
                             check (kb_evidence_status in ('pending', 'matched', 'insufficient', 'unavailable')),
  first_seen_scan_id         uuid references public.scan_jobs (id) on delete set null,
  last_seen_scan_id          uuid references public.scan_jobs (id) on delete set null,
  occurrence_count           integer not null default 1,
  reopened_count             integer not null default 0,
  assignee_id                uuid references public.profiles (id) on delete set null,
  due_date                   date,
  accepted_risk_justification text,
  created_at                 timestamptz not null default now(),
  updated_at                 timestamptz not null default now(),
  resolved_at                timestamptz,
  unique (project_id, fingerprint),
  -- A finding can only be resolved after a verification re-scan confirmed it is gone.
  constraint resolved_requires_verification
    check (status <> 'resolved' or verification_status = 'verified_resolved'),
  constraint accepted_risk_requires_justification
    check (status <> 'accepted_risk' or char_length(btrim(coalesce(accepted_risk_justification, ''))) >= 10)
);
create index vulnerabilities_project_idx on public.vulnerabilities (project_id, severity);
create index vulnerabilities_status_idx on public.vulnerabilities (status);
create index vulnerabilities_last_scan_idx on public.vulnerabilities (last_seen_scan_id);
create index vulnerabilities_cwe_idx on public.vulnerabilities using gin (cwe_ids);

-- Raw scanner hits, before deduplication. Several hits can map to one vulnerability.
create table public.scan_results (
  id               uuid primary key default gen_random_uuid(),
  scan_job_id      uuid not null references public.scan_jobs (id) on delete cascade,
  project_id       uuid not null references public.projects (id) on delete cascade,
  vulnerability_id uuid references public.vulnerabilities (id) on delete set null,
  scanner          text not null,
  rule_id          text not null,
  file_path        text not null,
  start_line       integer,
  end_line         integer,
  severity_raw     text,
  message          text,
  metadata         jsonb not null default '{}'::jsonb,
  fingerprint      text not null,
  created_at       timestamptz not null default now()
);
create index scan_results_job_idx on public.scan_results (scan_job_id);
create index scan_results_vuln_idx on public.scan_results (vulnerability_id);

create table public.finding_knowledge_refs (
  id               uuid primary key default gen_random_uuid(),
  vulnerability_id uuid not null references public.vulnerabilities (id) on delete cascade,
  document_id      uuid not null references public.knowledge_documents (id) on delete cascade,
  chunk_id         uuid references public.knowledge_chunks (id) on delete set null,
  similarity       real,
  match_type       text not null check (match_type in ('cwe_exact', 'semantic', 'cwe_and_semantic')),
  rank             integer not null default 0,
  retrieved_with   text,
  created_at       timestamptz not null default now(),
  unique (vulnerability_id, document_id)
);
create index finding_knowledge_refs_vuln_idx on public.finding_knowledge_refs (vulnerability_id, rank);

-- ---------------------------------------------------------------------------
-- Remediation, threats, collaboration, audit
-- ---------------------------------------------------------------------------

create table public.remediation_suggestions (
  id               uuid primary key default gen_random_uuid(),
  vulnerability_id uuid not null references public.vulnerabilities (id) on delete cascade,
  created_by       uuid references public.profiles (id) on delete set null,
  generator        text not null check (generator in ('llm', 'knowledge_base', 'manual')),
  model            text,
  root_cause       text,
  recommendation   text not null,
  before_code      text,
  after_code       text,
  patch_diff       text,
  rationale        text,
  side_effects     text,
  "references"     jsonb not null default '[]'::jsonb,
  status           text not null default 'proposed'
                   check (status in ('proposed', 'approved', 'rejected', 'applied', 'superseded', 'rolled_back')),
  -- Only a verification re-scan may set this.
  is_verified      boolean not null default false,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now()
);
create index remediation_suggestions_vuln_idx on public.remediation_suggestions (vulnerability_id);

create table public.remediation_history (
  id               uuid primary key default gen_random_uuid(),
  vulnerability_id uuid not null references public.vulnerabilities (id) on delete cascade,
  suggestion_id    uuid references public.remediation_suggestions (id) on delete set null,
  scan_job_id      uuid references public.scan_jobs (id) on delete set null,
  action           text not null check (action in ('proposed', 'approved', 'rejected', 'applied', 'rolled_back',
                                                   'verification_started', 'verification_result')),
  actor_id         uuid references public.profiles (id) on delete set null,
  details          jsonb not null default '{}'::jsonb,
  created_at       timestamptz not null default now()
);
create index remediation_history_vuln_idx on public.remediation_history (vulnerability_id, created_at);

create table public.threat_scenarios (
  id                      uuid primary key default gen_random_uuid(),
  project_id              uuid not null references public.projects (id) on delete cascade,
  scan_job_id             uuid references public.scan_jobs (id) on delete set null,
  title                   text not null,
  description             text,
  stride_category         text check (stride_category in ('spoofing', 'tampering', 'repudiation',
                                     'information_disclosure', 'denial_of_service', 'elevation_of_privilege')),
  threat_source           text,
  affected_component      text,
  attack_scenario         text,
  preconditions           text[] not null default '{}',
  impact                  text,
  likelihood              text check (likelihood in ('low', 'medium', 'high')),
  impact_level            text check (impact_level in ('low', 'medium', 'high')),
  mitigations             text[] not null default '{}',
  related_vulnerability_ids uuid[] not null default '{}',
  -- Threats are inferred from code and configuration, never observed network activity.
  basis                   text not null default 'inferred' check (basis in ('inferred')),
  status                  text not null default 'open' check (status in ('open', 'mitigated', 'accepted')),
  created_at              timestamptz not null default now(),
  updated_at              timestamptz not null default now()
);
create index threat_scenarios_project_idx on public.threat_scenarios (project_id);

create table public.finding_assignments (
  id               uuid primary key default gen_random_uuid(),
  vulnerability_id uuid not null references public.vulnerabilities (id) on delete cascade,
  assignee_id      uuid not null references public.profiles (id) on delete cascade,
  assigned_by      uuid references public.profiles (id) on delete set null,
  note             text check (char_length(note) <= 1000),
  created_at       timestamptz not null default now(),
  unassigned_at    timestamptz
);
create index finding_assignments_vuln_idx on public.finding_assignments (vulnerability_id);

create table public.finding_comments (
  id               uuid primary key default gen_random_uuid(),
  vulnerability_id uuid not null references public.vulnerabilities (id) on delete cascade,
  author_id        uuid not null references public.profiles (id) on delete cascade,
  body             text not null check (char_length(btrim(body)) between 1 and 5000),
  created_at       timestamptz not null default now(),
  edited_at        timestamptz
);
create index finding_comments_vuln_idx on public.finding_comments (vulnerability_id, created_at);

create table public.audit_logs (
  id          bigint generated always as identity primary key,
  actor_id    uuid references public.profiles (id) on delete set null,
  project_id  uuid references public.projects (id) on delete cascade,
  entity_type text not null,
  entity_id   uuid,
  action      text not null,
  old_values  jsonb,
  new_values  jsonb,
  created_at  timestamptz not null default now()
);
create index audit_logs_project_idx on public.audit_logs (project_id, created_at desc);
create index audit_logs_entity_idx on public.audit_logs (entity_type, entity_id);

-- Written by workers so the Settings page can show what is really configured.
-- Never contains secrets, only provider/model names and booleans.
create table public.worker_status (
  worker_id          text primary key,
  hostname           text,
  version            text,
  semgrep_version    text,
  embedding_provider text,
  embedding_model    text,
  llm_provider       text,
  llm_model          text,
  capabilities       jsonb not null default '{}'::jsonb,
  started_at         timestamptz not null default now(),
  last_heartbeat_at  timestamptz not null default now()
);
