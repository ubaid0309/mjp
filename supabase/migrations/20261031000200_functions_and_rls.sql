-- SecureMatrix access control, triggers and RPCs.
-- Rule of thumb: clients can read what their project membership allows; anything that
-- changes security-relevant state goes through a SECURITY DEFINER function that validates it.

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

create or replace function public.is_project_member(p_project_id uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.project_members
    where project_id = p_project_id and user_id = auth.uid()
  );
$$;

create or replace function public.can_edit_project(p_project_id uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.project_members
    where project_id = p_project_id and user_id = auth.uid() and role in ('owner', 'maintainer')
  );
$$;

create or replace function public.vulnerability_project(p_vulnerability_id uuid)
returns uuid language sql stable security definer set search_path = '' as $$
  select project_id from public.vulnerabilities where id = p_vulnerability_id;
$$;

create or replace function public.touch_updated_at()
returns trigger language plpgsql set search_path = '' as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

do $$
declare t text;
begin
  foreach t in array array['profiles', 'projects', 'scan_jobs', 'knowledge_documents', 'vulnerabilities',
                           'remediation_suggestions', 'threat_scenarios']
  loop
    execute format('create trigger %I_touch before update on public.%I
                    for each row execute function public.touch_updated_at()', t, t);
  end loop;
end $$;

-- ---------------------------------------------------------------------------
-- Profiles: created on sign-up. The very first user becomes admin so a fresh
-- deployment can be administered; later users are analysts.
-- ---------------------------------------------------------------------------

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  v_role text := 'analyst';
begin
  perform pg_advisory_xact_lock(hashtext('securematrix_first_admin'));
  if not exists (select 1 from public.profiles where role = 'admin') then
    v_role := 'admin';
  end if;
  insert into public.profiles (id, email, full_name, role)
  values (new.id, new.email, left(coalesce(new.raw_user_meta_data ->> 'full_name', ''), 120), v_role);
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Users may edit their own name, never their role.
create or replace function public.protect_profile_role()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if new.role is distinct from old.role and coalesce(auth.role(), '') <> 'service_role' and not public.is_admin() then
    raise exception 'Only administrators can change roles';
  end if;
  return new;
end;
$$;
create trigger profiles_protect_role before update on public.profiles
  for each row execute function public.protect_profile_role();

-- Project owner becomes a member automatically.
create or replace function public.add_project_owner()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.project_members (project_id, user_id, role)
  values (new.id, new.owner_id, 'owner')
  on conflict do nothing;
  insert into public.audit_logs (actor_id, project_id, entity_type, entity_id, action, new_values)
  values (auth.uid(), new.id, 'project', new.id, 'created', jsonb_build_object('name', new.name));
  return new;
end;
$$;
create trigger projects_add_owner after insert on public.projects
  for each row execute function public.add_project_owner();

-- ---------------------------------------------------------------------------
-- Knowledge documents: keep the keyword index and content hash current, and mark
-- indexed documents stale when their content changes so they get re-embedded.
-- ---------------------------------------------------------------------------

create or replace function public.knowledge_document_prepare()
returns trigger language plpgsql set search_path = '' as $$
declare
  v_text text;
  v_hash text;
begin
  v_text := concat_ws(E'\n', new.title, new.cwe_id, new.cwe_name, new.category, new.description,
                      array_to_string(new.prerequisites, E'\n'), array_to_string(new.impact, E'\n'),
                      array_to_string(new.detection_patterns, E'\n'), array_to_string(new.remediation, E'\n'),
                      new.vulnerable_example::text, new.secure_example::text);
  v_hash := encode(extensions.digest(v_text, 'sha256'), 'hex');
  new.search_tsv :=
    setweight(to_tsvector('english', coalesce(new.title, '') || ' ' || coalesce(new.cwe_id, '')), 'A') ||
    setweight(to_tsvector('english', coalesce(new.cwe_name, '') || ' ' || coalesce(new.category, '')), 'B') ||
    setweight(to_tsvector('english', v_text), 'C');
  if tg_op = 'UPDATE' and new.content_hash is distinct from v_hash then
    new.version := old.version + 1;
    if old.index_status = 'indexed' and new.index_status = 'indexed' then
      new.index_status := 'stale';
    end if;
  end if;
  new.content_hash := v_hash;
  return new;
end;
$$;
create trigger knowledge_documents_prepare before insert or update on public.knowledge_documents
  for each row execute function public.knowledge_document_prepare();

-- ---------------------------------------------------------------------------
-- Findings lifecycle
-- ---------------------------------------------------------------------------

create or replace function public.finding_transition_allowed(p_from text, p_to text)
returns boolean language sql immutable as $$
  select case p_from
    when 'new'                  then p_to in ('triaged', 'in_progress', 'fix_proposed', 'accepted_risk')
    when 'triaged'              then p_to in ('in_progress', 'fix_proposed', 'accepted_risk')
    when 'in_progress'          then p_to in ('triaged', 'fix_proposed', 'accepted_risk')
    when 'fix_proposed'         then p_to in ('in_progress', 'fix_applied')
    when 'fix_applied'          then p_to in ('verification_pending', 'in_progress')
    when 'verification_pending' then p_to in ('in_progress')        -- resolved is set by the verifier only
    when 'resolved'             then p_to in ('triaged', 'in_progress')  -- reopen
    when 'accepted_risk'        then p_to in ('triaged')                 -- revoke acceptance
    else false
  end;
$$;

create or replace function public.update_finding_status(
  p_vulnerability_id uuid,
  p_status text,
  p_note text default null
) returns public.vulnerabilities
language plpgsql security definer set search_path = '' as $$
declare
  v public.vulnerabilities;
  v_old_status text;
begin
  select * into v from public.vulnerabilities where id = p_vulnerability_id for update;
  v_old_status := v.status;
  if not found or not public.can_edit_project(v.project_id) then
    raise exception 'Finding not found or you do not have permission to change it' using errcode = '42501';
  end if;
  if v.status = p_status then
    return v;
  end if;
  if not public.finding_transition_allowed(v.status, p_status) then
    raise exception 'Status change % -> % is not allowed', v.status, p_status using errcode = '22023';
  end if;
  if p_status = 'accepted_risk' and char_length(btrim(coalesce(p_note, ''))) < 10 then
    raise exception 'Accepting a risk requires a justification of at least 10 characters' using errcode = '22023';
  end if;

  update public.vulnerabilities set
    status = p_status,
    accepted_risk_justification = case when p_status = 'accepted_risk' then btrim(p_note)
                                       when v.status = 'accepted_risk' then null
                                       else accepted_risk_justification end,
    reopened_count = reopened_count + case when v.status = 'resolved' then 1 else 0 end,
    resolved_at = case when v.status = 'resolved' then null else resolved_at end,
    verification_status = case when v.status = 'resolved' then 'not_started'
                               when p_status = 'verification_pending' then 'pending'
                               else verification_status end
  where id = p_vulnerability_id
  returning * into v;

  insert into public.audit_logs (actor_id, project_id, entity_type, entity_id, action, old_values, new_values)
  values (auth.uid(), v.project_id, 'vulnerability', v.id, 'status_changed',
          jsonb_build_object('status', v_old_status),
          jsonb_build_object('status', p_status, 'note', nullif(btrim(coalesce(p_note, '')), '')));
  return v;
end;
$$;

-- ---------------------------------------------------------------------------
-- Scans
-- ---------------------------------------------------------------------------

create or replace function public.create_scan_job(
  p_project_id uuid,
  p_archive_path text,
  p_archive_size_bytes bigint,
  p_config jsonb default '{}'::jsonb
) returns public.scan_jobs
language plpgsql security definer set search_path = '' as $$
declare
  v_job public.scan_jobs;
  v_config jsonb;
begin
  if not public.can_edit_project(p_project_id) then
    raise exception 'You do not have permission to scan this project' using errcode = '42501';
  end if;
  -- Uploads must live under <user id>/<project id>/ in the private bucket.
  if p_archive_path is null
     or split_part(p_archive_path, '/', 1) <> auth.uid()::text
     or split_part(p_archive_path, '/', 2) <> p_project_id::text
     or p_archive_path ~ '\.\.' then
    raise exception 'Invalid archive path' using errcode = '22023';
  end if;
  if exists (select 1 from public.scan_jobs where project_id = p_project_id and status in ('queued', 'running')) then
    raise exception 'A scan is already queued or running for this project' using errcode = '55000';
  end if;
  -- Keep only known settings, clamped to safe ranges.
  v_config := jsonb_build_object(
    'rulesets', coalesce((select jsonb_agg(r) from jsonb_array_elements_text(coalesce(p_config -> 'rulesets', '[]')) r
                          where r in ('securematrix', 'p/security-audit', 'p/owasp-top-ten', 'p/secrets',
                                      'p/python', 'p/javascript', 'p/typescript', 'p/java', 'p/php',
                                      'p/golang', 'p/c', 'p/sql-injection', 'p/xss', 'p/command-injection')),
                         '["securematrix", "p/security-audit", "p/secrets"]'::jsonb),
    'max_file_size_kb', least(greatest(coalesce((p_config ->> 'max_file_size_kb')::int, 512), 16), 4096),
    'max_files', least(greatest(coalesce((p_config ->> 'max_files')::int, 5000), 1), 20000),
    'batch_size', least(greatest(coalesce((p_config ->> 'batch_size')::int, 200), 10), 1000),
    'timeout_minutes', least(greatest(coalesce((p_config ->> 'timeout_minutes')::int, 30), 1), 120),
    'exclude_globs', coalesce(p_config -> 'exclude_globs', '[]'::jsonb)
  );

  insert into public.scan_jobs (project_id, created_by, archive_path, archive_size_bytes, config)
  values (p_project_id, auth.uid(), p_archive_path, p_archive_size_bytes, v_config)
  returning * into v_job;

  insert into public.scan_job_events (scan_job_id, stage, message)
  values (v_job.id, 'queued', 'Scan queued');
  insert into public.audit_logs (actor_id, project_id, entity_type, entity_id, action, new_values)
  values (auth.uid(), p_project_id, 'scan_job', v_job.id, 'queued', v_config);
  return v_job;
end;
$$;

create or replace function public.request_scan_cancel(p_scan_job_id uuid)
returns public.scan_jobs
language plpgsql security definer set search_path = '' as $$
declare
  v_job public.scan_jobs;
begin
  select * into v_job from public.scan_jobs where id = p_scan_job_id for update;
  if not found or not public.can_edit_project(v_job.project_id) then
    raise exception 'Scan not found' using errcode = '42501';
  end if;
  if v_job.status = 'queued' then
    update public.scan_jobs set status = 'cancelled', cancel_requested = true, finished_at = now()
    where id = p_scan_job_id returning * into v_job;
    insert into public.scan_job_events (scan_job_id, stage, level, message)
    values (p_scan_job_id, v_job.stage, 'warning', 'Cancelled before a worker picked it up');
  elsif v_job.status = 'running' then
    update public.scan_jobs set cancel_requested = true where id = p_scan_job_id returning * into v_job;
    insert into public.scan_job_events (scan_job_id, stage, level, message)
    values (p_scan_job_id, v_job.stage, 'warning', 'Cancellation requested; the worker stops after the current batch');
  end if;
  return v_job;
end;
$$;

-- Worker only. Picks the oldest queued job, or a running job whose worker stopped
-- sending heartbeats (crashed), up to 3 attempts.
create or replace function public.claim_next_scan_job(p_worker_id text)
returns setof public.scan_jobs
language plpgsql security definer set search_path = '' as $$
declare
  v_id uuid;
begin
  update public.scan_jobs set status = 'failed', finished_at = now(),
         error_message = 'Worker stopped responding and the retry limit was reached'
  where status = 'running' and heartbeat_at < now() - interval '10 minutes' and attempts >= 3;

  select id into v_id from public.scan_jobs
  where (status = 'queued' and not cancel_requested)
     or (status = 'running' and heartbeat_at < now() - interval '10 minutes' and attempts < 3)
  order by queued_at
  limit 1
  for update skip locked;

  if v_id is null then
    return;
  end if;

  return query
  update public.scan_jobs set
    status = 'running', worker_id = p_worker_id, attempts = attempts + 1,
    heartbeat_at = now(), started_at = coalesce(started_at, now()), error_message = null
  where id = v_id
  returning *;
end;
$$;

-- ---------------------------------------------------------------------------
-- RAG retrieval
-- ---------------------------------------------------------------------------

create or replace function public.match_knowledge_chunks(
  p_query_embedding extensions.vector(384),
  p_embedding_model text,
  p_match_count integer default 8,
  p_min_similarity real default 0.0,
  p_cwe_ids text[] default null
) returns table (
  chunk_id uuid,
  document_id uuid,
  slug text,
  cwe_id text,
  title text,
  category text,
  section text,
  content text,
  similarity real
)
language sql stable set search_path = '' as $$
  select c.id, d.id, d.slug, d.cwe_id, d.title, d.category, c.section, c.content,
         (1 - (c.embedding operator(extensions.<=>) p_query_embedding))::real as similarity
  from public.knowledge_chunks c
  join public.knowledge_documents d on d.id = c.document_id
  where d.is_enabled
    and c.embedding is not null
    and c.embedding_model = p_embedding_model
    and (p_cwe_ids is null or d.cwe_id = any (p_cwe_ids))
    and (1 - (c.embedding operator(extensions.<=>) p_query_embedding)) >= p_min_similarity
  order by c.embedding operator(extensions.<=>) p_query_embedding
  limit least(greatest(p_match_count, 1), 50);
$$;

-- Keyword fallback used when no embedding provider is configured. The UI labels it as such.
create or replace function public.search_knowledge_keyword(p_query text, p_limit integer default 20)
returns table (document_id uuid, slug text, cwe_id text, title text, category text, rank real)
language sql stable set search_path = '' as $$
  select d.id, d.slug, d.cwe_id, d.title, d.category,
         ts_rank(d.search_tsv, websearch_to_tsquery('english', p_query))::real
  from public.knowledge_documents d
  where d.is_enabled and d.search_tsv @@ websearch_to_tsquery('english', p_query)
  order by 6 desc
  limit least(greatest(p_limit, 1), 100);
$$;

-- Admin: queue documents for re-indexing (the worker picks up pending/stale documents).
create or replace function public.request_knowledge_reindex(p_document_ids uuid[] default null)
returns integer
language plpgsql security definer set search_path = '' as $$
declare
  v_count integer;
begin
  if not public.is_admin() then
    raise exception 'Administrator role required' using errcode = '42501';
  end if;
  update public.knowledge_documents set index_status = 'pending', index_error = null
  where (p_document_ids is null or id = any (p_document_ids)) and index_status <> 'indexing';
  get diagnostics v_count = row_count;
  insert into public.audit_logs (actor_id, entity_type, action, new_values)
  values (auth.uid(), 'knowledge_base', 'reindex_requested', jsonb_build_object('documents', v_count));
  return v_count;
end;
$$;

-- ---------------------------------------------------------------------------
-- Dashboard (SECURITY INVOKER: RLS limits everything to the caller's projects)
-- ---------------------------------------------------------------------------

create or replace function public.get_dashboard_stats()
returns jsonb language sql stable security invoker set search_path = '' as $$
  with v as (select * from public.vulnerabilities),
       open_v as (select * from v where status not in ('resolved', 'accepted_risk'))
  select jsonb_build_object(
    'projects', (select count(*) from public.projects),
    'projects_scanned', (select count(distinct project_id) from public.scan_jobs where status = 'completed'),
    'scans_total', (select count(*) from public.scan_jobs),
    'scans_running', (select count(*) from public.scan_jobs where status in ('queued', 'running')),
    'findings_total', (select count(*) from v),
    'findings_open', (select count(*) from open_v),
    'critical_open', (select count(*) from open_v where severity = 'critical'),
    'high_open', (select count(*) from open_v where severity = 'high'),
    'verified_fixes', (select count(*) from v where status = 'resolved' and verification_status = 'verified_resolved'),
    'accepted_risks', (select count(*) from v where status = 'accepted_risk'),
    'open_remediation_tasks', (select count(*) from open_v where status in ('triaged', 'in_progress', 'fix_proposed', 'fix_applied', 'verification_pending')),
    'threat_scenarios', (select count(*) from public.threat_scenarios),
    'severity', coalesce((select jsonb_object_agg(severity, n) from (select severity, count(*) n from open_v group by severity) s), '{}'::jsonb),
    'status', coalesce((select jsonb_object_agg(status, n) from (select status, count(*) n from v group by status) s), '{}'::jsonb),
    'categories', coalesce((select jsonb_agg(jsonb_build_object('category', category, 'count', n) order by n desc)
                            from (select coalesce(category, 'Uncategorised') category, count(*) n from open_v
                                  group by 1 order by 2 desc limit 8) s), '[]'::jsonb),
    'top_files', coalesce((select jsonb_agg(jsonb_build_object('project_id', project_id, 'file_path', file_path,
                                                               'count', n, 'max_risk', max_risk) order by max_risk desc, n desc)
                           from (select project_id, file_path, count(*) n, max(risk_score) max_risk from open_v
                                 group by 1, 2 order by 4 desc nulls last, 3 desc limit 6) s), '[]'::jsonb)
  );
$$;

-- ---------------------------------------------------------------------------
-- Row Level Security
-- ---------------------------------------------------------------------------

alter table public.profiles enable row level security;
alter table public.projects enable row level security;
alter table public.project_members enable row level security;
alter table public.scan_jobs enable row level security;
alter table public.scan_job_events enable row level security;
alter table public.project_files_metadata enable row level security;
alter table public.knowledge_documents enable row level security;
alter table public.knowledge_chunks enable row level security;
alter table public.vulnerabilities enable row level security;
alter table public.scan_results enable row level security;
alter table public.finding_knowledge_refs enable row level security;
alter table public.remediation_suggestions enable row level security;
alter table public.remediation_history enable row level security;
alter table public.threat_scenarios enable row level security;
alter table public.finding_assignments enable row level security;
alter table public.finding_comments enable row level security;
alter table public.audit_logs enable row level security;
alter table public.worker_status enable row level security;

-- profiles: everyone signed in can see names (needed for assignment pickers); edit only yourself.
create policy profiles_select on public.profiles for select to authenticated using (true);
create policy profiles_update_self on public.profiles for update to authenticated
  using (id = auth.uid() or public.is_admin()) with check (id = auth.uid() or public.is_admin());

-- projects
-- owner_id check lets INSERT ... RETURNING see the row before the membership trigger has run.
create policy projects_select on public.projects for select to authenticated
  using (owner_id = auth.uid() or public.is_project_member(id));
create policy projects_insert on public.projects for insert to authenticated
  with check (owner_id = auth.uid() and is_demo = false);
create policy projects_update on public.projects for update to authenticated
  using (public.can_edit_project(id)) with check (public.can_edit_project(id));
create policy projects_delete on public.projects for delete to authenticated
  using (owner_id = auth.uid());

-- project_members: members see the team; owners manage it.
create policy project_members_select on public.project_members for select to authenticated
  using (public.is_project_member(project_id));
create policy project_members_manage on public.project_members for all to authenticated
  using (exists (select 1 from public.projects p where p.id = project_id and p.owner_id = auth.uid()))
  with check (exists (select 1 from public.projects p where p.id = project_id and p.owner_id = auth.uid()));

-- scan data: read-only for members; written by the worker (service role) and RPCs.
create policy scan_jobs_select on public.scan_jobs for select to authenticated
  using (public.is_project_member(project_id));
create policy scan_job_events_select on public.scan_job_events for select to authenticated
  using (exists (select 1 from public.scan_jobs j where j.id = scan_job_id and public.is_project_member(j.project_id)));
create policy project_files_select on public.project_files_metadata for select to authenticated
  using (public.is_project_member(project_id));
create policy scan_results_select on public.scan_results for select to authenticated
  using (public.is_project_member(project_id));
create policy vulnerabilities_select on public.vulnerabilities for select to authenticated
  using (public.is_project_member(project_id));
create policy finding_refs_select on public.finding_knowledge_refs for select to authenticated
  using (public.is_project_member(public.vulnerability_project(vulnerability_id)));
create policy remediation_select on public.remediation_suggestions for select to authenticated
  using (public.is_project_member(public.vulnerability_project(vulnerability_id)));
create policy remediation_history_select on public.remediation_history for select to authenticated
  using (public.is_project_member(public.vulnerability_project(vulnerability_id)));
create policy threats_select on public.threat_scenarios for select to authenticated
  using (public.is_project_member(project_id));
create policy assignments_select on public.finding_assignments for select to authenticated
  using (public.is_project_member(public.vulnerability_project(vulnerability_id)));

-- comments: members read; members with edit rights write their own.
create policy comments_select on public.finding_comments for select to authenticated
  using (public.is_project_member(public.vulnerability_project(vulnerability_id)));
create policy comments_insert on public.finding_comments for insert to authenticated
  with check (author_id = auth.uid() and public.can_edit_project(public.vulnerability_project(vulnerability_id)));
create policy comments_update_own on public.finding_comments for update to authenticated
  using (author_id = auth.uid()) with check (author_id = auth.uid());
create policy comments_delete_own on public.finding_comments for delete to authenticated
  using (author_id = auth.uid());

-- audit log: members see their projects' history, admins see everything. Nobody edits it.
create policy audit_select on public.audit_logs for select to authenticated
  using ((project_id is not null and public.is_project_member(project_id)) or public.is_admin());

-- knowledge base: readable by every signed-in user, editable by admins.
create policy kb_docs_select on public.knowledge_documents for select to authenticated using (true);
create policy kb_docs_admin_insert on public.knowledge_documents for insert to authenticated
  with check (public.is_admin());
create policy kb_docs_admin_update on public.knowledge_documents for update to authenticated
  using (public.is_admin()) with check (public.is_admin());
create policy kb_chunks_select on public.knowledge_chunks for select to authenticated using (true);

-- worker status: visible to signed-in users (no secrets stored).
create policy worker_status_select on public.worker_status for select to authenticated using (true);

-- ---------------------------------------------------------------------------
-- Function privileges
-- ---------------------------------------------------------------------------

revoke execute on function public.claim_next_scan_job(text) from public, anon, authenticated;
grant execute on function public.claim_next_scan_job(text) to service_role;

revoke execute on function public.create_scan_job(uuid, text, bigint, jsonb) from public, anon;
revoke execute on function public.request_scan_cancel(uuid) from public, anon;
revoke execute on function public.update_finding_status(uuid, text, text) from public, anon;
revoke execute on function public.request_knowledge_reindex(uuid[]) from public, anon;
revoke execute on function public.get_dashboard_stats() from public, anon;
revoke execute on function public.match_knowledge_chunks(extensions.vector, text, integer, real, text[]) from public, anon;
revoke execute on function public.search_knowledge_keyword(text, integer) from public, anon;

-- ---------------------------------------------------------------------------
-- Storage: private buckets. Users upload to <their uid>/<project id>/...
-- ---------------------------------------------------------------------------

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values
  ('project-uploads', 'project-uploads', false, 52428800,
   array['application/zip', 'application/x-zip-compressed', 'application/octet-stream']),
  ('reports', 'reports', false, 52428800, array['application/pdf', 'application/json'])
on conflict (id) do nothing;

create policy uploads_insert_own on storage.objects for insert to authenticated
  with check (
    bucket_id = 'project-uploads'
    and (storage.foldername(name))[1] = auth.uid()::text
    and public.can_edit_project(((storage.foldername(name))[2])::uuid)
  );
create policy uploads_select_own on storage.objects for select to authenticated
  using (
    bucket_id = 'project-uploads'
    and (storage.foldername(name))[1] = auth.uid()::text
  );
create policy reports_select_members on storage.objects for select to authenticated
  using (
    bucket_id = 'reports'
    and public.is_project_member(((storage.foldername(name))[1])::uuid)
  );
