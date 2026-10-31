-- Worker-only RPCs (service role). They merge scan output into persistent findings.

create or replace function public.worker_upsert_findings(p_scan_job_id uuid, p_findings jsonb)
returns table (fingerprint text, vulnerability_id uuid, outcome text)
language plpgsql security definer set search_path = '' as $$
declare
  v_project uuid;
  f jsonb;
  v_existing public.vulnerabilities;
  v_id uuid;
begin
  select project_id into v_project from public.scan_jobs where id = p_scan_job_id;
  if v_project is null then
    raise exception 'unknown scan job %', p_scan_job_id;
  end if;

  for f in select * from jsonb_array_elements(p_findings)
  loop
    select * into v_existing from public.vulnerabilities v
    where v.project_id = v_project and v.fingerprint = f ->> 'fingerprint'
    for update;

    if not found then
      insert into public.vulnerabilities (
        project_id, fingerprint, title, description, category, severity, confidence, source, detection_method,
        rule_ids, cwe_ids, owasp_top10, language, file_path, start_line, end_line, snippet,
        requires_manual_review, risk_score, risk_rationale, priority, kb_evidence_status,
        first_seen_scan_id, last_seen_scan_id)
      values (
        v_project, f ->> 'fingerprint', f ->> 'title', f ->> 'description', f ->> 'category', f ->> 'severity',
        f ->> 'confidence', 'scanner_confirmed', f ->> 'detection_method',
        array(select jsonb_array_elements_text(f -> 'rule_ids')),
        array(select jsonb_array_elements_text(f -> 'cwe_ids')),
        array(select jsonb_array_elements_text(f -> 'owasp_top10')),
        f ->> 'language', f ->> 'file_path', (f ->> 'start_line')::int, (f ->> 'end_line')::int, f ->> 'snippet',
        coalesce((f ->> 'requires_manual_review')::boolean, true), (f ->> 'risk_score')::numeric,
        coalesce(f -> 'risk_rationale', '{}'::jsonb), f ->> 'priority', coalesce(f ->> 'kb_evidence_status', 'pending'),
        p_scan_job_id, p_scan_job_id)
      returning id into v_id;
      fingerprint := f ->> 'fingerprint'; vulnerability_id := v_id; outcome := 'new';
    else
      update public.vulnerabilities set
        title = f ->> 'title', description = f ->> 'description', category = f ->> 'category',
        severity = f ->> 'severity', confidence = f ->> 'confidence',
        rule_ids = array(select jsonb_array_elements_text(f -> 'rule_ids')),
        cwe_ids = array(select jsonb_array_elements_text(f -> 'cwe_ids')),
        owasp_top10 = array(select jsonb_array_elements_text(f -> 'owasp_top10')),
        start_line = (f ->> 'start_line')::int, end_line = (f ->> 'end_line')::int, snippet = f ->> 'snippet',
        risk_score = (f ->> 'risk_score')::numeric, risk_rationale = coalesce(f -> 'risk_rationale', '{}'::jsonb),
        priority = f ->> 'priority', kb_evidence_status = coalesce(f ->> 'kb_evidence_status', kb_evidence_status),
        last_seen_scan_id = p_scan_job_id,
        occurrence_count = occurrence_count + 1,
        -- A resolved finding that shows up again is reopened.
        status = case when v_existing.status = 'resolved' then 'triaged' else status end,
        verification_status = case when v_existing.status = 'resolved' then 'still_detected' else verification_status end,
        reopened_count = reopened_count + case when v_existing.status = 'resolved' then 1 else 0 end,
        resolved_at = case when v_existing.status = 'resolved' then null else resolved_at end
      where id = v_existing.id;
      if v_existing.status = 'resolved' then
        insert into public.audit_logs (project_id, entity_type, entity_id, action, old_values, new_values)
        values (v_project, 'vulnerability', v_existing.id, 'reopened',
                jsonb_build_object('status', 'resolved'),
                jsonb_build_object('status', 'triaged', 'scan_job_id', p_scan_job_id));
      end if;
      fingerprint := f ->> 'fingerprint'; vulnerability_id := v_existing.id;
      outcome := case when v_existing.status = 'resolved' then 'reopened' else 'existing' end;
    end if;
    return next;
  end loop;
end;
$$;

revoke execute on function public.worker_upsert_findings(uuid, jsonb) from public, anon, authenticated;
grant execute on function public.worker_upsert_findings(uuid, jsonb) to service_role;

-- Per-scan severity breakdown for the scan results page (RLS applies through the caller).
create or replace function public.get_scan_summary(p_scan_job_id uuid)
returns jsonb language sql stable security invoker set search_path = '' as $$
  select jsonb_build_object(
    'by_severity', coalesce((select jsonb_object_agg(severity, n) from (
        select severity, count(*) n from public.vulnerabilities
        where last_seen_scan_id = p_scan_job_id group by severity) s), '{}'::jsonb),
    'new_in_scan', (select count(*) from public.vulnerabilities where first_seen_scan_id = p_scan_job_id),
    'seen_in_scan', (select count(*) from public.vulnerabilities where last_seen_scan_id = p_scan_job_id),
    'raw_hits', (select count(*) from public.scan_results where scan_job_id = p_scan_job_id),
    'languages', coalesce((select jsonb_object_agg(coalesce(language, 'other'), n) from (
        select language, count(*) n from public.project_files_metadata
        where scan_job_id = p_scan_job_id and status = 'scanned' group by language) s), '{}'::jsonb)
  );
$$;
revoke execute on function public.get_scan_summary(uuid) from public, anon;
