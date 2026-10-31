import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Download } from "lucide-react";
import { supabase, unwrap } from "@/lib/supabase";
import { SCAN_STAGES, type ScanEvent, type ScanJob, type Severity, type Vulnerability } from "@/lib/types";
import { bytes, dateTime, duration, findingRef } from "@/lib/format";
import { downloadJsonReport } from "@/lib/report";
import { Button, ErrorNote, Loading, PageHeader, Panel, Stat, cx } from "@/components/ui";
import { PriorityTag, ScanStatusBadge, SeverityBadge } from "@/components/badges";
import { SeverityBar } from "@/components/SeverityBar";

const STAGE_LABEL: Record<string, string> = {
  queued: "Queued", extracting: "Extract", discovering: "Discover", scanning: "Scan", deduplicating: "Deduplicate",
  enriching: "Retrieve knowledge", scoring: "Score risk", finalizing: "Save", done: "Done",
};

function StageTracker({ job }: { job: ScanJob }) {
  const current = SCAN_STAGES.indexOf(job.stage);
  const stages = SCAN_STAGES.filter((s) => s !== "queued" && s !== "done");
  return (
    <ol className="grid grid-cols-2 gap-px overflow-hidden rounded-md border border-line bg-line sm:grid-cols-4 lg:grid-cols-7">
      {stages.map((s, i) => {
        const idx = SCAN_STAGES.indexOf(s);
        const done = job.status === "completed" || idx < current;
        const active = idx === current && job.status === "running";
        const failedHere = idx === current && (job.status === "failed" || job.status === "cancelled");
        return (
          <li key={s} className={cx("bg-panel px-3 py-2.5", active && "bg-accent/10")}>
            <div className="flex items-center gap-2 text-xs text-fg-faint">
              <span className={cx("flex h-5 w-5 items-center justify-center rounded-full border text-[11px] tabular-nums",
                done ? "border-ok bg-ok/15 text-ok" : active ? "border-accent text-accent" : failedHere ? "border-sev-critical text-sev-critical" : "border-line-strong")}>
                {done ? <Check className="h-3 w-3" /> : i + 1}
              </span>
            </div>
            <div className={cx("mt-1.5 text-[13px]", done || active ? "text-fg" : "text-fg-muted")}>{STAGE_LABEL[s]}</div>
          </li>
        );
      })}
    </ol>
  );
}

export default function ScanPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [reportBusy, setReportBusy] = useState(false);

  const job = useQuery({
    queryKey: ["scan", id],
    queryFn: async () => unwrap(await supabase.from("scan_jobs").select("*, projects(name)").eq("id", id!).single()) as ScanJob,
    refetchInterval: (q) => (q.state.data && ["queued", "running"].includes(q.state.data.status) ? 2000 : false),
  });
  const active = job.data && ["queued", "running"].includes(job.data.status);
  const events = useQuery({
    queryKey: ["scan", id, "events"],
    queryFn: async () => unwrap(await supabase.from("scan_job_events").select("*").eq("scan_job_id", id!).order("id")) as ScanEvent[],
    refetchInterval: active ? 2000 : false,
  });
  const findings = useQuery({
    queryKey: ["scan", id, "findings"],
    enabled: job.data?.status === "completed",
    queryFn: async () => unwrap(await supabase.from("vulnerabilities")
      .select("id, ref_no, title, severity, file_path, start_line, risk_score, priority, cwe_ids, first_seen_scan_id")
      .eq("last_seen_scan_id", id!).order("risk_score", { ascending: false }).limit(15)) as unknown as Vulnerability[],
  });
  const summary = useQuery({
    queryKey: ["scan", id, "summary"],
    enabled: job.data?.status === "completed",
    queryFn: async () => unwrap(await supabase.rpc("get_scan_summary", { p_scan_job_id: id })) as
      { by_severity: Partial<Record<Severity, number>>; new_in_scan: number; seen_in_scan: number; raw_hits: number },
  });
  const cancel = useMutation({
    mutationFn: async () => unwrap(await supabase.rpc("request_scan_cancel", { p_scan_job_id: id })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scan", id] }),
  });

  if (job.isLoading) return <Loading />;
  if (job.error) return <ErrorNote error={job.error} title="Scan not found or not accessible" />;
  const j = job.data!;
  const pct = j.batches_total ? Math.round((j.batches_done / j.batches_total) * 100) : 0;
  const cov = j.coverage ?? {};

  return (
    <>
      <PageHeader
        title={<span className="flex items-center gap-3">Scan of {j.projects?.name} <ScanStatusBadge status={j.status} /></span>}
        description={`Queued ${dateTime(j.queued_at)}${j.started_at ? `, ran for ${duration(j.started_at, j.finished_at)}` : ""}`}
        actions={<>
          <Button onClick={() => navigate(`/projects/${j.project_id}`)}>Project</Button>
          {active && <Button variant="danger" loading={cancel.isPending} disabled={j.cancel_requested} onClick={() => cancel.mutate()}>
            {j.cancel_requested ? "Cancelling" : "Cancel scan"}</Button>}
          {j.status === "completed" && (
            <Button loading={reportBusy} onClick={async () => { setReportBusy(true); try { await downloadJsonReport(j, j.projects?.name ?? "project"); } finally { setReportBusy(false); } }}>
              <Download className="h-3.5 w-3.5" /> JSON report
            </Button>
          )}
        </>} />

      <StageTracker job={j} />
      <ErrorNote error={cancel.error} title="Could not cancel" />

      {j.status === "queued" && (
        <p className="mt-3 text-[13px] text-fg-muted">
          Waiting for a worker to pick up this job. If it stays queued, check that the SecureMatrix worker is running (Settings shows its last heartbeat).
        </p>
      )}
      {j.status === "failed" && <div className="mt-4"><ErrorNote error={j.error_message ?? "Unknown error"} title="Scan failed" /></div>}

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Panel title="Progress" className="lg:col-span-2">
          <div className="flex items-baseline justify-between text-[13px]">
            <span>{j.batches_done} of {j.batches_total || "?"} batches complete</span>
            <span className="tabular-nums text-fg-muted">{pct}%</span>
          </div>
          <div className="mt-2 h-2 rounded-sm bg-panel-3" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
            <div className="h-full rounded-sm bg-accent transition-[width] duration-500" style={{ width: `${pct}%` }} />
          </div>
          <p className="mt-2 text-xs text-fg-muted">Progress counts completed Semgrep batches recorded by the worker.</p>
          <div className="mt-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Stat label="Files scanned" value={`${j.files_scanned}/${j.files_total}`} />
            <Stat label="Files excluded" value={j.files_excluded} />
            <Stat label="Archive" value={<span className="text-lg">{bytes(j.archive_size_bytes)}</span>} />
            <Stat label="Findings" value={j.status === "completed" ? j.findings_total : "-"} />
          </div>
        </Panel>
        <Panel title="Activity" bodyClass="max-h-72 overflow-y-auto">
          <ol className="space-y-2 p-4 text-[13px]">
            {(events.data ?? []).map((e) => (
              <li key={e.id} className="flex gap-2">
                <span className={cx("mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full",
                  e.level === "error" ? "bg-sev-critical" : e.level === "warning" ? "bg-sev-medium" : "bg-fg-faint")} />
                <span><span className="text-fg-muted">{new Date(e.created_at).toLocaleTimeString()}</span> {e.message}</span>
              </li>
            ))}
          </ol>
        </Panel>
      </div>

      {j.status === "completed" && (
        <>
          <div className="mt-4 grid gap-4 lg:grid-cols-3">
            <Panel title="Findings in this scan" className="lg:col-span-2">
              <SeverityBar counts={summary.data?.by_severity ?? {}} onSelect={(s) => navigate(`/findings?scan=${j.id}&severity=${s}`)} />
              {summary.data && (
                <p className="mt-3 text-xs text-fg-muted">
                  {summary.data.raw_hits} raw scanner results were merged into {summary.data.seen_in_scan} findings;
                  {" "}{summary.data.new_in_scan} were first seen in this scan.
                </p>
              )}
            </Panel>
            <Panel title="Scanner coverage">
              <dl className="space-y-2 text-[13px]">
                <div className="flex justify-between gap-2"><dt className="text-fg-muted">Engine</dt><dd>Semgrep {cov.scanner_version}</dd></div>
                <div className="flex justify-between gap-2"><dt className="text-fg-muted">Knowledge retrieval</dt><dd className="text-right">{cov.retrieval}</dd></div>
                <div className="flex justify-between gap-2"><dt className="text-fg-muted">Scanner errors</dt><dd>{cov.scanner_errors ?? 0}</dd></div>
              </dl>
              <div className="mt-3 space-y-1">
                {(cov.rulesets ?? []).map((r) => (
                  <div key={r.name} className="flex items-center justify-between text-[13px]">
                    <span className="font-mono text-xs">{r.name}</span>
                    <span className={r.status === "loaded" ? "text-ok" : "text-sev-medium"} title={r.detail}>{r.status}</span>
                  </div>
                ))}
              </div>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {Object.entries(cov.languages ?? {}).map(([l, n]) => (
                  <span key={l} className="rounded bg-panel-3 px-1.5 py-0.5 text-xs text-fg-muted">{l} {n}</span>
                ))}
              </div>
            </Panel>
          </div>

          <Panel title="Highest-risk findings" className="mt-4" bodyClass=""
            actions={<Link to={`/findings?scan=${j.id}`} className="text-[13px]">Open all {j.findings_total} in explorer</Link>}>
            <div className="overflow-x-auto">
              <table className="tbl">
                <thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Location</th><th className="text-right">Risk</th><th>Priority</th></tr></thead>
                <tbody>
                  {(findings.data ?? []).map((f) => (
                    <tr key={f.id} className="cursor-pointer" onClick={() => navigate(`/findings/${f.id}`)}>
                      <td className="whitespace-nowrap font-mono text-xs text-fg-muted">{findingRef(f.ref_no)}</td>
                      <td><SeverityBadge severity={f.severity} /></td>
                      <td><Link to={`/findings/${f.id}`} className="text-fg">{f.title}</Link>
                        {f.first_seen_scan_id === j.id && <span className="ml-2 text-xs text-accent">new</span>}</td>
                      <td className="max-w-[360px] truncate font-mono text-xs text-fg-muted" title={`${f.file_path}:${f.start_line}`}>{f.file_path}:{f.start_line}</td>
                      <td className="text-right tabular-nums">{f.risk_score}</td>
                      <td><PriorityTag priority={f.priority} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <Panel title="Excluded from analysis">
              {Object.keys(cov.excluded_directories ?? {}).length === 0 ? <p className="text-fg-muted">No dependency or build folders were found.</p> : (
                <ul className="space-y-1 text-[13px]">
                  {Object.entries(cov.excluded_directories ?? {}).map(([d, n]) => (
                    <li key={d} className="flex justify-between"><span className="font-mono text-xs">{d}/</span><span className="text-fg-muted">{n} files</span></li>
                  ))}
                </ul>
              )}
              <p className="mt-3 text-xs text-fg-muted">{j.files_excluded} files in total were skipped (dependencies, build output, binaries, unsupported or oversized files).</p>
            </Panel>
            <Panel title="Limitations of this scan">
              <ul className="list-disc space-y-1.5 pl-5 text-[13px] text-fg-muted">
                {(cov.limitations ?? []).map((l) => <li key={l}>{l}</li>)}
              </ul>
            </Panel>
          </div>
        </>
      )}
    </>
  );
}
