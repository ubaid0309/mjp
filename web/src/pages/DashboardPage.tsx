import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { supabase, unwrap } from "@/lib/supabase";
import { STATUS_LABEL, type DashboardStats, type FindingStatus, type ScanJob, type Vulnerability } from "@/lib/types";
import { findingRef, timeAgo } from "@/lib/format";
import { Button, EmptyState, ErrorNote, Loading, PageHeader, Panel, Stat } from "@/components/ui";
import { ScanStatusBadge, SeverityBadge } from "@/components/badges";
import { SeverityBar } from "@/components/SeverityBar";

const LIFECYCLE: FindingStatus[] = ["new", "triaged", "in_progress", "fix_proposed", "fix_applied", "verification_pending", "resolved", "accepted_risk"];

export default function DashboardPage() {
  const navigate = useNavigate();
  const stats = useQuery({
    queryKey: ["dashboard"],
    queryFn: async () => unwrap(await supabase.rpc("get_dashboard_stats")) as DashboardStats,
  });
  const scans = useQuery({
    queryKey: ["scans", "recent"],
    queryFn: async () => unwrap(await supabase.from("scan_jobs").select("*, projects(name)").order("created_at", { ascending: false }).limit(6)) as ScanJob[],
  });
  const findings = useQuery({
    queryKey: ["findings", "recent"],
    queryFn: async () => unwrap(await supabase.from("vulnerabilities")
      .select("id, ref_no, title, severity, file_path, start_line, created_at, project_id, projects(name)")
      .order("created_at", { ascending: false }).order("risk_score", { ascending: false }).limit(8)) as unknown as Vulnerability[],
  });

  if (stats.isLoading) return <Loading />;
  if (stats.error) return <ErrorNote error={stats.error} title="Could not load the dashboard" />;
  const s = stats.data!;

  if (s.projects === 0) {
    return (
      <>
        <PageHeader title="Dashboard" />
        <Panel>
          <EmptyState title="No projects yet"
            action={<Button variant="primary" onClick={() => navigate("/scans/new")}>Upload a project</Button>}>
            Upload a ZIP of your source code to run the first scan. The repository includes a deliberately vulnerable demo
            project in <code>demo/bytemart-vulnerable</code> you can use.
          </EmptyState>
        </Panel>
      </>
    );
  }

  const totalStatus = LIFECYCLE.reduce((n, k) => n + (s.status[k] ?? 0), 0);
  const maxCat = Math.max(1, ...s.categories.map((c) => c.count));

  return (
    <>
      <PageHeader title="Dashboard" description="Security posture across the projects you can access."
        actions={<Button variant="primary" onClick={() => navigate("/scans/new")}>New scan</Button>} />

      <div className="grid items-start gap-4 lg:grid-cols-3">
        <Panel title="Open findings by severity" className="lg:col-span-2">
          <SeverityBar counts={s.severity} onSelect={(sev) => navigate(`/findings?severity=${sev}`)} />
        </Panel>
        <Panel title="At a glance" bodyClass="grid grid-cols-2 gap-x-4 gap-y-4 p-4">
          <Stat label="Projects scanned" value={`${s.projects_scanned}/${s.projects}`} />
          <Stat label="Scans run" value={s.scans_total} hint={s.scans_running ? `${s.scans_running} in progress` : undefined} />
          <Stat label="Total findings" value={s.findings_total} hint={`${s.findings_open} open`} />
          <Stat label="Critical + high open" value={s.critical_open + s.high_open} tone={s.critical_open ? "text-[#FF8A8E]" : undefined} />
          <Stat label="Verified fixes" value={s.verified_fixes} hint="Confirmed by re-scan" />
          <Stat label="Open remediation tasks" value={s.open_remediation_tasks} hint={`${s.threat_scenarios} threat scenarios`} />
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Panel title="Most common open weakness categories">
          {s.categories.length === 0 ? <p className="text-fg-muted">No open findings.</p> : (
            <ul className="space-y-2.5">
              {s.categories.map((c) => (
                <li key={c.category}>
                  <Link to={`/findings?category=${encodeURIComponent(c.category)}`} className="block text-fg hover:text-fg">
                    <div className="flex justify-between text-[13px]"><span>{c.category}</span><span className="tabular-nums text-fg-muted">{c.count}</span></div>
                    <div className="mt-1 h-1.5 rounded-sm bg-panel-3"><div className="h-full rounded-sm bg-accent/80" style={{ width: `${(c.count / maxCat) * 100}%` }} /></div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Remediation progress">
          {totalStatus === 0 ? <p className="text-fg-muted">No findings yet.</p> : (
            <table className="w-full text-[13px]">
              <tbody>
                {LIFECYCLE.map((k) => (
                  <tr key={k}>
                    <td className="w-44 py-1 text-fg-muted">{STATUS_LABEL[k]}</td>
                    <td className="py-1"><div className="h-1.5 rounded-sm bg-panel-3">
                      <div className={k === "resolved" ? "h-full rounded-sm bg-ok" : "h-full rounded-sm bg-fg-faint"}
                        style={{ width: `${((s.status[k] ?? 0) / totalStatus) * 100}%` }} /></div></td>
                    <td className="w-12 py-1 text-right tabular-nums">{s.status[k] ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <Panel title="Recent scans" bodyClass="" actions={<Link to="/scans" className="text-[13px]">All scans</Link>}>
          {scans.error ? <div className="p-4"><ErrorNote error={scans.error} /></div> : (
            <table className="tbl">
              <thead><tr><th>Project</th><th>Status</th><th className="text-right">Findings</th><th>Started</th></tr></thead>
              <tbody>
                {(scans.data ?? []).map((j) => (
                  <tr key={j.id} className="cursor-pointer" onClick={() => navigate(`/scans/${j.id}`)}>
                    <td><Link to={`/scans/${j.id}`} className="text-fg">{j.projects?.name}</Link></td>
                    <td><ScanStatusBadge status={j.status} /></td>
                    <td className="text-right tabular-nums">{j.status === "completed" ? j.findings_total : "-"}</td>
                    <td className="text-fg-muted">{timeAgo(j.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title="Recently detected" bodyClass="" actions={<Link to="/findings" className="text-[13px]">All findings</Link>}>
          <table className="tbl">
            <tbody>
              {(findings.data ?? []).map((f) => (
                <tr key={f.id} className="cursor-pointer" onClick={() => navigate(`/findings/${f.id}`)}>
                  <td className="w-24"><SeverityBadge severity={f.severity} /></td>
                  <td className="w-full max-w-0">
                    <Link to={`/findings/${f.id}`} className="text-fg">{f.title}</Link>
                    <div className="truncate font-mono text-xs text-fg-muted" title={`${f.file_path}:${f.start_line}`}>{f.file_path}:{f.start_line}</div>
                  </td>
                  <td className="whitespace-nowrap text-right font-mono text-xs text-fg-faint">{findingRef(f.ref_no)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>

      {s.top_files.length > 0 && (
        <Panel title="Highest-risk files" className="mt-4" bodyClass="">
          <table className="tbl">
            <thead><tr><th>File</th><th className="text-right">Open findings</th><th className="text-right">Max risk score</th></tr></thead>
            <tbody>
              {s.top_files.map((f) => (
                <tr key={f.project_id + f.file_path}>
                  <td className="font-mono text-xs">
                    <Link to={`/findings?file=${encodeURIComponent(f.file_path)}&project=${f.project_id}`} className="text-fg">{f.file_path}</Link>
                  </td>
                  <td className="text-right tabular-nums">{f.count}</td>
                  <td className="text-right tabular-nums">{f.max_risk ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </>
  );
}
