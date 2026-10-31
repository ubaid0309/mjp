import { Link, useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { supabase, unwrap } from "@/lib/supabase";
import type { Project, ScanJob, Severity } from "@/lib/types";
import { dateTime, duration } from "@/lib/format";
import { Button, EmptyState, ErrorNote, Loading, PageHeader, Panel } from "@/components/ui";
import { ScanStatusBadge } from "@/components/badges";
import { SeverityBar } from "@/components/SeverityBar";

export default function ProjectDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const project = useQuery({
    queryKey: ["project", id],
    queryFn: async () => unwrap(await supabase.from("projects").select("*").eq("id", id!).single()) as Project,
  });
  const scans = useQuery({
    queryKey: ["project", id, "scans"],
    queryFn: async () => unwrap(await supabase.from("scan_jobs").select("*").eq("project_id", id!).order("created_at", { ascending: false })) as ScanJob[],
    refetchInterval: (q) => (q.state.data?.some((s) => s.status === "queued" || s.status === "running") ? 3000 : false),
  });
  const severity = useQuery({
    queryKey: ["project", id, "severity"],
    queryFn: async () => {
      const rows = unwrap(await supabase.from("vulnerabilities").select("severity").eq("project_id", id!)
        .not("status", "in", "(resolved,accepted_risk)")) as { severity: Severity }[];
      return rows.reduce<Partial<Record<Severity, number>>>((acc, r) => ({ ...acc, [r.severity]: (acc[r.severity] ?? 0) + 1 }), {});
    },
  });

  if (project.isLoading) return <Loading />;
  if (project.error) return <ErrorNote error={project.error} title="Project not found or not accessible" />;
  const p = project.data!;

  return (
    <>
      <PageHeader title={p.name} description={p.description ?? `${p.primary_language ?? "Mixed"} project, created ${dateTime(p.created_at)}`}
        actions={<>
          <Button onClick={() => navigate(`/findings?project=${p.id}`)}>View findings</Button>
          <Button variant="primary" onClick={() => navigate(`/scans/new?project=${p.id}`)}>Upload and scan</Button>
        </>} />

      <Panel title="Open findings">
        <SeverityBar counts={severity.data ?? {}} onSelect={(s) => navigate(`/findings?project=${p.id}&severity=${s}`)} />
      </Panel>

      <Panel title="Scan history" className="mt-4" bodyClass="">
        {scans.isLoading ? <Loading /> : (scans.data ?? []).length === 0 ? (
          <EmptyState title="This project has not been scanned"
            action={<Button variant="primary" onClick={() => navigate(`/scans/new?project=${p.id}`)}>Upload and scan</Button>} />
        ) : (
          <div className="overflow-x-auto">
            <table className="tbl">
              <thead><tr><th>Started</th><th>Type</th><th>Status</th><th className="text-right">Files</th><th className="text-right">Findings</th><th>Duration</th></tr></thead>
              <tbody>
                {scans.data!.map((s) => (
                  <tr key={s.id} className="cursor-pointer" onClick={() => navigate(`/scans/${s.id}`)}>
                    <td><Link to={`/scans/${s.id}`} className="text-fg">{dateTime(s.created_at)}</Link></td>
                    <td className="capitalize text-fg-muted">{s.scan_type}</td>
                    <td><ScanStatusBadge status={s.status} /></td>
                    <td className="text-right tabular-nums">{s.files_scanned}/{s.files_total}</td>
                    <td className="text-right tabular-nums">{s.status === "completed" ? s.findings_total : "-"}</td>
                    <td className="text-fg-muted">{duration(s.started_at, s.finished_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}
