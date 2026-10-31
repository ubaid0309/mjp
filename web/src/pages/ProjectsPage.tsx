import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { supabase, unwrap } from "@/lib/supabase";
import type { Project, ScanJob } from "@/lib/types";
import { timeAgo } from "@/lib/format";
import { Button, EmptyState, ErrorNote, Input, Loading, PageHeader, Panel } from "@/components/ui";
import { ScanStatusBadge } from "@/components/badges";

interface Row extends Project { scan_jobs: Pick<ScanJob, "id" | "status" | "created_at" | "findings_total">[] }

export default function ProjectsPage() {
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const projects = useQuery({
    queryKey: ["projects"],
    queryFn: async () => unwrap(await supabase.from("projects")
      .select("*, scan_jobs(id, status, created_at, findings_total)")
      .order("updated_at", { ascending: false })
      .order("created_at", { referencedTable: "scan_jobs", ascending: false })) as Row[],
  });
  const openCounts = useQuery({
    queryKey: ["projects", "open-counts"],
    queryFn: async () => {
      const rows = unwrap(await supabase.from("vulnerabilities").select("project_id, severity")
        .not("status", "in", "(resolved,accepted_risk)")) as { project_id: string; severity: string }[];
      const out: Record<string, { open: number; critical: number }> = {};
      for (const r of rows) {
        out[r.project_id] ??= { open: 0, critical: 0 };
        out[r.project_id].open++;
        if (r.severity === "critical") out[r.project_id].critical++;
      }
      return out;
    },
  });

  const rows = (projects.data ?? []).filter((p) => p.name.toLowerCase().includes(q.toLowerCase()));

  return (
    <>
      <PageHeader title="Projects" description="Each project keeps its uploads, scan history and findings together."
        actions={<Button variant="primary" onClick={() => navigate("/scans/new")}>New project scan</Button>} />
      <Panel bodyClass="">
        <div className="border-b border-line p-3">
          <div className="relative max-w-xs">
            <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-fg-faint" />
            <Input className="pl-8" placeholder="Filter by name" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter projects" />
          </div>
        </div>
        {projects.isLoading ? <Loading /> : projects.error ? <div className="p-4"><ErrorNote error={projects.error} /></div> :
          rows.length === 0 ? (
            <EmptyState title={q ? "No projects match that name" : "No projects yet"}
              action={!q && <Button variant="primary" onClick={() => navigate("/scans/new")}>Upload a project</Button>} />
          ) : (
            <div className="overflow-x-auto">
              <table className="tbl">
                <thead><tr><th>Name</th><th>Language</th><th>Last scan</th><th className="text-right">Open findings</th><th className="text-right">Critical</th><th>Scans</th></tr></thead>
                <tbody>
                  {rows.map((p) => {
                    const last = p.scan_jobs[0];
                    const c = openCounts.data?.[p.id];
                    return (
                      <tr key={p.id} className="cursor-pointer" onClick={() => navigate(`/projects/${p.id}`)}>
                        <td>
                          <Link to={`/projects/${p.id}`} className="font-medium text-fg">{p.name}</Link>
                          {p.description && <div className="max-w-md truncate text-xs text-fg-muted">{p.description}</div>}
                        </td>
                        <td className="text-fg-muted">{p.primary_language ?? "-"}</td>
                        <td>{last ? <span className="flex items-center gap-2"><ScanStatusBadge status={last.status} /><span className="text-fg-muted">{timeAgo(last.created_at)}</span></span> : <span className="text-fg-faint">Never scanned</span>}</td>
                        <td className="text-right tabular-nums">{c?.open ?? 0}</td>
                        <td className="text-right tabular-nums">{c?.critical ? <span className="text-[#FF8A8E]">{c.critical}</span> : 0}</td>
                        <td className="tabular-nums text-fg-muted">{p.scan_jobs.length}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
      </Panel>
    </>
  );
}
