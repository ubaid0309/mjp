import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { supabase, unwrap } from "@/lib/supabase";
import type { ScanJob, ScanStatus } from "@/lib/types";
import { dateTime, duration } from "@/lib/format";
import { Button, EmptyState, ErrorNote, Loading, PageHeader, Pagination, Panel, Select } from "@/components/ui";
import { ScanStatusBadge } from "@/components/badges";

const PAGE = 25;

export default function ScanHistoryPage() {
  const navigate = useNavigate();
  const [status, setStatus] = useState<"" | ScanStatus>("");
  const [page, setPage] = useState(0);
  const scans = useQuery({
    queryKey: ["scans", status, page],
    queryFn: async () => {
      let q = supabase.from("scan_jobs").select("*, projects(name)", { count: "exact" }).order("created_at", { ascending: false });
      if (status) q = q.eq("status", status);
      const res = await q.range(page * PAGE, page * PAGE + PAGE - 1);
      return { rows: unwrap(res) as ScanJob[], count: res.count ?? 0 };
    },
    refetchInterval: (q) => (q.state.data?.rows.some((s) => s.status === "queued" || s.status === "running") ? 3000 : false),
  });

  return (
    <>
      <PageHeader title="Scan history" description="Every scan across your projects, with its outcome and coverage."
        actions={<Button variant="primary" onClick={() => navigate("/scans/new")}>New scan</Button>} />
      <Panel bodyClass="">
        <div className="flex gap-2 border-b border-line p-3">
          <Select className="w-44" value={status} onChange={(e) => { setStatus(e.target.value as ScanStatus | ""); setPage(0); }} aria-label="Filter by status">
            <option value="">All statuses</option>
            {["queued", "running", "completed", "failed", "cancelled"].map((s) => <option key={s} value={s}>{s}</option>)}
          </Select>
        </div>
        {scans.isLoading ? <Loading /> : scans.error ? <div className="p-4"><ErrorNote error={scans.error} /></div> :
          scans.data!.rows.length === 0 ? <EmptyState title="No scans found" /> : (
            <>
              <div className="overflow-x-auto">
                <table className="tbl">
                  <thead><tr><th>Project</th><th>Started</th><th>Status</th><th>Rule sets</th><th className="text-right">Files</th><th className="text-right">Findings</th><th>Duration</th></tr></thead>
                  <tbody>
                    {scans.data!.rows.map((s) => (
                      <tr key={s.id} className="cursor-pointer" onClick={() => navigate(`/scans/${s.id}`)}>
                        <td><Link to={`/scans/${s.id}`} className="text-fg">{s.projects?.name}</Link></td>
                        <td className="text-fg-muted">{dateTime(s.created_at)}</td>
                        <td><ScanStatusBadge status={s.status} /></td>
                        <td className="font-mono text-xs text-fg-muted">{((s.config?.rulesets as string[]) ?? []).join(", ")}</td>
                        <td className="text-right tabular-nums">{s.files_scanned}/{s.files_total}</td>
                        <td className="text-right tabular-nums">{s.status === "completed" ? s.findings_total : "-"}</td>
                        <td className="text-fg-muted">{duration(s.started_at, s.finished_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination page={page} pageSize={PAGE} total={scans.data!.count} onPage={setPage} />
            </>
          )}
      </Panel>
    </>
  );
}
