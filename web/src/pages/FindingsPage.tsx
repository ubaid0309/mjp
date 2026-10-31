import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Download, Search, X } from "lucide-react";
import { supabase, unwrap } from "@/lib/supabase";
import { SEVERITIES, STATUS_LABEL, type FindingStatus, type Vulnerability } from "@/lib/types";
import { findingRef } from "@/lib/format";
import { Button, EmptyState, ErrorNote, Input, Loading, PageHeader, Pagination, Panel, Select } from "@/components/ui";
import { PriorityTag, SeverityBadge, StatusBadge } from "@/components/badges";

const PAGE = 30;
const SORTS: Record<string, [string, boolean]> = {
  risk: ["risk_score", false], newest: ["created_at", false], severity: ["severity", true], file: ["file_path", true],
};
const COLUMNS = "id, ref_no, project_id, title, severity, confidence, status, category, language, file_path, start_line, risk_score, priority, cwe_ids, rule_ids, source, kb_evidence_status, created_at, projects(name)";

type Filters = Record<"project" | "scan" | "severity" | "status" | "language" | "category" | "confidence" | "file" | "q" | "sort", string>;

function applyFilters<T extends { eq: Function; ilike: Function; or: Function; not: Function }>(query: T, f: Filters): T {
  let q = query;
  if (f.project) q = q.eq("project_id", f.project);
  if (f.scan) q = q.eq("last_seen_scan_id", f.scan);
  if (f.severity) q = q.eq("severity", f.severity);
  if (f.status === "open") q = q.not("status", "in", "(resolved,accepted_risk)");
  else if (f.status) q = q.eq("status", f.status);
  if (f.language) q = q.eq("language", f.language);
  if (f.category) q = q.eq("category", f.category);
  if (f.confidence) q = q.eq("confidence", f.confidence);
  if (f.file) q = q.ilike("file_path", `%${f.file}%`);
  if (f.q) {
    const term = f.q.replace(/[%,()]/g, " ").trim();
    if (/^CWE-\d+$/i.test(term)) q = (q as any).contains("cwe_ids", [term.toUpperCase()]);
    else if (term) q = q.or(`title.ilike.%${term}%,description.ilike.%${term}%`);
  }
  return q;
}

function csvCell(v: unknown) {
  const s = Array.isArray(v) ? v.join(" ") : String(v ?? "");
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export default function FindingsPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const f = Object.fromEntries(["project", "scan", "severity", "status", "language", "category", "confidence", "file", "q", "sort"]
    .map((k) => [k, params.get(k) ?? ""])) as Filters;
  const page = Number(params.get("page") ?? 0);
  const [search, setSearch] = useState(f.q);
  const [exporting, setExporting] = useState(false);

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v); else next.delete(k);
    next.delete("page");
    setParams(next);
  };

  const facets = useQuery({
    queryKey: ["findings", "facets"],
    queryFn: async () => {
      const rows = unwrap(await supabase.from("vulnerabilities").select("language, category").limit(5000)) as { language: string | null; category: string | null }[];
      const projects = unwrap(await supabase.from("projects").select("id, name").order("name")) as { id: string; name: string }[];
      return {
        languages: [...new Set(rows.map((r) => r.language).filter(Boolean))].sort() as string[],
        categories: [...new Set(rows.map((r) => r.category).filter(Boolean))].sort() as string[],
        projects,
      };
    },
  });

  const list = useQuery({
    queryKey: ["findings", f, page],
    queryFn: async () => {
      const [col, asc] = SORTS[f.sort] ?? SORTS.risk;
      let q = applyFilters(supabase.from("vulnerabilities").select(COLUMNS, { count: "exact" }), f)
        .order(col, { ascending: asc, nullsFirst: false });
      if (col !== "risk_score") q = q.order("risk_score", { ascending: false, nullsFirst: false });
      const res = await q.range(page * PAGE, page * PAGE + PAGE - 1);
      return { rows: unwrap(res) as unknown as Vulnerability[], count: res.count ?? 0 };
    },
  });

  async function exportCsv() {
    setExporting(true);
    try {
      const rows = unwrap(await applyFilters(supabase.from("vulnerabilities").select("*, projects(name)"), f)
        .order("risk_score", { ascending: false }).limit(5000)) as unknown as Vulnerability[];
      const cols = ["ref", "project", "title", "severity", "confidence", "status", "risk_score", "priority", "cwe_ids", "owasp_top10", "file_path", "start_line", "rule_ids", "source"];
      const lines = [cols.join(",")].concat(rows.map((r) => [findingRef(r.ref_no), r.projects?.name, r.title, r.severity, r.confidence, r.status,
        r.risk_score, r.priority, r.cwe_ids, r.owasp_top10, r.file_path, r.start_line, r.rule_ids, r.source].map(csvCell).join(",")));
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/csv" }));
      a.download = "securematrix-findings.csv";
      a.click();
      URL.revokeObjectURL(a.href);
    } finally {
      setExporting(false);
    }
  }

  const activeFilters = Object.entries(f).filter(([k, v]) => v && k !== "sort");

  return (
    <>
      <PageHeader title="Vulnerabilities" description="All findings from scans of your projects. Each one is a scanner result that still needs human review before it is considered exploitable."
        actions={<Button onClick={exportCsv} loading={exporting}><Download className="h-3.5 w-3.5" /> Export CSV</Button>} />
      <Panel bodyClass="">
        <div className="space-y-3 border-b border-line p-3">
          <form className="flex flex-wrap gap-2" onSubmit={(e) => { e.preventDefault(); set("q", search); }}>
            <div className="relative min-w-[220px] flex-1">
              <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-fg-faint" />
              <Input className="pl-8" placeholder="Search title or description, or enter a CWE such as CWE-89" value={search}
                onChange={(e) => setSearch(e.target.value)} aria-label="Search findings" />
            </div>
            <Input className="w-48" placeholder="File path contains" defaultValue={f.file} aria-label="File path"
              onBlur={(e) => e.target.value !== f.file && set("file", e.target.value)} />
            <Button type="submit">Search</Button>
          </form>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 xl:grid-cols-8">
            <Select value={f.project} onChange={(e) => set("project", e.target.value)} aria-label="Project">
              <option value="">All projects</option>
              {facets.data?.projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </Select>
            <Select value={f.severity} onChange={(e) => set("severity", e.target.value)} aria-label="Severity">
              <option value="">Any severity</option>
              {SEVERITIES.map((s) => <option key={s} value={s} className="capitalize">{s}</option>)}
            </Select>
            <Select value={f.status} onChange={(e) => set("status", e.target.value)} aria-label="Status">
              <option value="">Any status</option>
              <option value="open">Open (not resolved or accepted)</option>
              {(Object.keys(STATUS_LABEL) as FindingStatus[]).map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
            </Select>
            <Select value={f.confidence} onChange={(e) => set("confidence", e.target.value)} aria-label="Confidence">
              <option value="">Any confidence</option>
              {["high", "medium", "low"].map((s) => <option key={s} value={s}>{s} confidence</option>)}
            </Select>
            <Select value={f.language} onChange={(e) => set("language", e.target.value)} aria-label="Language">
              <option value="">Any language</option>
              {facets.data?.languages.map((l) => <option key={l}>{l}</option>)}
            </Select>
            <Select value={f.category} onChange={(e) => set("category", e.target.value)} aria-label="Category" className="xl:col-span-2">
              <option value="">Any category</option>
              {facets.data?.categories.map((c) => <option key={c}>{c}</option>)}
            </Select>
            <Select value={f.sort || "risk"} onChange={(e) => set("sort", e.target.value === "risk" ? "" : e.target.value)} aria-label="Sort">
              <option value="risk">Highest risk first</option>
              <option value="newest">Newest first</option>
              <option value="severity">By severity</option>
              <option value="file">By file</option>
            </Select>
          </div>
          {activeFilters.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5 text-xs">
              {activeFilters.map(([k, v]) => (
                <button key={k} onClick={() => { set(k, ""); if (k === "q") setSearch(""); }}
                  className="inline-flex items-center gap-1 rounded bg-panel-3 px-2 py-1 text-fg-muted hover:text-fg">
                  {k}: {k === "project" ? facets.data?.projects.find((p) => p.id === v)?.name ?? "…" : k === "scan" ? v.slice(0, 8) : v}
                  <X className="h-3 w-3" />
                </button>
              ))}
              <button className="px-1 text-fg-muted hover:text-fg" onClick={() => { setParams({}); setSearch(""); }}>Clear all</button>
            </div>
          )}
        </div>

        {list.isLoading ? <Loading /> : list.error ? <div className="p-4"><ErrorNote error={list.error} /></div> :
          list.data!.rows.length === 0 ? (
            <EmptyState title="No findings match these filters">Try removing a filter, or run a scan if this project has none yet.</EmptyState>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="tbl">
                  <thead>
                    <tr><th>ID</th><th>Severity</th><th>Finding</th><th>Location</th><th>CWE</th><th className="text-right">Risk</th><th>Priority</th><th>Status</th></tr>
                  </thead>
                  <tbody>
                    {list.data!.rows.map((v) => (
                      <tr key={v.id} className="cursor-pointer" onClick={() => navigate(`/findings/${v.id}`)}>
                        <td className="whitespace-nowrap font-mono text-xs text-fg-muted">{findingRef(v.ref_no)}</td>
                        <td><SeverityBadge severity={v.severity} /></td>
                        <td className="min-w-[220px]">
                          <Link to={`/findings/${v.id}`} className="text-fg">{v.title}</Link>
                          <div className="flex gap-3 text-xs text-fg-muted">
                            <span>{v.projects?.name}</span><span>{v.confidence} confidence</span>
                            {v.kb_evidence_status !== "matched" && <span>no KB evidence</span>}
                          </div>
                        </td>
                        <td className="max-w-[280px] truncate font-mono text-xs text-fg-muted" title={`${v.file_path}:${v.start_line}`}>{v.file_path}:{v.start_line}</td>
                        <td className="whitespace-nowrap font-mono text-xs">{v.cwe_ids[0] ?? "-"}</td>
                        <td className="text-right tabular-nums">{v.risk_score ?? "-"}</td>
                        <td><PriorityTag priority={v.priority} /></td>
                        <td className="whitespace-nowrap"><StatusBadge status={v.status} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination page={page} pageSize={PAGE} total={list.data!.count}
                onPage={(p) => { const n = new URLSearchParams(params); n.set("page", String(p)); setParams(n); }} />
            </>
          )}
      </Panel>
    </>
  );
}
