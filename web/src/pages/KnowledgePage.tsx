import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { supabase, unwrap } from "@/lib/supabase";
import { useAuth } from "@/lib/auth";
import { SEVERITIES, type KnowledgeDocument } from "@/lib/types";
import { workerApi, type AskResponse, type SearchResponse } from "@/lib/worker";
import { Button, EmptyState, ErrorNote, Input, Loading, Notice, PageHeader, Pagination, Panel, Select, Stat, cx } from "@/components/ui";
import { SeverityBadge } from "@/components/badges";

type Mode = "keyword" | "semantic" | "ask";
type DocRow = Pick<KnowledgeDocument, "id" | "slug" | "cwe_id" | "title" | "category" | "owasp_top10" | "owasp_api" |
  "severity_default" | "is_enabled" | "index_status" | "chunk_count" | "embedding_model" | "source" | "references">;

const INDEX_TONE: Record<string, string> = { indexed: "text-ok", pending: "text-fg-muted", stale: "text-sev-medium", failed: "text-[#FF8A8E]", indexing: "text-accent" };

export default function KnowledgePage() {
  const { isAdmin } = useAuth();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [category, setCategory] = useState("");
  const [severity, setSeverity] = useState("");
  const [indexFilter, setIndexFilter] = useState("");
  const [mode, setMode] = useState<Mode>("semantic");
  const [query, setQuery] = useState("");
  const [keywordHits, setKeywordHits] = useState<Set<string> | null>(null);
  const [semantic, setSemantic] = useState<SearchResponse | null>(null);
  const [answer, setAnswer] = useState<AskResponse | null>(null);
  const [page, setPage] = useState(0);

  const docs = useQuery({
    queryKey: ["kb", "docs"],
    queryFn: async () => unwrap(await supabase.from("knowledge_documents")
      .select("id, slug, cwe_id, title, category, owasp_top10, owasp_api, severity_default, is_enabled, index_status, chunk_count, embedding_model, source, references")
      .order("category").order("title")) as DocRow[],
    refetchInterval: (q) => (q.state.data?.some((d) => d.index_status === "pending" || d.index_status === "indexing") ? 5000 : false),
  });

  const search = useMutation({
    mutationFn: async () => {
      setSemantic(null); setAnswer(null); setKeywordHits(null);
      if (mode === "keyword") {
        const rows = unwrap(await supabase.rpc("search_knowledge_keyword", { p_query: query, p_limit: 100 })) as { document_id: string }[];
        setKeywordHits(new Set(rows.map((r) => r.document_id)));
        setPage(0);
      } else if (mode === "semantic") setSemantic(await workerApi.search(query, 8));
      else setAnswer(await workerApi.ask(query));
    },
  });

  const reindex = useMutation({
    mutationFn: async () => unwrap(await supabase.rpc("request_knowledge_reindex", { p_document_ids: null })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["kb"] }),
  });

  const all = docs.data ?? [];
  const categories = useMemo(() => {
    const m = new Map<string, number>();
    all.forEach((d) => m.set(d.category, (m.get(d.category) ?? 0) + 1));
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [all]);
  const rows = all.filter((d) => (!category || d.category === category) && (!severity || d.severity_default === severity)
    && (!indexFilter || d.index_status === indexFilter) && (!keywordHits || keywordHits.has(d.id)));
  const indexed = all.filter((d) => d.index_status === "indexed").length;
  const models = [...new Set(all.map((d) => d.embedding_model).filter(Boolean))];

  return (
    <>
      <PageHeader title="Security knowledge base"
        description="Weakness classes keyed by CWE, mapped to OWASP, with detection patterns and remediation. Scans retrieve from here to explain findings."
        actions={isAdmin && <>
          <Button loading={reindex.isPending} onClick={() => reindex.mutate()}>Re-index all</Button>
          <Button variant="primary" onClick={() => navigate("/knowledge/new")}>Add document</Button>
        </>} />
      <ErrorNote error={reindex.error} title="Re-index not requested" />
      {reindex.isSuccess && <Notice>Queued {String(reindex.data)} documents. The worker re-embeds them within about 30 seconds.</Notice>}

      <div className="grid gap-4 lg:grid-cols-[1fr_280px]">
        <div className="min-w-0 space-y-4">
          <Panel>
            <form className="flex flex-wrap gap-2" onSubmit={(e) => { e.preventDefault(); if (query.trim().length >= 3) search.mutate(); }}>
              <div className="flex rounded-md border border-line p-0.5" role="radiogroup" aria-label="Search mode">
                {(["semantic", "keyword", "ask"] as Mode[]).map((m) => (
                  <button key={m} type="button" role="radio" aria-checked={mode === m} onClick={() => setMode(m)}
                    className={cx("rounded px-2.5 py-1 text-[13px]", mode === m ? "bg-panel-3 text-fg" : "text-fg-muted hover:text-fg")}>
                    {m === "semantic" ? "Semantic" : m === "keyword" ? "Keyword" : "Ask"}
                  </button>
                ))}
              </div>
              <div className="relative min-w-[240px] flex-1">
                <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-fg-faint" />
                <Input className="pl-8" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search the knowledge base"
                  placeholder={mode === "ask" ? "e.g. How should I store user passwords in a Flask app?" : mode === "semantic" ? "Describe a weakness, e.g. user input reaches a shell command" : "Words or CWE ID"} />
              </div>
              <Button type="submit" variant="primary" loading={search.isPending}>{mode === "ask" ? "Ask" : "Search"}</Button>
              {(keywordHits || semantic || answer) && <Button type="button" variant="ghost" onClick={() => { setKeywordHits(null); setSemantic(null); setAnswer(null); }}>Clear</Button>}
            </form>
            <p className="mt-2 text-xs text-fg-muted">
              {mode === "semantic" && "Embeds your query and ranks knowledge chunks by cosine similarity in pgvector."}
              {mode === "keyword" && "Postgres full-text search over titles, CWE names and content. Filters the table below."}
              {mode === "ask" && "Retrieves the best-matching chunks, then the language model answers using only those chunks, with citations."}
            </p>
            <div className="mt-2"><ErrorNote error={search.error} title="Search failed" /></div>

            {semantic && (
              <div className="mt-4">
                {!semantic.evidence_sufficient && <Notice tone="warning">No chunk reached the evidence threshold ({semantic.min_similarity}). The closest matches are shown, but the knowledge base may not cover this.</Notice>}
                <ol className="mt-2 divide-y divide-line">
                  {semantic.results.map((r) => (
                    <li key={r.chunk_id} className="py-2.5">
                      <div className="flex items-baseline justify-between gap-3">
                        <Link to={`/knowledge/${r.document_id}`} className="font-medium text-fg">{r.cwe_id} {r.title}</Link>
                        <span className={cx("shrink-0 tabular-nums text-xs", r.above_threshold ? "text-ok" : "text-fg-faint")}>{r.similarity.toFixed(3)}</span>
                      </div>
                      <div className="text-xs text-fg-muted">{r.category}, {r.section} section</div>
                      <p className="mt-1 line-clamp-2 text-[13px] text-fg-muted">{r.content.split("\n").slice(1).join(" ").slice(0, 260)}</p>
                    </li>
                  ))}
                </ol>
                <p className="mt-1 text-xs text-fg-faint">Embedding model: {semantic.model}</p>
              </div>
            )}

            {answer && (
              <div className="mt-4 space-y-2">
                {!answer.llm_configured && answer.grounded === false && answer.sources.length > 0
                  ? <Notice tone="warning">No language model is configured on the worker, so only the retrieved passages are shown.</Notice>
                  : <div className="whitespace-pre-wrap rounded-md border border-line bg-ink-2 p-3 text-[13px]">{answer.answer}</div>}
                <div className="text-xs text-fg-muted">
                  {answer.sources.map((s, i) => <div key={s.chunk_id}>[{i + 1}] <Link to={`/knowledge/${s.document_id}`}>{s.cwe_id} {s.title}</Link> ({s.section}, similarity {s.similarity.toFixed(3)})</div>)}
                </div>
                <p className="text-xs text-fg-faint">AI-generated from retrieved knowledge. Verify before acting on it.</p>
              </div>
            )}
          </Panel>

          <Panel bodyClass="">
            <div className="flex flex-wrap gap-2 border-b border-line p-3">
              <Select className="w-56" value={category} onChange={(e) => { setCategory(e.target.value); setPage(0); }} aria-label="Category">
                <option value="">All categories ({all.length})</option>
                {categories.map(([c, n]) => <option key={c} value={c}>{c} ({n})</option>)}
              </Select>
              <Select className="w-40" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(0); }} aria-label="Default severity">
                <option value="">Any severity</option>
                {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
              </Select>
              <Select className="w-40" value={indexFilter} onChange={(e) => { setIndexFilter(e.target.value); setPage(0); }} aria-label="Index status">
                <option value="">Any index status</option>
                {["indexed", "pending", "stale", "failed"].map((s) => <option key={s}>{s}</option>)}
              </Select>
              {keywordHits && <span className="self-center text-[13px] text-fg-muted">{rows.length} keyword matches</span>}
            </div>
            {docs.isLoading ? <Loading /> : docs.error ? <div className="p-4"><ErrorNote error={docs.error} /></div> :
              rows.length === 0 ? <EmptyState title="No documents match">{all.length === 0 && "Run `python -m securematrix_worker kb-import` to load the seed knowledge base."}</EmptyState> : (
                <div className="overflow-x-auto">
                  <table className="tbl">
                    <thead><tr><th>CWE</th><th>Title</th><th>Category</th><th>OWASP</th><th>Default severity</th><th>Index</th></tr></thead>
                    <tbody>
                      {rows.slice(page * 25, page * 25 + 25).map((d) => (
                        <tr key={d.id} className={cx("cursor-pointer", !d.is_enabled && "opacity-50")} onClick={() => navigate(`/knowledge/${d.id}`)}>
                          <td className="whitespace-nowrap font-mono text-xs">{d.cwe_id ?? "-"}</td>
                          <td><Link to={`/knowledge/${d.id}`} className="text-fg">{d.title}</Link>{!d.is_enabled && <span className="ml-2 text-xs text-fg-faint">disabled</span>}</td>
                          <td className="text-fg-muted">{d.category}</td>
                          <td className="whitespace-nowrap text-xs text-fg-muted">{[...d.owasp_top10, ...d.owasp_api].map((o) => o.split("-")[0]).join(", ") || "-"}</td>
                          <td><SeverityBadge severity={d.severity_default} /></td>
                          <td className={cx("whitespace-nowrap text-xs", INDEX_TONE[d.index_status])}>{d.index_status}{d.index_status === "indexed" ? ` (${d.chunk_count})` : ""}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <Pagination page={Math.min(page, Math.floor(Math.max(rows.length - 1, 0) / 25))} pageSize={25} total={rows.length} onPage={setPage} />
                </div>
              )}
          </Panel>
        </div>

        <div className="space-y-4">
          <Panel title="Coverage" bodyClass="grid grid-cols-2 gap-4 p-4">
            <Stat label="Documents" value={all.length} hint={`${all.filter((d) => d.is_enabled).length} enabled`} />
            <Stat label="Unique CWEs" value={new Set(all.map((d) => d.cwe_id).filter(Boolean)).size} />
            <Stat label="Indexed" value={`${indexed}/${all.length}`} />
            <Stat label="Chunks" value={all.reduce((n, d) => n + d.chunk_count, 0)} />
          </Panel>
          <Panel title="Embedding index">
            <p className="text-[13px] text-fg-muted">{models.length ? <>Vectors built with <code className="text-xs text-fg">{models.join(", ")}</code>, 384 dimensions, HNSW cosine index.</> : "No document has been embedded yet. Start the worker with an embedding provider configured."}</p>
          </Panel>
          <Panel title="Categories" bodyClass="py-2">
            <ul>
              {categories.map(([c, n]) => (
                <li key={c}>
                  <button onClick={() => { setCategory(category === c ? "" : c); setPage(0); }}
                    className={cx("flex w-full justify-between px-4 py-1 text-left text-[13px] hover:bg-panel-2", category === c ? "text-accent" : "text-fg-muted")}>
                    <span>{c}</span><span className="tabular-nums">{n}</span>
                  </button>
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      </div>
    </>
  );
}
