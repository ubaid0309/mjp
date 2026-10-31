import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Sparkles } from "lucide-react";
import { supabase, unwrap } from "@/lib/supabase";
import { useAuth } from "@/lib/auth";
import { STATUS_LABEL, TRANSITIONS, type FindingStatus, type KnowledgeRef, type Vulnerability } from "@/lib/types";
import { cweUrl, dateTime, findingRef, shortRule, timeAgo } from "@/lib/format";
import { workerApi, type AskResponse } from "@/lib/worker";
import { Button, ErrorNote, Field, Loading, Notice, Panel, Select, Textarea, cx } from "@/components/ui";
import { PriorityTag, SeverityBadge, SourceTag, StatusBadge } from "@/components/badges";
import { CodeBlock } from "@/components/CodeBlock";

const MATCH_LABEL: Record<KnowledgeRef["match_type"], string> = {
  cwe_and_semantic: "CWE match + semantic", cwe_exact: "CWE match", semantic: "Semantic match",
};

interface AuditRow { id: number; action: string; old_values: Record<string, unknown> | null; new_values: Record<string, unknown> | null; created_at: string; profiles: { full_name: string | null; email: string | null } | null }
interface CommentRow { id: string; body: string; created_at: string; author_id: string; profiles: { full_name: string | null; email: string | null } | null }

function List({ items }: { items: string[] }) {
  return <ul className="list-disc space-y-1 pl-5 text-[13px]">{items.map((i) => <li key={i}>{i}</li>)}</ul>;
}

export default function FindingDetailPage() {
  const { id } = useParams();
  const qc = useQueryClient();
  const { session } = useAuth();
  const [nextStatus, setNextStatus] = useState<FindingStatus | "">("");
  const [note, setNote] = useState("");
  const [comment, setComment] = useState("");
  const [answer, setAnswer] = useState<AskResponse | null>(null);

  const v = useQuery({
    queryKey: ["finding", id],
    queryFn: async () => unwrap(await supabase.from("vulnerabilities").select("*, projects(name)").eq("id", id!).single()) as Vulnerability,
  });
  const refs = useQuery({
    queryKey: ["finding", id, "refs"],
    queryFn: async () => unwrap(await supabase.from("finding_knowledge_refs")
      .select("*, knowledge_documents(*), knowledge_chunks(section, content)").eq("vulnerability_id", id!).order("rank")) as unknown as KnowledgeRef[],
  });
  const audit = useQuery({
    queryKey: ["finding", id, "audit"],
    queryFn: async () => unwrap(await supabase.from("audit_logs").select("id, action, old_values, new_values, created_at, profiles(full_name, email)")
      .eq("entity_type", "vulnerability").eq("entity_id", id!).order("created_at", { ascending: false })) as unknown as AuditRow[],
  });
  const comments = useQuery({
    queryKey: ["finding", id, "comments"],
    queryFn: async () => unwrap(await supabase.from("finding_comments").select("id, body, created_at, author_id, profiles(full_name, email)")
      .eq("vulnerability_id", id!).order("created_at")) as unknown as CommentRow[],
  });

  const changeStatus = useMutation({
    mutationFn: async () => unwrap(await supabase.rpc("update_finding_status", { p_vulnerability_id: id, p_status: nextStatus, p_note: note || null })),
    onSuccess: () => { setNextStatus(""); setNote(""); qc.invalidateQueries({ queryKey: ["finding", id] }); qc.invalidateQueries({ queryKey: ["dashboard"] }); },
  });
  const addComment = useMutation({
    mutationFn: async () => unwrap(await supabase.from("finding_comments").insert({ vulnerability_id: id, author_id: session!.user.id, body: comment.trim() })),
    onSuccess: () => { setComment(""); qc.invalidateQueries({ queryKey: ["finding", id, "comments"] }); },
  });
  const ask = useMutation({
    mutationFn: async () => {
      const f = v.data!;
      return workerApi.ask(`A static analysis scanner reported "${f.title}" (${f.cwe_ids.join(", ") || "no CWE"}) in ${f.language ?? "source"} code: ${f.description ?? ""}\n` +
        `Explain the root cause, how it could be exploited, and the specific secure coding fix for this kind of code.`);
    },
    onSuccess: setAnswer,
  });

  if (v.isLoading) return <Loading />;
  if (v.error) return <ErrorNote error={v.error} title="Finding not found or not accessible" />;
  const f = v.data!;
  const primary = refs.data?.[0]?.knowledge_documents;
  const allowed = TRANSITIONS[f.status];

  return (
    <>
      <div className="mb-6">
        <div className="flex flex-wrap items-center gap-2 text-[13px] text-fg-muted">
          <Link to="/findings">Vulnerabilities</Link><span>/</span>
          <span className="font-mono text-xs">{findingRef(f.ref_no)}</span>
        </div>
        <h1 className="mt-2 text-xl font-semibold">{f.title}</h1>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <SeverityBadge severity={f.severity} />
          <SourceTag source={f.source} />
          <span className="text-[13px] text-fg-muted">{f.confidence} confidence</span>
          <span className="text-fg-faint">|</span>
          <StatusBadge status={f.status} />
          <span className="text-fg-faint">|</span>
          <Link to={`/projects/${f.project_id}`} className="text-[13px]">{f.projects?.name}</Link>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1fr_380px]">
        <div className="min-w-0 space-y-4">
          <Panel title="What the scanner found">
            <p className="text-[13px]">{f.description}</p>
            <div className="mt-3 font-mono text-xs text-fg-muted">{f.file_path}:{f.start_line}{f.end_line && f.end_line !== f.start_line ? `-${f.end_line}` : ""}</div>
            {f.snippet && <CodeBlock className="mt-2" code={f.snippet} highlight={[f.start_line ?? 0, f.end_line ?? f.start_line ?? 0]}
              label="Code at the reported location (secrets are redacted)" />}
            <div className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-[13px]">
              <span className="text-fg-muted">Detected by <span className="text-fg">{f.detection_method}</span></span>
              <span className="text-fg-muted">Rules: {f.rule_ids.map((r) => <code key={r} className="mr-2 text-xs text-fg" title={r}>{shortRule(r)}</code>)}</span>
            </div>
            {f.requires_manual_review && (
              <Notice tone="warning">
                <span className="font-medium">Needs manual review.</span>{" "}
                <span className="text-fg-muted">Static analysis matched a vulnerable pattern but cannot prove the code path is reachable or exploitable.</span>
              </Notice>
            )}
          </Panel>

          <Panel title="Knowledge base guidance" actions={<span className="text-xs text-fg-muted">Retrieved from the SecureMatrix knowledge base</span>}>
            {refs.isLoading ? <Loading /> : !primary ? (
              <Notice tone="warning">
                The knowledge base does not contain enough evidence for this finding
                {f.kb_evidence_status === "unavailable" ? " (no embedding provider was configured when it was scanned, and no CWE matched)" : ""}.
                Review it against the scanner rule documentation.
              </Notice>
            ) : (
              <div className="space-y-4">
                <div>
                  <div className="flex flex-wrap items-baseline gap-2">
                    <Link to={`/knowledge/${primary.id}`} className="font-medium text-fg">{primary.cwe_id} {primary.title}</Link>
                    <span className="text-xs text-fg-muted">{primary.category}</span>
                  </div>
                  <p className="mt-1 text-[13px] text-fg-muted">{primary.description}</p>
                </div>
                <div className="grid gap-4 md:grid-cols-2">
                  <div><h3 className="mb-1.5 text-[13px] font-medium">Potential impact</h3><List items={primary.impact} /></div>
                  <div><h3 className="mb-1.5 text-[13px] font-medium">Attack prerequisites</h3><List items={primary.prerequisites} /></div>
                </div>
                <div><h3 className="mb-1.5 text-[13px] font-medium">Recommended remediation</h3><List items={primary.remediation} /></div>
                {primary.secure_example && (
                  <div className="grid gap-3 lg:grid-cols-2">
                    {primary.vulnerable_example && <CodeBlock code={primary.vulnerable_example.code} label={`Vulnerable pattern (${primary.vulnerable_example.language})`} />}
                    <CodeBlock code={primary.secure_example.code} label={`Secure pattern (${primary.secure_example.language})`} />
                  </div>
                )}
                <p className="text-xs text-fg-muted">
                  This is general guidance for the weakness class. It has not been applied to or verified against this code.
                  Patch generation and re-scan verification are part of the Remediation module.
                </p>
                <div>
                  <h3 className="mb-1.5 text-[13px] font-medium">Retrieved references</h3>
                  <table className="tbl">
                    <thead><tr><th>Document</th><th>Match</th><th className="text-right">Similarity</th></tr></thead>
                    <tbody>
                      {refs.data!.map((r) => (
                        <tr key={r.id}>
                          <td><Link to={`/knowledge/${r.document_id}`} className="text-fg">{r.knowledge_documents.cwe_id} {r.knowledge_documents.title}</Link>
                            {r.knowledge_chunks && <div className="text-xs text-fg-muted">best chunk: {r.knowledge_chunks.section}</div>}</td>
                          <td className="text-fg-muted">{MATCH_LABEL[r.match_type]}</td>
                          <td className="text-right tabular-nums">{r.similarity != null ? r.similarity.toFixed(3) : "-"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <p className="mt-1.5 text-xs text-fg-faint">Retrieved with {refs.data!.find((r) => r.retrieved_with && r.retrieved_with !== "cwe-metadata")?.retrieved_with ?? "CWE metadata only"} (cosine similarity, pgvector).</p>
                </div>
              </div>
            )}
          </Panel>

          <Panel title="Explain with AI" actions={<span className="text-xs text-fg-muted">Grounded on retrieved knowledge</span>}>
            {!answer ? (
              <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="max-w-xl text-[13px] text-fg-muted">
                  Retrieves the most relevant knowledge-base passages for this finding and asks the configured language model to explain it
                  using only those passages. The answer is AI-generated and unverified.
                </p>
                <Button onClick={() => ask.mutate()} loading={ask.isPending}><Sparkles className="h-3.5 w-3.5" /> Generate explanation</Button>
              </div>
            ) : (
              <div className="space-y-3">
                {!answer.llm_configured ? (
                  <Notice tone="warning">No language model is configured on the worker (set OPENAI_API_KEY). The passages it would have used are listed below.</Notice>
                ) : (
                  <div className={cx("whitespace-pre-wrap rounded-md border border-line bg-ink-2 p-3 text-[13px]", !answer.grounded && "text-fg-muted")}>{answer.answer}</div>
                )}
                <div className="text-xs text-fg-muted">
                  Sources: {answer.sources.map((s, i) => <span key={s.chunk_id} className="mr-3">[{i + 1}] {s.cwe_id} {s.title} ({s.section}, {s.similarity.toFixed(2)})</span>)}
                </div>
                <div className="text-xs text-fg-faint">{answer.llm_model ? `Model: ${answer.llm_model}. ` : ""}Embeddings: {answer.model}. AI-generated, unverified.</div>
              </div>
            )}
            <ErrorNote error={ask.error} title="Explanation unavailable" />
          </Panel>
        </div>

        <div className="space-y-4">
          <Panel title="Lifecycle">
            <div className="text-[13px]">Current status: <StatusBadge status={f.status} /></div>
            <div className="mt-1 text-xs text-fg-muted">Verification: {f.verification_status.replace(/_/g, " ")}</div>
            {f.status === "accepted_risk" && f.accepted_risk_justification && (
              <p className="mt-2 rounded border border-line bg-ink-2 p-2 text-xs">Justification: {f.accepted_risk_justification}</p>
            )}
            <form className="mt-3 space-y-2" onSubmit={(e) => { e.preventDefault(); changeStatus.mutate(); }}>
              <Field label="Move to" htmlFor="status">
                <Select id="status" value={nextStatus} onChange={(e) => setNextStatus(e.target.value as FindingStatus)}>
                  <option value="">Choose a status</option>
                  {allowed.map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
                </Select>
              </Field>
              {nextStatus && (
                <Field label={nextStatus === "accepted_risk" ? "Justification (required)" : "Note (optional)"} htmlFor="note">
                  <Textarea id="note" value={note} onChange={(e) => setNote(e.target.value)} maxLength={1000}
                    placeholder={nextStatus === "accepted_risk" ? "Why is this risk acceptable, and who approved it?" : ""} />
                </Field>
              )}
              <Button type="submit" variant="primary" disabled={!nextStatus || (nextStatus === "accepted_risk" && note.trim().length < 10)}
                loading={changeStatus.isPending}>Update status</Button>
              <ErrorNote error={changeStatus.error} title="Status not changed" />
              <p className="text-xs text-fg-faint">Resolved can only be set by a verification re-scan, never by hand.</p>
            </form>
          </Panel>

          <Panel title="Risk score">
            <div className="flex items-baseline gap-3">
              <span className="text-3xl font-semibold tabular-nums">{f.risk_score ?? "-"}</span>
              <span className="text-fg-muted">/ 100</span>
              <span className="ml-auto"><PriorityTag priority={f.priority} /></span>
            </div>
            <table className="mt-3 w-full text-[13px]">
              <tbody>
                {(f.risk_rationale.factors ?? []).map((x) => (
                  <tr key={x.name} className="align-top">
                    <td className="py-1 pr-2 capitalize text-fg-muted">{x.name}</td>
                    <td className="py-1 pr-2 tabular-nums">{x.value}</td>
                    <td className="py-1 text-xs text-fg-muted">{x.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="mt-2 text-xs text-fg-faint">{f.risk_rationale.formula}. {f.risk_rationale.note}</p>
          </Panel>

          <Panel title="Classification">
            <dl className="space-y-2 text-[13px]">
              <div><dt className="text-fg-muted">CWE</dt><dd className="flex flex-wrap gap-2">
                {f.cwe_ids.length ? f.cwe_ids.map((c) => <a key={c} href={cweUrl(c)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1">{c}<ExternalLink className="h-3 w-3" /></a>) : "Not mapped"}
              </dd></div>
              <div><dt className="text-fg-muted">OWASP Top 10 (2021)</dt><dd>{f.owasp_top10.length ? f.owasp_top10.join(", ") : "Not mapped"}</dd></div>
              <div><dt className="text-fg-muted">Category</dt><dd>{f.category ?? "Uncategorised"}</dd></div>
              <div><dt className="text-fg-muted">Language</dt><dd>{f.language ?? "-"}</dd></div>
              <div><dt className="text-fg-muted">First detected</dt><dd>{dateTime(f.created_at)} {f.first_seen_scan_id && <Link to={`/scans/${f.first_seen_scan_id}`}>(scan)</Link>}</dd></div>
              <div><dt className="text-fg-muted">Seen in scans</dt><dd>{f.occurrence_count}{f.reopened_count ? `, reopened ${f.reopened_count} time(s)` : ""}</dd></div>
            </dl>
          </Panel>

          <Panel title="Discussion and history">
            <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); if (comment.trim()) addComment.mutate(); }}>
              <Textarea value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Add a remediation note" maxLength={5000} aria-label="Comment" />
              <Button type="submit" disabled={!comment.trim()} loading={addComment.isPending}>Add note</Button>
              <ErrorNote error={addComment.error} title="Note not saved" />
            </form>
            <ol className="mt-4 space-y-3 text-[13px]">
              {[
                ...(comments.data ?? []).map((c) => ({ key: `c${c.id}`, at: c.created_at, who: c.profiles?.full_name || c.profiles?.email, text: c.body, kind: "comment" })),
                ...(audit.data ?? []).map((a) => ({
                  key: `a${a.id}`, at: a.created_at, who: a.profiles?.full_name || a.profiles?.email || "System", kind: "event",
                  text: a.action === "status_changed"
                    ? `changed status from ${STATUS_LABEL[a.old_values?.status as FindingStatus] ?? a.old_values?.status} to ${STATUS_LABEL[a.new_values?.status as FindingStatus] ?? a.new_values?.status}${a.new_values?.note ? `: ${a.new_values.note}` : ""}`
                    : a.action === "reopened" ? "reopened the finding because a scan detected it again" : a.action,
                })),
                { key: "detected", at: f.created_at, who: "Scanner", text: "detected this finding", kind: "event" },
              ].sort((x, y) => y.at.localeCompare(x.at)).map((e) => (
                <li key={e.key} className={e.kind === "comment" ? "rounded-md border border-line bg-ink-2 p-2.5" : "text-fg-muted"}>
                  <span className="font-medium text-fg">{e.who}</span> {e.kind === "comment" ? <span className="text-xs text-fg-faint">{timeAgo(e.at)}</span> : <>{e.text} <span className="text-xs text-fg-faint">{timeAgo(e.at)}</span></>}
                  {e.kind === "comment" && <p className="mt-1 whitespace-pre-wrap">{e.text}</p>}
                </li>
              ))}
            </ol>
          </Panel>
        </div>
      </div>
    </>
  );
}
