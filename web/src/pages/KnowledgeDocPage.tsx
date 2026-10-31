import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";
import { supabase, unwrap } from "@/lib/supabase";
import { useAuth } from "@/lib/auth";
import { SEVERITIES, type KnowledgeDocument, type Severity } from "@/lib/types";
import { dateTime } from "@/lib/format";
import { Button, ErrorNote, Field, Input, Loading, Notice, PageHeader, Panel, Select, Textarea } from "@/components/ui";
import { SeverityBadge } from "@/components/badges";
import { CodeBlock } from "@/components/CodeBlock";

const CATEGORIES = ["Injection", "Cross-Site Scripting", "Access Control", "Authentication", "Session Management", "Cryptography",
  "Secrets & Credentials", "Input Validation", "File Handling", "Deserialization", "Server-Side Request Forgery", "XML Processing",
  "Memory Safety", "Concurrency", "Resource Management & DoS", "Security Misconfiguration", "Logging & Monitoring",
  "Information Exposure", "Error Handling", "Supply Chain", "Web Security", "Business Logic", "AI/LLM Security"];

interface Form {
  cwe_id: string; title: string; cwe_name: string; category: string; severity_default: Severity; description: string;
  owasp_top10: string; owasp_api: string; languages: string; prerequisites: string; impact: string; detection_patterns: string;
  remediation: string; vulnerable_lang: string; vulnerable_code: string; secure_lang: string; secure_code: string; references: string;
}
const empty: Form = { cwe_id: "", title: "", cwe_name: "", category: "Injection", severity_default: "medium", description: "", owasp_top10: "",
  owasp_api: "", languages: "", prerequisites: "", impact: "", detection_patterns: "", remediation: "", vulnerable_lang: "", vulnerable_code: "",
  secure_lang: "", secure_code: "", references: "" };

const lines = (s: string) => s.split("\n").map((x) => x.trim()).filter(Boolean);

function toForm(d: KnowledgeDocument): Form {
  return {
    cwe_id: d.cwe_id ?? "", title: d.title, cwe_name: d.cwe_name ?? "", category: d.category, severity_default: d.severity_default,
    description: d.description, owasp_top10: d.owasp_top10.join("\n"), owasp_api: d.owasp_api.join("\n"), languages: d.languages.join(", "),
    prerequisites: d.prerequisites.join("\n"), impact: d.impact.join("\n"), detection_patterns: d.detection_patterns.join("\n"),
    remediation: d.remediation.join("\n"), vulnerable_lang: d.vulnerable_example?.language ?? "", vulnerable_code: d.vulnerable_example?.code ?? "",
    secure_lang: d.secure_example?.language ?? "", secure_code: d.secure_example?.code ?? "",
    references: d.references.map((r) => `${r.title} | ${r.url}`).join("\n"),
  };
}

function Bullets({ title, items }: { title: string; items: string[] }) {
  if (!items.length) return null;
  return (
    <div>
      <h3 className="mb-1.5 text-[13px] font-medium">{title}</h3>
      <ul className="list-disc space-y-1 pl-5 text-[13px] text-fg-muted">{items.map((i) => <li key={i}>{i}</li>)}</ul>
    </div>
  );
}

export default function KnowledgeDocPage() {
  const { id } = useParams();
  const isNew = !id;
  const { isAdmin, session } = useAuth();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [editing, setEditing] = useState(isNew);
  const [form, setForm] = useState<Form>(empty);

  const doc = useQuery({
    queryKey: ["kb", "doc", id],
    enabled: !isNew,
    queryFn: async () => unwrap(await supabase.from("knowledge_documents").select("*").eq("id", id!).single()) as KnowledgeDocument,
  });
  useEffect(() => { if (doc.data) setForm(toForm(doc.data)); }, [doc.data]);

  const save = useMutation({
    mutationFn: async () => {
      if (form.cwe_id && !/^CWE-\d+$/.test(form.cwe_id)) throw new Error("CWE ID must look like CWE-79.");
      if (form.title.trim().length < 3 || form.description.trim().length < 20) throw new Error("Add a title and a description of at least 20 characters.");
      const refs = lines(form.references).map((l) => { const [title, url] = l.split("|").map((s) => s.trim()); return { title, url }; });
      if (refs.some((r) => !r.url?.startsWith("https://"))) throw new Error("Each reference must be 'Title | https://...'.");
      const row = {
        cwe_id: form.cwe_id || null, title: form.title.trim(), cwe_name: form.cwe_name.trim() || null, category: form.category,
        severity_default: form.severity_default, description: form.description.trim(), owasp_top10: lines(form.owasp_top10),
        owasp_api: lines(form.owasp_api), languages: form.languages.split(",").map((s) => s.trim()).filter(Boolean),
        prerequisites: lines(form.prerequisites), impact: lines(form.impact), detection_patterns: lines(form.detection_patterns),
        remediation: lines(form.remediation),
        vulnerable_example: form.vulnerable_code ? { language: form.vulnerable_lang || "text", code: form.vulnerable_code } : null,
        secure_example: form.secure_code ? { language: form.secure_lang || "text", code: form.secure_code } : null,
        references: refs, updated_by: session!.user.id,
      };
      if (isNew) {
        const slug = `${form.cwe_id ? form.cwe_id.toLowerCase() + "-" : ""}${form.title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")}`.slice(0, 80);
        return unwrap(await supabase.from("knowledge_documents").insert({ ...row, slug, source: "manual", created_by: session!.user.id }).select("id").single()) as { id: string };
      }
      unwrap(await supabase.from("knowledge_documents").update(row).eq("id", id!));
      return { id: id! };
    },
    onSuccess: (r) => { qc.invalidateQueries({ queryKey: ["kb"] }); setEditing(false); if (isNew) navigate(`/knowledge/${r.id}`); },
  });
  const toggle = useMutation({
    mutationFn: async () => unwrap(await supabase.from("knowledge_documents").update({ is_enabled: !doc.data!.is_enabled }).eq("id", id!)),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["kb"] }),
  });
  const reindex = useMutation({
    mutationFn: async () => unwrap(await supabase.rpc("request_knowledge_reindex", { p_document_ids: [id] })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["kb", "doc", id] }),
  });

  if (!isNew && doc.isLoading) return <Loading />;
  if (doc.error) return <ErrorNote error={doc.error} title="Document not found" />;
  const d = doc.data;
  const set = (k: keyof Form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });

  if (editing) {
    if (!isAdmin) return <Notice tone="warning">Only administrators can edit the knowledge base.</Notice>;
    const submit = (e: FormEvent) => { e.preventDefault(); save.mutate(); };
    return (
      <>
        <PageHeader title={isNew ? "Add knowledge document" : `Edit ${d?.cwe_id ?? ""} ${d?.title ?? ""}`}
          description="Saved changes mark the document as stale; the worker re-embeds it automatically." />
        <form onSubmit={submit} className="space-y-4">
          <Panel title="Identity">
            <div className="grid gap-4 md:grid-cols-3">
              <Field label="CWE ID" htmlFor="cwe"><Input id="cwe" value={form.cwe_id} onChange={set("cwe_id")} placeholder="CWE-79" /></Field>
              <Field label="Title" htmlFor="title"><Input id="title" value={form.title} onChange={set("title")} required /></Field>
              <Field label="Official CWE name" htmlFor="cwename"><Input id="cwename" value={form.cwe_name} onChange={set("cwe_name")} /></Field>
              <Field label="Category" htmlFor="cat"><Select id="cat" value={form.category} onChange={set("category")}>{CATEGORIES.map((c) => <option key={c}>{c}</option>)}</Select></Field>
              <Field label="Default severity" htmlFor="sev"><Select id="sev" value={form.severity_default} onChange={set("severity_default")}>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</Select></Field>
              <Field label="Languages" htmlFor="langs" hint="Comma separated"><Input id="langs" value={form.languages} onChange={set("languages")} /></Field>
            </div>
            <div className="mt-4"><Field label="Description" htmlFor="desc"><Textarea id="desc" value={form.description} onChange={set("description")} required /></Field></div>
          </Panel>
          <Panel title="Mappings and guidance (one item per line)">
            <div className="grid gap-4 md:grid-cols-2">
              <Field label="OWASP Top 10 2021" htmlFor="o1"><Textarea id="o1" value={form.owasp_top10} onChange={set("owasp_top10")} placeholder="A03:2021-Injection" /></Field>
              <Field label="OWASP API Security 2023" htmlFor="o2"><Textarea id="o2" value={form.owasp_api} onChange={set("owasp_api")} /></Field>
              <Field label="Attack prerequisites" htmlFor="pre"><Textarea id="pre" value={form.prerequisites} onChange={set("prerequisites")} /></Field>
              <Field label="Impact" htmlFor="imp"><Textarea id="imp" value={form.impact} onChange={set("impact")} /></Field>
              <Field label="Detection patterns" htmlFor="det"><Textarea id="det" value={form.detection_patterns} onChange={set("detection_patterns")} /></Field>
              <Field label="Remediation" htmlFor="rem"><Textarea id="rem" value={form.remediation} onChange={set("remediation")} /></Field>
            </div>
          </Panel>
          <Panel title="Examples and references">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2"><Field label="Vulnerable example language" htmlFor="vl"><Input id="vl" value={form.vulnerable_lang} onChange={set("vulnerable_lang")} /></Field>
                <Textarea aria-label="Vulnerable code" className="min-h-[140px] font-mono" value={form.vulnerable_code} onChange={set("vulnerable_code")} /></div>
              <div className="space-y-2"><Field label="Secure example language" htmlFor="sl"><Input id="sl" value={form.secure_lang} onChange={set("secure_lang")} /></Field>
                <Textarea aria-label="Secure code" className="min-h-[140px] font-mono" value={form.secure_code} onChange={set("secure_code")} /></div>
            </div>
            <div className="mt-4"><Field label="References" htmlFor="refs" hint="One per line: Title | https://url"><Textarea id="refs" value={form.references} onChange={set("references")} /></Field></div>
          </Panel>
          <ErrorNote error={save.error} title="Not saved" />
          <div className="flex gap-2">
            <Button type="submit" variant="primary" loading={save.isPending}>{isNew ? "Add document" : "Save changes"}</Button>
            <Button type="button" variant="ghost" onClick={() => (isNew ? navigate("/knowledge") : setEditing(false))}>Cancel</Button>
          </div>
        </form>
      </>
    );
  }

  return (
    <>
      <div className="mb-2 text-[13px] text-fg-muted"><Link to="/knowledge">Knowledge base</Link> / {d!.cwe_id ?? d!.slug}</div>
      <PageHeader title={`${d!.cwe_id ? d!.cwe_id + " " : ""}${d!.title}`} description={d!.cwe_name ?? undefined}
        actions={isAdmin && <>
          <Button onClick={() => reindex.mutate()} loading={reindex.isPending}>Re-index</Button>
          <Button onClick={() => toggle.mutate()} loading={toggle.isPending}>{d!.is_enabled ? "Disable" : "Enable"}</Button>
          <Button variant="primary" onClick={() => setEditing(true)}>Edit</Button>
        </>} />
      <ErrorNote error={toggle.error ?? reindex.error} />
      {!d!.is_enabled && <Notice tone="warning">This document is disabled and is excluded from retrieval.</Notice>}

      <div className="mt-4 grid gap-4 xl:grid-cols-[1fr_320px]">
        <Panel>
          <div className="space-y-5">
            <p className="text-[13px] leading-relaxed">{d!.description}</p>
            <div className="grid gap-5 md:grid-cols-2">
              <Bullets title="Attack prerequisites" items={d!.prerequisites} />
              <Bullets title="Impact" items={d!.impact} />
            </div>
            <Bullets title="How to detect it" items={d!.detection_patterns} />
            <Bullets title="Remediation" items={d!.remediation} />
            <div className="grid gap-3 lg:grid-cols-2">
              {d!.vulnerable_example && <CodeBlock code={d!.vulnerable_example.code} label={`Vulnerable (${d!.vulnerable_example.language})`} />}
              {d!.secure_example && <CodeBlock code={d!.secure_example.code} label={`Secure (${d!.secure_example.language})`} />}
            </div>
          </div>
        </Panel>
        <div className="space-y-4">
          <Panel title="Classification">
            <dl className="space-y-2 text-[13px]">
              <div><dt className="text-fg-muted">Category</dt><dd>{d!.category}</dd></div>
              <div><dt className="text-fg-muted">Default severity</dt><dd><SeverityBadge severity={d!.severity_default} /></dd></div>
              <div><dt className="text-fg-muted">OWASP Top 10 2021</dt><dd>{d!.owasp_top10.join(", ") || "-"}</dd></div>
              <div><dt className="text-fg-muted">OWASP API Security 2023</dt><dd>{d!.owasp_api.join(", ") || "-"}</dd></div>
              <div><dt className="text-fg-muted">Languages</dt><dd>{d!.languages.join(", ")}</dd></div>
            </dl>
          </Panel>
          {d!.cve_examples.length > 0 && (
            <Panel title="Known CVE examples">
              <ul className="space-y-2 text-[13px]">
                {d!.cve_examples.map((c) => (
                  <li key={c.id}><a href={`https://nvd.nist.gov/vuln/detail/${c.id}`} target="_blank" rel="noreferrer" className="font-mono text-xs">{c.id}</a>
                    <div className="text-fg-muted">{c.summary}</div></li>
                ))}
              </ul>
            </Panel>
          )}
          <Panel title="References">
            <ul className="space-y-1.5 text-[13px]">
              {d!.references.map((r) => <li key={r.url}><a href={r.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1">{r.title}<ExternalLink className="h-3 w-3" /></a></li>)}
            </ul>
          </Panel>
          <Panel title="Index">
            <dl className="space-y-1.5 text-[13px]">
              <div className="flex justify-between"><dt className="text-fg-muted">Status</dt><dd>{d!.index_status}</dd></div>
              <div className="flex justify-between"><dt className="text-fg-muted">Chunks</dt><dd>{d!.chunk_count}</dd></div>
              <div className="flex justify-between gap-2"><dt className="text-fg-muted">Model</dt><dd className="truncate font-mono text-xs">{d!.embedding_model ?? "-"}</dd></div>
              <div className="flex justify-between"><dt className="text-fg-muted">Indexed</dt><dd>{dateTime(d!.indexed_at)}</dd></div>
              <div className="flex justify-between"><dt className="text-fg-muted">Version</dt><dd>{d!.version} ({d!.source})</dd></div>
            </dl>
            {d!.index_error && <p className="mt-2 text-xs text-[#FF8A8E]">{d!.index_error}</p>}
          </Panel>
        </div>
      </div>
    </>
  );
}
