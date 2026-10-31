import { useMemo, useRef, useState, type DragEvent, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { FileArchive, UploadCloud } from "lucide-react";
import { supabase, unwrap } from "@/lib/supabase";
import { useAuth } from "@/lib/auth";
import type { Project, ScanJob } from "@/lib/types";
import { bytes } from "@/lib/format";
import { Button, ErrorNote, Field, Input, Notice, PageHeader, Panel, Select, Textarea, cx } from "@/components/ui";

const MAX_UPLOAD = 50 * 1024 * 1024;
const RULESETS = [
  { id: "securematrix", label: "SecureMatrix bundled rules", hint: "53 rules for Python, JS/TS, PHP, Java, secrets and config. Works offline." },
  { id: "p/security-audit", label: "Semgrep security-audit", hint: "Broad community security pack (downloaded from the Semgrep registry)." },
  { id: "p/secrets", label: "Semgrep secrets", hint: "Hard-coded credentials and tokens." },
  { id: "p/owasp-top-ten", label: "Semgrep OWASP Top 10", hint: "Rules tagged with OWASP Top 10 categories." },
];
const LANGUAGES = ["Python", "JavaScript", "TypeScript", "Java", "PHP", "Go", "C/C++", "C#", "Mixed"];

export default function NewScanPage() {
  const { session } = useAuth();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [params] = useSearchParams();
  const projects = useQuery({
    queryKey: ["projects", "names"],
    queryFn: async () => unwrap(await supabase.from("projects").select("id, name, primary_language").order("name")) as Pick<Project, "id" | "name" | "primary_language">[],
  });

  const [projectId, setProjectId] = useState(params.get("project") ?? "new");
  const [name, setName] = useState("");
  const [language, setLanguage] = useState("Mixed");
  const [description, setDescription] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [rulesets, setRulesets] = useState<string[]>(["securematrix", "p/security-audit", "p/secrets"]);
  const [maxFileKb, setMaxFileKb] = useState(512);
  const [maxFiles, setMaxFiles] = useState(5000);
  const [batchSize, setBatchSize] = useState(200);
  const [timeout, setTimeoutMin] = useState(30);
  const [excludes, setExcludes] = useState("");
  const [stage, setStage] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const fileProblem = useMemo(() => {
    if (!file) return null;
    if (!/\.zip$/i.test(file.name)) return "Only .zip archives are accepted.";
    if (file.size > MAX_UPLOAD) return `The archive is ${bytes(file.size)}; the upload limit is 50 MB.`;
    return null;
  }, [file]);

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDragging(false);
    if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (!file || fileProblem) return setError(new Error(fileProblem ?? "Choose a ZIP archive to upload."));
    if (rulesets.length === 0) return setError(new Error("Select at least one rule set."));
    try {
      let pid = projectId;
      if (pid === "new") {
        if (name.trim().length < 2) throw new Error("Give the project a name of at least 2 characters.");
        setStage("Creating project");
        const created = unwrap(await supabase.from("projects").insert({
          owner_id: session!.user.id, name: name.trim(), primary_language: language, description: description.trim() || null,
        }).select("id").single()) as { id: string };
        pid = created.id;
      }
      setStage(`Uploading ${bytes(file.size)} to private storage`);
      const path = `${session!.user.id}/${pid}/${crypto.randomUUID()}.zip`;
      const up = await supabase.storage.from("project-uploads").upload(path, file, { contentType: "application/zip", upsert: false });
      if (up.error) throw new Error(`Upload failed: ${up.error.message}`);
      setStage("Queueing scan");
      const job = unwrap(await supabase.rpc("create_scan_job", {
        p_project_id: pid, p_archive_path: path, p_archive_size_bytes: file.size,
        p_config: {
          rulesets, max_file_size_kb: maxFileKb, max_files: maxFiles, batch_size: batchSize, timeout_minutes: timeout,
          exclude_globs: excludes.split("\n").map((s) => s.trim()).filter(Boolean),
        },
      })) as ScanJob;
      qc.invalidateQueries();
      navigate(`/scans/${job.id}`);
    } catch (err) {
      setError(err);
      setStage(null);
    }
  }

  return (
    <>
      <PageHeader title="Upload and scan" description="Upload a ZIP of your source code. It is stored in a private bucket, extracted safely by the worker, and analysed in batches." />
      <form onSubmit={submit} className="grid gap-4 lg:grid-cols-[1fr_360px]">
        <div className="space-y-4">
          <Panel title="Project">
            <div className="space-y-4">
              <Field label="Project" htmlFor="project">
                <Select id="project" value={projectId} onChange={(e) => setProjectId(e.target.value)}>
                  <option value="new">Create a new project</option>
                  {(projects.data ?? []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                </Select>
              </Field>
              {projectId === "new" && (
                <>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <Field label="Name" htmlFor="name"><Input id="name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} required /></Field>
                    <Field label="Main language" htmlFor="lang">
                      <Select id="lang" value={language} onChange={(e) => setLanguage(e.target.value)}>
                        {LANGUAGES.map((l) => <option key={l}>{l}</option>)}
                      </Select>
                    </Field>
                  </div>
                  <Field label="Description" htmlFor="desc"><Textarea id="desc" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={2000} /></Field>
                </>
              )}
            </div>
          </Panel>

          <Panel title="Source archive">
            <div
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
              className={cx("flex flex-col items-center justify-center gap-2 rounded-md border border-dashed px-4 py-10 text-center",
                dragging ? "border-accent bg-accent/5" : "border-line-strong")}
            >
              {file ? (
                <>
                  <FileArchive className="h-6 w-6 text-accent" aria-hidden />
                  <div className="font-medium">{file.name}</div>
                  <div className="text-fg-muted">{bytes(file.size)}</div>
                  <Button type="button" variant="ghost" onClick={() => setFile(null)}>Choose a different file</Button>
                </>
              ) : (
                <>
                  <UploadCloud className="h-6 w-6 text-fg-muted" aria-hidden />
                  <div>Drop a .zip here or <button type="button" className="text-link underline-offset-2 hover:underline" onClick={() => inputRef.current?.click()}>browse</button></div>
                  <div className="text-xs text-fg-muted">Up to 50 MB. Dependency folders, build output and binaries are skipped automatically.</div>
                </>
              )}
              <input ref={inputRef} type="file" accept=".zip,application/zip" className="sr-only"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)} aria-label="Choose ZIP archive" />
            </div>
            {fileProblem && <p className="mt-2 text-[13px] text-[#FF8A8E]">{fileProblem}</p>}
            <p className="mt-3 text-xs text-fg-muted">
              Importing from a repository URL is planned for a later phase; for now, download the repository as a ZIP.
            </p>
          </Panel>
        </div>

        <div className="space-y-4">
          <Panel title="Rule sets">
            <div className="space-y-3">
              {RULESETS.map((r) => (
                <label key={r.id} className="flex gap-2.5">
                  <input type="checkbox" className="mt-1 accent-[#3FB8D8]" checked={rulesets.includes(r.id)}
                    onChange={(e) => setRulesets(e.target.checked ? [...rulesets, r.id] : rulesets.filter((x) => x !== r.id))} />
                  <span><span className="block text-[13px]">{r.label}</span><span className="block text-xs text-fg-muted">{r.hint}</span></span>
                </label>
              ))}
            </div>
          </Panel>
          <Panel title="Limits">
            <div className="grid grid-cols-2 gap-3">
              <Field label="Max file size (KB)" htmlFor="mfs"><Input id="mfs" type="number" min={16} max={4096} value={maxFileKb} onChange={(e) => setMaxFileKb(+e.target.value)} /></Field>
              <Field label="Max files" htmlFor="mf"><Input id="mf" type="number" min={1} max={20000} value={maxFiles} onChange={(e) => setMaxFiles(+e.target.value)} /></Field>
              <Field label="Files per batch" htmlFor="bs"><Input id="bs" type="number" min={10} max={1000} value={batchSize} onChange={(e) => setBatchSize(+e.target.value)} /></Field>
              <Field label="Time limit (min)" htmlFor="to"><Input id="to" type="number" min={1} max={120} value={timeout} onChange={(e) => setTimeoutMin(+e.target.value)} /></Field>
            </div>
            <div className="mt-3">
              <Field label="Exclude patterns" htmlFor="ex" hint="One glob per line, e.g. docs/** or *.generated.ts">
                <Textarea id="ex" value={excludes} onChange={(e) => setExcludes(e.target.value)} className="font-mono" />
              </Field>
            </div>
          </Panel>
          <ErrorNote error={error} title="Scan not started" />
          {stage && <Notice>{stage}</Notice>}
          <Button type="submit" variant="primary" className="h-9 w-full" loading={Boolean(stage)} disabled={!file || Boolean(fileProblem)}>
            Upload and start scan
          </Button>
        </div>
      </form>
    </>
  );
}
