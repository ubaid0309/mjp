import { useQuery } from "@tanstack/react-query";
import { supabase, unwrap, workerApiUrl } from "@/lib/supabase";
import { useAuth } from "@/lib/auth";
import type { WorkerStatus } from "@/lib/types";
import { timeAgo } from "@/lib/format";
import { workerApi } from "@/lib/worker";
import { ErrorNote, Loading, PageHeader, Panel, cx } from "@/components/ui";

function Check({ ok, label, detail }: { ok: boolean | null; label: string; detail: string }) {
  return (
    <div className="flex gap-3 py-2.5">
      <span className={cx("mt-1.5 h-2 w-2 shrink-0 rounded-full", ok === null ? "bg-fg-faint" : ok ? "bg-ok" : "bg-sev-critical")} aria-hidden />
      <div>
        <div className="text-[13px]">{label}</div>
        <div className="text-xs text-fg-muted">{detail}</div>
      </div>
    </div>
  );
}

export default function SettingsPage() {
  const { profile, session } = useAuth();
  const workers = useQuery({
    queryKey: ["workers"],
    queryFn: async () => unwrap(await supabase.from("worker_status").select("*").order("last_heartbeat_at", { ascending: false })) as WorkerStatus[],
    refetchInterval: 15000,
  });
  const health = useQuery({ queryKey: ["worker-health"], queryFn: workerApi.health, retry: false });

  const w = workers.data?.[0];
  const alive = w ? Date.now() - new Date(w.last_heartbeat_at).getTime() < 2 * 60 * 1000 : false;

  return (
    <>
      <PageHeader title="Settings" description="What is configured right now. Secrets live only in the worker's environment and are never shown here." />
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="System status" bodyClass="divide-y divide-line px-4 py-1">
          {workers.isLoading ? <Loading /> : (
            <>
              <Check ok={alive} label="Scan worker" detail={w ? `${w.hostname ?? w.worker_id}, version ${w.version}, last heartbeat ${timeAgo(w.last_heartbeat_at)}` : "No worker has ever connected. Start it with docker compose up worker."} />
              <Check ok={w ? Boolean(w.semgrep_version) : null} label="Static analysis engine" detail={w?.semgrep_version ? `Semgrep ${w.semgrep_version}` : "Semgrep not found on the worker"} />
              <Check ok={w ? Boolean(w.embedding_model) : null} label="Embedding provider (RAG retrieval)"
                detail={w?.embedding_model ? `${w.embedding_provider}: ${w.embedding_model}` : "Not configured. Set OPENAI_API_KEY (or EMBEDDING_PROVIDER=local) on the worker. Findings still get exact CWE references."} />
              <Check ok={w ? Boolean(w.llm_model) : null} label="Language model (grounded explanations)"
                detail={w?.llm_model ? `${w.llm_provider}: ${w.llm_model}` : "Not configured. Explanations are disabled; retrieved knowledge is still shown."} />
              <Check ok={health.isSuccess} label="Worker API reachable from this browser"
                detail={health.isSuccess ? `${workerApiUrl} responded` : `${workerApiUrl || "VITE_WORKER_API_URL not set"}: ${health.error instanceof Error ? health.error.message : "checking"}`} />
            </>
          )}
          <ErrorNote error={workers.error} />
        </Panel>

        <Panel title="Your account">
          <dl className="space-y-2 text-[13px]">
            <div className="flex justify-between"><dt className="text-fg-muted">Name</dt><dd>{profile?.full_name || "-"}</dd></div>
            <div className="flex justify-between"><dt className="text-fg-muted">Email</dt><dd>{session?.user.email}</dd></div>
            <div className="flex justify-between"><dt className="text-fg-muted">Role</dt><dd className="capitalize">{profile?.role}</dd></div>
          </dl>
          <p className="mt-3 text-xs text-fg-muted">Administrators can edit the knowledge base and trigger re-indexing. Project access is controlled per project membership.</p>
        </Panel>

        <Panel title="Configuring API keys" className="lg:col-span-2">
          <div className="space-y-2 text-[13px] text-fg-muted">
            <p>Keys are read by the worker from <code className="text-fg">worker/.env</code>; the browser never sees them.</p>
            <ul className="list-disc space-y-1 pl-5">
              <li><code className="text-fg">SUPABASE_URL</code> and <code className="text-fg">SUPABASE_SERVICE_ROLE_KEY</code>: required, from Supabase project settings, API.</li>
              <li><code className="text-fg">OPENAI_API_KEY</code>: enables embeddings (text-embedding-3-small at 384 dimensions) and grounded explanations.</li>
              <li><code className="text-fg">OPENAI_CHAT_MODEL</code>: optional, the model used for explanations.</li>
              <li><code className="text-fg">EMBEDDING_PROVIDER=local</code>: optional, runs bge-small-en-v1.5 on the worker's CPU instead of OpenAI.</li>
            </ul>
            <p>After changing keys, restart the worker. Switching embedding model re-indexes the knowledge base automatically.</p>
          </div>
        </Panel>
      </div>
    </>
  );
}
