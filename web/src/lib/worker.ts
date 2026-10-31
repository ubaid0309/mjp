import { supabase, workerApiUrl } from "./supabase";

export interface RagResult {
  chunk_id: string; document_id: string; slug: string; cwe_id: string | null; title: string; category: string;
  section: string; content: string; similarity: number; above_threshold: boolean;
}
export interface SearchResponse { mode: string; model: string; min_similarity: number; results: RagResult[]; evidence_sufficient: boolean }
export interface AskResponse {
  model: string; min_similarity: number; sources: RagResult[]; answer: string | null; grounded: boolean;
  llm_configured: boolean; llm_model?: string;
}
export interface WorkerHealth { status: string; version: string; semgrep_version: string | null; embedding_model: string | null; llm_configured: boolean; llm_model: string | null }

async function call<T>(path: string, body?: unknown): Promise<T> {
  if (!workerApiUrl) throw new Error("VITE_WORKER_API_URL is not set, so the worker API cannot be reached.");
  const { data } = await supabase.auth.getSession();
  let res: Response;
  try {
    res = await fetch(`${workerApiUrl}${path}`, {
      method: body ? "POST" : "GET",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${data.session?.access_token ?? ""}` },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new Error(`The SecureMatrix worker is not reachable at ${workerApiUrl}. Start it with docker compose up.`);
  }
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((json as { detail?: string }).detail ?? `Worker returned ${res.status}`);
  return json as T;
}

export const workerApi = {
  health: () => call<WorkerHealth>("/health"),
  search: (query: string, top_k = 6) => call<SearchResponse>("/api/rag/search", { query, top_k }),
  ask: (question: string) => call<AskResponse>("/api/rag/ask", { question }),
};
