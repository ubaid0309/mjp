import { createClient } from "@supabase/supabase-js";

const url = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const key = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;

export const supabaseConfigured = Boolean(url && key);

// The anon/publishable key is designed to be public; Row Level Security decides what each user can read.
export const supabase = createClient(url ?? "http://localhost:54321", key ?? "missing-key", {
  auth: { persistSession: true, autoRefreshToken: true },
});

export const workerApiUrl = (import.meta.env.VITE_WORKER_API_URL as string | undefined)?.replace(/\/$/, "") ?? "";

/** Throw a readable error from a Supabase response. Database internals are not shown to users. */
export function unwrap<T>(res: { data: T | null; error: { message: string; code?: string } | null }): T {
  if (res.error) {
    const msg = res.error.message || "Request failed";
    throw new Error(res.error.code === "42501" ? "You do not have permission to do that." : msg);
  }
  return res.data as T;
}
