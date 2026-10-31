export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "-";
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  if (s < 86400 * 30) return `${Math.round(s / 86400)} d ago`;
  return new Date(iso).toLocaleDateString();
}

export function dateTime(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "-";
}

export function duration(from: string | null, to: string | null): string {
  if (!from) return "-";
  const ms = (to ? new Date(to).getTime() : Date.now()) - new Date(from).getTime();
  const s = Math.max(0, Math.round(ms / 1000));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}

export function bytes(n: number | null | undefined): string {
  if (n == null) return "-";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function findingRef(refNo: number): string {
  return `SM-${String(refNo).padStart(4, "0")}`;
}

export function cweUrl(cwe: string): string {
  return `https://cwe.mitre.org/data/definitions/${cwe.replace("CWE-", "")}.html`;
}

export function shortRule(ruleId: string): string {
  const parts = ruleId.split(".");
  return parts.length > 2 ? parts.slice(-2).join(".") : ruleId;
}
