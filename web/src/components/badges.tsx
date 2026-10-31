import { STATUS_LABEL, type FindingStatus, type ScanStatus, type Severity } from "@/lib/types";
import { cx } from "./ui";

const SEV: Record<Severity, string> = {
  critical: "bg-sev-critical/15 text-[#FF8A8E] ring-sev-critical/40",
  high: "bg-sev-high/15 text-[#FFB07F] ring-sev-high/40",
  medium: "bg-sev-medium/15 text-[#F0CD74] ring-sev-medium/40",
  low: "bg-sev-low/15 text-[#93C8F0] ring-sev-low/40",
  info: "bg-sev-info/15 text-[#AFB9CC] ring-sev-info/40",
};
export const SEV_DOT: Record<Severity, string> = {
  critical: "bg-sev-critical", high: "bg-sev-high", medium: "bg-sev-medium", low: "bg-sev-low", info: "bg-sev-info",
};
const SEV_LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={cx("inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset", SEV[severity])}>
      <span className={cx("h-1.5 w-1.5 rounded-full", SEV_DOT[severity])} aria-hidden />
      {SEV_LABEL[severity]}
    </span>
  );
}

const STATUS_TONE: Partial<Record<FindingStatus, string>> = {
  new: "text-fg", resolved: "text-ok", accepted_risk: "text-sev-medium", verification_pending: "text-accent",
};
export function StatusBadge({ status }: { status: FindingStatus }) {
  return <span className={cx("text-[13px]", STATUS_TONE[status] ?? "text-fg-muted")}>{STATUS_LABEL[status]}</span>;
}

const SCAN_TONE: Record<ScanStatus, string> = {
  queued: "text-fg-muted ring-line-strong", running: "text-accent ring-accent/40", completed: "text-ok ring-ok/40",
  failed: "text-[#FF8A8E] ring-sev-critical/40", cancelled: "text-fg-muted ring-line",
};
export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span className={cx("inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-xs font-medium capitalize ring-1 ring-inset", SCAN_TONE[status])}>
      {status === "running" && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" aria-hidden />}
      {status}
    </span>
  );
}

export function SourceTag({ source }: { source: "scanner_confirmed" | "ai_potential" }) {
  return source === "scanner_confirmed"
    ? <span className="rounded bg-panel-3 px-1.5 py-0.5 text-xs text-fg-muted" title="Reported by a static analysis rule">Scanner-confirmed</span>
    : <span className="rounded bg-sev-medium/15 px-1.5 py-0.5 text-xs text-sev-medium" title="Suggested by AI, not confirmed by a scanner">AI-suggested</span>;
}

export function PriorityTag({ priority }: { priority: string | null }) {
  if (!priority) return <span className="text-fg-faint">-</span>;
  const tone = priority === "P1" ? "text-[#FF8A8E]" : priority === "P2" ? "text-[#FFB07F]" : "text-fg-muted";
  return <span className={cx("font-mono text-xs font-medium", tone)}>{priority}</span>;
}
