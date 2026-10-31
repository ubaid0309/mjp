import { SEVERITIES, type Severity } from "@/lib/types";
import { SEV_DOT } from "./badges";
import { cx } from "./ui";

/** One stacked bar of open findings by severity, with a legend that doubles as the numbers. */
export function SeverityBar({ counts, onSelect }: { counts: Partial<Record<Severity, number>>; onSelect?: (s: Severity) => void }) {
  const total = SEVERITIES.reduce((n, s) => n + (counts[s] ?? 0), 0);
  return (
    <div>
      <div className="flex h-3 w-full overflow-hidden rounded-sm bg-panel-3" role="img"
        aria-label={SEVERITIES.map((s) => `${counts[s] ?? 0} ${s}`).join(", ")}>
        {total > 0 && SEVERITIES.map((s) => (counts[s] ?? 0) > 0 && (
          <div key={s} className={cx(SEV_DOT[s], "h-full border-r border-ink last:border-r-0")}
            style={{ width: `${((counts[s] ?? 0) / total) * 100}%` }} />
        ))}
      </div>
      <div className="mt-3 grid grid-cols-5 gap-2">
        {SEVERITIES.map((s) => (
          <button key={s} type="button" onClick={() => onSelect?.(s)} disabled={!onSelect}
            className="group text-left disabled:cursor-default">
            <div className="flex items-center gap-1.5 text-xs capitalize text-fg-muted group-enabled:group-hover:text-fg">
              <span className={cx("h-2 w-2 rounded-sm", SEV_DOT[s])} aria-hidden />{s}
            </div>
            <div className="text-lg font-semibold tabular-nums">{counts[s] ?? 0}</div>
          </button>
        ))}
      </div>
    </div>
  );
}
