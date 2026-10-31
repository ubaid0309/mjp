import { cx } from "./ui";

/**
 * Renders code text only (never HTML). Snippets from scans arrive as "  12 | code" lines; when
 * `highlight` is given, those line numbers are emphasised.
 */
export function CodeBlock({ code, highlight, className, label }:
  { code: string; highlight?: [number, number]; className?: string; label?: string }) {
  const lines = code.split("\n");
  return (
    <div className={cx("overflow-hidden rounded-md border border-line bg-ink-2", className)}>
      {label && <div className="border-b border-line px-3 py-1.5 text-xs text-fg-muted">{label}</div>}
      <pre className="overflow-x-auto py-2 text-[12.5px] leading-[1.6]">
        {lines.map((line, i) => {
          const m = /^\s*(\d+) \| /.exec(line);
          const num = m ? Number(m[1]) : null;
          const hot = highlight && num !== null && num >= highlight[0] && num <= highlight[1];
          return (
            <div key={i} className={cx("px-3", hot && "bg-sev-high/10 shadow-[inset_2px_0_0_#F08A4B]")}>
              {m ? (<><span className="select-none text-fg-faint">{line.slice(0, m[0].length)}</span>{line.slice(m[0].length)}</>) : line || " "}
            </div>
          );
        })}
      </pre>
    </div>
  );
}
