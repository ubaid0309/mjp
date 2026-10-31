import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from "react";
import { AlertTriangle, Loader2 } from "lucide-react";

const cx = (...c: (string | false | null | undefined)[]) => c.filter(Boolean).join(" ");
export { cx };

type Variant = "primary" | "secondary" | "ghost" | "danger";
const variants: Record<Variant, string> = {
  primary: "bg-accent text-accent-ink hover:bg-accent-strong font-medium",
  secondary: "bg-panel-2 text-fg border border-line hover:border-line-strong hover:bg-panel-3",
  ghost: "text-fg-muted hover:text-fg hover:bg-panel-2",
  danger: "bg-sev-critical/15 text-[#FF8A8E] border border-sev-critical/40 hover:bg-sev-critical/25",
};

export function Button({ variant = "secondary", loading, className, children, disabled, ...rest }:
  ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; loading?: boolean }) {
  return (
    <button
      className={cx("inline-flex items-center justify-center gap-1.5 rounded-md px-3 h-8 text-[13px] transition-colors",
        "disabled:opacity-50 disabled:cursor-not-allowed", variants[variant], className)}
      disabled={disabled || loading}
      {...rest}
    >
      {loading && <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />}
      {children}
    </button>
  );
}

const fieldBase = "w-full rounded-md bg-ink-2 border border-line px-3 text-[13px] text-fg placeholder:text-fg-faint focus:border-accent focus:outline-none";

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cx(fieldBase, "h-9", className)} {...rest} />;
}
export function Textarea({ className, ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cx(fieldBase, "py-2 min-h-[80px]", className)} {...rest} />;
}
export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select className={cx(fieldBase, "h-9 pr-8", className)} {...rest}>{children}</select>;
}

export function Field({ label, hint, children, htmlFor }: { label: string; hint?: ReactNode; children: ReactNode; htmlFor?: string }) {
  return (
    <div className="space-y-1.5">
      <label htmlFor={htmlFor} className="block text-[13px] font-medium text-fg">{label}</label>
      {children}
      {hint && <p className="text-xs text-fg-muted">{hint}</p>}
    </div>
  );
}

export function Panel({ title, actions, children, className, bodyClass }:
  { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClass?: string }) {
  return (
    <section className={cx("rounded-lg border border-line bg-panel", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          <h2 className="text-[13px] font-semibold">{title}</h2>
          {actions}
        </header>
      )}
      <div className={bodyClass ?? "p-4"}>{children}</div>
    </section>
  );
}

export function PageHeader({ title, description, actions }: { title: ReactNode; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-fg-muted">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-start gap-2 px-4 py-10 sm:items-center sm:text-center">
      <p className="font-medium">{title}</p>
      {children && <div className="max-w-md text-fg-muted">{children}</div>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function ErrorNote({ error, title = "Something went wrong" }: { error: unknown; title?: string }) {
  if (!error) return null;
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div role="alert" className="flex gap-2 rounded-md border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-[13px]">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-sev-critical" aria-hidden />
      <div><span className="font-medium">{title}.</span> <span className="text-fg-muted">{msg}</span></div>
    </div>
  );
}

export function Notice({ tone = "info", children }: { tone?: "info" | "warning"; children: ReactNode }) {
  return (
    <div className={cx("rounded-md border px-3 py-2 text-[13px]",
      tone === "warning" ? "border-sev-medium/40 bg-sev-medium/10" : "border-accent/30 bg-accent/5")}>
      {children}
    </div>
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 px-4 py-8 text-fg-muted" role="status">
      <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> {label}
    </div>
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: string }) {
  return (
    <div className="min-w-0">
      <div className="text-[13px] text-fg-muted">{label}</div>
      <div className={cx("mt-0.5 text-2xl font-semibold tabular-nums", tone)}>{value}</div>
      {hint && <div className="text-xs text-fg-faint">{hint}</div>}
    </div>
  );
}

export function Pagination({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="flex items-center justify-between gap-3 px-3 py-2 text-[13px] text-fg-muted">
      <span>{total === 0 ? "No results" : `${page * pageSize + 1}–${Math.min(total, (page + 1) * pageSize)} of ${total}`}</span>
      <div className="flex gap-1">
        <Button variant="ghost" disabled={page === 0} onClick={() => onPage(page - 1)}>Previous</Button>
        <Button variant="ghost" disabled={page + 1 >= pages} onClick={() => onPage(page + 1)}>Next</Button>
      </div>
    </div>
  );
}
