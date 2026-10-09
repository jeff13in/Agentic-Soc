import { type ReactNode, useState } from "react";
import { SEVERITY_ORDER, VERDICT_TEXT } from "../lib/format";
import type { Severity, VerdictLabel } from "../types";

export function Card({ title, actions, children, className = "" }: {
  title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={`rounded-lg border border-line bg-surface ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          <h2 className="text-sm font-semibold">{title}</h2>
          {actions}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

// Status colors never carry meaning alone: every badge has an icon and a text label.
const VERDICT_STYLE: Record<VerdictLabel, { icon: string; cls: string }> = {
  true_positive: { icon: "▲", cls: "text-critical-ink border-critical/40 bg-critical/10" },
  false_positive: { icon: "✓", cls: "text-good-ink border-good/40 bg-good/10" },
  needs_escalation: { icon: "?", cls: "text-warning-ink border-warning/50 bg-warning/10" },
};

export function VerdictBadge({ verdict, prefix }: { verdict: VerdictLabel; prefix?: string }) {
  const s = VERDICT_STYLE[verdict];
  return (
    <span className={`inline-flex items-center gap-1 whitespace-nowrap rounded border px-1.5 py-0.5 text-xs font-medium ${s.cls}`}>
      <span aria-hidden>{s.icon}</span>
      {prefix && <span className="font-normal opacity-80">{prefix}</span>}
      {VERDICT_TEXT[verdict]}
    </span>
  );
}

const SEVERITY_CLS: Record<Severity, string> = {
  low: "text-ink-2 border-line",
  medium: "text-warning-ink border-warning/50",
  high: "text-serious-ink border-serious/50",
  critical: "text-critical-ink border-critical/50",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const level = SEVERITY_ORDER.indexOf(severity) + 1;
  return (
    <span className={`inline-flex items-center gap-1 whitespace-nowrap rounded border px-1.5 py-0.5 text-xs ${SEVERITY_CLS[severity]}`}
      title={`severity ${level} of 4`}>
      <span aria-hidden className="tracking-tighter">{"▮".repeat(level)}<span className="opacity-25">{"▮".repeat(4 - level)}</span></span>
      {severity}
    </span>
  );
}

export function Tag({ children }: { children: ReactNode }) {
  return <span className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-xs text-ink-2">{children}</span>;
}

export function StatTile({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="rounded-lg border border-line bg-surface px-4 py-3">
      <div className="text-xs text-muted">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
      {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
    </div>
  );
}

export function JsonView({ value, collapsed = true, label = "JSON", bare = false }: {
  value: unknown; collapsed?: boolean; label?: string; bare?: boolean;
}) {
  const [open, setOpen] = useState(!collapsed);
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return (
    <div>
      {!bare && <button type="button" onClick={() => setOpen(!open)} aria-expanded={open}
        className="text-xs text-accent-ink hover:underline">
        {open ? "▾" : "▸"} {label} <span className="text-muted">({text.length.toLocaleString()} chars)</span>
      </button>}
      {open && (
        <pre className="mt-1 max-h-96 overflow-auto rounded border border-line bg-surface-2 p-2 font-mono text-xs leading-relaxed whitespace-pre-wrap break-all">
          {text}
        </pre>
      )}
    </div>
  );
}

export function Loading({ what = "Loading" }: { what?: string }) {
  return <p className="py-6 text-sm text-muted" role="status">{what}…</p>;
}

export function ErrorBox({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div role="alert" className="rounded border border-critical/40 bg-critical/10 px-3 py-2 text-sm text-critical-ink">
      <span aria-hidden>⚠ </span>{msg}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded border border-dashed border-line px-4 py-6 text-sm text-ink-2">{children}</div>;
}

export const inputCls =
  "rounded border border-line bg-surface px-2 py-1 text-sm text-ink focus:outline-2 focus:outline-accent";
