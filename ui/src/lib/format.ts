import type { Severity, VerdictLabel } from "../types";

export function pct(v: number | null | undefined, digits = 1): string {
  return v === null || v === undefined || Number.isNaN(v) ? "–" : `${(v * 100).toFixed(digits)}%`;
}

export function num(v: number | null | undefined, digits = 2): string {
  if (v === null || v === undefined || Number.isNaN(v)) return "–";
  return Math.abs(v) >= 1000 ? Math.round(v).toLocaleString() : Number(v.toFixed(digits)).toString();
}

export function usd(v: number | null | undefined): string {
  if (v === null || v === undefined) return "–";
  if (v === 0) return "$0";
  return v < 0.01 ? `$${v.toFixed(4)}` : `$${v.toFixed(3)}`;
}

export function seconds(v: number | null | undefined): string {
  if (v === null || v === undefined) return "–";
  return v < 1 ? `${Math.round(v * 1000)} ms` : `${v.toFixed(1)} s`;
}

export function when(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().replace("T", " ").slice(0, 19) + "Z";
}

export const VERDICT_TEXT: Record<VerdictLabel, string> = {
  true_positive: "True positive",
  false_positive: "False positive",
  needs_escalation: "Escalate",
};

export const SEVERITY_ORDER: Severity[] = ["low", "medium", "high", "critical"];

/** Basename of a Windows or POSIX path. */
export function basename(path: string | null | undefined): string {
  if (!path) return "";
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}
