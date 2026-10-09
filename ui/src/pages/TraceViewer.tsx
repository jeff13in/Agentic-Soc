import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { Card, ErrorBox, JsonView, Loading, SeverityBadge, StatTile, Tag, VerdictBadge } from "../components/ui";
import { num, pct, seconds, usd, when } from "../lib/format";
import { useAsync } from "../lib/useAsync";
import type { ToolCallRecord, Trace } from "../types";

const STATUS_NOTE: Record<string, string> = {
  ok: "Verdict accepted on the first try.",
  repaired: "First verdict failed validation; the repair attempt was accepted.",
  invalid_verdict: "Two invalid verdicts; escalated to a human.",
  budget_exhausted: "Step or time budget ran out without a verdict; escalated.",
  verifier_escalated: "The verifier disagreed with the verdict; escalated instead of accepted.",
  refusal: "The model declined the request.",
  error: "The run failed with an error.",
};

export function TraceViewer() {
  const { id = "" } = useParams();
  const { data, error, loading } = useAsync(() => api.trace(id), [id]);
  if (loading) return <Loading />;
  if (error !== undefined) return <ErrorBox error={error} />;
  const t = data!;
  const v = t.verdict;
  const steps = t.tool_calls.filter((c) => c.name !== "submit_verdict").length;

  return (
    <div className="space-y-4">
      <div>
        <Link to={`/alerts/${encodeURIComponent(t.alert_id)}`} className="text-xs text-accent-ink hover:underline">
          ← Alert {t.alert_id}
        </Link>
        <h1 className="mt-1 text-lg font-semibold">Trace</h1>
        <p className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted">
          <Tag>{t.backend}</Tag><Tag>{t.model}</Tag><span>prompt {t.prompt_version} ({t.prompt_hash})</span>
          <span>defenses: {t.defenses.join(", ") || "none"}</span><span>{when(t.started_at)}</span>
          {t.run_id && <span>run {t.run_id}</span>}
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <StatTile label="Status" value={<span className="text-base">{t.status}</span>} hint={STATUS_NOTE[t.status]} />
        <StatTile label="Tool calls" value={steps} hint={`${t.turns.length} model turns`} />
        <StatTile label="Latency" value={seconds(t.latency_s)} />
        <StatTile label="Tokens" value={num(t.input_tokens + t.output_tokens, 0)} hint={`${num(t.input_tokens, 0)} in · ${num(t.output_tokens, 0)} out`} />
        <StatTile label="Cost" value={usd(t.cost_usd)} />
      </div>

      {t.error && <ErrorBox error={t.error} />}

      <div className="grid gap-4 lg:grid-cols-5">
        <div className="space-y-4 lg:col-span-2">
          <Card title="Verdict">
            {!v ? <p className="text-sm text-ink-2">No verdict: the alert goes to a human.</p> : (
              <div className="space-y-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <VerdictBadge verdict={v.verdict} />
                  <SeverityBadge severity={v.severity} />
                  <span className="text-xs text-muted">confidence {pct(v.confidence, 0)}</span>
                </div>
                <p className="leading-relaxed">{v.summary}</p>
                {v.attack_techniques.length > 0 && (
                  <div className="flex flex-wrap gap-1">{v.attack_techniques.map((x) => <Tag key={x}>{x}</Tag>)}</div>
                )}
                <div>
                  <h3 className="mb-1 text-xs font-medium text-muted">Evidence</h3>
                  <ul className="space-y-1.5">
                    {v.evidence.map((e, i) => (
                      <li key={i} className="rounded border border-line px-2 py-1.5">
                        <Tag>{e.tool}</Tag> <span>{e.finding}</span>
                        {e.event_ref && <span className="ml-1 font-mono text-xs text-muted">{e.event_ref}</span>}
                      </li>
                    ))}
                  </ul>
                </div>
                {v.recommended_actions.length > 0 && (
                  <div>
                    <h3 className="mb-1 text-xs font-medium text-muted">Recommended actions (for a human)</h3>
                    <ul className="list-disc space-y-0.5 pl-5">{v.recommended_actions.map((a, i) => <li key={i}>{a}</li>)}</ul>
                  </div>
                )}
              </div>
            )}
          </Card>
          {t.verifier && (
            <Card title="Verifier">
              <div className="space-y-1 text-sm">
                <p>{t.verifier.agree ? "✓ Agreed" : "✗ Disagreed"} <span className="text-xs text-muted">({t.verifier.model})</span></p>
                <p className="text-ink-2">{t.verifier.reason}</p>
                {!t.verifier.agree && <p className="text-xs"><VerdictBadge verdict={t.verifier.original_verdict} prefix="original:" /></p>}
              </div>
            </Card>
          )}
        </div>

        <Card title="Investigation" className="lg:col-span-3">
          <Timeline trace={t} />
        </Card>
      </div>
    </div>
  );
}

function Timeline({ trace }: { trace: Trace }) {
  const byStep = new Map<number, ToolCallRecord[]>();
  for (const c of trace.tool_calls) byStep.set(c.step, [...(byStep.get(c.step) ?? []), c]);
  return (
    <ol className="space-y-4">
      {trace.turns.map((turn) => (
        <li key={turn.step} className="relative border-l-2 border-line pl-4">
          <div className="mb-1 flex flex-wrap items-center gap-2 text-xs text-muted">
            <span className="font-medium text-ink">Step {turn.step + 1}</span>
            <span className="tabular">{seconds(turn.latency_ms / 1000)}</span>
            <span className="tabular">{num(turn.input_tokens, 0)} in / {num(turn.output_tokens, 0)} out</span>
            {turn.cache_read_tokens > 0 && <span className="tabular">{num(turn.cache_read_tokens, 0)} cached</span>}
          </div>
          {turn.text && <p className="mb-2 text-sm whitespace-pre-wrap text-ink-2">{turn.text}</p>}
          {turn.tool_calls.length === 0 && <p className="text-sm text-muted">Replied in plain text (nudged to submit a verdict).</p>}
          <div className="space-y-2">
            {(byStep.get(turn.step) ?? []).map((c) => (
              <div key={c.call_id} className={`rounded border px-3 py-2 ${c.is_error ? "border-critical/40 bg-critical/5" : "border-line"}`}>
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="font-mono font-medium">{c.name}</span>
                  <span className="font-mono text-xs text-muted break-all">{argsPreview(c.arguments)}</span>
                  <span className="ml-auto tabular text-xs text-muted">{seconds(c.latency_ms / 1000)}</span>
                </div>
                {c.is_error ? (
                  <p className="mt-1 text-xs text-critical-ink"><span aria-hidden>⚠ </span>{c.error}</p>
                ) : c.name === "submit_verdict" ? (
                  <p className="mt-1 text-xs text-good-ink">✓ verdict accepted</p>
                ) : (
                  <ToolIO args={c.arguments} result={c.result} />
                )}
              </div>
            ))}
          </div>
        </li>
      ))}
    </ol>
  );
}

/** Toggles side by side; the opened JSON spans the full width below them. */
function ToolIO({ args, result }: { args: unknown; result: unknown }) {
  const [open, setOpen] = useState<"args" | "result" | null>(null);
  const toggle = (k: "args" | "result") => setOpen(open === k ? null : k);
  const btn = (k: "args" | "result", label: string, v: unknown) => (
    <button type="button" onClick={() => toggle(k)} aria-expanded={open === k} className="text-xs text-accent-ink hover:underline">
      {open === k ? "▾" : "▸"} {label} <span className="text-muted">({JSON.stringify(v).length.toLocaleString()} chars)</span>
    </button>
  );
  return (
    <div className="mt-1">
      <div className="flex gap-4">{btn("args", "Arguments", args)}{btn("result", "Result", result)}</div>
      {open && <JsonView value={open === "args" ? args : result} collapsed={false} bare />}
    </div>
  );
}

function argsPreview(args: Record<string, unknown>): string {
  const s = Object.entries(args)
    .filter(([k]) => k !== "evidence" && k !== "summary" && k !== "recommended_actions")
    .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
    .join(" ");
  return s.length > 140 ? s.slice(0, 140) + "…" : s;
}
