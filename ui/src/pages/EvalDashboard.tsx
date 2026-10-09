import { useState } from "react";
import { ApiError, api } from "../api";
import { RateBarChart } from "../components/BarChart";
import { Card, Empty, ErrorBox, inputCls, Loading, StatTile, Tag } from "../components/ui";
import { num, pct, seconds, usd, when } from "../lib/format";
import { useAsync } from "../lib/useAsync";
import type { EvalRun, RobustnessReport } from "../types";

const LABELS = ["true_positive", "false_positive", "needs_escalation"] as const;
const SHORT: Record<string, string> = { true_positive: "TP", false_positive: "FP", needs_escalation: "Escalate" };

export function EvalDashboard() {
  const runs = useAsync(() => api.evals(), []);
  const robustness = useAsync(() => api.robustness(), []);
  const [selected, setSelected] = useState<string>("");

  // Robustness/benchmark runs are bookkeeping rows; the headline is a plain eval run.
  const evalRuns = (runs.data ?? []).filter((r) => !r.split.includes(":"));
  const run = evalRuns.find((r) => r.run_id === selected) ?? evalRuns[0];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end gap-3">
        <h1 className="mr-auto text-lg font-semibold">Evaluation</h1>
        {evalRuns.length > 0 && (
          <label className="flex w-full min-w-0 flex-col text-xs text-muted sm:w-auto">Run
            <select className={`${inputCls} max-w-full`} value={run?.run_id} onChange={(e) => setSelected(e.target.value)}>
              {evalRuns.map((r) => <option key={r.run_id} value={r.run_id}>{r.run_id} ({r.split}, n={r.n_alerts})</option>)}
            </select>
          </label>
        )}
      </div>

      {runs.loading && <Loading />}
      {runs.error !== undefined && <ErrorBox error={runs.error} />}
      {runs.data && evalRuns.length === 0 && (
        <Empty>No eval runs yet. Run <code className="font-mono">python -m evals.run_eval --backend heuristic</code> on the API server.</Empty>
      )}
      {run && <RunDetail run={run} />}
      {evalRuns.length > 0 && <RunHistory runs={evalRuns} />}

      <section className="space-y-3">
        <h2 className="text-base font-semibold">Prompt-injection robustness</h2>
        {robustness.loading && <Loading />}
        {robustness.error instanceof ApiError && robustness.error.status === 404 && (
          <Empty>No robustness sweep yet. Run <code className="font-mono">python -m evals.adversarial.run_robustness --backend claude</code>.</Empty>
        )}
        {robustness.error !== undefined && !(robustness.error instanceof ApiError && robustness.error.status === 404) && (
          <ErrorBox error={robustness.error} />
        )}
        {robustness.data && <Robustness report={robustness.data} />}
      </section>
    </div>
  );
}

function RunDetail({ run }: { run: EvalRun }) {
  const m = run.metrics;
  const spread = (k: string) => (run.repeats > 1 && m[`${k}_std`] ? `± ${pct(m[`${k}_std`])} over ${run.repeats} runs` : undefined);
  const confusion = m.confusion ?? {};
  return (
    <div className="space-y-4">
      <p className="flex flex-wrap items-center gap-2 text-xs text-muted">
        <Tag>{run.backend}</Tag><Tag>{run.model}</Tag><span>prompt {run.prompt_version} ({run.prompt_hash})</span>
        <span>defenses: {run.defenses.join(", ") || "none"}</span><span>split {run.split}</span>
        <span>dataset {run.dataset_version}</span><span>commit {run.git_commit}</span><span>{when(run.created_at)}</span>
      </p>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-8">
        <StatTile label="Accuracy" value={pct(m.accuracy)} hint={spread("accuracy") ?? "target > 85%"} />
        <StatTile label="False-negative rate" value={pct(m.fn_rate)} hint={spread("fn_rate") ?? "target < 5%"} />
        <StatTile label="False-positive rate" value={pct(m.fp_rate)} hint={spread("fp_rate")} />
        <StatTile label="Escalated" value={pct(m.escalation_rate)} hint={spread("escalation_rate")} />
        <StatTile label="Faithfulness" value={pct(m.faithfulness)} />
        <StatTile label="Tool-call validity" value={pct(m.tool_call_validity)} hint="target > 95%" />
        <StatTile label="Latency p50 / p95" value={<span className="text-xl">{seconds(m.latency_p50_s)}</span>} hint={`p95 ${seconds(m.latency_p95_s)}`} />
        <StatTile label="Cost per alert" value={usd(m.cost_per_alert_usd)} hint={`${num(m.steps_mean, 1)} tool calls, ${num(m.tokens_mean, 0)} tokens`} />
      </div>
      <Card title={`Confusion matrix (first run, n=${run.n_alerts})`}>
        <table className="text-sm tabular">
          <thead>
            <tr className="text-xs text-muted">
              <th className="pr-4 text-left font-medium">Label ↓ / Verdict →</th>
              {LABELS.map((p) => <th key={p} className="px-3 text-right font-medium">{SHORT[p]}</th>)}
            </tr>
          </thead>
          <tbody>
            {LABELS.slice(0, 2).map((l) => (
              <tr key={l}>
                <th className="pr-4 text-left font-medium text-ink-2">{SHORT[l]}</th>
                {LABELS.map((p) => {
                  const n = confusion[`${l}->${p}`] ?? 0;
                  const bad = (l === "true_positive" && p === "false_positive") || (l === "false_positive" && p === "true_positive");
                  return <td key={p} className={`px-3 py-1 text-right ${l === p ? "font-semibold" : bad && n ? "text-critical-ink" : "text-ink-2"}`}>{n}</td>;
                })}
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-2 text-xs text-muted">A true positive called false positive is a missed attack, the costliest error.</p>
      </Card>
    </div>
  );
}

function RunHistory({ runs }: { runs: EvalRun[] }) {
  const cols: [string, string, (v: number | null | undefined) => string][] = [
    ["accuracy", "Accuracy", pct], ["fn_rate", "FN rate", pct], ["escalation_rate", "Escalated", pct],
    ["faithfulness", "Faithful", pct], ["tool_call_validity", "Tool valid", pct],
    ["latency_p50_s", "p50", seconds], ["cost_per_alert_usd", "$/alert", usd],
  ];
  return (
    <Card title="Run history">
      <div className="-mx-4 -my-4 overflow-x-auto">
        <table className="w-full text-sm tabular">
          <thead className="border-b border-line text-left text-xs text-muted">
            <tr>
              <th className="px-4 py-2 font-medium">Run</th><th className="px-2 py-2 font-medium">Backend</th>
              <th className="px-2 py-2 font-medium">Prompt</th><th className="px-2 py-2 font-medium">Defenses</th>
              <th className="px-2 py-2 text-right font-medium">n</th>
              {cols.map(([, label]) => <th key={label} className="px-2 py-2 text-right font-medium">{label}</th>)}
            </tr>
          </thead>
          <tbody>
            {runs.map((r) => (
              <tr key={r.run_id} className="border-b border-line last:border-0">
                <td className="px-4 py-1.5 whitespace-nowrap text-ink-2">{when(r.created_at)}</td>
                <td className="px-2 py-1.5">{r.backend}</td>
                <td className="px-2 py-1.5">{r.prompt_version}</td>
                <td className="px-2 py-1.5 text-ink-2">{r.defenses.join(", ") || "none"}</td>
                <td className="px-2 py-1.5 text-right">{r.n_alerts}</td>
                {cols.map(([k, label, f]) => <td key={label} className="px-2 py-1.5 text-right">{f(r.metrics[k])}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function Robustness({ report }: { report: RobustnessReport }) {
  const entries = Object.entries(report.configs);
  const categories = entries.length ? Object.keys(entries[0][1].summary.by_category) : [];
  return (
    <div className="space-y-4">
      <p className="text-xs text-muted">
        {report.backend} · {report.true_positives} true-positive alerts × {report.payloads.length} payloads · split {report.split} · {when(report.created_at)}
      </p>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <RateBarChart
            title="Attack success rate by defense profile (lower is better)"
            bars={entries.map(([name, c]) => ({
              label: name,
              value: c.summary.asr,
              detail: `${c.summary.eligible} cases · prompt ${c.prompt_version} · ${c.defenses.join(" + ") || "no defenses"}`,
            }))}
          />
        </Card>
        <Card title="Outcomes per profile">
          <table className="w-full text-sm tabular">
            <thead className="text-left text-xs text-muted">
              <tr><th className="pb-1 font-medium">Profile</th><th className="pb-1 text-right font-medium">Flipped</th>
                <th className="pb-1 text-right font-medium">Sev. drop</th><th className="pb-1 text-right font-medium">Escalated</th>
                <th className="pb-1 text-right font-medium">Still TP</th></tr>
            </thead>
            <tbody>
              {entries.map(([name, c]) => (
                <tr key={name}><td className="py-0.5">{name}</td><td className="text-right">{pct(c.summary.flip_rate)}</td>
                  <td className="text-right">{pct(c.summary.severity_drop_rate)}</td><td className="text-right">{pct(c.summary.escalated_rate)}</td>
                  <td className="text-right">{pct(c.summary.detected_tp_rate)}</td></tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
      <Card title="Attack success by payload category">
        <div className="-mx-4 -my-4 overflow-x-auto">
          <table className="w-full text-sm tabular">
            <thead className="border-b border-line text-left text-xs text-muted">
              <tr><th className="px-4 py-2 font-medium">Profile</th>
                {categories.map((c) => <th key={c} className="px-2 py-2 text-right font-medium">{c.replace("_", " ")}</th>)}</tr>
            </thead>
            <tbody>
              {entries.map(([name, c]) => (
                <tr key={name} className="border-b border-line last:border-0">
                  <td className="px-4 py-1.5">{name}</td>
                  {categories.map((k) => <td key={k} className="px-2 py-1.5 text-right">{pct(c.summary.by_category[k]?.asr)}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
