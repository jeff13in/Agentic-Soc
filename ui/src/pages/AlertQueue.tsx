import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { Card, Empty, ErrorBox, inputCls, Loading, SeverityBadge, Tag, VerdictBadge } from "../components/ui";
import { when } from "../lib/format";
import { useAsync } from "../lib/useAsync";

const PAGE = 50;

export function AlertQueue() {
  const [params, setParams] = useSearchParams();
  const split = params.get("split") ?? "test";
  const rule = params.get("rule") ?? "";
  const host = params.get("host") ?? "";
  const page = Number(params.get("page") ?? "0");
  const [hostDraft, setHostDraft] = useState(host);
  const navigate = useNavigate();

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k !== "page") next.delete("page");
    setParams(next);
  };

  const { data, error, loading } = useAsync(
    () => api.alerts({ split: split === "all" ? undefined : split, rule_id: rule, host, limit: PAGE, offset: page * PAGE }),
    [split, rule, host, page],
  );
  const config = useAsync(() => api.config(), []);
  const rules = useMemo(() => Array.from({ length: 12 }, (_, i) => `R${String(i + 1).padStart(3, "0")}`), []);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-3">
        <h1 className="mr-auto text-lg font-semibold">Alert queue</h1>
        <label className="flex flex-col text-xs text-muted">Split
          <select className={inputCls} value={split} onChange={(e) => set("split", e.target.value)}>
            <option value="test">test (held out)</option>
            <option value="dev">dev</option>
            <option value="review">review (unlabelled)</option>
            <option value="all">all</option>
          </select>
        </label>
        <label className="flex flex-col text-xs text-muted">Rule
          <select className={inputCls} value={rule} onChange={(e) => set("rule", e.target.value)}>
            <option value="">all rules</option>
            {rules.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </label>
        <form className="flex flex-col text-xs text-muted" onSubmit={(e) => { e.preventDefault(); set("host", hostDraft.trim()); }}>
          Host
          <input className={inputCls} placeholder="e.g. WS-003" value={hostDraft} onChange={(e) => setHostDraft(e.target.value)} />
        </form>
      </div>

      {config.data && !config.data.data_ready && (
        <ErrorBox error="No dataset built yet. Run `python -m data.build` on the API server." />
      )}

      <Card title={data ? `${data.total.toLocaleString()} alerts` : "Alerts"}>
        {loading && <Loading />}
        {error !== undefined && <ErrorBox error={error} />}
        {data && data.items.length === 0 && <Empty>No alerts match these filters.</Empty>}
        {data && data.items.length > 0 && (
          <>
          <ul className="-mx-4 -my-4 divide-y divide-line md:hidden">
            {data.items.map((a) => (
              <li key={a.alert_id}>
                <Link to={`/alerts/${encodeURIComponent(a.alert_id)}`} className="block space-y-1 px-4 py-3 hover:bg-surface-2">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-sm"><Tag>{a.rule_id}</Tag> {a.rule_name}</span>
                    <SeverityBadge severity={a.severity} />
                  </div>
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-ink-2">
                    <span className="tabular">{when(a.timestamp)}</span>
                    <span className="font-mono">{a.host}</span>
                    <span>{a.user ?? "–"}</span>
                    {a.split !== "review" && <VerdictBadge verdict={a.label} />}
                  </div>
                </Link>
              </li>
            ))}
          </ul>
          <div className="-mx-4 -my-4 hidden overflow-x-auto md:block">
            <table className="w-full text-sm">
              <thead className="border-b border-line text-left text-xs text-muted">
                <tr>
                  <th className="px-4 py-2 font-medium">Time (UTC)</th>
                  <th className="px-2 py-2 font-medium">Rule</th>
                  <th className="px-2 py-2 font-medium">Severity</th>
                  <th className="px-2 py-2 font-medium">Host</th>
                  <th className="px-2 py-2 font-medium">User</th>
                  <th className="px-4 py-2 font-medium">Ground truth</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((a) => (
                  <tr key={a.alert_id} className="cursor-pointer border-b border-line last:border-0 hover:bg-surface-2"
                    onClick={() => navigate(`/alerts/${encodeURIComponent(a.alert_id)}`)}>
                    <td className="px-4 py-2 whitespace-nowrap tabular text-ink-2">{when(a.timestamp)}</td>
                    <td className="px-2 py-2">
                      <Link to={`/alerts/${encodeURIComponent(a.alert_id)}`} className="hover:underline"
                        onClick={(e) => e.stopPropagation()}>
                        <Tag>{a.rule_id}</Tag> {a.rule_name}
                      </Link>
                    </td>
                    <td className="px-2 py-2"><SeverityBadge severity={a.severity} /></td>
                    <td className="px-2 py-2 font-mono text-xs">{a.host}</td>
                    <td className="px-2 py-2 text-ink-2">{a.user ?? "–"}</td>
                    <td className="px-4 py-2">
                      {a.split === "review" ? <span className="text-xs text-muted">unlabelled</span> : <VerdictBadge verdict={a.label} />}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          </>
        )}
      </Card>

      {data && data.total > PAGE && (
        <div className="flex items-center justify-end gap-3 text-sm">
          <button type="button" className={inputCls} disabled={page === 0} onClick={() => set("page", String(page - 1))}>← Prev</button>
          <span className="tabular text-ink-2">page {page + 1} of {Math.ceil(data.total / PAGE)}</span>
          <button type="button" className={inputCls} disabled={(page + 1) * PAGE >= data.total}
            onClick={() => set("page", String(page + 1))}>Next →</button>
        </div>
      )}
      <p className="text-xs text-muted">Ground truth comes from the dataset labels and is shown for evaluation; the agent never sees it.</p>
    </div>
  );
}
