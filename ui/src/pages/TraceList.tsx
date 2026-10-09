import { Link } from "react-router-dom";
import { api } from "../api";
import { Card, Empty, ErrorBox, Loading, VerdictBadge } from "../components/ui";
import { when } from "../lib/format";
import { useAsync } from "../lib/useAsync";

export function TraceList() {
  const { data, error, loading } = useAsync(() => api.traces({ limit: 200 }), []);
  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Recent traces</h1>
      <Card>
        {loading && <Loading />}
        {error !== undefined && <ErrorBox error={error} />}
        {data && data.length === 0 && <Empty>No traces yet. Triage an alert from the queue, or run an eval.</Empty>}
        {data && data.length > 0 && (
          <div className="-mx-4 -my-4 overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-line text-left text-xs text-muted">
                <tr>
                  <th className="px-4 py-2 font-medium">Time (UTC)</th><th className="px-2 py-2 font-medium">Alert</th>
                  <th className="px-2 py-2 font-medium">Backend</th><th className="px-2 py-2 font-medium">Prompt</th>
                  <th className="px-2 py-2 font-medium">Status</th><th className="px-4 py-2 font-medium">Verdict</th>
                </tr>
              </thead>
              <tbody>
                {data.map((t) => (
                  <tr key={t.trace_id} className="border-b border-line last:border-0 hover:bg-surface-2">
                    <td className="px-4 py-2 whitespace-nowrap tabular text-ink-2">{when(t.created_at)}</td>
                    <td className="px-2 py-2"><Link className="font-mono text-xs text-accent-ink hover:underline" to={`/traces/${t.trace_id}`}>{t.alert_id}</Link></td>
                    <td className="px-2 py-2">{t.backend}</td>
                    <td className="px-2 py-2 text-ink-2">{t.prompt_version}</td>
                    <td className="px-2 py-2 text-ink-2">{t.status}</td>
                    <td className="px-4 py-2"><VerdictBadge verdict={t.verdict} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
