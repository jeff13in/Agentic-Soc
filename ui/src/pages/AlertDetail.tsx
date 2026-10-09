import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api";
import { Card, Empty, ErrorBox, inputCls, JsonView, Loading, SeverityBadge, Tag, VerdictBadge } from "../components/ui";
import { basename, when } from "../lib/format";
import { useAsync } from "../lib/useAsync";

export function AlertDetail() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const alert = useAsync(() => api.alert(id), [id]);
  const config = useAsync(() => api.config(), []);
  const [traceKey, setTraceKey] = useState(0);
  const traces = useAsync(() => api.traces({ alert_id: id, limit: 20 }), [id, traceKey]);
  const [backend, setBackend] = useState("");
  const [profile, setProfile] = useState("");
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<unknown>();

  useEffect(() => {
    if (!config.data) return;
    const first = config.data.backends.find((b) => b.id === config.data!.default_backend && b.available)
      ?? config.data.backends.find((b) => b.available);
    setBackend((b) => b || first?.id || "heuristic");
    setProfile((p) => p || config.data!.default_profile);
  }, [config.data]);

  async function run() {
    setRunning(true);
    setRunError(undefined);
    try {
      const trace = await api.triage(id, { backend, profile });
      setTraceKey((k) => k + 1);
      navigate(`/traces/${trace.trace_id}`);
    } catch (e) {
      setRunError(e);
    } finally {
      setRunning(false);
    }
  }

  if (alert.loading) return <Loading />;
  if (alert.error !== undefined) return <ErrorBox error={alert.error} />;
  const la = alert.data!;
  const a = la.alert;
  const selected = config.data?.backends.find((b) => b.id === backend);

  return (
    <div className="space-y-4">
      <div>
        <Link to="/" className="text-xs text-accent-ink hover:underline">← Alert queue</Link>
        <h1 className="mt-1 flex flex-wrap items-center gap-2 text-lg font-semibold">
          <Tag>{a.rule_id}</Tag> {a.rule_name} <SeverityBadge severity={a.rule_severity} />
        </h1>
        <p className="mt-1 font-mono text-xs text-muted">{a.alert_id}</p>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Alert" className="lg:col-span-2">
          <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-sm">
            <dt className="text-muted">Time</dt><dd className="tabular">{when(a.timestamp)}</dd>
            <dt className="text-muted">Host</dt><dd className="font-mono text-xs">{a.host}</dd>
            <dt className="text-muted">User</dt><dd>{a.user ?? "–"}</dd>
            <dt className="text-muted">Event</dt><dd>ID {a.event_id} · <span className="font-mono text-xs">{a.event_uid}</span></dd>
            {a.image && <><dt className="text-muted">Process</dt><dd><span className="font-medium">{basename(a.image)}</span> <span className="text-xs text-muted">{a.image}</span></dd></>}
            {a.parent_image && <><dt className="text-muted">Parent</dt><dd>{basename(a.parent_image)}</dd></>}
            <dt className="text-muted">ATT&amp;CK (rule)</dt><dd className="flex flex-wrap gap-1">{a.rule_tags.map((t) => <Tag key={t}>{t}</Tag>)}</dd>
          </dl>
          {a.command_line && (
            <div className="mt-3">
              <div className="mb-1 text-xs text-muted">Command line <span className="italic">(attacker-controlled)</span></div>
              <pre className="overflow-x-auto rounded border border-line bg-surface-2 p-2 font-mono text-xs whitespace-pre-wrap break-all">{a.command_line}</pre>
            </div>
          )}
          <div className="mt-3"><JsonView value={a.raw_event} label="Raw event" /></div>
        </Card>

        <div className="space-y-4">
          <Card title="Run triage">
            {config.error !== undefined && <ErrorBox error={config.error} />}
            {config.data && (
              <div className="space-y-3 text-sm">
                <label className="flex flex-col gap-1 text-xs text-muted">Backend
                  <select className={inputCls} value={backend} onChange={(e) => setBackend(e.target.value)}>
                    {config.data.backends.map((b) => (
                      <option key={b.id} value={b.id} disabled={!b.available}>{b.label}{b.available ? "" : " (unavailable)"}</option>
                    ))}
                  </select>
                </label>
                {selected?.note && <p className="text-xs text-muted">{selected.note}</p>}
                <label className="flex flex-col gap-1 text-xs text-muted">Defense profile
                  <select className={inputCls} value={profile} onChange={(e) => setProfile(e.target.value)}>
                    {config.data.profiles.map((p) => (
                      <option key={p.id} value={p.id}>{p.id}: prompt {p.prompt_version}, {p.defenses.join(" + ") || "no defenses"}</option>
                    ))}
                  </select>
                </label>
                <button type="button" onClick={run} disabled={running || !backend}
                  className="w-full rounded bg-button px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50">
                  {running ? "Investigating…" : "Triage this alert"}
                </button>
                {running && <p className="text-xs text-muted" role="status">An LLM backend can take up to a minute.</p>}
                {runError !== undefined && <ErrorBox error={runError} />}
              </div>
            )}
          </Card>

          <Card title="Ground truth">
            {la.split === "review" ? (
              <p className="text-sm text-ink-2">Unlabelled: OTRF lab background awaiting a hand label.</p>
            ) : (
              <div className="space-y-2 text-sm">
                <VerdictBadge verdict={la.label} />
                {la.techniques.length > 0 && <div className="flex flex-wrap gap-1">{la.techniques.map((t) => <Tag key={t}>{t}</Tag>)}</div>}
                <p className="text-xs text-muted">Split: {la.split} · source: {la.scenario}</p>
              </div>
            )}
          </Card>
        </div>
      </div>

      <Card title="Previous triage runs">
        {traces.loading && <Loading />}
        {traces.data && traces.data.length === 0 && <Empty>No traces yet. Run triage above.</Empty>}
        {traces.data && traces.data.length > 0 && (
          <ul className="divide-y divide-line text-sm">
            {traces.data.map((t) => (
              <li key={t.trace_id} className="flex flex-wrap items-center gap-3 py-2">
                <VerdictBadge verdict={t.verdict} />
                <Link to={`/traces/${t.trace_id}`} className="text-accent-ink hover:underline">{t.backend} · {t.model}</Link>
                <span className="text-xs text-muted">prompt {t.prompt_version} · {t.status}</span>
                <span className="ml-auto tabular text-xs text-muted">{when(t.created_at)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
