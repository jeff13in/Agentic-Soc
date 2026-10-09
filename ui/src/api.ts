import type { AlertSummary, AppConfig, EvalRun, LabelledAlert, RobustnessReport, Trace, TraceSummary } from "./types";

const BASE = "/api";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  config: () => request<AppConfig>("/config"),
  alerts: (params: Record<string, string | number | undefined>) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "") q.set(k, String(v));
    return request<{ total: number; items: AlertSummary[] }>(`/alerts?${q}`);
  },
  alert: (id: string) => request<LabelledAlert>(`/alerts/${encodeURIComponent(id)}`),
  triage: (id: string, body: { backend: string; profile: string }) =>
    request<Trace>(`/triage/${encodeURIComponent(id)}`, { method: "POST", body: JSON.stringify(body) }),
  traces: (params: { alert_id?: string; limit?: number } = {}) => {
    const q = new URLSearchParams();
    if (params.alert_id) q.set("alert_id", params.alert_id);
    q.set("limit", String(params.limit ?? 100));
    return request<TraceSummary[]>(`/traces?${q}`);
  },
  trace: (id: string) => request<Trace>(`/traces/${encodeURIComponent(id)}`),
  evals: () => request<EvalRun[]>("/evals"),
  robustness: () => request<RobustnessReport>("/evals/robustness"),
};
