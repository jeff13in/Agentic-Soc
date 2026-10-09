// Mirrors agent/schemas.py and the API responses.
export type VerdictLabel = "true_positive" | "false_positive" | "needs_escalation";
export type Severity = "low" | "medium" | "high" | "critical";

export interface AlertSummary {
  alert_id: string;
  timestamp: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  host: string;
  user: string | null;
  split: string;
  label: VerdictLabel;
}

export interface Alert {
  alert_id: string;
  rule_id: string;
  rule_name: string;
  rule_severity: Severity;
  rule_tags: string[];
  timestamp: string;
  host: string;
  user: string | null;
  event_id: number;
  event_uid: string;
  process_guid: string | null;
  image: string | null;
  parent_image: string | null;
  command_line: string | null;
  raw_event: Record<string, string>;
}

export interface LabelledAlert {
  alert: Alert;
  label: VerdictLabel;
  techniques: string[];
  scenario: string | null;
  split: string;
}

export interface Evidence {
  tool: string;
  finding: string;
  event_ref: string | null;
}

export interface Verdict {
  alert_id: string;
  verdict: VerdictLabel;
  confidence: number;
  severity: Severity;
  attack_techniques: string[];
  summary: string;
  evidence: Evidence[];
  recommended_actions: string[];
}

export interface ToolCallRecord {
  step: number;
  call_id: string;
  name: string;
  arguments: Record<string, unknown>;
  result: unknown;
  is_error: boolean;
  error: string | null;
  latency_ms: number;
}

export interface ModelTurnRecord {
  step: number;
  text: string;
  tool_calls: string[];
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  latency_ms: number;
  stop_reason: string | null;
  model: string | null;
}

export interface Trace {
  trace_id: string;
  alert_id: string;
  run_id: string | null;
  backend: string;
  model: string;
  prompt_version: string;
  prompt_hash: string;
  defenses: string[];
  started_at: string;
  latency_s: number;
  status: string;
  verdict: Verdict | null;
  verifier: { model: string | null; agree: boolean; reason: string; original_verdict: VerdictLabel } | null;
  turns: ModelTurnRecord[];
  tool_calls: ToolCallRecord[];
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
  error: string | null;
}

export interface TraceSummary {
  trace_id: string;
  alert_id: string;
  run_id: string | null;
  backend: string;
  model: string;
  prompt_version: string;
  status: string;
  verdict: VerdictLabel;
  created_at: string;
}

export type Metrics = Record<string, number | null> & {
  confusion?: Record<string, number>;
};

export interface EvalRun {
  run_id: string;
  created_at: string;
  backend: string;
  model: string;
  prompt_version: string;
  prompt_hash: string;
  defenses: string[];
  split: string;
  dataset_version: string;
  git_commit: string;
  n_alerts: number;
  repeats: number;
  metrics: Metrics;
}

export interface Backend {
  id: string;
  label: string;
  available: boolean;
  note?: string | null;
}

export interface Profile {
  id: string;
  prompt_version: string;
  defenses: string[];
}

export interface AppConfig {
  default_backend: string;
  backends: Backend[];
  profiles: Profile[];
  default_profile: string;
  data_ready: boolean;
  alerts: number;
}

export interface RobustnessSummary {
  cases: number;
  eligible: number;
  clean_missed: number;
  asr: number | null;
  flip_rate: number | null;
  severity_drop_rate: number | null;
  escalated_rate: number | null;
  detected_tp_rate: number | null;
  by_category: Record<string, { eligible: number; asr: number | null }>;
}

export interface RobustnessReport {
  backend: string;
  split: string;
  true_positives: number;
  payloads: string[];
  repeats: number;
  created_at: string;
  configs: Record<string, { prompt_version: string; defenses: string[]; summary: RobustnessSummary }>;
}
