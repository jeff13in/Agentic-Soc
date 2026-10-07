from __future__ import annotations

from datetime import UTC, datetime

from agent.schemas import Alert, LabelledAlert, ToolCallRecord, Trace, Verdict
from evals import metrics
from evals.gate import check
from evals.judges import faithfulness
from evals.run_eval import stratified_subset


def make(label, pred, techniques=(), gold=(), latency=1.0, evidence_tool="lookup_ip", summary="Nothing malicious found.", result=None):
    alert = Alert(alert_id=f"a{id(object())}", rule_id="R", rule_name="r", rule_severity="high",
                  timestamp=datetime(2026, 9, 1, tzinfo=UTC), host="WS-001", event_id=1, event_uid="evt-1")
    tr = Trace(trace_id="t", alert_id=alert.alert_id, backend="b", model="m", prompt_version="v1", prompt_hash="h",
               started_at=datetime.now(UTC), latency_s=latency, input_tokens=100, output_tokens=10, cost_usd=0.01,
               tool_calls=[ToolCallRecord(step=0, call_id="c", name="lookup_ip", arguments={},
                                          result=result or {"ip": "52.1.2.3", "abuse_confidence": 0})])
    if pred is not None:
        tr.verdict = Verdict(alert_id=alert.alert_id, verdict=pred, confidence=0.9, severity="low",
                             attack_techniques=list(techniques), summary=summary,
                             evidence=[{"tool": evidence_tool, "finding": "looked it up"}])
    return LabelledAlert(alert=alert, label=label, techniques=list(gold)), tr


def test_confusion_metrics():
    pairs = [make("true_positive", "true_positive", ["T1059.001"], ["T1059.001"]),
             make("true_positive", "false_positive"),
             make("true_positive", "needs_escalation"),
             make("false_positive", "false_positive"),
             make("false_positive", "true_positive", ["T1003"], []),
             make("false_positive", None)]
    m = metrics.compute(pairs)
    assert m["n"] == 6 and m["accuracy"] == 2 / 6
    assert m["fn_rate"] == 1 / 3 and m["fp_rate"] == 1 / 3
    assert m["escalation_rate"] == 2 / 6  # missing verdict counts as escalation
    assert m["precision"] == 1 / 2 and m["recall"] == 1 / 3 and m["attack_match"] == 1.0
    assert m["decided_accuracy"] == 2 / 4


def test_aggregate_reports_spread():
    a = metrics.compute([make("true_positive", "true_positive")])
    b = metrics.compute([make("true_positive", "false_positive")])
    agg = metrics.aggregate([a, b])
    assert agg["accuracy"] == 0.5 and agg["accuracy_std"] == 0.5 and agg["repeats"] == 2


def test_faithfulness_catches_unseen_indicators_and_tools():
    la, tr = make("true_positive", "true_positive", summary="Beacon to 52.1.2.3 observed.")
    assert faithfulness.check(la.alert, tr).score == 1.0
    la, tr = make("true_positive", "true_positive", summary="Beacon to 45.9.9.9 from evil.exe observed.")
    res = faithfulness.check(la.alert, tr)
    assert res.score == 0.0 and any("45.9.9.9" in p for p in res.problems) and any("evil.exe" in p for p in res.problems)
    la, tr = make("true_positive", "true_positive", evidence_tool="lookup_hash")
    assert faithfulness.check(la.alert, tr).score == 0.0


def test_gate():
    assert check({"fn_rate": 0.1, "accuracy": 0.9}, {"fn_rate": {"max": 0.05}, "accuracy": {"min": 0.85}}) == [
        "fn_rate = 0.100 > max 0.05"]
    assert check({"fn_rate": None}, {"fn_rate": {"max": 0.05}}) == []


def test_stratified_subset_keeps_both_labels_and_is_deterministic():
    pairs = [make("true_positive", None)[0] for _ in range(3)] + [make("false_positive", None)[0] for _ in range(30)]
    sub = stratified_subset(pairs, 10)
    assert {la.label.value for la in sub} == {"true_positive", "false_positive"} and len(sub) <= 10
    assert [la.alert.alert_id for la in sub] == [la.alert.alert_id for la in stratified_subset(pairs, 10)]


def test_gate_skips_fn_rate_on_tiny_samples():
    m = {"fn_rate": 1.0, "accuracy": 0.9, "per_run": [{"n_true_positive": 1}]}
    assert check(m, {"min_true_positives": 10, "fn_rate": {"max": 0.05}, "accuracy": {"min": 0.85}}) == []
    m["per_run"] = [{"n_true_positive": 20}]
    assert check(m, {"min_true_positives": 10, "fn_rate": {"max": 0.05}}) == ["fn_rate = 1.000 > max 0.05"]
