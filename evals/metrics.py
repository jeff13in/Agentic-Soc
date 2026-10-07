"""Triage metrics over (labelled alert, trace) pairs.

Labels are true_positive / false_positive. Predictions may also be needs_escalation, which is
counted separately: it is never a false negative, but it does count against accuracy and is
reported as the escalation rate (an agent that escalates everything is useless).
"""

from __future__ import annotations

import statistics
from collections import Counter
from typing import Any

from agent.schemas import LabelledAlert, Trace, VerdictLabel
from evals.judges import faithfulness

TP, FP, ESC = VerdictLabel.TRUE_POSITIVE, VerdictLabel.FALSE_POSITIVE, VerdictLabel.NEEDS_ESCALATION

HEADLINE = ["accuracy", "fn_rate", "fp_rate", "escalation_rate", "precision", "recall", "attack_match",
            "faithfulness", "tool_call_validity", "steps_mean", "tokens_mean", "latency_p50_s", "latency_p95_s",
            "cost_per_alert_usd", "error_rate"]


def _ratio(a: float, b: float) -> float | None:
    return a / b if b else None


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    return s[min(len(s) - 1, round(q * (len(s) - 1)))]


def compute(pairs: list[tuple[LabelledAlert, Trace]]) -> dict[str, Any]:
    cm = Counter((la.label, tr.final_label) for la, tr in pairs)
    n = len(pairs)
    n_tp = sum(v for (lab, _), v in cm.items() if lab == TP)
    n_fp = sum(v for (lab, _), v in cm.items() if lab == FP)
    pred_tp = cm[(TP, TP)] + cm[(FP, TP)]

    jaccards = []
    for la, tr in pairs:
        if la.label == TP and la.techniques and tr.verdict and tr.final_label == TP:
            pred, gold = set(tr.verdict.attack_techniques), set(la.techniques)
            # parent/sub-technique count as a match: T1059 ~ T1059.001
            pred_p, gold_p = {t.split(".")[0] for t in pred}, {t.split(".")[0] for t in gold}
            jaccards.append(len(pred_p & gold_p) / len(pred_p | gold_p) if pred_p | gold_p else 0.0)

    calls = [c for _, tr in pairs for c in tr.tool_calls]
    latencies = [tr.latency_s for _, tr in pairs]
    return {
        "n": n,
        "n_true_positive": n_tp,
        "n_false_positive": n_fp,
        "confusion": {f"{lab.value}->{pred.value}": v for (lab, pred), v in sorted(cm.items())},
        "accuracy": _ratio(cm[(TP, TP)] + cm[(FP, FP)], n),
        "decided_accuracy": _ratio(cm[(TP, TP)] + cm[(FP, FP)], n - cm[(TP, ESC)] - cm[(FP, ESC)]),
        "fn_rate": _ratio(cm[(TP, FP)], n_tp),
        "fp_rate": _ratio(cm[(FP, TP)], n_fp),
        "escalation_rate": _ratio(cm[(TP, ESC)] + cm[(FP, ESC)], n),
        "precision": _ratio(cm[(TP, TP)], pred_tp),
        "recall": _ratio(cm[(TP, TP)], n_tp),
        "attack_match": statistics.mean(jaccards) if jaccards else None,
        "faithfulness": statistics.mean(faithfulness.check(la.alert, tr).score for la, tr in pairs) if pairs else None,
        "tool_call_validity": _ratio(sum(1 for c in calls if not c.is_error), len(calls)),
        "steps_mean": statistics.mean(sum(1 for c in tr.tool_calls if c.name != "submit_verdict") for _, tr in pairs) if pairs else None,
        "tokens_mean": statistics.mean(tr.input_tokens + tr.output_tokens for _, tr in pairs) if pairs else None,
        "latency_p50_s": _pct(latencies, 0.5),
        "latency_p95_s": _pct(latencies, 0.95),
        "cost_per_alert_usd": statistics.mean(tr.cost_usd for _, tr in pairs) if pairs else None,
        "error_rate": _ratio(sum(1 for _, tr in pairs if tr.status in ("error", "refusal")), n),
        "status": dict(Counter(tr.status for _, tr in pairs)),
    }


def aggregate(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Mean and population std of each headline metric across repeated runs."""
    out: dict[str, Any] = {"repeats": len(runs), "n": runs[0]["n"] if runs else 0}
    for k in HEADLINE + ["decided_accuracy"]:
        vals = [r[k] for r in runs if r.get(k) is not None]
        out[k] = statistics.mean(vals) if vals else None
        out[f"{k}_std"] = statistics.pstdev(vals) if len(vals) > 1 else 0.0
    out["per_run"] = runs
    return out
