"""Distil stored agent traces into chat-format SFT examples for QLoRA.

    python -m training.build_sft_data                          # Claude traces on the dev split
    python -m training.build_sft_data --backend claude --extra training/handwritten.jsonl

Keeps only traces that (1) are on the dev split, never test, (2) finished cleanly, (3) got the
verdict right and (4) pass the faithfulness check. Injected variants of dev alerts (from
`run_robustness --split dev`) are included when the agent still called them true positives:
they teach the model to ignore planted instructions.

Each example reproduces exactly what the model saw (same system prompt, alert message and
tool-result rendering as agent/loop.py) in the OpenAI/Hugging Face tool-calling chat format:
    {"messages": [...], "tools": [...], "meta": {...}}
Qwen2.5's chat template renders this directly with apply_chat_template(messages, tools=tools).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from agent.config import ROOT, get_settings
from agent.loop import FINAL, alert_message, load_prompt, render_tool_result
from agent.schemas import LabelledAlert, Trace, Verdict
from agent.store import TraceStore
from agent.tools import SUBMIT_VERDICT, tool_specs
from evals.adversarial.payloads import PAYLOADS, inject
from evals.judges import faithfulness
from evals.run_eval import load_split

OUT_DIR = ROOT / "training" / "data"
PAYLOADS_BY_ID = {p.id: p for p in PAYLOADS}


def openai_tools() -> list[dict[str, Any]]:
    return [{"type": "function", "function": spec} for spec in tool_specs()]


def resolve_alert(alert_id: str, dev: dict[str, LabelledAlert], test_ids: set[str]) -> tuple[LabelledAlert | None, str]:
    """Labelled alert for a trace, rebuilding injected variants. Second value is a drop reason or ''."""
    base_id, _, payload_id = alert_id.partition("~")
    if base_id in test_ids:
        return None, "test_split"
    if base_id not in dev:
        return None, "not_in_dev_split"
    if not payload_id:
        return dev[base_id], ""
    payload = PAYLOADS_BY_ID.get(payload_id)
    out = inject(dev[base_id], payload) if payload else None
    return (out[0], "") if out else (None, "unknown_payload")


def trace_to_messages(trace: Trace, la: LabelledAlert) -> list[dict[str, Any]]:
    system, _ = load_prompt(trace.prompt_version)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": alert_message(la.alert, "sanitize" in trace.defenses)},
    ]
    for turn in trace.turns:
        calls = [c for c in trace.tool_calls if c.step == turn.step]
        messages.append({"role": "assistant", "content": turn.text or "", "tool_calls": [
            {"id": c.call_id, "type": "function", "function": {"name": c.name, "arguments": c.arguments}}
            for c in calls]})
        if any(c.name == SUBMIT_VERDICT and not c.is_error for c in calls):
            break  # the accepted verdict ends the conversation
        for c in calls:
            messages.append({"role": "tool", "tool_call_id": c.call_id, "name": c.name,
                             "content": render_tool_result(c, trace.defenses)})
        if trace.final_note_step == turn.step:
            messages.append({"role": "user", "content": FINAL})
    return messages


def validate_example(ex: dict[str, Any]) -> list[str]:
    """Structural checks every example must pass before it reaches the trainer."""
    msgs = ex.get("messages", [])
    problems = []
    if len(msgs) < 3 or msgs[0]["role"] != "system" or msgs[1]["role"] != "user":
        problems.append("must start with system then user")
    pending: set[str] = set()
    for m in msgs[2:]:
        if m["role"] == "assistant":
            if pending:
                problems.append(f"unanswered tool calls before next assistant turn: {sorted(pending)}")
            pending = {c["id"] for c in m.get("tool_calls", [])}
        elif m["role"] == "tool":
            if m["tool_call_id"] not in pending:
                problems.append(f"tool result for unknown call {m['tool_call_id']}")
            pending.discard(m["tool_call_id"])
    last = msgs[-1] if msgs else {}
    finals = [c for c in last.get("tool_calls", []) if c["function"]["name"] == SUBMIT_VERDICT]
    if last.get("role") != "assistant" or not finals:
        problems.append("must end with an assistant submit_verdict call")
    else:
        try:
            Verdict.model_validate({"alert_id": "x", **finals[-1]["function"]["arguments"]})
        except Exception as e:  # noqa: BLE001 - report any schema failure
            problems.append(f"final verdict invalid: {e}")
    return problems


def select(traces: list[Trace], dev: dict[str, LabelledAlert], test_ids: set[str], max_steps: int,
           allow_tool_errors: bool = False) -> tuple[list[dict[str, Any]], Counter]:
    reasons: Counter = Counter()
    best: dict[str, tuple[tuple, dict[str, Any]]] = {}
    for tr in traces:
        la, why = resolve_alert(tr.alert_id, dev, test_ids)
        if la is None:
            reasons[why] += 1
            continue
        if tr.status != "ok" or tr.verdict is None:
            reasons[f"status_{tr.status}"] += 1
            continue
        if tr.final_label != la.label:
            reasons["wrong_verdict"] += 1
            continue
        if any(not t.tool_calls for t in tr.turns):
            reasons["plain_text_turn"] += 1
            continue
        steps = sum(1 for c in tr.tool_calls if c.name != SUBMIT_VERDICT)
        if steps >= max_steps:
            reasons["hit_step_budget"] += 1
            continue
        if not allow_tool_errors and any(c.is_error for c in tr.tool_calls):
            reasons["tool_errors"] += 1
            continue
        if faithfulness.check(la.alert, tr).score < 1.0:
            reasons["unfaithful"] += 1
            continue
        ex = {"messages": trace_to_messages(tr, la), "tools": openai_tools(),
              "meta": {"alert_id": tr.alert_id, "label": la.label.value, "trace_id": tr.trace_id,
                       "model": tr.model, "prompt_version": tr.prompt_version, "defenses": tr.defenses,
                       "injected": "~" in tr.alert_id}}
        problems = validate_example(ex)
        if problems:
            reasons["invalid_example"] += 1
            continue
        key = (steps, tr.trace_id)  # one example per alert: the most direct correct investigation
        if tr.alert_id not in best or key < best[tr.alert_id][0]:
            if tr.alert_id in best:
                reasons["duplicate_alert"] += 1
            best[tr.alert_id] = (key, ex)
        else:
            reasons["duplicate_alert"] += 1
    return [ex for _, ex in sorted(best.values(), key=lambda kv: kv[1]["meta"]["alert_id"])], reasons


def split_validation(examples: list[dict[str, Any]], fraction: float) -> tuple[list, list]:
    """Hold out a validation slice by base alert, so injected variants stay with their source."""
    def bucket(ex: dict[str, Any]) -> float:
        base = ex["meta"]["alert_id"].split("~")[0]
        return int(hashlib.sha256(base.encode()).hexdigest(), 16) % 10_000 / 10_000

    return [e for e in examples if bucket(e) >= fraction], [e for e in examples if bucket(e) < fraction]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", default="claude", help="only distil traces from this backend")
    ap.add_argument("--run-ids", default=None, help="comma-separated eval run ids (default: every run)")
    ap.add_argument("--extra", type=Path, action="append", default=[], help="hand-written examples (.jsonl)")
    ap.add_argument("--val-fraction", type=float, default=0.1)
    ap.add_argument("--allow-tool-errors", action="store_true")
    ap.add_argument("--out", type=Path, default=OUT_DIR)
    args = ap.parse_args(argv)

    settings = get_settings()
    dev = {la.alert.alert_id: la for la in load_split(settings.labels_dir, "dev")}
    test_ids = {la.alert.alert_id for la in load_split(settings.labels_dir, "test")}
    store = TraceStore(settings.db_path)
    if args.run_ids:
        traces = [t for rid in args.run_ids.split(",") for t in store.run_traces(rid)]
    else:
        traces = store.all_traces(backend=args.backend)
    traces = [t for t in traces if t.backend == args.backend]

    examples, reasons = select(traces, dev, test_ids, settings.max_steps, args.allow_tool_errors)
    for path in args.extra:
        for i, line in enumerate(path.read_text().splitlines()):
            if not line.strip():
                continue
            ex = json.loads(line)
            ex.setdefault("tools", openai_tools())
            ex.setdefault("meta", {"alert_id": f"extra:{path.name}:{i}", "source": str(path)})
            problems = validate_example(ex)
            if problems:
                raise SystemExit(f"{path}:{i + 1}: {problems}")
            examples.append(ex)

    train, val = split_validation(examples, args.val_fraction)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, items in (("sft_train.jsonl", train), ("sft_val.jsonl", val)):
        with (args.out / name).open("w") as f:
            for ex in items:
                f.write(json.dumps(ex, default=str) + "\n")
    stats = {"traces_considered": len(traces), "examples": len(examples), "train": len(train), "val": len(val),
             "injected_examples": sum(1 for e in examples if e["meta"].get("injected")),
             "labels": dict(Counter(e["meta"].get("label", "extra") for e in examples)), "dropped": dict(reasons)}
    (args.out / "sft_stats.json").write_text(json.dumps(stats, indent=2))
    print(json.dumps(stats, indent=2))
    if reasons.get("test_split"):
        print(f"note: ignored {reasons['test_split']} traces on the test split (never used for training)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
