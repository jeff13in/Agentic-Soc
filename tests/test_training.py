from __future__ import annotations

import json

from agent.llm.heuristic_client import HeuristicClient
from agent.loop import FINAL, LoopConfig, alert_message, load_prompt, triage
from evals.benchmark import markdown, parse_target, run_benchmark
from tests.test_loop import Scripted, call, verdict
from training.build_sft_data import main as build_main
from training.build_sft_data import resolve_alert, select, trace_to_messages, validate_example


def _dev(labelled):
    return {la.alert.alert_id: la for la in labelled}


def test_examples_reproduce_exactly_what_the_model_saw(ctx, labelled):
    la = next(x for x in labelled if x.label == "false_positive")
    a = la.alert
    c = Scripted([call("get_host_context", {"host": a.host}, 0), call("search_logs", {"host": "nope"}, 1),
                  call("submit_verdict", verdict(a), 2)])
    cfg = LoopConfig(prompt_version="v2", defenses=["tagging", "sanitize"], max_steps=2)
    tr = triage(a, c, ctx, cfg)
    assert tr.status == "ok" and tr.final_note_step == 1
    msgs = trace_to_messages(tr, la)
    assert msgs[0] == {"role": "system", "content": load_prompt("v2")[0]}
    assert msgs[1]["content"] == c.seen[0][0]["content"] == alert_message(a, sanitize=True)
    tool_msgs = [m for m in msgs if m["role"] == "tool"]
    seen = [r.content for m in c.seen[-1] if m["role"] == "tool" for r in m["results"]]
    assert [m["content"] for m in tool_msgs] == seen  # byte-identical tool results, incl. the error
    assert msgs[-2] == {"role": "user", "content": FINAL}  # budget note where the loop put it
    assert msgs[-1]["tool_calls"][0]["function"]["name"] == "submit_verdict"
    assert validate_example({"messages": msgs}) == []


def test_resolve_alert_guards_test_split_and_rebuilds_injections(labelled):
    tp = next(x for x in labelled if x.label == "true_positive")
    dev = {tp.alert.alert_id: tp}
    assert resolve_alert(tp.alert.alert_id, dev, {tp.alert.alert_id})[1] == "test_split"
    assert resolve_alert("nope", dev, set())[1] == "not_in_dev_split"
    injected, why = resolve_alert(f"{tp.alert.alert_id}~direct-1", dev, set())
    assert why == "" and "NOTE TO AI ANALYST" in injected.alert.command_line
    assert resolve_alert(f"{tp.alert.alert_id}~bogus", dev, set())[1] == "unknown_payload"


def test_select_filters_and_dedupes(ctx, labelled):
    fp = next(x for x in labelled if x.label == "false_positive")
    a = fp.alert
    good_long = triage(a, Scripted([call("get_host_context", {"host": a.host}, 0),
                                    call("get_host_context", {"host": a.host}, 1),
                                    call("submit_verdict", verdict(a), 2)]), ctx, LoopConfig())
    good_short = triage(a, Scripted([call("get_host_context", {"host": a.host}, 0),
                                     call("submit_verdict", verdict(a), 1)]), ctx, LoopConfig())
    wrong = triage(a, Scripted([call("get_host_context", {"host": a.host}, 0),
                                call("submit_verdict", verdict(a, verdict="true_positive", severity="high"), 1)]),
                   ctx, LoopConfig())
    errored = triage(a, Scripted([call("lookup_ip", {"ip": "bad"}, 0), call("submit_verdict", verdict(a), 1)]),
                     ctx, LoopConfig())
    unfaithful = triage(a, Scripted([call("get_host_context", {"host": a.host}, 0),
                                     call("submit_verdict", verdict(a, summary="Beacon to 45.6.7.8 seen."), 1)]),
                        ctx, LoopConfig())
    examples, reasons = select([good_long, good_short, wrong, errored, unfaithful], _dev(labelled), set(), 10)
    assert len(examples) == 1 and examples[0]["meta"]["trace_id"] == good_short.trace_id
    assert reasons == {"duplicate_alert": 1, "wrong_verdict": 1, "tool_errors": 1, "unfaithful": 1}
    _, leak = select([good_short], _dev(labelled), {a.alert_id}, 10)
    assert leak == {"test_split": 1}


def test_validate_example_catches_broken_conversations():
    tc = {"id": "1", "type": "function", "function": {"name": "lookup_ip", "arguments": {"ip": "1.1.1.1"}}}
    base = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    assert "must end with an assistant submit_verdict call" in validate_example({"messages": base})
    bad = base + [{"role": "assistant", "content": "", "tool_calls": [tc]},
                  {"role": "assistant", "content": "", "tool_calls": [
                      {"id": "2", "type": "function", "function": {"name": "submit_verdict", "arguments": {}}}]}]
    problems = validate_example({"messages": bad})
    assert any("unanswered" in p for p in problems) and any("final verdict invalid" in p for p in problems)


def test_cli_writes_train_val_without_test_leakage(built, labelled, tmp_path):
    from evals.run_eval import run_eval

    run_eval("heuristic", split="dev", limit=30, defenses=["tagging"], write_results=False)
    run_eval("heuristic", split="test", limit=10, write_results=False)
    assert build_main(["--backend", "heuristic", "--out", str(tmp_path), "--val-fraction", "0.2"]) == 0
    stats = json.loads((tmp_path / "sft_stats.json").read_text())
    assert stats["examples"] > 0 and stats["dropped"].get("test_split", 0) >= 10
    test_ids = {la.alert.alert_id for la in labelled if la.split == "test"}
    rows = [json.loads(x) for f in ("sft_train.jsonl", "sft_val.jsonl")
            for x in (tmp_path / f).read_text().splitlines()]
    assert len(rows) == stats["examples"] and not {r["meta"]["alert_id"] for r in rows} & test_ids
    assert all(r["tools"][0]["type"] == "function" for r in rows)


def test_benchmark_targets_and_throughput_cost(built):
    assert parse_target("tuned=vllm:soc-qwen-lora") == {"name": "tuned", "backend": "vllm", "model": "soc-qwen-lora"}
    assert parse_target("claude") == {"name": "claude", "backend": "claude", "model": None}
    report = run_benchmark(["rules=heuristic", "tuned=vllm:soc-qwen-lora"], limit=12, workers=2,
                           clients={"tuned": HeuristicClient()})
    rules, tuned = report["rows"]
    assert rules["alerts_per_min"] > 0 and rules["cost_per_alert_usd"] == 0
    assert tuned["cost_per_alert_usd"] > 0 and "GPU-hour" in tuned["cost_basis"]
    assert "| tuned |" in markdown(report)
