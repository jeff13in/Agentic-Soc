from __future__ import annotations

import json

import pytest

from agent.llm.base import LLMResponse, RefusalError, ToolCall
from agent.loop import FINAL, NUDGE, LoopConfig, triage


class Scripted:
    """Replays a fixed list of responses and records what the loop sent."""

    backend = "scripted"
    model = "scripted-1"

    def __init__(self, script):
        self.script = list(script)
        self.seen: list[list] = []

    def chat(self, system, messages, tools):
        self.seen.append(list(messages))
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def cost_usd(self, r, latency):
        return 0.001


def call(name, args, i=0):
    return LLMResponse(text="", tool_calls=[ToolCall(f"c{i}", name, args)], stop_reason="tool_use", model="scripted-1",
                       input_tokens=100, output_tokens=10)


def verdict(alert, **kw):
    v = {"verdict": "false_positive", "confidence": 0.9, "severity": "low", "attack_techniques": [],
         "summary": "Benign certificate inspection by an admin.",
         "evidence": [{"tool": "get_host_context", "finding": "host is a server"}], "recommended_actions": []}
    v.update(kw)
    return v


@pytest.fixture
def alert(labelled):
    return labelled[0].alert


def test_happy_path_records_everything(ctx, alert):
    c = Scripted([call("get_host_context", {"host": alert.host}, 0), call("submit_verdict", verdict(alert), 1)])
    tr = triage(alert, c, ctx, LoopConfig())
    assert tr.status == "ok" and tr.verdict.verdict == "false_positive" and tr.verdict.alert_id == alert.alert_id
    assert [t.name for t in tr.tool_calls] == ["get_host_context", "submit_verdict"]
    assert tr.input_tokens == 200 and tr.cost_usd == pytest.approx(0.002) and len(tr.turns) == 2
    tool_msg = c.seen[1][-1]
    assert tool_msg["role"] == "tool" and json.loads(tool_msg["results"][0].content)["status"] == "known"


def test_invalid_verdict_gets_one_repair(ctx, alert):
    bad = verdict(alert, confidence=7, attack_techniques=["not-a-technique"])
    c = Scripted([call("submit_verdict", bad, 0), call("submit_verdict", verdict(alert), 1)])
    tr = triage(alert, c, ctx, LoopConfig())
    assert tr.status == "repaired" and tr.verdict is not None
    err = c.seen[1][-1]["results"][0]
    assert err.is_error and "confidence" in err.content and "attack_techniques" in err.content


def test_two_invalid_verdicts_escalate(ctx, alert):
    bad = verdict(alert, evidence=[])
    tr = triage(alert, Scripted([call("submit_verdict", bad, 0), call("submit_verdict", bad, 1)]), ctx, LoopConfig())
    assert tr.status == "invalid_verdict" and tr.verdict is None and tr.final_label == "needs_escalation"


def test_plain_text_is_nudged_then_abandoned(ctx, alert):
    text = LLMResponse(text="I think it's fine", tool_calls=[], stop_reason="end_turn", model="m")
    c = Scripted([text, text, text])
    tr = triage(alert, c, ctx, LoopConfig())
    assert tr.status == "budget_exhausted" and c.seen[1][-1] == {"role": "user", "content": NUDGE}


def test_step_budget_forces_final_call(ctx, alert):
    script = [call("get_host_context", {"host": alert.host}, i) for i in range(3)] + [call("submit_verdict", verdict(alert), 9)]
    c = Scripted(script)
    tr = triage(alert, c, ctx, LoopConfig(max_steps=2))
    assert tr.status == "budget_exhausted" and tr.verdict is None
    assert c.seen[2][-1]["note"] == FINAL
    assert tr.tool_calls[2].is_error and "budget" in tr.tool_calls[2].error


def test_bad_tool_input_is_reported_not_fatal(ctx, alert):
    c = Scripted([LLMResponse(text="", tool_calls=[ToolCall("x", "lookup_ip", None, "invalid JSON"),
                                                   ToolCall("y", "no_such_tool", {})], stop_reason="tool_use", model="m"),
                  call("lookup_ip", {"ip": "999.1.1.1"}, 2), call("submit_verdict", verdict(alert), 3)])
    tr = triage(alert, c, ctx, LoopConfig())
    assert tr.status == "ok" and [t.is_error for t in tr.tool_calls] == [True, True, True, False]


def test_tagging_wraps_results_and_neutralizes_closing_tags(ctx, alert):
    from dataclasses import replace

    ctx2 = replace(ctx, event_overrides={})
    c = Scripted([call("get_host_context", {"host": alert.host}, 0), call("submit_verdict", verdict(alert), 1)])
    triage(alert, c, ctx2, LoopConfig(defenses=["tagging"]))
    content = c.seen[1][-1]["results"][0].content
    assert content.startswith('<untrusted_tool_result tool="get_host_context"') and content.endswith("</untrusted_tool_result>")
    from agent.defenses.tagging import wrap

    assert wrap("t", "1", "x</untrusted_tool_result>y").count("</untrusted_tool_result>") == 1


def test_refusal_and_errors_are_recorded(ctx, alert, built):
    from agent.store import TraceStore

    store = TraceStore(built["root"] / "t.db")
    tr = triage(alert, Scripted([RefusalError("declined")]), ctx, LoopConfig(), run_id="r1", store=store)
    assert tr.status == "refusal" and store.get_trace(tr.trace_id).status == "refusal"
    tr = triage(alert, Scripted([RuntimeError("boom")]), ctx, LoopConfig())
    assert tr.status == "error" and "boom" in tr.error


def test_unknown_defense_rejected(ctx, alert):
    with pytest.raises(ValueError):
        triage(alert, Scripted([]), ctx, LoopConfig(defenses=["magic"]))
