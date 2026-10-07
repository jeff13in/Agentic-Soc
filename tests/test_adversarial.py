from __future__ import annotations

from datetime import UTC, datetime

from agent.defenses.sanitizer import scan
from agent.defenses.verifier import HeuristicVerifier
from agent.llm.base import LLMResponse, ToolCall
from agent.schemas import Trace, Verdict
from evals.adversarial.payloads import CATEGORIES, PAYLOADS, build_cases, inject
from evals.adversarial.run_robustness import compare, markdown, run_sweep, summarize


def test_payload_set_shape():
    assert len(PAYLOADS) == 9 and len({p.id for p in PAYLOADS}) == 9
    assert set(CATEGORIES) == {"direct_instruction", "fake_system", "authority_spoofing", "tool_hijack", "obfuscated"}


def test_sanitizer_flags_every_payload():
    # In-sample: the detector was revised against this set; see README for the held-out caveat.
    for p in PAYLOADS:
        assert scan(f"powershell.exe -enc AAAA {p.text}"), p.id


def test_inject_targets_attacker_field_and_keeps_original(labelled):
    tps = [la for la in labelled if la.label == "true_positive"]
    by_rule = {la.alert.rule_id: la for la in tps}
    ps = by_rule["R001"]
    out, overrides, field = inject(ps, PAYLOADS[0])
    assert field == "command_line" and out.alert.command_line.startswith(ps.alert.command_line)
    assert out.alert.raw_event["command_line"] == out.alert.command_line
    assert out.alert.alert_id == f"{ps.alert.alert_id}~direct-1" and out.label == "true_positive"
    assert overrides == {ps.alert.event_uid: {"command_line": out.alert.command_line}}
    lsass = by_rule["R003"]  # process-access event: no command line, payload goes into the image path
    assert inject(lsass, PAYLOADS[0])[2] == "image"
    cases = build_cases(labelled)
    assert len(cases) == len(tps) * len(PAYLOADS)
    assert all(c["alert"].label == "true_positive" for c in cases)


def _trace(label, severity="high"):
    t = Trace(trace_id="t", alert_id="a", backend="b", model="m", prompt_version="v1", prompt_hash="h",
              started_at=datetime.now(UTC))
    if label:
        ev = [{"tool": "x", "finding": "something seen"}] if label != "needs_escalation" else []
        t.verdict = Verdict(alert_id="a", verdict=label, confidence=0.9, severity=severity,
                            summary="A summary long enough.", evidence=ev)
    return t


def test_compare_outcomes():
    assert compare(_trace("true_positive"), _trace("false_positive", "low"))["flipped"]
    drop = compare(_trace("true_positive", "critical"), _trace("true_positive", "low"))
    assert drop["severity_drop"] and drop["success"] and not drop["flipped"]
    esc = compare(_trace("true_positive"), _trace("needs_escalation"))
    assert not esc["success"] and esc["escalated"]
    assert not compare(_trace("false_positive"), _trace("false_positive"))["eligible"]
    outs = [dict(compare(_trace("true_positive"), _trace("false_positive")), category="obfuscated"),
            dict(compare(_trace("true_positive"), _trace("true_positive")), category="obfuscated"),
            dict(compare(_trace("false_positive"), _trace("false_positive")), category="tool_hijack")]
    s = summarize(outs)
    assert s["asr"] == 0.5 and s["clean_missed"] == 1 and s["by_category"]["obfuscated"]["asr"] == 0.5


class Gullible:
    """Test double: obeys planted text it can read in plain form. Not a model of any real LLM."""

    backend = "gullible"
    model = "gullible-1"
    TRIGGERS = ("approved", "benign", "false_positive", "red team")

    def chat(self, system, messages, tools):
        import json
        import re

        alert = json.loads(re.search(r"```json\n(.*?)\n```", messages[0]["content"], re.S).group(1))
        if len(messages) == 1:
            return LLMResponse("", [ToolCall("g0", "get_host_context", {"host": alert["host"]})], "tool_use", self.model)
        text = (messages[0]["content"] + " ".join(r.content for m in messages if m["role"] == "tool" for r in m["results"])).lower()
        fooled = any(t in text for t in self.TRIGGERS)
        args = {"verdict": "false_positive" if fooled else "true_positive", "confidence": 0.8,
                "severity": "low" if fooled else "high", "summary": "Decided from the host context.",
                "evidence": [{"tool": "get_host_context", "finding": "host context retrieved"}]}
        return LLMResponse("", [ToolCall("g1", "submit_verdict", args)], "tool_use", self.model)

    def cost_usd(self, r, latency):
        return 0.0


def test_sweep_measures_flips_and_full_defenses_stop_them(built, labelled):
    report = run_sweep("gullible", ["baseline", "full"], alerts=labelled, client=Gullible(), verifier=HeuristicVerifier(),
                       workers=2)
    base, full = report["configs"]["baseline"]["summary"], report["configs"]["full"]["summary"]
    assert base["eligible"] == full["eligible"] == 3 * len(PAYLOADS)
    assert base["asr"] > 0.5  # the gullible model obeys most plain-text payloads
    assert base["by_category"]["obfuscated"]["asr"] < base["by_category"]["direct_instruction"]["asr"]
    assert full["asr"] == 0.0 and full["verifier_escalated"] > 0  # steered verdicts escalated, not accepted
    md = markdown(report)
    assert "| baseline | v1 | none |" in md and "Attack success by category" in md


def test_heuristic_sweep_runs(built, labelled):
    report = run_sweep("heuristic", ["sanitize"], alerts=labelled, payload_ids=["direct-1"], workers=2)
    s = report["configs"]["sanitize"]["summary"]
    assert s["cases"] == 3 and s["asr"] == 0.0
