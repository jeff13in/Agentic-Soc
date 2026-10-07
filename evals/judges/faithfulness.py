"""Faithfulness: is every claim in the verdict backed by something the agent actually saw?

Deterministic check (always on, used for the headline metric):
  * each evidence entry cites a tool that was called and returned without error;
  * each event_ref exists in the alert or a tool result;
  * every indicator in the summary and findings (IPs, hashes, domains, file names, ATT&CK IDs)
    appears in the alert or a tool result (techniques may also come from the verdict's own list).
Optional LLM judge (--judge claude) scores whether the summary's claims follow from the evidence.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from agent.schemas import Alert, Trace

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HEX = re.compile(r"\b[0-9a-f]{12,64}\b", re.I)
FILE = re.compile(r"\b[\w\-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|sct|docm|xlsm|dmp|cpl)\b", re.I)
DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|info|io|xyz|top|online|ru|cn|local)\b", re.I)
TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


@dataclass
class FaithfulnessResult:
    score: float
    problems: list[str] = field(default_factory=list)


def _corpus(alert: Alert, trace: Trace) -> str:
    parts = [json.dumps(alert.agent_view(), default=str)]
    parts += [json.dumps(c.result, default=str) for c in trace.tool_calls if not c.is_error and c.result is not None]
    return "\n".join(parts).lower().replace("\\\\", "\\")


def check(alert: Alert, trace: Trace) -> FaithfulnessResult:
    v = trace.verdict
    if v is None:
        return FaithfulnessResult(0.0, ["no verdict"])
    corpus = _corpus(alert, trace)
    ok_tools = {c.name for c in trace.tool_calls if not c.is_error and c.name != "submit_verdict"}
    problems = []
    for e in v.evidence:
        if e.tool not in ok_tools:
            problems.append(f"evidence cites tool '{e.tool}' that returned nothing")
        if e.event_ref and e.event_ref.lower() not in corpus:
            problems.append(f"event_ref {e.event_ref} not found")
    text = " ".join([v.summary, *(e.finding for e in v.evidence)])
    allowed_tech = {t.lower() for t in v.attack_techniques}
    for pattern in (IPV4, HEX, FILE, DOMAIN):
        for m in pattern.findall(text):
            if m.lower() not in corpus:
                problems.append(f"'{m}' does not appear in any tool result")
    for m in TECH.findall(text):
        if m.lower() not in corpus and m.lower() not in allowed_tech:
            problems.append(f"technique {m} unsupported")
    if not v.evidence and v.verdict.value != "needs_escalation":
        problems.append("no evidence entries")
    return FaithfulnessResult(0.0 if problems else 1.0, sorted(set(problems)))


JUDGE_PROMPT = """You check a SOC analyst's alert verdict for faithfulness. You get the verdict's summary and its \
evidence list. Decide, claim by claim, whether each factual claim in the summary is supported by at least one evidence \
entry. Ignore whether the verdict itself is right; judge only support. Reply with JSON."""

JUDGE_SCHEMA = {
    "type": "object",
    "properties": {
        "unsupported_claims": {"type": "array", "items": {"type": "string"}},
        "supported_fraction": {"type": "number"},
    },
    "required": ["unsupported_claims", "supported_fraction"],
    "additionalProperties": False,
}


class LLMJudge:
    """Claude-based faithfulness judge. Uses a cheaper model than the agent by default."""

    def __init__(self, model: str = "claude-haiku-4-5"):
        import anthropic

        self.model = model
        self._client = anthropic.Anthropic()

    def score(self, trace: Trace) -> dict[str, Any]:
        if trace.verdict is None:
            return {"supported_fraction": 0.0, "unsupported_claims": ["no verdict"]}
        payload = {"summary": trace.verdict.summary,
                   "evidence": [e.model_dump() for e in trace.verdict.evidence]}
        resp = self._client.messages.create(
            model=self.model, max_tokens=1024, system=JUDGE_PROMPT,
            messages=[{"role": "user", "content": json.dumps(payload)}],
            output_config={"format": {"type": "json_schema", "schema": JUDGE_SCHEMA}},
        )
        text = next(b.text for b in resp.content if b.type == "text")
        return json.loads(text)
