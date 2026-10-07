"""Bounded ReAct-style investigation loop.

read alert -> model picks tools -> results appended -> repeat until submit_verdict, the step
budget (tool calls) or the time budget runs out. The verdict is validated with Pydantic; one
repair attempt is allowed, after which the alert is escalated. Every prompt, tool call, result
and token count is recorded in the Trace.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from agent.defenses import tagging
from agent.llm.base import LLMClient, RefusalError, ToolResult
from agent.schemas import Alert, ModelTurnRecord, ToolCallRecord, Trace, Verdict
from agent.store import TraceStore
from agent.tools import SUBMIT_VERDICT, TOOLS, tool_specs
from agent.tools.base import ToolContext, ToolError

PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"
KNOWN_DEFENSES = {"tagging"}

NUDGE = "Call submit_verdict now. Do not reply in plain text."
FINAL = "The investigation budget is used up. Call submit_verdict now with the evidence you already have."


def load_prompt(version: str) -> tuple[str, str]:
    text = (PROMPTS_DIR / f"{version}.md").read_text()
    return text, hashlib.sha256(text.encode()).hexdigest()[:12]


def alert_message(alert: Alert) -> str:
    return ("Investigate this alert and submit a verdict.\n\nALERT:\n```json\n"
            + json.dumps(alert.agent_view(), indent=1) + "\n```")


@dataclass
class LoopConfig:
    max_steps: int = 10
    max_seconds: float = 60.0
    prompt_version: str = "v1"
    defenses: list[str] = field(default_factory=list)
    max_repairs: int = 1


def _summarize_validation(e: ValidationError) -> str:
    return "; ".join(f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in e.errors(include_url=False))


def triage(alert: Alert, client: LLMClient, ctx: ToolContext, cfg: LoopConfig,
           run_id: str | None = None, store: TraceStore | None = None) -> Trace:
    unknown = set(cfg.defenses) - KNOWN_DEFENSES
    if unknown:
        raise ValueError(f"unknown defenses: {sorted(unknown)}")
    ctx = replace(ctx, alert=alert)
    system, prompt_hash = load_prompt(cfg.prompt_version)
    specs = tool_specs()
    trace = Trace(trace_id=str(uuid.uuid4()), alert_id=alert.alert_id, run_id=run_id, backend=client.backend,
                  model=client.model, prompt_version=cfg.prompt_version, prompt_hash=prompt_hash,
                  defenses=list(cfg.defenses), started_at=datetime.now(UTC))
    messages: list[dict[str, Any]] = [{"role": "user", "content": alert_message(alert)}]
    t0 = time.monotonic()
    steps = repairs = nudges = 0
    final_call = False
    max_turns = cfg.max_steps + 4

    try:
        for turn in range(max_turns):
            t_call = time.monotonic()
            resp = client.chat(system, messages, specs)
            latency = time.monotonic() - t_call
            trace.turns.append(ModelTurnRecord(
                step=turn, text=resp.text, tool_calls=[c.name for c in resp.tool_calls],
                input_tokens=resp.input_tokens + resp.cache_write_tokens + resp.cache_read_tokens,
                output_tokens=resp.output_tokens, cache_read_tokens=resp.cache_read_tokens,
                latency_ms=latency * 1000, stop_reason=resp.stop_reason, model=resp.model))
            trace.input_tokens += resp.input_tokens + resp.cache_write_tokens + resp.cache_read_tokens
            trace.output_tokens += resp.output_tokens
            trace.cost_usd += client.cost_usd(resp, latency)
            messages.append({"role": "assistant", "response": resp})

            if not resp.tool_calls:
                nudges += 1
                if nudges > 2 or final_call:
                    trace.status = "budget_exhausted"
                    break
                messages.append({"role": "user", "content": NUDGE})
                continue

            results: list[ToolResult] = []
            for call in resp.tool_calls:
                rec = ToolCallRecord(step=turn, call_id=call.id, name=call.name, arguments=call.arguments or {})
                t_tool = time.monotonic()
                if call.parse_error:
                    rec.is_error, rec.error = True, call.parse_error
                elif call.name == SUBMIT_VERDICT:
                    try:
                        verdict = Verdict.model_validate({"alert_id": alert.alert_id, **call.arguments})
                        if verdict.alert_id != alert.alert_id:
                            raise ValueError(f"alert_id must be {alert.alert_id}")
                        trace.verdict = verdict
                        trace.status = "repaired" if repairs else "ok"
                        rec.result = "accepted"
                    except (ValidationError, ValueError) as e:
                        repairs += 1
                        msg = _summarize_validation(e) if isinstance(e, ValidationError) else str(e)
                        rec.is_error, rec.error = True, f"verdict rejected: {msg}"
                elif call.name not in TOOLS:
                    rec.is_error, rec.error = True, f"unknown tool {call.name!r}"
                elif steps >= cfg.max_steps:
                    rec.is_error, rec.error = True, "step budget exhausted; call submit_verdict"
                else:
                    steps += 1
                    try:
                        rec.result = TOOLS[call.name].run(ctx, call.arguments)
                    except ToolError as e:
                        rec.is_error, rec.error = True, str(e)
                    except Exception as e:  # a tool bug must not kill the investigation
                        rec.is_error, rec.error = True, f"tool failed: {type(e).__name__}: {e}"
                rec.latency_ms = (time.monotonic() - t_tool) * 1000
                trace.tool_calls.append(rec)
                content = json.dumps(rec.result, default=str) if not rec.is_error else json.dumps({"error": rec.error})
                if "tagging" in cfg.defenses and call.name != SUBMIT_VERDICT:
                    content = tagging.wrap(call.name, call.id, content)
                results.append(ToolResult(call.id, call.name, content, rec.is_error))

            if trace.verdict is not None:
                break
            if repairs > cfg.max_repairs:
                trace.status = "invalid_verdict"
                break
            if final_call:
                trace.status = "budget_exhausted"
                break
            note = None
            if steps >= cfg.max_steps or time.monotonic() - t0 > cfg.max_seconds:
                final_call = True
                note = FINAL
            messages.append({"role": "tool", "results": results, **({"note": note} if note else {})})
        else:
            trace.status = "budget_exhausted"
    except RefusalError as e:
        trace.status, trace.error = "refusal", str(e)
    except Exception as e:
        trace.status, trace.error = "error", f"{type(e).__name__}: {e}"

    trace.latency_s = time.monotonic() - t0
    if store is not None:
        store.save_trace(trace)
    return trace
