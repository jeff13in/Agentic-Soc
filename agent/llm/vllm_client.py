"""Adapter for a local model behind vLLM's (or SGLang's) OpenAI-compatible server."""

from __future__ import annotations

import json
from typing import Any

from openai import OpenAI

from agent.config import Settings
from agent.llm.base import LLMResponse, ToolCall


class VLLMClient:
    backend = "vllm"

    def __init__(self, settings: Settings, model: str | None = None, client: OpenAI | None = None):
        self.model = model or settings.vllm_model
        self.gpu_usd_per_hour = settings.vllm_gpu_usd_per_hour
        self.concurrency = max(settings.vllm_concurrency, 1)
        self._client = client or OpenAI(base_url=settings.vllm_base_url, api_key=settings.vllm_api_key)

    @staticmethod
    def to_wire(system: str, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        wire: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for m in messages:
            if m["role"] == "user":
                wire.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                r = m["response"]
                msg: dict[str, Any] = {"role": "assistant", "content": r.text or None}
                if r.tool_calls:
                    msg["tool_calls"] = [{"id": c.id, "type": "function", "function": {
                        "name": c.name, "arguments": json.dumps(c.arguments) if c.arguments is not None else "{}"}}
                        for c in r.tool_calls]
                wire.append(msg)
            elif m["role"] == "tool":
                for res in m["results"]:
                    wire.append({"role": "tool", "tool_call_id": res.call_id, "content": res.content})
                if m.get("note"):
                    wire.append({"role": "user", "content": m["note"]})
        return wire

    def chat(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMResponse:
        extra = {"tools": [{"type": "function", "function": t} for t in tools], "tool_choice": "auto"} if tools else {}
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=self.to_wire(system, messages),
            temperature=0,
            max_tokens=4096,
            **extra,
        )
        choice = resp.choices[0]
        calls = []
        for tc in choice.message.tool_calls or []:
            try:
                args = json.loads(tc.function.arguments or "{}")
                err = None if isinstance(args, dict) else "arguments are not a JSON object"
            except json.JSONDecodeError as e:
                args, err = None, f"invalid JSON arguments: {e}"
            calls.append(ToolCall(id=tc.id, name=tc.function.name, arguments=args if err is None else None,
                                  parse_error=err))
        u = resp.usage
        return LLMResponse(text=choice.message.content or "", tool_calls=calls, stop_reason=choice.finish_reason,
                           model=resp.model, input_tokens=u.prompt_tokens if u else 0,
                           output_tokens=u.completion_tokens if u else 0)

    def cost_usd(self, r: LLMResponse, latency_s: float) -> float:
        # GPU time attributed to this call, assuming the server was saturated at `concurrency`.
        return latency_s * self.gpu_usd_per_hour / 3600 / self.concurrency
