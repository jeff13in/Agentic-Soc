"""Claude adapter (Anthropic Messages API, native tool use)."""

from __future__ import annotations

from typing import Any

import anthropic

from agent.config import PRICING, Settings
from agent.llm.base import LLMResponse, RefusalError, ToolCall

FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_TOKENS = 16000


class AnthropicClient:
    backend = "claude"

    def __init__(self, settings: Settings, model: str | None = None, client: anthropic.Anthropic | None = None):
        self.model = model or settings.claude_model
        self.effort = settings.claude_effort
        self.fallbacks = settings.claude_fallbacks
        self._client = client or anthropic.Anthropic()

    @staticmethod
    def to_wire(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        wire: list[dict[str, Any]] = []
        for m in messages:
            if m["role"] == "user":
                wire.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                # Replay the provider's own content blocks unchanged (keeps thinking blocks valid).
                wire.append({"role": "assistant", "content": m["response"].raw})
            elif m["role"] == "tool":
                blocks = [{"type": "tool_result", "tool_use_id": r.call_id, "content": r.content,
                           "is_error": r.is_error} for r in m["results"]]
                if m.get("note"):
                    blocks.append({"type": "text", "text": m["note"]})
                wire.append({"role": "user", "content": blocks})
        return wire

    @staticmethod
    def to_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]} for t in tools]

    def chat(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMResponse:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": MAX_TOKENS,
            "system": system,
            "tools": self.to_tools(tools),
            "messages": self.to_wire(messages),
            "output_config": {"effort": self.effort},
            # System prompt and tools are identical across alerts; cache that prefix.
            "cache_control": {"type": "ephemeral"},
        }
        if self.fallbacks:
            resp = self._client.beta.messages.create(betas=[FALLBACK_BETA], fallbacks="default", **kwargs)
        else:
            resp = self._client.messages.create(**kwargs)

        if resp.stop_reason == "refusal":
            details = getattr(resp, "stop_details", None)
            raise RefusalError(f"model declined: {getattr(details, 'category', None)}")

        text_parts, calls = [], []
        for block in resp.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                calls.append(ToolCall(id=block.id, name=block.name,
                                      arguments=block.input if isinstance(block.input, dict) else None,
                                      parse_error=None if isinstance(block.input, dict) else "input is not an object"))
        u = resp.usage
        return LLMResponse(
            text="\n".join(text_parts), tool_calls=calls, stop_reason=resp.stop_reason, model=resp.model,
            input_tokens=u.input_tokens or 0, output_tokens=u.output_tokens or 0,
            cache_read_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
            cache_write_tokens=getattr(u, "cache_creation_input_tokens", 0) or 0,
            raw=[b.model_dump(exclude_none=True) for b in resp.content],
        )

    def cost_usd(self, r: LLMResponse, latency_s: float) -> float:
        inp, out = PRICING.get(r.model, PRICING.get(self.model, (0.0, 0.0)))
        return (r.input_tokens * inp + r.cache_write_tokens * inp * 1.25 + r.cache_read_tokens * inp * 0.1
                + r.output_tokens * out) / 1e6
