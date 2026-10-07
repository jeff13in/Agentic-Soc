from __future__ import annotations

import json
from types import SimpleNamespace as NS

from agent.config import Settings
from agent.llm.anthropic_client import FALLBACK_BETA, AnthropicClient
from agent.llm.base import LLMResponse, ToolCall, ToolResult
from agent.llm.vllm_client import VLLMClient

TOOLS = [{"name": "lookup_ip", "description": "d", "parameters": {"type": "object", "properties": {}}}]


class Block(NS):
    def model_dump(self, exclude_none=True):
        return {k: v for k, v in vars(self).items() if v is not None}


class FakeAnthropic:
    def __init__(self, resp):
        self.calls = []
        self.beta = NS(messages=NS(create=self._create))
        self.messages = NS(create=self._create)
        self.resp = resp

    def _create(self, **kw):
        self.calls.append(kw)
        return self.resp


def anthropic_resp(stop="tool_use", model="claude-sonnet-5-5"):
    return NS(content=[Block(type="thinking", thinking="", signature="sig"), Block(type="text", text="checking"),
                       Block(type="tool_use", id="tu1", name="lookup_ip", input={"ip": "1.2.3.4"})],
              stop_reason=stop, model=model, stop_details=None,
              usage=NS(input_tokens=1000, output_tokens=100, cache_read_input_tokens=5000, cache_creation_input_tokens=0))


def test_anthropic_request_shape_and_parsing():
    fake = FakeAnthropic(anthropic_resp())
    c = AnthropicClient(Settings(), client=fake)
    r = c.chat("sys", [{"role": "user", "content": "alert"}], TOOLS)
    kw = fake.calls[0]
    assert kw["betas"] == [FALLBACK_BETA] and kw["fallbacks"] == "default"
    assert kw["model"] == "claude-sonnet-5-5" and kw["output_config"] == {"effort": "medium"}
    assert "temperature" not in kw and "tool_choice" not in kw
    assert kw["tools"][0]["input_schema"] == TOOLS[0]["parameters"]
    assert r.tool_calls[0].arguments == {"ip": "1.2.3.4"} and r.text == "checking"
    # cost: 1000 in + 5000 cache read at 10% + 100 out, at $2/$10 per MTok
    assert abs(c.cost_usd(r, 1.0) - (1000 * 2 + 5000 * 0.2 + 100 * 10) / 1e6) < 1e-12


def test_anthropic_history_replays_raw_blocks_and_batches_tool_results():
    fake = FakeAnthropic(anthropic_resp())
    c = AnthropicClient(Settings(), client=fake)
    first = c.chat("sys", [{"role": "user", "content": "alert"}], TOOLS)
    history = [{"role": "user", "content": "alert"}, {"role": "assistant", "response": first},
               {"role": "tool", "results": [ToolResult("tu1", "lookup_ip", "{}"), ToolResult("tu2", "x", "e", True)],
                "note": "wrap up"}]
    wire = c.to_wire(history)
    assert wire[1]["content"][0]["type"] == "thinking"  # thinking block preserved verbatim
    assert [b["type"] for b in wire[2]["content"]] == ["tool_result", "tool_result", "text"]
    assert wire[2]["content"][1]["is_error"] is True


def test_anthropic_refusal_raises():
    import pytest

    from agent.llm.base import RefusalError

    c = AnthropicClient(Settings(claude_fallbacks=False), client=FakeAnthropic(anthropic_resp(stop="refusal")))
    with pytest.raises(RefusalError):
        c.chat("s", [{"role": "user", "content": "a"}], TOOLS)


def test_vllm_wire_format_and_bad_json_arguments():
    msg = NS(content=None, tool_calls=[
        NS(id="a", function=NS(name="lookup_ip", arguments='{"ip": "1.1.1.1"}')),
        NS(id="b", function=NS(name="lookup_hash", arguments="{broken"))])
    resp = NS(choices=[NS(message=msg, finish_reason="tool_calls")], model="soc-qwen-lora",
              usage=NS(prompt_tokens=50, completion_tokens=5))
    calls = []
    fake = NS(chat=NS(completions=NS(create=lambda **kw: calls.append(kw) or resp)))
    c = VLLMClient(Settings(), client=fake)
    r = c.chat("sys", [{"role": "user", "content": "x"}], TOOLS)
    assert calls[0]["temperature"] == 0 and calls[0]["messages"][0] == {"role": "system", "content": "sys"}
    assert r.tool_calls[0].arguments == {"ip": "1.1.1.1"} and r.tool_calls[1].parse_error
    prior = LLMResponse("", [ToolCall("a", "lookup_ip", {"ip": "1.1.1.1"})], "tool_calls", "m")
    wire = c.to_wire("s", [{"role": "user", "content": "x"}, {"role": "assistant", "response": prior},
                           {"role": "tool", "results": [ToolResult("a", "lookup_ip", "{}")]}])
    assert json.loads(wire[2]["tool_calls"][0]["function"]["arguments"]) == {"ip": "1.1.1.1"}
    assert wire[3] == {"role": "tool", "tool_call_id": "a", "content": "{}"}
    assert c.cost_usd(r, 3600) == Settings().vllm_gpu_usd_per_hour / Settings().vllm_concurrency
