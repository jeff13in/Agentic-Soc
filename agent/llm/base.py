"""Provider-neutral LLM interface used by the investigation loop.

The loop keeps one neutral history; each adapter converts it to its provider's wire format:
    {"role": "user", "content": str}
    {"role": "assistant", "response": LLMResponse}           # replayed verbatim by its adapter
    {"role": "tool", "results": [ToolResult, ...]}
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any] | None
    parse_error: str | None = None  # set when the model emitted arguments that aren't valid JSON


@dataclass
class ToolResult:
    call_id: str
    name: str
    content: str
    is_error: bool = False


@dataclass
class LLMResponse:
    text: str
    tool_calls: list[ToolCall]
    stop_reason: str | None
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    raw: Any = field(default=None, repr=False)  # provider-native assistant content, for replay


class RefusalError(RuntimeError):
    """The provider declined the request (after any configured fallback)."""


class LLMClient(Protocol):
    backend: str
    model: str

    def chat(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMResponse: ...

    def cost_usd(self, response: LLMResponse, latency_s: float) -> float: ...
