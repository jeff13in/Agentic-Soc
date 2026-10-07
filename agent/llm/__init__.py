from __future__ import annotations

from agent.config import Settings
from agent.llm.base import LLMClient


def make_client(backend: str, settings: Settings, model: str | None = None) -> LLMClient:
    if backend == "claude":
        from agent.llm.anthropic_client import AnthropicClient

        return AnthropicClient(settings, model)
    if backend == "vllm":
        from agent.llm.vllm_client import VLLMClient

        return VLLMClient(settings, model)
    if backend == "heuristic":
        from agent.llm.heuristic_client import HeuristicClient

        return HeuristicClient()
    raise ValueError(f"unknown backend {backend!r} (expected claude, vllm or heuristic)")
