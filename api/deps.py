"""Shared, lazily built state for the API process."""

from __future__ import annotations

from functools import lru_cache

from agent.config import Settings, get_settings
from agent.schemas import LabelledAlert
from agent.store import TraceStore
from agent.tools import build_context
from agent.tools.base import ToolContext


@lru_cache
def settings() -> Settings:
    return get_settings()


@lru_cache
def store() -> TraceStore:
    return TraceStore(settings().db_path)


@lru_cache
def tool_context() -> ToolContext:
    return build_context(settings())


@lru_cache
def alerts() -> dict[str, LabelledAlert]:
    out: dict[str, LabelledAlert] = {}
    for split in ("dev", "test", "review"):
        path = settings().labels_dir / f"{split}.jsonl"
        if path.exists():
            for line in path.read_text().splitlines():
                if line.strip():
                    la = LabelledAlert.model_validate_json(line)
                    out[la.alert.alert_id] = la
    return out
