"""Tool plumbing: a Tool pairs a JSON-schema spec (from a Pydantic model) with a read-only function."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ValidationError

if TYPE_CHECKING:
    from agent.logstore import LogStore
    from agent.schemas import Alert
    from agent.tools.attack_map import AttackIndex
    from agent.tools.threat_intel import ThreatIntel

MAX_FIELD_CHARS = 2000


@dataclass
class ToolContext:
    logs: LogStore
    intel: ThreatIntel
    attack: AttackIndex
    assets: dict[str, Any]
    alert: Alert | None = None
    # Phase 2: per-alert replacements for stored events (injected variants), keyed by event_uid.
    event_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)

    def apply_overrides(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not self.event_overrides:
            return rows
        return [{**r, **self.event_overrides[r["event_uid"]]} if r.get("event_uid") in self.event_overrides else r
                for r in rows]


class ToolError(Exception):
    """Raised by a tool for a bad request the model can fix (reported back as is_error)."""


@dataclass
class Tool:
    name: str
    description: str
    args_model: type[BaseModel]
    fn: Callable[[ToolContext, Any], Any]

    def spec(self) -> dict[str, Any]:
        schema = self.args_model.model_json_schema()
        schema.pop("title", None)
        for prop in schema.get("properties", {}).values():
            prop.pop("title", None)
        return {"name": self.name, "description": self.description, "parameters": schema}

    def run(self, ctx: ToolContext, arguments: dict[str, Any]) -> Any:
        try:
            args = self.args_model.model_validate(arguments)
        except ValidationError as e:
            raise ToolError(f"invalid arguments: {e.errors(include_url=False)}") from e
        return self.fn(ctx, args)


def clip(rec: dict[str, Any]) -> dict[str, Any]:
    """Drop empty fields and truncate long strings so one event can't flood the context."""
    out = {}
    for k, v in rec.items():
        if v is None or v == "":
            continue
        if isinstance(v, str) and len(v) > MAX_FIELD_CHARS:
            v = v[:MAX_FIELD_CHARS] + f"...[truncated {len(v) - MAX_FIELD_CHARS} chars]"
        out[k] = v
    return out
