"""Tool registry. Every tool is read-only; submit_verdict is handled by the loop itself."""

from __future__ import annotations

from typing import Any

import yaml

from agent.config import ROOT, Settings
from agent.logstore import LogStore
from agent.schemas import Verdict
from agent.tools import host_context, process_tree, search_logs
from agent.tools.attack_map import TOOL as ATTACK_TOOL
from agent.tools.attack_map import AttackIndex, load_techniques
from agent.tools.base import Tool, ToolContext
from agent.tools.threat_intel import DOMAIN_TOOL, HASH_TOOL, IP_TOOL, ThreatIntel

TOOLS: dict[str, Tool] = {t.name: t for t in [
    search_logs.TOOL, process_tree.TOOL, IP_TOOL, HASH_TOOL, DOMAIN_TOOL, ATTACK_TOOL, host_context.TOOL,
]}

SUBMIT_VERDICT = "submit_verdict"


def _inline_refs(schema: dict[str, Any]) -> dict[str, Any]:
    defs = schema.pop("$defs", {})

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            if "$ref" in node:
                return walk(dict(defs[node["$ref"].split("/")[-1]]))
            return {k: walk(v) for k, v in node.items() if k != "title"}
        if isinstance(node, list):
            return [walk(x) for x in node]
        return node

    return walk(schema)


def submit_verdict_spec() -> dict[str, Any]:
    return {
        "name": SUBMIT_VERDICT,
        "description": "Submit the final triage verdict. Ends the investigation. Every claim in summary must be "
                       "backed by an evidence entry citing the tool that produced it.",
        "parameters": _inline_refs(Verdict.model_json_schema()),
    }


def tool_specs() -> list[dict[str, Any]]:
    return [t.spec() for t in TOOLS.values()] + [submit_verdict_spec()]


def build_context(settings: Settings, logs: LogStore | None = None) -> ToolContext:
    logs = logs or LogStore(settings.data_dir / "events.parquet")
    intel = ThreatIntel(settings.intel_mode, settings.data_dir / "mock_intel.json",
                        ROOT / "data" / "intel" / "live_cache.json",
                        settings.abuseipdb_api_key, settings.virustotal_api_key)
    attack = AttackIndex(load_techniques(ROOT / "data" / "attack"))
    assets = yaml.safe_load((ROOT / "data" / "assets.yml").read_text())
    return ToolContext(logs=logs, intel=intel, attack=attack, assets=assets)
