"""Offline ATT&CK technique lookup.

Uses BM25 over technique names and descriptions. Loads the full MITRE ATT&CK STIX bundle from
data/attack/enterprise-attack.json when present, otherwise a bundled 46-technique subset.
Deterministic and offline, so eval scores don't depend on an embedding service; swapping in an
embedding index only changes AttackIndex.search.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path

from pydantic import BaseModel, Field

from agent.tools.base import Tool, ToolContext

TOKEN = re.compile(r"[a-z0-9]+")
STOP = {"the", "a", "an", "of", "to", "or", "and", "in", "on", "by", "for", "with", "as", "is", "are", "e", "g",
        "such", "via", "from", "that", "be", "used", "using", "into", "other"}


def _tokens(text: str) -> list[str]:
    return [t for t in TOKEN.findall(text.lower()) if t not in STOP]


def load_techniques(attack_dir: Path) -> list[dict]:
    stix = attack_dir / "enterprise-attack.json"
    if stix.exists():
        out = []
        for obj in json.loads(stix.read_text())["objects"]:
            if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            ext = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
            if ext:
                tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]
                out.append({"id": ext["external_id"], "name": obj["name"], "tactic": ",".join(tactics),
                            "description": obj.get("description", "")[:1500]})
        return out
    return json.loads((attack_dir / "techniques.json").read_text())


class AttackIndex:
    def __init__(self, techniques: list[dict], k1: float = 1.4, b: float = 0.75):
        self.techniques = techniques
        self.docs = [Counter(_tokens(f"{t['id']} {t['name']} {t['name']} {t['description']}")) for t in techniques]
        self.lengths = [sum(d.values()) for d in self.docs]
        self.avg = sum(self.lengths) / max(len(self.lengths), 1)
        df = Counter(tok for d in self.docs for tok in d)
        n = len(self.docs)
        self.idf = {tok: math.log(1 + (n - f + 0.5) / (f + 0.5)) for tok, f in df.items()}
        self.k1, self.b = k1, b
        self.by_id = {t["id"]: t for t in techniques}

    def search(self, query: str, k: int = 5) -> list[dict]:
        q = _tokens(query)
        scores = []
        for i, doc in enumerate(self.docs):
            s = 0.0
            for tok in q:
                f = doc.get(tok)
                if f:
                    s += self.idf[tok] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * self.lengths[i] / self.avg))
            if s > 0:
                scores.append((s, i))
        scores.sort(reverse=True)
        return [{"id": self.techniques[i]["id"], "name": self.techniques[i]["name"],
                 "tactic": self.techniques[i]["tactic"], "score": round(s, 2)} for s, i in scores[:k]]


class AttackArgs(BaseModel):
    behavior: str = Field(min_length=3, description="Plain-language description of the observed behavior")
    k: int = Field(5, ge=1, le=10)


def map_attack(ctx: ToolContext, a: AttackArgs) -> dict:
    return {"candidates": ctx.attack.search(a.behavior, a.k),
            "note": "lexical match; confirm the technique fits the evidence before citing it"}


TOOL = Tool(
    name="map_attack",
    description="Suggest MITRE ATT&CK technique IDs for a behavior description, ranked by relevance.",
    args_model=AttackArgs,
    fn=map_attack,
)
