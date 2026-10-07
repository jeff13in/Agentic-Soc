"""A small Sigma-style rule engine over normalized events.

Supported syntax: ``detection.selection`` (all fields must match) and an optional
``detection.filter`` (an event matching it is suppressed). Field modifiers: ``contains``,
``startswith``, ``endswith``, ``re``; no modifier means case-insensitive equality. A list of
values means any of them may match.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

RULES_DIR = Path(__file__).resolve().parent / "rules"


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    tags: tuple[str, ...]
    description: str
    selection: dict[str, Any]
    filter: dict[str, Any] | None


def load_rules(rules_dir: Path = RULES_DIR) -> list[Rule]:
    rules = []
    for path in sorted(rules_dir.glob("*.yml")):
        r = yaml.safe_load(path.read_text())
        det = r["detection"]
        rules.append(Rule(r["id"], r["name"], r["severity"], tuple(r.get("tags", [])), r.get("description", ""),
                          det["selection"], det.get("filter")))
    return rules


def _match_value(actual: Any, modifier: str | None, expected: Any) -> bool:
    if actual is None:
        return False
    candidates = expected if isinstance(expected, list) else [expected]
    if modifier is None and isinstance(actual, int) and not isinstance(actual, bool):
        return any(str(actual) == str(c) for c in candidates)
    a = str(actual)
    al = a.lower()
    for c in candidates:
        c = str(c)
        if modifier == "re":
            if re.search(c, a):
                return True
        elif modifier == "contains":
            if c.lower() in al:
                return True
        elif modifier == "startswith":
            if al.startswith(c.lower()):
                return True
        elif modifier == "endswith":
            if al.endswith(c.lower()):
                return True
        elif al == c.lower():
            return True
    return False


def _match_block(event: dict[str, Any], block: dict[str, Any]) -> bool:
    for key, expected in block.items():
        field, _, modifier = key.partition("|")
        if not _match_value(event.get(field), modifier or None, expected):
            return False
    return True


def matches(rule: Rule, event: dict[str, Any]) -> bool:
    if not _match_block(event, rule.selection):
        return False
    return not (rule.filter and _match_block(event, rule.filter))


def run_rules(events: list[dict[str, Any]], rules: list[Rule]) -> list[tuple[Rule, dict[str, Any]]]:
    hits = []
    for ev in events:
        for rule in rules:
            if matches(rule, ev):
                hits.append((rule, ev))
    return hits
