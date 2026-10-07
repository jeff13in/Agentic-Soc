"""Deterministic rule-based backend that speaks the LLMClient interface.

It walks a fixed investigation plan through the same tools and the same loop as the LLM
backends, then scores the evidence with hand-written weights. Uses:
  * runs the whole pipeline offline and in CI, with no API key or GPU;
  * a floor every model has to beat.
Its weights were written alongside the benign generator, so its score on generated false
positives is optimistic. It never reads free-text instructions, so it is immune to prompt
injection by construction; that is a property of rules, not a defense worth reporting. With the
sanitize defense on it treats flagged fields as evidence of malice, as the v2 prompt asks an LLM to.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import Any

from agent.defenses.sanitizer import flagged_fields
from agent.llm.base import LLMResponse, ToolCall

MGMT_PARENTS = ("\\ccmexec.exe", "\\msiexec.exe", "\\msmpeng.exe", "\\services.exe")
OFFICE = ("\\winword.exe", "\\excel.exe", "\\powerpnt.exe", "\\outlook.exe")
USER_WRITABLE = ("\\users\\public\\", "\\appdata\\", "\\temp\\", "\\downloads\\", "\\perflogs\\")
DUMP_ACCESS = {"0x1fffff", "0x1010", "0x1f3fff", "0x143a"}
JSON_BLOCK = re.compile(r"```json\n(.*?)\n```", re.S)
TAGGED = re.compile(r"<untrusted_tool_result[^>]*>\n?(.*?)\n?</untrusted_tool_result>", re.S)


def _load(content: str) -> Any:
    m = TAGGED.search(content)
    try:
        return json.loads(m.group(1) if m else content)
    except (json.JSONDecodeError, TypeError):
        return None


class HeuristicClient:
    backend = "heuristic"
    model = "heuristic-v1"

    def chat(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMResponse:
        alert = json.loads(JSON_BLOCK.search(messages[0]["content"]).group(1))
        calls_made: list[ToolCall] = []
        results: dict[str, Any] = {}
        for m in messages:
            if m["role"] == "assistant":
                calls_made += m["response"].tool_calls
            elif m["role"] == "tool":
                for r in m["results"]:
                    results[r.call_id] = None if r.is_error else _load(r.content)
        done = {self._key(c.name, c.arguments or {}) for c in calls_made}
        by_tool: dict[str, list[Any]] = {}
        for c in calls_made:
            by_tool.setdefault(c.name, []).append(results.get(c.id))

        for name, args in self._plan(alert, by_tool):
            if self._key(name, args) not in done:
                return self._call(name, args, len(calls_made))
        return self._call("submit_verdict", self._verdict(alert, by_tool), len(calls_made))

    @staticmethod
    def _key(name: str, args: dict[str, Any]) -> str:
        return name + json.dumps(args, sort_keys=True)

    def _call(self, name: str, args: dict[str, Any], n: int) -> LLMResponse:
        return LLMResponse(text="", tool_calls=[ToolCall(id=f"h{n}", name=name, arguments=args)],
                           stop_reason="tool_use", model=self.model)

    def _plan(self, alert: dict[str, Any], by_tool: dict[str, list[Any]]) -> list[tuple[str, dict[str, Any]]]:
        host = alert["host"]
        ts = datetime.fromisoformat(alert["timestamp"])
        raw = alert.get("raw_event", {})
        plan: list[tuple[str, dict[str, Any]]] = [("get_host_context", {"host": host})]
        if alert.get("process_guid"):
            plan.append(("get_process_tree", {"host": host, "process_guid": alert["process_guid"]}))
            plan.append(("search_logs", {"host": host, "start_time": (ts - timedelta(minutes=10)).isoformat(),
                                         "end_time": (ts + timedelta(minutes=30)).isoformat(),
                                         "process_guid": alert["process_guid"]}))
        else:
            plan.append(("search_logs", {"host": host, "start_time": (ts - timedelta(minutes=5)).isoformat(),
                                         "end_time": (ts + timedelta(minutes=5)).isoformat()}))
        if raw.get("sha256"):
            plan.append(("lookup_hash", {"sha256": raw["sha256"]}))
        ips, domains = [], []
        for res in by_tool.get("search_logs", []):
            for ev in (res or {}).get("events", []):
                if ev.get("dst_ip") and ev["dst_ip"] not in ips:
                    ips.append(ev["dst_ip"])
                if ev.get("query_name") and ev["query_name"] not in domains:
                    domains.append(ev["query_name"])
        plan += [("lookup_ip", {"ip": ip}) for ip in ips[:2]]
        plan += [("lookup_domain", {"domain": d}) for d in domains[:2]]
        plan.append(("map_attack", {"behavior": alert["rule_name"]}))
        return plan

    def _verdict(self, alert: dict[str, Any], by_tool: dict[str, list[Any]]) -> dict[str, Any]:
        score = 0
        ev: list[dict[str, str]] = []

        def add(points: int, tool: str, finding: str, ref: str | None = None) -> None:
            nonlocal score
            score += points
            ev.append({"tool": tool, "finding": finding, **({"event_ref": ref} if ref else {})})

        image = (alert.get("image") or "").lower()
        host_ctx = next(iter(by_tool.get("get_host_context", [])), None) or {}
        tree = next(iter(by_tool.get("get_process_tree", [])), None) or {}
        chain = [(a.get("image") or "").lower() for a in tree.get("ancestors_nearest_first", [])]
        if not chain and alert.get("parent_image"):
            chain = [alert["parent_image"].lower()]

        for h in by_tool.get("lookup_hash", []):
            if not h:
                continue
            if h.get("status") == "found" and (h.get("detections") or 0) >= 5:
                add(4, "lookup_hash", f"{h['sha256'][:12]}... flagged by {h['detections']} engines ({h.get('family')})")
            elif h.get("status") == "found" and h.get("signed") and not h.get("detections"):
                add(-1, "lookup_hash", f"hash is known-clean and signed ({', '.join(h.get('names') or [])})")
            elif h.get("status") == "not_found" and any(p in image for p in USER_WRITABLE):
                add(2, "lookup_hash", f"unknown binary running from a user-writable path: {alert.get('image')}")
        for ip in by_tool.get("lookup_ip", []):
            if ip and (ip.get("abuse_confidence") or 0) >= 50:
                add(3, "lookup_ip", f"{ip['ip']} has abuse confidence {ip['abuse_confidence']}")
        for d in by_tool.get("lookup_domain", []):
            if d and d.get("status") == "found" and ((d.get("malicious_votes") or 0) > 0 or (d.get("age_days") or 9999) < 30):
                add(3, "lookup_domain", f"{d['domain']} is {d.get('age_days')} days old with {d.get('malicious_votes')} malicious votes")

        if any(p.endswith(OFFICE) for p in chain[:2]):
            add(2, "get_process_tree", f"spawned by an Office application ({chain[0].split(chr(92))[-1]})")
        raw = alert.get("raw_event", {})
        if alert["event_id"] == 10 and str(raw.get("granted_access", "")).lower() in DUMP_ACCESS \
                and "\\program" not in image and "\\windows\\system32\\taskmgr" not in image:
            add(3, "search_logs", f"{alert.get('image')} opened LSASS with {raw.get('granted_access')}",
                alert["event_uid"])
        svc = str(raw.get("service_path", "")).lower()
        if alert["event_id"] == 7045 and ("admin$" in svc or "%comspec%" in svc or
                                          ("\\program files" not in svc and "\\programdata\\microsoft\\windows defender" not in svc)):
            add(3, "search_logs", f"service '{raw.get('service_name')}' runs from an unusual path", alert["event_uid"])
        if any(p.endswith(MGMT_PARENTS) for p in chain[:2]) or "\\program files" in image or "\\windows defender\\" in image:
            add(-3, "get_process_tree", f"launched by a management or vendor component ({(chain or [image])[0].split(chr(92))[-1]})")
        user = (alert.get("user") or "").lower()
        if host_ctx.get("role") not in (None, "workstation") and user in [a.lower() for a in host_ctx.get("admins", [])]:
            add(-1, "get_host_context", f"{alert.get('user')} is a known admin on {host_ctx.get('role')} {alert['host']}")
        # Only present when the sanitize defense is on: the loop annotates, this backend never scans text itself.
        injected = sorted(set(flagged_fields(alert) + flagged_fields(by_tool)))
        if injected:
            add(3, "search_logs", f"instruction-like text injected into {', '.join(injected)}", alert["event_uid"])
        if alert["rule_severity"] in ("high", "critical"):
            score += 1

        if score >= 3:
            label = "true_positive"
        elif score <= 0:
            label = "false_positive"
        else:
            label = "needs_escalation"
        if not ev:
            ev.append({"tool": "get_host_context",
                       "finding": f"{alert['host']} is a {host_ctx.get('role', 'unknown')} host; no malicious indicators found"})
        sev = alert["rule_severity"] if label == "true_positive" else ("low" if label == "false_positive" else "medium")
        if label == "true_positive" and host_ctx.get("criticality") == "critical":
            sev = "critical"
        techniques = list(alert.get("rule_tags", [])) if label == "true_positive" else []
        summary = (f"Rule '{alert['rule_name']}' on {alert['host']} scored {score}: "
                   + "; ".join(e["finding"] for e in ev[:4]) + ".")
        actions = {"true_positive": ["Isolate the host pending analyst review", "Collect the process image and memory"],
                   "false_positive": ["Close as benign; consider tuning the rule for this activity"],
                   "needs_escalation": ["Escalate to Tier-2 for manual review"]}[label]
        return {"alert_id": alert["alert_id"], "verdict": label, "confidence": round(min(0.95, 0.5 + 0.1 * abs(score)), 2),
                "severity": sev, "attack_techniques": techniques, "summary": summary, "evidence": ev,
                "recommended_actions": actions}

    def cost_usd(self, response: LLMResponse, latency_s: float) -> float:
        return 0.0
