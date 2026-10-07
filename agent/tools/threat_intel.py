"""Threat-intel lookups with three modes.

mock  - recorded responses only (data/generated/mock_intel.json); used for evals so scores
        don't move when a vendor's data changes
cache - recorded/cached responses first, live API on a miss, result written to the cache
live  - always call AbuseIPDB / VirusTotal
"""

from __future__ import annotations

import ipaddress
import json
import re
import threading
import time
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, Field, field_validator

from agent.tools.base import Tool, ToolContext, ToolError

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VT_URL = "https://www.virustotal.com/api/v3"


class ThreatIntel:
    def __init__(self, mode: str, recorded_path: Path, cache_path: Path,
                 abuseipdb_key: str | None = None, virustotal_key: str | None = None):
        if mode not in ("mock", "cache", "live"):
            raise ValueError(f"unknown intel mode {mode!r}")
        self.mode = mode
        self.recorded: dict[str, dict] = {"ip": {}, "hash": {}, "domain": {}}
        if recorded_path.exists():
            self.recorded.update(json.loads(recorded_path.read_text()))
        self.cache_path = cache_path
        self.cache: dict[str, dict] = {"ip": {}, "hash": {}, "domain": {}}
        if mode != "mock" and cache_path.exists():
            self.cache.update(json.loads(cache_path.read_text()))
        self.abuseipdb_key = abuseipdb_key
        self.virustotal_key = virustotal_key
        self._lock = threading.Lock()

    def lookup(self, kind: str, key: str) -> dict[str, Any]:
        key = key.strip().lower()
        if self.mode != "live":
            for source in (self.recorded, self.cache):
                if key in source.get(kind, {}):
                    return {"status": "found", "source": "recorded", **source[kind][key]}
            if self.mode == "mock":
                return {"status": "not_found", kind: key, "note": "no record in threat intel"}
        result = self._live(kind, key)
        if self.mode == "cache":
            with self._lock:
                self.cache.setdefault(kind, {})[key] = result
                self.cache_path.parent.mkdir(parents=True, exist_ok=True)
                self.cache_path.write_text(json.dumps(self.cache, indent=1, sort_keys=True))
        return {"status": "found" if result.get("found", True) else "not_found", "source": "live", **result}

    # ------------------------------------------------------------------ live providers
    def _live(self, kind: str, key: str) -> dict[str, Any]:
        if kind == "ip":
            if not self.abuseipdb_key:
                raise ToolError("live IP lookups need SOC_ABUSEIPDB_API_KEY")
            r = httpx.get(ABUSEIPDB_URL, params={"ipAddress": key, "maxAgeInDays": 90},
                          headers={"Key": self.abuseipdb_key, "Accept": "application/json"}, timeout=15)
            r.raise_for_status()
            d = r.json()["data"]
            return {"ip": key, "abuse_confidence": d.get("abuseConfidenceScore"), "asn": d.get("isp"),
                    "country": d.get("countryCode"), "total_reports": d.get("totalReports"),
                    "usage_type": d.get("usageType"), "fetched_at": int(time.time())}
        if not self.virustotal_key:
            raise ToolError("live hash/domain lookups need SOC_VIRUSTOTAL_API_KEY")
        path = f"files/{key}" if kind == "hash" else f"domains/{key}"
        r = httpx.get(f"{VT_URL}/{path}", headers={"x-apikey": self.virustotal_key}, timeout=15)
        if r.status_code == 404:
            return {"found": False, kind: key}
        r.raise_for_status()
        attrs = r.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        if kind == "hash":
            return {"sha256": key, "detections": stats.get("malicious", 0) + stats.get("suspicious", 0),
                    "total_engines": sum(stats.values()) if stats else None,
                    "family": (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"),
                    "signed": bool(attrs.get("signature_info")), "names": attrs.get("names", [])[:5],
                    "fetched_at": int(time.time())}
        created = attrs.get("creation_date")
        return {"domain": key, "age_days": int((time.time() - created) / 86400) if created else None,
                "malicious_votes": stats.get("malicious", 0), "reputation": attrs.get("reputation"),
                "categories": sorted(set((attrs.get("categories") or {}).values())), "fetched_at": int(time.time())}


class IPArgs(BaseModel):
    ip: str = Field(description="IPv4 or IPv6 address")

    @field_validator("ip")
    @classmethod
    def _valid(cls, v: str) -> str:
        ipaddress.ip_address(v.strip())
        return v.strip()


class HashArgs(BaseModel):
    sha256: str = Field(description="SHA-256 file hash (64 hex characters)")

    @field_validator("sha256")
    @classmethod
    def _valid(cls, v: str) -> str:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", v.strip()):
            raise ValueError("expected 64 hex characters")
        return v.strip().lower()


class DomainArgs(BaseModel):
    domain: str = Field(description="Fully qualified domain name")

    @field_validator("domain")
    @classmethod
    def _valid(cls, v: str) -> str:
        v = v.strip().lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", v):
            raise ValueError("not a domain name")
        return v


def lookup_ip(ctx: ToolContext, a: IPArgs) -> dict:
    addr = ipaddress.ip_address(a.ip)
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return {"status": "internal", "ip": a.ip, "note": "private/internal address; no external reputation"}
    return ctx.intel.lookup("ip", a.ip)


def lookup_hash(ctx: ToolContext, a: HashArgs) -> dict:
    return ctx.intel.lookup("hash", a.sha256)


def lookup_domain(ctx: ToolContext, a: DomainArgs) -> dict:
    return ctx.intel.lookup("domain", a.domain)


IP_TOOL = Tool("lookup_ip", "IP reputation: abuse confidence (0-100), ASN, country, report count.", IPArgs, lookup_ip)
HASH_TOOL = Tool("lookup_hash", "File reputation by SHA-256: engine detections, malware family, signature.",
                 HashArgs, lookup_hash)
DOMAIN_TOOL = Tool("lookup_domain", "Domain reputation: age in days, malicious votes, categories.",
                   DomainArgs, lookup_domain)
