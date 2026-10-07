"""Load OTRF Security-Datasets (formerly Mordor) into the normalized event schema.

Datasets are recorded in a lab while an ATT&CK technique is executed, so each file holds the
attack plus whatever else the lab host was doing. A manifest (see
data/otrf_manifest.example.yml) says which file holds which techniques and, optionally,
which events are the attack (time window and/or field filters). Events the manifest marks as
the attack become ground truth; other events from the file are kept as context but their
alerts are labelled ``review`` and excluded from the splits until hand-checked.

The loader also maps lab hostnames onto the asset inventory and shifts timestamps so each
dataset sits inside the benign week produced by data/generate.py.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from data.generate import DAYS, START

SYSMON_CHANNEL = "microsoft-windows-sysmon/operational"
KEEP_SYSMON_IDS = {1, 3, 10, 11, 13, 22}


@dataclass
class DatasetSpec:
    name: str
    file: Path
    techniques: list[str]
    host_map: dict[str, str] = field(default_factory=dict)
    default_host: str | None = None
    place_at: datetime | None = None
    attack_window: tuple[datetime, datetime] | None = None
    attack_filter: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class OTRFResult:
    events: list[dict[str, Any]] = field(default_factory=list)
    truth: dict[str, dict[str, Any]] = field(default_factory=dict)
    groups: dict[str, str] = field(default_factory=dict)
    datasets: list[dict[str, Any]] = field(default_factory=list)


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    s = str(value).strip().replace(" ", "T", 1)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def load_manifest(path: Path) -> list[DatasetSpec]:
    raw = yaml.safe_load(path.read_text()) or {}
    base = path.parent
    specs = []
    for d in raw.get("datasets", []):
        window = d.get("attack_window")
        filt = {k: v if isinstance(v, list) else [v] for k, v in (d.get("attack_filter") or {}).items()}
        f = Path(d["file"])
        specs.append(DatasetSpec(
            name=d["name"],
            file=f if f.is_absolute() else (base / f),
            techniques=list(d.get("techniques", [])),
            host_map=dict(d.get("host_map") or {}),
            default_host=d.get("default_host"),
            place_at=_parse_ts(d.get("place_at")),
            attack_window=(_parse_ts(window["start"]), _parse_ts(window["end"])) if window else None,
            attack_filter=filt,
        ))
    return specs


def iter_records(path: Path) -> Iterator[dict[str, Any]]:
    """Yield raw event dicts from a .json / .jsonl file or a .zip/.tar of them."""
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as zf:
            for member in sorted(zf.namelist()):
                if member.endswith((".json", ".jsonl")):
                    yield from _iter_json_text(zf.read(member).decode("utf-8", errors="replace"))
        return
    yield from _iter_json_text(path.read_text(encoding="utf-8", errors="replace"))


def _iter_json_text(text: str) -> Iterator[dict[str, Any]]:
    stripped = text.lstrip()
    if stripped.startswith("["):
        for rec in json.loads(stripped):
            if isinstance(rec, dict):
                yield rec
        return
    for line in io.StringIO(text):
        line = line.strip()
        if line:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                yield rec


def _get(rec: dict[str, Any], *keys: str) -> Any:
    lower = {k.lower(): v for k, v in rec.items()}
    for k in keys:
        v = lower.get(k.lower())
        if v not in (None, "", "-"):
            return v
    return None


def _host(rec: dict[str, Any]) -> str | None:
    h = _get(rec, "Hostname", "Computer", "host")
    if isinstance(h, dict):
        h = h.get("name") or h.get("hostname")
    return str(h) if h else None


def _sha256(hashes: Any) -> str | None:
    if not hashes:
        return None
    for part in str(hashes).split(","):
        k, _, v = part.partition("=")
        if k.strip().upper() == "SHA256" and v:
            return v.strip().lower()
    return None


def normalize(rec: dict[str, Any]) -> dict[str, Any] | None:
    """Map one raw OTRF record to the normalized schema, or None if it is out of scope."""
    try:
        eid = int(_get(rec, "EventID", "event_id") or -1)
    except (TypeError, ValueError):
        return None
    channel = str(_get(rec, "Channel") or "").lower()
    ts = _parse_ts(_get(rec, "@timestamp", "UtcTime", "TimeCreated", "EventTime"))
    host = _host(rec)
    if ts is None or host is None:
        return None

    ev: dict[str, Any] = {"timestamp": ts, "host": host, "event_id": eid}
    if channel == SYSMON_CHANNEL and eid in KEEP_SYSMON_IDS:
        source = eid == 10
        ev.update(
            user=_get(rec, "SourceUser", "User") if source else _get(rec, "User"),
            process_guid=_get(rec, "SourceProcessGUID", "SourceProcessGuid") if source else _get(rec, "ProcessGuid"),
            parent_process_guid=_get(rec, "ParentProcessGuid"),
            image=_get(rec, "SourceImage") if source else _get(rec, "Image"),
            parent_image=_get(rec, "ParentImage"),
            command_line=_get(rec, "CommandLine"),
            parent_command_line=_get(rec, "ParentCommandLine"),
            sha256=_sha256(_get(rec, "Hashes", "Hash")),
            pid=_get(rec, "SourceProcessId") if source else _get(rec, "ProcessId"),
            target_image=_get(rec, "TargetImage"),
            granted_access=_get(rec, "GrantedAccess"),
            dst_ip=_get(rec, "DestinationIp"),
            dst_port=_get(rec, "DestinationPort"),
            query_name=_get(rec, "QueryName"),
            target_filename=_get(rec, "TargetFilename"),
            registry_key=_get(rec, "TargetObject"),
            registry_value=_get(rec, "Details"),
        )
    elif eid == 7045:  # System: service installed
        ev.update(user=_get(rec, "AccountName") or "SYSTEM", service_name=_get(rec, "ServiceName"),
                  service_path=_get(rec, "ImagePath"), image="C:\\Windows\\System32\\services.exe")
    elif eid == 4688:  # Security: process creation, mapped onto Sysmon ID 1
        pid = _get(rec, "NewProcessId")
        ppid = _get(rec, "ProcessId")
        ev.update(event_id=1, user=_get(rec, "TargetUserName", "SubjectUserName"),
                  process_guid=f"pid-{host}-{pid}" if pid else None,
                  parent_process_guid=f"pid-{host}-{ppid}" if ppid else None,
                  image=_get(rec, "NewProcessName"), parent_image=_get(rec, "ParentProcessName"),
                  command_line=_get(rec, "CommandLine"), pid=pid)
    else:
        return None

    for k in ("dst_port", "pid"):
        if ev.get(k) is not None:
            try:
                ev[k] = int(str(ev[k]), 0) if str(ev[k]).startswith("0x") else int(ev[k])
            except ValueError:
                ev[k] = None
    if ev.get("granted_access") is not None:
        ev["granted_access"] = str(ev["granted_access"]).lower()
    return ev


def _matches_filter(ev: dict[str, Any], filt: dict[str, list[str]]) -> bool:
    for fld, needles in filt.items():
        value = str(ev.get(fld) or "").lower()
        if not any(n.lower() in value for n in needles):
            return False
    return True


def _default_placement(name: str) -> datetime:
    """Deterministic slot inside the benign week, during working hours."""
    h = int(hashlib.sha256(name.encode()).hexdigest(), 16)
    return START + timedelta(days=h % DAYS, hours=9 + (h >> 8) % 8, minutes=(h >> 16) % 60)


def load_dataset(spec: DatasetSpec, result: OTRFResult) -> None:
    raw_events = []
    for idx, rec in enumerate(iter_records(spec.file)):
        ev = normalize(rec)
        if ev is not None:
            raw_events.append((idx, ev))
    if not raw_events:
        result.datasets.append({"name": spec.name, "file": str(spec.file), "events": 0, "attack_events": 0})
        return

    first = min(ev["timestamp"] for _, ev in raw_events)
    shift = (spec.place_at or _default_placement(spec.name)) - first
    attack = 0
    for idx, ev in raw_events:
        original_ts = ev["timestamp"]
        in_window = spec.attack_window is None or spec.attack_window[0] <= original_ts <= spec.attack_window[1]
        is_attack = in_window and _matches_filter(ev, spec.attack_filter)
        lab_host = ev["host"]
        mapped = spec.host_map.get(lab_host) or spec.host_map.get(lab_host.split(".")[0]) or spec.default_host
        ev["host"] = mapped or lab_host.split(".")[0].upper()
        ev["timestamp"] = (original_ts + shift).isoformat()
        ev["event_uid"] = "otrf-" + hashlib.sha1(f"{spec.name}:{idx}".encode()).hexdigest()[:12]
        ev.setdefault("user", None)
        result.events.append(ev)
        result.groups[ev["event_uid"]] = f"otrf:{spec.name}"
        result.truth[ev["event_uid"]] = {
            "dataset": spec.name,
            "techniques": spec.techniques,
            "is_attack": is_attack,
        }
        attack += is_attack
    result.datasets.append({
        "name": spec.name, "file": str(spec.file), "events": len(raw_events), "attack_events": attack,
        "sha256": hashlib.sha256(spec.file.read_bytes()).hexdigest(), "techniques": spec.techniques,
    })


def load_all(manifest: Path) -> OTRFResult:
    result = OTRFResult()
    for spec in load_manifest(manifest):
        if not spec.file.exists():
            raise FileNotFoundError(f"OTRF dataset '{spec.name}' not found at {spec.file}; download it first")
        load_dataset(spec, result)
    return result
