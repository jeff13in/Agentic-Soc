"""Build the labelled alert set.

    python -m data.build                                  # benign week + data/raw/manifest.yml
    python -m data.build --manifest path/to/manifest.yml

Steps: generate the benign week, load OTRF datasets into it, write events to Parquet, run the
detection rules, label each alert, split dev/test by source group (so one attack or one benign
activity never lands in both splits), and record a dataset version hash.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq
import yaml

from agent.config import ROOT, get_settings
from agent.schemas import Alert, LabelledAlert, VerdictLabel
from data.detect import RULES_DIR, load_rules, run_rules
from data.generate import Generator
from data.ingest.otrf import load_all

EVENT_COLUMNS = [
    "event_uid", "timestamp", "host", "user", "event_id", "process_guid", "parent_process_guid", "image",
    "parent_image", "command_line", "parent_command_line", "sha256", "pid", "target_image", "granted_access",
    "dst_ip", "dst_port", "query_name", "target_filename", "registry_key", "registry_value", "service_name",
    "service_path",
]
INT_COLUMNS = {"event_id", "pid", "dst_port"}
DEFAULT_MANIFEST = ROOT / "data" / "raw" / "manifest.yml"
RECORDED_INTEL = ROOT / "data" / "intel" / "recorded.json"
OVERRIDES = ROOT / "data" / "labels" / "overrides.yml"


def write_events(events: list[dict[str, Any]], path: Path) -> None:
    cols: dict[str, list] = {c: [] for c in EVENT_COLUMNS}
    for ev in events:
        for c in EVENT_COLUMNS:
            v = ev.get(c)
            cols[c].append(v if v is None or c in INT_COLUMNS else str(v))
    schema = pa.schema([(c, pa.int64() if c in INT_COLUMNS else pa.string()) for c in EVENT_COLUMNS])
    pq.write_table(pa.table(cols, schema=schema), path)


def _hash_files(paths: list[Path]) -> str:
    h = hashlib.sha256()
    for p in sorted(paths):
        h.update(p.name.encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def assign_split(group: str, dev_fraction: float, seed: int) -> str:
    bucket = int(hashlib.sha256(f"{seed}:{group}".encode()).hexdigest(), 16) % 10_000
    return "dev" if bucket < dev_fraction * 10_000 else "test"


def build(manifest: Path | None, seed: int = 1337, dev_fraction: float = 0.57,
          out_dir: Path | None = None, labels_dir: Path | None = None) -> dict[str, Any]:
    settings = get_settings()
    out_dir = out_dir or settings.data_dir
    labels_dir = labels_dir or settings.labels_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    labels_dir.mkdir(parents=True, exist_ok=True)

    gen = Generator(seed=seed).build()
    events = list(gen.events)
    groups = dict(gen.groups)
    truth: dict[str, dict[str, Any]] = {}
    datasets: list[dict[str, Any]] = []
    if manifest is not None:
        otrf = load_all(manifest)
        events += otrf.events
        groups.update(otrf.groups)
        truth = otrf.truth
        datasets = otrf.datasets
    events.sort(key=lambda e: str(e["timestamp"]))
    write_events(events, out_dir / "events.parquet")

    intel = gen.intel
    if RECORDED_INTEL.exists():
        recorded = json.loads(RECORDED_INTEL.read_text())
        for kind in ("ip", "hash", "domain"):
            intel[kind].update(recorded.get(kind, {}))
    (out_dir / "mock_intel.json").write_text(json.dumps(intel, indent=1, sort_keys=True))

    overrides: dict[str, str] = {}
    if OVERRIDES.exists():
        overrides = (yaml.safe_load(OVERRIDES.read_text()) or {}).get("labels", {}) or {}

    rules = load_rules()
    by_split: dict[str, list[LabelledAlert]] = {"dev": [], "test": [], "review": []}
    for rule, ev in run_rules(events, rules):
        alert_id = f"{rule.id}-{ev['event_uid']}"
        t = truth.get(ev["event_uid"])
        if alert_id in overrides:
            label: str = overrides[alert_id]
        elif t is None:
            label = VerdictLabel.FALSE_POSITIVE.value
        elif t["is_attack"]:
            label = VerdictLabel.TRUE_POSITIVE.value
        else:
            label = "review"
        raw = {k: v for k, v in ev.items() if v is not None and k in EVENT_COLUMNS}
        alert = Alert(
            alert_id=alert_id, rule_id=rule.id, rule_name=rule.name, rule_severity=rule.severity,
            rule_tags=list(rule.tags), timestamp=datetime.fromisoformat(str(ev["timestamp"])), host=ev["host"],
            user=ev.get("user"), event_id=ev["event_id"], event_uid=ev["event_uid"],
            process_guid=ev.get("process_guid"), image=ev.get("image"), parent_image=ev.get("parent_image"),
            command_line=ev.get("command_line"), raw_event={k: str(v) for k, v in raw.items()},
        )
        group = groups.get(ev["event_uid"], "unknown")
        if label == "review":
            by_split["review"].append(LabelledAlert(alert=alert, label=VerdictLabel.NEEDS_ESCALATION,
                                                    techniques=t["techniques"] if t else [], scenario=group,
                                                    split="review"))
            continue
        split = assign_split(group, dev_fraction, seed)
        by_split[split].append(LabelledAlert(
            alert=alert, label=VerdictLabel(label),
            techniques=(t["techniques"] if t and label == VerdictLabel.TRUE_POSITIVE.value else []),
            scenario=group, split=split,
        ))

    for split, items in by_split.items():
        items.sort(key=lambda la: la.alert.alert_id)
        with (labels_dir / f"{split}.jsonl").open("w") as f:
            for la in items:
                f.write(la.model_dump_json() + "\n")

    version_inputs = {
        "seed": seed, "dev_fraction": dev_fraction,
        "rules": _hash_files(list(RULES_DIR.glob("*.yml"))),
        "generator": _hash_files([ROOT / "data" / "generate.py", ROOT / "data" / "assets.yml"]),
        "datasets": [d.get("sha256") for d in datasets],
        "overrides": sorted(overrides.items()),
    }
    version = hashlib.sha256(json.dumps(version_inputs, sort_keys=True).encode()).hexdigest()[:12]
    counts = {s: dict(Counter(la.label.value for la in items)) for s, items in by_split.items()}
    meta = {"version": version, "inputs": version_inputs, "events": len(events), "datasets": datasets,
            "counts": counts, "rules": [r.id for r in rules]}
    (labels_dir / "dataset.json").write_text(json.dumps(meta, indent=2))
    return meta


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", type=Path, default=None, help=f"OTRF manifest (default: {DEFAULT_MANIFEST} if present)")
    ap.add_argument("--no-otrf", action="store_true", help="benign week only (every alert is a false positive)")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--dev-fraction", type=float, default=0.57)
    args = ap.parse_args(argv)

    manifest = None
    if not args.no_otrf:
        manifest = args.manifest or (DEFAULT_MANIFEST if DEFAULT_MANIFEST.exists() else None)
        if manifest is None:
            print("No OTRF manifest found. Download datasets into data/raw/ and copy "
                  "data/otrf_manifest.example.yml to data/raw/manifest.yml, or pass --no-otrf.", file=sys.stderr)
            return 2
    meta = build(manifest, seed=args.seed, dev_fraction=args.dev_fraction)
    print(f"dataset {meta['version']}: {meta['events']} events")
    for split, c in meta["counts"].items():
        print(f"  {split:7s} {c}")
    if meta["counts"].get("review"):
        print("Alerts labelled 'review' came from OTRF lab background; hand-check them and record labels in "
              "data/labels/overrides.yml, or narrow attack_window/attack_filter in the manifest.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
