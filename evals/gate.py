"""Fail (exit 1) if the latest eval run crosses a threshold in evals/thresholds.yml.

    python -m evals.gate                         # checks evals/results/latest.json
    python -m evals.gate --run path/to/run.json --profile default
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from agent.config import ROOT

THRESHOLDS = ROOT / "evals" / "thresholds.yml"


def check(metrics: dict, limits: dict) -> list[str]:
    failures = []
    min_tp = limits.get("min_true_positives", 0)
    n_tp = min((r.get("n_true_positive", 0) for r in metrics.get("per_run", [])), default=None)
    for name, bound in limits.items():
        if name == "min_true_positives":
            continue
        if name in ("fn_rate", "recall") and n_tp is not None and n_tp < min_tp:
            print(f"  WARN {name} not gated: only {n_tp} true positives in the sample (need {min_tp})")
            continue
        value = metrics.get(name)
        if value is None:
            continue  # e.g. fn_rate on a split with no true positives
        if "max" in bound and value > bound["max"]:
            failures.append(f"{name} = {value:.3f} > max {bound['max']}")
        if "min" in bound and value < bound["min"]:
            failures.append(f"{name} = {value:.3f} < min {bound['min']}")
    return failures


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", type=Path, default=ROOT / "evals" / "results" / "latest.json")
    ap.add_argument("--profile", default=None, help="thresholds profile (default: the run's backend, else default)")
    args = ap.parse_args(argv)
    row = json.loads(args.run.read_text())
    profiles = yaml.safe_load(THRESHOLDS.read_text())
    profile = args.profile or (row["backend"] if row["backend"] in profiles else "default")
    print(f"gate: run {row['run_id']} ({row['backend']}/{row['model']}), profile '{profile}'")
    failures = check(row["metrics"], profiles[profile])
    for f in failures:
        print("  FAIL", f)
    if not failures:
        print("  pass")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
