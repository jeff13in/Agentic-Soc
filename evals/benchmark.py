"""Head-to-head benchmark across backends on the same split.

    python -m evals.benchmark --targets "claude,base=vllm:Qwen/Qwen2.5-7B-Instruct,tuned=vllm:soc-qwen-lora"
    python -m evals.benchmark --targets heuristic --limit 50 --workers 8

A target is `[name=]backend[:model]`. Each target runs the same alerts, prompt and defenses;
the table adds throughput under concurrent load (alerts per minute with --workers in flight).
For vLLM targets, cost per alert is also derived from measured throughput and the GPU's hourly
price (SOC_VLLM_GPU_USD_PER_HOUR), which is what a rented box actually costs per alert.
Writes evals/results/benchmark.{md,json}.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from typing import Any

from agent.config import ROOT, get_settings
from evals.defense_configs import DEFENSE_CONFIGS
from evals.run_eval import PCT, fmt, load_split, run_eval, stratified_subset

RESULTS_DIR = ROOT / "evals" / "results"
COLUMNS = [("accuracy", "Accuracy"), ("fn_rate", "FN rate"), ("escalation_rate", "Escalated"),
           ("faithfulness", "Faithful"), ("tool_call_validity", "Tool valid"), ("latency_p50_s", "p50 s"),
           ("latency_p95_s", "p95 s"), ("cost_per_alert_usd", "$/alert"), ("alerts_per_min", "Alerts/min")]


def parse_target(spec: str) -> dict[str, str | None]:
    name, _, rest = spec.partition("=") if "=" in spec else (None, "", spec)
    backend, _, model = rest.partition(":")
    return {"name": name or rest, "backend": backend, "model": model or None}


def run_benchmark(targets: list[str], split: str = "test", limit: int | None = None, repeats: int = 1,
                  workers: int = 8, defense_config: str = "spotlight", clients: dict[str, Any] | None = None
                  ) -> dict[str, Any]:
    settings = get_settings()
    cfg = DEFENSE_CONFIGS[defense_config]
    alerts = stratified_subset(load_split(settings.labels_dir, split), limit)
    rows = []
    for spec in targets:
        t = parse_target(spec)
        start = time.monotonic()
        res = run_eval(t["backend"], split, repeats=repeats, workers=workers, prompt_version=cfg["prompt_version"],
                       defenses=cfg["defenses"], model=t["model"], alerts=alerts, write_results=False,
                       tag=f"benchmark-{t['name']}", client=(clients or {}).get(t["name"]))
        wall = time.monotonic() - start
        m = res["row"]["metrics"]
        row = {"target": t["name"], "backend": t["backend"], "model": res["row"]["model"],
               "run_id": res["row"]["run_id"], "n": len(alerts), "repeats": repeats, "workers": workers,
               "wall_s": wall, "alerts_per_min": len(alerts) * repeats / wall * 60 if wall else None,
               **{k: m.get(k) for k, _ in COLUMNS if k != "alerts_per_min"},
               **{f"{k}_std": m.get(f"{k}_std") for k, _ in COLUMNS}}
        if t["backend"] == "vllm" and row["alerts_per_min"]:
            row["cost_per_alert_usd"] = settings.vllm_gpu_usd_per_hour / (row["alerts_per_min"] * 60)
            row["cost_basis"] = f"${settings.vllm_gpu_usd_per_hour}/GPU-hour at measured throughput"
        rows.append(row)
    return {"split": split, "defense_config": defense_config, "n_alerts": len(alerts), "repeats": repeats,
            "workers": workers, "created_at": datetime.now(UTC).isoformat(), "rows": rows}


def markdown(report: dict[str, Any]) -> str:
    head = "| Target | Model | " + " | ".join(t for _, t in COLUMNS) + " |"
    lines = [f"# Backend benchmark ({report['split']} split, {report['n_alerts']} alerts × {report['repeats']}, "
             f"{report['workers']} concurrent, profile `{report['defense_config']}`)", "", head,
             "|---|---|" + "---|" * len(COLUMNS)]
    for r in report["rows"]:
        cells = []
        for k, _ in COLUMNS:
            cell = f"{r[k]:,.0f}" if k == "alerts_per_min" and r.get(k) else fmt(r.get(k), k in PCT)
            if r.get(f"{k}_std") and r["repeats"] > 1:
                cell += f" ± {fmt(r[f'{k}_std'], k in PCT)}"
            cells.append(cell)
        lines.append(f"| {r['target']} | {r['model']} | " + " | ".join(cells) + " |")
    notes = [f"{r['target']}: cost from {r['cost_basis']}" for r in report["rows"] if r.get("cost_basis")]
    return "\n".join(lines + ([""] + notes if notes else [])) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", required=True, help="comma-separated [name=]backend[:model]")
    ap.add_argument("--split", default="test", choices=["dev", "test"])
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--defense-config", default="spotlight", choices=sorted(DEFENSE_CONFIGS))
    args = ap.parse_args(argv)
    report = run_benchmark([t for t in args.targets.split(",") if t], args.split, args.limit, args.repeats,
                           args.workers, args.defense_config)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    md = markdown(report)
    (RESULTS_DIR / "benchmark.md").write_text(md)
    (RESULTS_DIR / "benchmark.json").write_text(json.dumps(report, indent=1, default=str))
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
