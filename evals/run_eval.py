"""Score a backend + prompt version against a labelled split.

    python -m evals.run_eval --backend claude                 # held-out test split, 1 run
    python -m evals.run_eval --backend claude --repeats 3     # mean and spread over 3 runs
    python -m evals.run_eval --backend heuristic --split dev --limit 30

Writes every trace to the trace store, one row per eval run to the eval_runs table, and
appends the summary to evals/results/results.csv and evals/results/latest.md.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent.config import ROOT, get_settings
from agent.defenses import make_verifier
from agent.llm import make_client
from agent.loop import LoopConfig, load_prompt, triage
from agent.schemas import LabelledAlert, Trace
from agent.store import TraceStore
from agent.tools import build_context
from evals import metrics
from evals.defense_configs import DEFENSE_CONFIGS

RESULTS_DIR = ROOT / "evals" / "results"
CSV_COLUMNS = ["run_id", "created_at", "backend", "model", "prompt_version", "prompt_hash", "defenses", "split",
               "dataset_version", "git_commit", "repeats", *metrics.HEADLINE, "n"]


def load_split(labels_dir: Path, split: str) -> list[LabelledAlert]:
    path = labels_dir / f"{split}.jsonl"
    if not path.exists():
        raise SystemExit(f"{path} not found; run `python -m data.build` first")
    return [LabelledAlert.model_validate_json(line) for line in path.read_text().splitlines() if line.strip()]


def stratified_subset(alerts: list[LabelledAlert], limit: int | None) -> list[LabelledAlert]:
    """Deterministic subset that keeps the label mix (and at least one alert of each label)."""
    if not limit or limit >= len(alerts):
        return alerts
    by_label: dict[str, list[LabelledAlert]] = {}
    for la in sorted(alerts, key=lambda a: hashlib.sha256(a.alert.alert_id.encode()).hexdigest()):
        by_label.setdefault(la.label.value, []).append(la)
    out = []
    for items in by_label.values():
        out += items[:max(1, round(limit * len(items) / len(alerts)))]
    return sorted(out[:limit] if len(out) > limit else out, key=lambda a: a.alert.alert_id)


def git_commit() -> str:
    try:
        sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                             check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        return sha + ("-dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def fmt(v: Any, pct: bool = False) -> str:
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v * 100:.1f}%" if pct else f"{v:.3g}"
    return str(v)


PCT = {"accuracy", "fn_rate", "fp_rate", "escalation_rate", "precision", "recall", "attack_match", "faithfulness",
       "tool_call_validity", "error_rate"}
TABLE = [("accuracy", "Accuracy"), ("fn_rate", "FN rate"), ("fp_rate", "FP rate"), ("escalation_rate", "Escalated"),
         ("attack_match", "ATT&CK"), ("faithfulness", "Faithful"), ("tool_call_validity", "Tool valid"),
         ("steps_mean", "Steps"), ("latency_p50_s", "p50 s"), ("latency_p95_s", "p95 s"),
         ("cost_per_alert_usd", "$/alert")]


def markdown_table(rows: list[dict[str, Any]]) -> str:
    head = "| Backend | Model | Prompt | Defenses | n | " + " | ".join(t for _, t in TABLE) + " |"
    sep = "|" + "---|" * (5 + len(TABLE))
    lines = [head, sep]
    for r in rows:
        cells = []
        for k, _ in TABLE:
            cell = fmt(r.get(k), k in PCT)
            std = r.get(f"{k}_std")
            if std and r.get("repeats", 1) > 1:
                cell += f" ± {fmt(std, k in PCT)}"
            cells.append(cell)
        defenses = r["defenses"] if isinstance(r["defenses"], str) else ",".join(r["defenses"]) or "none"
        lines.append(f"| {r['backend']} | {r['model']} | {r['prompt_version']} | {defenses} | {r['n']} | "
                     + " | ".join(cells) + " |")
    return "\n".join(lines)


def run_eval(backend: str, split: str = "test", limit: int | None = None, repeats: int = 1, workers: int = 4,
             prompt_version: str | None = None, defenses: list[str] | None = None, model: str | None = None,
             judge: str | None = None, alerts: list[LabelledAlert] | None = None,
             overrides: dict[str, dict[str, dict[str, Any]]] | None = None, write_results: bool = True,
             tag: str | None = None) -> dict[str, Any]:
    settings = get_settings()
    cfg = LoopConfig(max_steps=settings.max_steps, max_seconds=settings.max_seconds,
                     prompt_version=prompt_version or settings.prompt_version, defenses=defenses or [])
    _, prompt_hash = load_prompt(cfg.prompt_version)
    client = make_client(backend, settings, model)
    verifier = make_verifier(backend, settings) if "verifier" in cfg.defenses else None
    base_ctx = build_context(settings)
    store = TraceStore(settings.db_path)
    alerts = alerts if alerts is not None else stratified_subset(load_split(settings.labels_dir, split), limit)
    dataset_meta = json.loads((settings.labels_dir / "dataset.json").read_text())
    run_id = f"{datetime.now(UTC):%Y%m%d-%H%M%S}-{backend}-{uuid.uuid4().hex[:6]}"

    def one(la: LabelledAlert) -> Trace:
        from dataclasses import replace

        ctx = replace(base_ctx, event_overrides=(overrides or {}).get(la.alert.alert_id, {}))
        return triage(la.alert, client, ctx, cfg, run_id=run_id, store=store, verifier=verifier)

    per_run, all_pairs = [], []
    for _ in range(repeats):
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            traces = list(pool.map(one, alerts))
        pairs = list(zip(alerts, traces, strict=True))
        per_run.append(metrics.compute(pairs))
        all_pairs += pairs

    summary = metrics.aggregate(per_run)
    if judge == "claude":
        from evals.judges.faithfulness import LLMJudge

        j = LLMJudge()
        scores = [j.score(tr)["supported_fraction"] for _, tr in all_pairs]
        summary["faithfulness_llm_judge"] = sum(scores) / len(scores) if scores else None

    row = {
        "run_id": run_id, "created_at": datetime.now(UTC).isoformat(), "backend": backend, "model": client.model,
        "prompt_version": cfg.prompt_version, "prompt_hash": prompt_hash, "defenses": cfg.defenses,
        "split": f"{split}:{tag}" if tag else split,
        "dataset_version": dataset_meta["version"], "git_commit": git_commit(), "n_alerts": len(alerts),
        "repeats": repeats, "metrics": summary,
    }
    store.save_eval_run(row)
    flat = {**{k: v for k, v in row.items() if k != "metrics"}, **{k: v for k, v in summary.items() if k != "per_run"}}
    flat["defenses"] = ",".join(cfg.defenses) or "none"
    if write_results:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        csv_path = RESULTS_DIR / "results.csv"
        new = not csv_path.exists()
        with csv_path.open("a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
            if new:
                w.writeheader()
            w.writerow(flat)
        (RESULTS_DIR / "latest.md").write_text(
            f"# Eval run {run_id}\n\nsplit `{split}` · dataset `{row['dataset_version']}` · commit `{row['git_commit']}` "
            f"· prompt `{cfg.prompt_version}` ({prompt_hash}) · {repeats} run(s)\n\n" + markdown_table([flat]) + "\n\n"
            "Confusion (label->prediction), first run: " + json.dumps(per_run[0]["confusion"]) + "\n")
        (RESULTS_DIR / "latest.json").write_text(json.dumps(row, indent=1, default=str))
    return {"row": row, "flat": flat, "pairs": all_pairs}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", default=None, help="claude | vllm | heuristic (default: SOC_BACKEND)")
    ap.add_argument("--model", default=None)
    ap.add_argument("--split", default="test", choices=["dev", "test"])
    ap.add_argument("--limit", type=int, default=None, help="stratified subset size")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--prompt-version", default=None)
    ap.add_argument("--defenses", default="", help="comma-separated: tagging, sanitize, verifier")
    ap.add_argument("--defense-config", choices=sorted(DEFENSE_CONFIGS), default=None,
                    help="named prompt+defenses profile; overrides --prompt-version and --defenses")
    ap.add_argument("--judge", choices=["claude"], default=None, help="add an LLM faithfulness judge")
    args = ap.parse_args(argv)

    backend = args.backend or get_settings().backend
    prompt_version, defenses = args.prompt_version, [d for d in args.defenses.split(",") if d]
    if args.defense_config:
        prompt_version = DEFENSE_CONFIGS[args.defense_config]["prompt_version"]
        defenses = DEFENSE_CONFIGS[args.defense_config]["defenses"]
    res = run_eval(backend, args.split, args.limit, args.repeats, args.workers, prompt_version, defenses,
                   args.model, args.judge, tag=args.defense_config)
    flat = res["flat"]
    print(f"run {flat['run_id']}  split={args.split}  dataset={flat['dataset_version']}  commit={flat['git_commit']}")
    print(markdown_table([flat]))
    print("status:", res["row"]["metrics"]["per_run"][0]["status"])
    print("confusion:", res["row"]["metrics"]["per_run"][0]["confusion"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
