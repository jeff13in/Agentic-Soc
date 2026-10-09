from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query

from agent.config import ROOT
from agent.schemas import Trace
from api import deps

router = APIRouter(tags=["traces"])


@router.get("/traces")
def list_traces(alert_id: str | None = None, run_id: str | None = None, limit: int = Query(100, le=1000)) -> list[dict]:
    return deps.store().list_traces(alert_id, run_id, limit)


@router.get("/traces/{trace_id}")
def get_trace(trace_id: str) -> Trace:
    tr = deps.store().get_trace(trace_id)
    if tr is None:
        raise HTTPException(404, "trace not found")
    return tr


@router.get("/evals")
def list_evals(limit: int = Query(50, le=500)) -> list[dict]:
    runs = deps.store().list_eval_runs(limit)
    for r in runs:
        per_run = r["metrics"].pop("per_run", None) or [{}]
        r["metrics"]["confusion"] = per_run[0].get("confusion", {})
    return runs


def _result_file(name: str) -> dict:
    path = ROOT / "evals" / "results" / f"{name}.json"
    if not path.exists():
        raise HTTPException(404, f"no {name} results yet; run `python -m evals.{'adversarial.run_robustness' if name == 'robustness' else name}`")
    return json.loads(path.read_text())


@router.get("/evals/robustness")
def robustness() -> dict:
    """Latest prompt-injection sweep, without per-case outcomes."""
    report = _result_file("robustness")
    for cfg in report.get("configs", {}).values():
        cfg.pop("outcomes", None)
    return report


@router.get("/evals/benchmark")
def benchmark() -> dict:
    return _result_file("benchmark")
