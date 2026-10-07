from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

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
        r["metrics"].pop("per_run", None)
    return runs
