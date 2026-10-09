"""FastAPI service: browse alerts, run triage, read traces and eval results.

    uvicorn api.main:app --reload
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api import deps
from api.routes import alerts, meta, traces, triage

app = FastAPI(title="SOC Triage Agent", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])
app.include_router(alerts.router)
app.include_router(triage.router)
app.include_router(traces.router)
app.include_router(meta.router)


@app.get("/health")
def health() -> dict:
    s = deps.settings()
    return {"status": "ok", "backend": s.backend, "intel_mode": s.intel_mode,
            "data_ready": (s.data_dir / "events.parquet").exists(), "alerts": len(deps.alerts())}
