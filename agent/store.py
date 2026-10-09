"""SQLite store for traces and eval runs. One store feeds the API, the evals and SFT data."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from agent.schemas import Trace

SCHEMA = """
CREATE TABLE IF NOT EXISTS traces (
    trace_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    run_id TEXT,
    backend TEXT,
    model TEXT,
    prompt_version TEXT,
    status TEXT,
    verdict TEXT,
    created_at TEXT,
    trace_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS traces_alert ON traces(alert_id);
CREATE INDEX IF NOT EXISTS traces_run ON traces(run_id);
CREATE TABLE IF NOT EXISTS eval_runs (
    run_id TEXT PRIMARY KEY,
    created_at TEXT,
    backend TEXT,
    model TEXT,
    prompt_version TEXT,
    prompt_hash TEXT,
    defenses TEXT,
    split TEXT,
    dataset_version TEXT,
    git_commit TEXT,
    n_alerts INTEGER,
    repeats INTEGER,
    metrics_json TEXT NOT NULL
);
"""


class TraceStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._con = sqlite3.connect(path, check_same_thread=False)
        self._con.row_factory = sqlite3.Row
        self._con.executescript(SCHEMA)
        self._lock = threading.Lock()

    def save_trace(self, trace: Trace) -> None:
        with self._lock, self._con:
            self._con.execute(
                "INSERT OR REPLACE INTO traces VALUES (?,?,?,?,?,?,?,?,?,?)",
                (trace.trace_id, trace.alert_id, trace.run_id, trace.backend, trace.model, trace.prompt_version,
                 trace.status, trace.final_label.value, trace.started_at.isoformat(), trace.model_dump_json()),
            )

    def get_trace(self, trace_id: str) -> Trace | None:
        row = self._con.execute("SELECT trace_json FROM traces WHERE trace_id = ?", (trace_id,)).fetchone()
        return Trace.model_validate_json(row["trace_json"]) if row else None

    def list_traces(self, alert_id: str | None = None, run_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT trace_id, alert_id, run_id, backend, model, prompt_version, status, verdict, created_at FROM traces"
        where, params = [], []
        if alert_id:
            where.append("alert_id = ?")
            params.append(alert_id)
        if run_id:
            where.append("run_id = ?")
            params.append(run_id)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at DESC LIMIT ?"
        return [dict(r) for r in self._con.execute(sql, [*params, limit]).fetchall()]

    def run_traces(self, run_id: str) -> list[Trace]:
        rows = self._con.execute("SELECT trace_json FROM traces WHERE run_id = ?", (run_id,)).fetchall()
        return [Trace.model_validate_json(r["trace_json"]) for r in rows]

    def all_traces(self, backend: str | None = None) -> list[Trace]:
        sql, params = "SELECT trace_json FROM traces", []
        if backend:
            sql += " WHERE backend = ?"
            params.append(backend)
        return [Trace.model_validate_json(r["trace_json"]) for r in self._con.execute(sql + " ORDER BY created_at", params)]

    def save_eval_run(self, row: dict[str, Any]) -> None:
        with self._lock, self._con:
            self._con.execute(
                "INSERT OR REPLACE INTO eval_runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (row["run_id"], row["created_at"], row["backend"], row["model"], row["prompt_version"],
                 row["prompt_hash"], json.dumps(row["defenses"]), row["split"], row["dataset_version"],
                 row["git_commit"], row["n_alerts"], row["repeats"], json.dumps(row["metrics"])),
            )

    def list_eval_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._con.execute("SELECT * FROM eval_runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["metrics"] = json.loads(d.pop("metrics_json"))
            d["defenses"] = json.loads(d["defenses"])
            out.append(d)
        return out
