"""Read-only DuckDB view over the normalized events Parquet file."""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb

MAX_RESULTS = 50


def _naive_utc(dt: datetime) -> datetime:
    """Events are stored as naive UTC timestamps (avoids DuckDB's pytz dependency)."""
    return dt.astimezone(UTC).replace(tzinfo=None) if dt.tzinfo else dt


class LogStore:
    def __init__(self, parquet_path: Path):
        if not parquet_path.exists():
            raise FileNotFoundError(f"{parquet_path} not found; run `python -m data.build` first")
        self._con = duckdb.connect(":memory:")
        self._con.execute(
            "CREATE TABLE events AS SELECT * REPLACE "
            "(timezone('UTC', CAST(timestamp AS TIMESTAMPTZ)) AS timestamp) FROM read_parquet(?)",
            [str(parquet_path)],
        )
        self._lock = threading.Lock()  # one DuckDB connection shared by worker threads

    def _query(self, sql: str, params: list[Any]) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._con.cursor()
            rows = cur.execute(sql, params).fetchall()
            cols = [d[0] for d in cur.description]
        out = []
        for row in rows:
            rec = {}
            for c, v in zip(cols, row, strict=True):
                if v is None:
                    continue
                rec[c] = v.isoformat() + "+00:00" if isinstance(v, datetime) else v
            out.append(rec)
        return out

    def search(self, host: str, start: datetime, end: datetime, event_id: int | None = None,
               process_guid: str | None = None, text: str | None = None,
               limit: int = MAX_RESULTS) -> tuple[list[dict[str, Any]], int]:
        """Events on a host in [start, end], optionally filtered. Returns (rows, total_matches)."""
        where = ["lower(host) = lower(?)", "timestamp BETWEEN ? AND ?"]
        params: list[Any] = [host, _naive_utc(start), _naive_utc(end)]
        if event_id is not None:
            where.append("event_id = ?")
            params.append(event_id)
        if process_guid:
            where.append("(process_guid = ? OR parent_process_guid = ?)")
            params += [process_guid, process_guid]
        if text:
            where.append(
                "(contains(lower(coalesce(command_line, '')), lower(?)) OR contains(lower(coalesce(image, '')), lower(?))"
                " OR contains(lower(coalesce(query_name, '')), lower(?)) OR contains(lower(coalesce(target_filename, '')), lower(?))"
                " OR contains(lower(coalesce(registry_key, '')), lower(?)) OR contains(lower(coalesce(service_path, '')), lower(?)))"
            )
            params += [text] * 6
        clause = " AND ".join(where)
        total = self._query(f"SELECT count(*) AS n FROM events WHERE {clause}", params)[0]["n"]
        rows = self._query(f"SELECT * FROM events WHERE {clause} ORDER BY timestamp LIMIT ?",
                           params + [min(limit, MAX_RESULTS)])
        return rows, total

    def process(self, host: str, process_guid: str) -> dict[str, Any] | None:
        rows = self._query("SELECT * FROM events WHERE event_id = 1 AND lower(host) = lower(?) AND process_guid = ? LIMIT 1",
                           [host, process_guid])
        return rows[0] if rows else None

    def children(self, host: str, process_guid: str) -> list[dict[str, Any]]:
        return self._query(
            "SELECT * FROM events WHERE event_id = 1 AND lower(host) = lower(?) AND parent_process_guid = ? "
            "ORDER BY timestamp LIMIT ?", [host, process_guid, MAX_RESULTS])

    def event(self, event_uid: str) -> dict[str, Any] | None:
        rows = self._query("SELECT * FROM events WHERE event_uid = ?", [event_uid])
        return rows[0] if rows else None
