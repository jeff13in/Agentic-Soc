from __future__ import annotations

from datetime import datetime, timedelta

from pydantic import BaseModel, Field

from agent.logstore import MAX_RESULTS
from agent.tools.base import Tool, ToolContext, ToolError, clip

MAX_WINDOW = timedelta(hours=24)


class SearchLogsArgs(BaseModel):
    host: str = Field(description="Host name exactly as it appears in the alert, e.g. WS-003")
    start_time: datetime = Field(description="Window start, ISO 8601 with timezone")
    end_time: datetime = Field(description="Window end, ISO 8601 with timezone; window may be at most 24h")
    event_id: int | None = Field(None, description="Sysmon/Windows event id: 1 process, 3 network, 10 process access, "
                                                   "11 file create, 13 registry set, 22 DNS, 7045 service install")
    process_guid: str | None = Field(None, description="Only events from this process or its direct children")
    text: str | None = Field(None, description="Case-insensitive substring over command line, image, DNS name, "
                                               "file path, registry key and service path")
    limit: int = Field(MAX_RESULTS, ge=1, le=MAX_RESULTS)


def search_logs(ctx: ToolContext, a: SearchLogsArgs) -> dict:
    if a.end_time <= a.start_time:
        raise ToolError("end_time must be after start_time")
    if a.end_time - a.start_time > MAX_WINDOW:
        raise ToolError("time window too large; use at most 24 hours")
    rows, total = ctx.logs.search(a.host, a.start_time, a.end_time, a.event_id, a.process_guid, a.text, a.limit)
    rows = ctx.apply_overrides(rows)
    return {"total_matches": total, "returned": len(rows), "truncated": total > len(rows),
            "events": [clip(r) for r in rows]}


TOOL = Tool(
    name="search_logs",
    description="Search stored endpoint telemetry for one host in a time window. Returns at most 50 events, "
                "oldest first, plus the total match count. Narrow with event_id, process_guid or text.",
    args_model=SearchLogsArgs,
    fn=search_logs,
)
