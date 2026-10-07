from __future__ import annotations

from pydantic import BaseModel, Field

from agent.tools.base import Tool, ToolContext


class HostArgs(BaseModel):
    host: str = Field(description="Host name from the alert")


def host_context(ctx: ToolContext, a: HostArgs) -> dict:
    hosts = ctx.assets.get("hosts", {})
    match = next((h for h in hosts if h.lower() == a.host.lower()), None)
    if match is None:
        return {"host": a.host, "status": "unknown", "note": "host is not in the asset inventory"}
    return {"host": match, "status": "known", **hosts[match],
            "admins": ctx.assets.get("admins", []), "service_accounts": ctx.assets.get("service_accounts", []),
            "environment_notes": ctx.assets.get("notes", [])}


TOOL = Tool(
    name="get_host_context",
    description="Asset inventory entry for a host: role, OS, owner, department, criticality, plus known admin and "
                "service accounts and environment notes.",
    args_model=HostArgs,
    fn=host_context,
)
