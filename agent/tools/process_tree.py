from __future__ import annotations

from pydantic import BaseModel, Field

from agent.tools.base import Tool, ToolContext, ToolError, clip

MAX_DEPTH = 8
TREE_FIELDS = ("event_uid", "timestamp", "process_guid", "parent_process_guid", "image", "command_line", "user",
               "sha256", "pid")


class ProcessTreeArgs(BaseModel):
    host: str = Field(description="Host name from the alert")
    process_guid: str = Field(description="Process GUID from the alert or a search_logs result")


def _node(ctx: ToolContext, rec: dict) -> dict:
    rec = ctx.apply_overrides([rec])[0]
    return clip({k: rec.get(k) for k in TREE_FIELDS})


def process_tree(ctx: ToolContext, a: ProcessTreeArgs) -> dict:
    proc = ctx.logs.process(a.host, a.process_guid)
    if proc is None:
        raise ToolError(f"no process-creation event for {a.process_guid} on {a.host}")
    ancestors = []
    cur = proc
    seen = {proc["process_guid"]}
    while len(ancestors) < MAX_DEPTH and cur.get("parent_process_guid"):
        parent = ctx.logs.process(a.host, cur["parent_process_guid"])
        if parent is None or parent["process_guid"] in seen:
            if cur.get("parent_image"):
                ancestors.append({"image": cur["parent_image"], "process_guid": cur["parent_process_guid"],
                                  "note": "parent creation event not in store"})
            break
        seen.add(parent["process_guid"])
        ancestors.append(_node(ctx, parent))
        cur = parent
    children = [_node(ctx, c) for c in ctx.logs.children(a.host, a.process_guid)]
    return {"process": _node(ctx, proc), "ancestors_nearest_first": ancestors, "children": children}


TOOL = Tool(
    name="get_process_tree",
    description="Return a process with its parent chain (nearest first, up to 8 levels) and its direct children, "
                "built from process-creation events.",
    args_model=ProcessTreeArgs,
    fn=process_tree,
)
