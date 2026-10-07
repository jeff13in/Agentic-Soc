from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from agent.defenses import make_verifier
from agent.llm import make_client
from agent.loop import LoopConfig, triage
from agent.schemas import Alert, Trace
from api import deps

router = APIRouter(prefix="/triage", tags=["triage"])


class TriageOptions(BaseModel):
    backend: str | None = None
    model: str | None = None
    prompt_version: str | None = None
    defenses: list[str] = []


def _run(alert: Alert, opts: TriageOptions) -> Trace:
    s = deps.settings()
    try:
        backend = opts.backend or s.backend
        client = make_client(backend, s, opts.model)
        verifier = make_verifier(backend, s) if "verifier" in opts.defenses else None
        cfg = LoopConfig(max_steps=s.max_steps, max_seconds=s.max_seconds,
                         prompt_version=opts.prompt_version or s.prompt_version, defenses=opts.defenses)
        return triage(alert, client, deps.tool_context(), cfg, store=deps.store(), verifier=verifier)
    except (ValueError, FileNotFoundError) as e:
        raise HTTPException(400, str(e)) from e


@router.post("/{alert_id}")
def triage_stored(alert_id: str, opts: TriageOptions | None = None) -> Trace:
    la = deps.alerts().get(alert_id)
    if la is None:
        raise HTTPException(404, "alert not found")
    return _run(la.alert, opts or TriageOptions())


class AdHocRequest(BaseModel):
    alert: Alert
    options: TriageOptions = TriageOptions()


@router.post("")
def triage_adhoc(req: AdHocRequest) -> Trace:
    return _run(req.alert, req.options)
