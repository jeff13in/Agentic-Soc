from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from api import deps

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
def list_alerts(split: str | None = None, rule_id: str | None = None, host: str | None = None,
                limit: int = Query(100, le=1000), offset: int = 0) -> dict:
    items = [la for la in deps.alerts().values()
             if (split is None or la.split == split) and (rule_id is None or la.alert.rule_id == rule_id)
             and (host is None or la.alert.host.lower() == host.lower())]
    items.sort(key=lambda la: la.alert.timestamp, reverse=True)
    page = items[offset:offset + limit]
    return {"total": len(items), "items": [
        {"alert_id": la.alert.alert_id, "timestamp": la.alert.timestamp, "rule_id": la.alert.rule_id,
         "rule_name": la.alert.rule_name, "severity": la.alert.rule_severity, "host": la.alert.host,
         "user": la.alert.user, "split": la.split, "label": la.label} for la in page]}


@router.get("/{alert_id}")
def get_alert(alert_id: str) -> dict:
    la = deps.alerts().get(alert_id)
    if la is None:
        raise HTTPException(404, "alert not found")
    return la.model_dump(mode="json")
