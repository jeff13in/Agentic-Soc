"""Whole pipeline offline: built dataset -> heuristic backend -> loop -> metrics -> store -> API."""

from __future__ import annotations


def test_heuristic_eval_runs_end_to_end(built):
    from evals.run_eval import run_eval

    res = run_eval("heuristic", split="test", limit=40, defenses=["tagging"], write_results=False)
    m = res["row"]["metrics"]
    assert m["n"] == len(res["pairs"]) > 0
    assert m["error_rate"] == 0 and m["tool_call_validity"] > 0.9 and m["faithfulness"] == 1.0
    assert all(tr.status == "ok" for _, tr in res["pairs"])
    assert res["row"]["dataset_version"] == built["meta"]["version"]


def test_api(built):
    from fastapi.testclient import TestClient

    from api.main import app

    c = TestClient(app)
    assert c.get("/health").json()["data_ready"] is True
    page = c.get("/alerts", params={"split": "test", "limit": 5}).json()
    assert page["total"] > 0 and len(page["items"]) == 5
    aid = page["items"][0]["alert_id"]
    assert c.get(f"/alerts/{aid}").json()["alert"]["alert_id"] == aid
    tr = c.post(f"/triage/{aid}", json={"backend": "heuristic"}).json()
    assert tr["status"] == "ok" and tr["verdict"]["alert_id"] == aid
    assert c.get(f"/traces/{tr['trace_id']}").status_code == 200
    assert any(t["trace_id"] == tr["trace_id"] for t in c.get("/traces", params={"alert_id": aid}).json())
    assert c.post(f"/triage/{aid}", json={"backend": "nope"}).status_code == 400
    assert c.get("/alerts/nope").status_code == 404
    assert isinstance(c.get("/evals").json(), list)
