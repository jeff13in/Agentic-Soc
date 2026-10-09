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


def test_dashboard_endpoints(built, tmp_path, monkeypatch):
    import json

    from fastapi.testclient import TestClient

    import api.routes.traces as traces_routes
    from api.main import app

    c = TestClient(app)
    cfg = c.get("/config").json()
    assert {b["id"] for b in cfg["backends"]} == {"heuristic", "claude", "vllm"}
    assert {p["id"] for p in cfg["profiles"]} == {"baseline", "spotlight", "sanitize", "full"}
    aid = c.get("/alerts", params={"split": "test", "limit": 1}).json()["items"][0]["alert_id"]
    tr = c.post(f"/triage/{aid}", json={"backend": "heuristic", "profile": "full"}).json()
    assert tr["prompt_version"] == "v2" and tr["defenses"] == ["tagging", "sanitize", "verifier"]
    assert tr["verifier"] is not None
    assert c.post(f"/triage/{aid}", json={"backend": "heuristic", "profile": "nope"}).status_code == 400

    from evals.run_eval import run_eval

    run_eval("heuristic", split="test", limit=5, write_results=False)
    runs = c.get("/evals").json()
    assert "per_run" not in runs[0]["metrics"] and isinstance(runs[0]["metrics"]["confusion"], dict)
    assert sum(runs[0]["metrics"]["confusion"].values()) == runs[0]["n_alerts"]

    monkeypatch.setattr(traces_routes, "ROOT", tmp_path)
    assert c.get("/evals/robustness").status_code == 404
    (tmp_path / "evals" / "results").mkdir(parents=True)
    report = {"backend": "x", "configs": {"baseline": {"summary": {"asr": 0.5}, "outcomes": [{"a": 1}]}}}
    (tmp_path / "evals" / "results" / "robustness.json").write_text(json.dumps(report))
    got = c.get("/evals/robustness").json()
    assert got["configs"]["baseline"]["summary"]["asr"] == 0.5 and "outcomes" not in got["configs"]["baseline"]
