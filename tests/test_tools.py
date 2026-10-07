from dataclasses import replace
from datetime import timedelta

import pytest

from agent.tools import TOOLS, tool_specs
from agent.tools.base import ToolError


def tp_alert(labelled):
    return next(la.alert for la in labelled if la.label == "true_positive" and la.alert.rule_id == "R001")


def test_specs_have_no_refs_and_include_submit_verdict():
    import json

    specs = tool_specs()
    assert {s["name"] for s in specs} >= {"search_logs", "get_process_tree", "lookup_ip", "lookup_hash",
                                          "lookup_domain", "map_attack", "get_host_context", "submit_verdict"}
    assert "$ref" not in json.dumps(specs)


def test_search_logs_window_and_validation(ctx, labelled):
    a = tp_alert(labelled)
    r = TOOLS["search_logs"].run(ctx, {"host": a.host, "start_time": (a.timestamp - timedelta(minutes=10)).isoformat(),
                                       "end_time": (a.timestamp + timedelta(minutes=10)).isoformat()})
    assert r["returned"] >= 4 and all(e["host"] == "WS-007" for e in r["events"])
    with pytest.raises(ToolError):
        TOOLS["search_logs"].run(ctx, {"host": a.host, "start_time": a.timestamp.isoformat(),
                                       "end_time": (a.timestamp + timedelta(days=2)).isoformat()})
    with pytest.raises(ToolError):
        TOOLS["search_logs"].run(ctx, {"host": a.host})


def test_process_tree_children_and_missing(ctx, labelled):
    a = tp_alert(labelled)
    tree = TOOLS["get_process_tree"].run(ctx, {"host": a.host, "process_guid": a.process_guid})
    assert [c["image"].split("\\")[-1] for c in tree["children"]] == ["whoami.exe"]
    assert tree["ancestors_nearest_first"][0]["note"] == "parent creation event not in store"
    with pytest.raises(ToolError):
        TOOLS["get_process_tree"].run(ctx, {"host": a.host, "process_guid": "{nope}"})


def test_intel_mock_modes(ctx):
    assert TOOLS["lookup_ip"].run(ctx, {"ip": "10.1.2.3"})["status"] == "internal"
    assert TOOLS["lookup_ip"].run(ctx, {"ip": "13.107.42.14"})["status"] == "found"
    assert TOOLS["lookup_hash"].run(ctx, {"sha256": "0" * 64})["status"] == "not_found"
    with pytest.raises(ToolError):
        TOOLS["lookup_hash"].run(ctx, {"sha256": "xyz"})
    with pytest.raises(ToolError):
        TOOLS["lookup_domain"].run(ctx, {"domain": "not a domain"})


def test_attack_map_and_host_context(ctx):
    top = TOOLS["map_attack"].run(ctx, {"behavior": "process opened lsass memory to dump credentials"})["candidates"][0]
    assert top["id"] == "T1003.001"
    assert TOOLS["get_host_context"].run(ctx, {"host": "srv-dc01"})["criticality"] == "critical"
    assert TOOLS["get_host_context"].run(ctx, {"host": "nope"})["status"] == "unknown"


def test_event_overrides_replace_stored_fields(ctx, labelled):
    a = tp_alert(labelled)
    c2 = replace(ctx, event_overrides={a.event_uid: {"command_line": "OVERRIDDEN"}})
    tree = TOOLS["get_process_tree"].run(c2, {"host": a.host, "process_guid": a.process_guid})
    assert tree["process"]["command_line"] == "OVERRIDDEN"
