from datetime import UTC, datetime
from pathlib import Path

from data.ingest.otrf import DatasetSpec, OTRFResult, load_dataset, load_manifest, normalize

FIX = Path(__file__).parent / "fixtures" / "otrf"


def test_normalize_process_access_uses_source_fields():
    ev = normalize({"@timestamp": "2020-01-01T10:00:00Z", "Hostname": "h.lab", "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "EventID": 10, "SourceImage": "C:\\a.exe", "SourceProcessGUID": "{g}", "TargetImage": "C:\\lsass.exe",
                    "GrantedAccess": "0x1FFFFF", "SourceUser": "LAB\\u"})
    assert ev["image"] == "C:\\a.exe" and ev["process_guid"] == "{g}" and ev["granted_access"] == "0x1fffff"
    assert ev["user"] == "LAB\\u"


def test_normalize_extracts_sha256_and_maps_4688():
    ev = normalize({"@timestamp": "2020-01-01 10:00:00.123", "Hostname": "h", "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "EventID": "1", "Image": "C:\\x.exe", "Hashes": "MD5=aa,SHA256=ABCD,IMPHASH=ff", "ProcessId": "12"})
    assert ev["sha256"] == "abcd" and ev["pid"] == 12 and ev["timestamp"].tzinfo is not None
    sec = normalize({"@timestamp": "2020-01-01T10:00:00Z", "Hostname": "h", "Channel": "Security", "EventID": 4688,
                     "NewProcessName": "C:\\y.exe", "NewProcessId": "0x10", "ProcessId": "0x4"})
    assert sec["event_id"] == 1 and sec["process_guid"] == "pid-h-0x10" and sec["parent_process_guid"] == "pid-h-0x4"


def test_out_of_scope_events_are_dropped():
    assert normalize({"@timestamp": "2020-01-01T10:00:00Z", "Hostname": "h", "Channel": "Security", "EventID": 4624}) is None
    assert normalize({"Hostname": "h", "Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}) is None


def test_load_dataset_maps_hosts_shifts_time_and_labels_window():
    spec = load_manifest(FIX / "manifest.yml")[0]
    res = OTRFResult()
    load_dataset(spec, res)
    assert res.datasets[0]["events"] == 5 and res.datasets[0]["attack_events"] == 3
    assert {e["host"] for e in res.events} == {"WS-007"}
    first = min(datetime.fromisoformat(e["timestamp"]) for e in res.events)
    assert first == datetime(2026, 9, 2, 11, 0, tzinfo=UTC)
    attack = {e["image"].split("\\")[-1] for e in res.events if res.truth[e["event_uid"]]["is_attack"]}
    assert attack == {"powershell.exe", "whoami.exe", "tool.exe"}
    # uids are stable across loads
    res2 = OTRFResult()
    load_dataset(spec, res2)
    assert [e["event_uid"] for e in res.events] == [e["event_uid"] for e in res2.events]


def test_attack_filter_narrows_labels(tmp_path):
    spec = DatasetSpec(name="f", file=FIX / "sample.jsonl", techniques=["T1059.001"],
                       attack_filter={"image": ["powershell.exe"]})
    res = OTRFResult()
    load_dataset(spec, res)
    assert sum(t["is_attack"] for t in res.truth.values()) == 1


def test_build_labels_and_splits(built, labelled):
    counts = built["meta"]["counts"]
    assert counts["review"] == {"needs_escalation": 1}  # lab background ipconfig before the attack window
    tps = [la for la in labelled if la.label == "true_positive"]
    assert len(tps) == 3 and len({la.split for la in tps}) == 1  # one source group never straddles splits
    groups = {}
    for la in labelled:
        groups.setdefault(la.scenario, set()).add(la.split)
    assert all(len(s) == 1 for s in groups.values())
