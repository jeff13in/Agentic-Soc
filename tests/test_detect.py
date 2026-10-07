from data.detect import Rule, load_rules, matches


def rule(selection, filt=None):
    return Rule("T", "t", "low", (), "", selection, filt)


def test_all_rules_load_with_ids_and_tags():
    rules = load_rules()
    assert len(rules) >= 10
    assert len({r.id for r in rules}) == len(rules)
    assert all(r.tags and r.severity in {"low", "medium", "high", "critical"} for r in rules)


def test_modifiers_are_case_insensitive_and_lists_mean_any():
    r = rule({"event_id": 1, "image|endswith": ["\\a.exe", "\\B.EXE"], "command_line|contains": "/Create"})
    assert matches(r, {"event_id": 1, "image": "C:\\x\\b.exe", "command_line": "schtasks /create /tn x"})
    assert not matches(r, {"event_id": 1, "image": "C:\\x\\c.exe", "command_line": "/create"})
    assert not matches(r, {"event_id": 3, "image": "C:\\x\\a.exe", "command_line": "/create"})


def test_missing_field_never_matches():
    assert not matches(rule({"command_line|contains": "x"}), {"event_id": 1})


def test_filter_suppresses():
    r = rule({"event_id": 3}, {"dst_ip|re": r"^10\."})
    assert matches(r, {"event_id": 3, "dst_ip": "52.1.1.1"})
    assert not matches(r, {"event_id": 3, "dst_ip": "10.0.0.5"})


def test_encoded_powershell_rule_does_not_fire_on_execution_policy():
    r = next(r for r in load_rules() if r.id == "R001")
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    assert matches(r, {"event_id": 1, "image": ps, "command_line": "powershell.exe -NoProfile -enc AAAA"})
    assert matches(r, {"event_id": 1, "image": ps, "command_line": "powershell -EncodedCommand AAAA"})
    assert not matches(r, {"event_id": 1, "image": ps, "command_line": "powershell -ExecutionPolicy Bypass -File a.ps1"})


def test_wmic_rule_values_parse_as_strings():
    r = next(r for r in load_rules() if r.id == "R011")
    assert matches(r, {"event_id": 1, "image": "C:\\Windows\\System32\\wbem\\WMIC.exe",
                       "command_line": "wmic /node:WS-001 computersystem get model"})
