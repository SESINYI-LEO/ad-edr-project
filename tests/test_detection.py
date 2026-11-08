"""Unit tests (white-box + black-box) for the rule engine: operators, thresholds, rule loading."""
from datetime import datetime, timedelta

import pytest
import yaml

from server.app.config import BASE
from server.app.detection import Detector, check, load_rules, matches

RULES = load_rules(str(BASE / "rules" / "rules.yaml"))
T0 = datetime(2026, 10, 19, 8, 0, 0)


def test_all_rules_load_and_are_mapped_to_attack():
    assert len(RULES) == 14
    assert len({r.id for r in RULES}) == 14
    assert all(r.technique.startswith("T") and r.tactic for r in RULES)


@pytest.mark.parametrize("cond,ev,expected", [
    ({"field": "a", "op": "eq", "value": "PowerShell.exe"}, {"a": "powershell.EXE"}, True),      # case-insensitive
    ({"field": "a", "op": "eq", "value": "x"}, {"a": "y"}, False),
    ({"field": "a", "op": "ne", "value": "x"}, {"a": "y"}, True),
    ({"field": "a", "op": "in", "value": ["a.exe", "b.exe"]}, {"a": "B.EXE"}, True),
    ({"field": "a", "op": "in", "value": ["a.exe"]}, {"a": "c.exe"}, False),
    ({"field": "a", "op": "not_in", "value": ["a.exe"]}, {"a": "c.exe"}, True),
    ({"field": "a", "op": "not_in", "value": ["a.exe"]}, {"a": "A.exe"}, False),
    ({"field": "a", "op": "regex", "value": r"\bfoo\d+"}, {"a": "xx FOO12"}, True),
    ({"field": "a", "op": "regex", "value": r"\bfoo\d+"}, {"a": "bar"}, False),
    ({"field": "a", "op": "contains_any", "value": ["bad", "evil"]}, {"a": "so EVIL"}, True),
    ({"field": "a", "op": "gte", "value": 10}, {"a": 10}, True),                                  # boundary
    ({"field": "a", "op": "gte", "value": 10}, {"a": 9.99}, False),
    ({"field": "a", "op": "lte", "value": 10}, {"a": "0x0a"}, True),                              # hex input
    ({"field": "a", "op": "is_public_ip", "value": True}, {"a": "8.8.8.8"}, True),
    ({"field": "a", "op": "is_public_ip", "value": True}, {"a": "10.1.2.3"}, False),
    ({"field": "a", "op": "is_public_ip", "value": True}, {"a": "192.168.0.1"}, False),
    ({"field": "a", "op": "is_public_ip", "value": True}, {"a": "127.0.0.1"}, False),
    ({"field": "a", "op": "is_public_ip", "value": True}, {"a": "not-an-ip"}, False),
    ({"field": "missing", "op": "eq", "value": "x"}, {"a": "x"}, False),                          # missing field never matches
    ({"field": "missing", "op": "ne", "value": "x"}, {"a": "x"}, False),
])
def test_condition_operators(cond, ev, expected):
    assert check(ev, cond) is expected


def test_loader_rejects_bad_severity_and_operator(tmp_path):
    base = {"id": "X1", "name": "n", "severity": "high", "technique": "T1", "tactic": "t", "confidence": 5,
            "conditions": [{"field": "a", "op": "eq", "value": "1"}]}
    for patch in ({"severity": "extreme"}, {"conditions": [{"field": "a", "op": "bogus", "value": 1}]}):
        p = tmp_path / "r.yaml"
        p.write_text(yaml.safe_dump([{**base, **patch}]))
        with pytest.raises(ValueError):
            load_rules(str(p))


def _bf(i, user="lab\\x", host=1, sec=None):
    return {"_id": i, "timestamp": T0 + timedelta(seconds=i if sec is None else sec), "endpoint_id": host,
            "event_type": "logon_failure", "user": user, "process_name": None, "command_line": None}


@pytest.mark.parametrize("n,window_ok,fires", [(4, True, False), (5, True, True), (6, True, True)])
def test_brute_force_threshold_boundary(n, window_ok, fires):
    d = Detector(RULES)
    hits = [x for i in range(n) for x in d.evaluate(_bf(i))]
    assert bool([h for h in hits if h.rule.id == "R009"]) is fires


def test_brute_force_outside_window_does_not_fire():
    d = Detector(RULES)
    hits = [x for i in range(8) for x in d.evaluate(_bf(i, sec=i * 20))]  # one every 20 s: never 5 inside 60 s
    assert not [h for h in hits if h.rule.id == "R009"]


def test_brute_force_is_per_user_and_per_host():
    d = Detector(RULES)
    hits = []
    for i in range(10):
        hits += d.evaluate(_bf(i, user=f"lab\\u{i % 2}", host=1))   # 5 each across two users interleaved over 10 s
    assert [h for h in hits if h.rule.id == "R009"]  # 5 per user inside 60 s fires
    d2 = Detector(RULES)
    hits2 = []
    for i in range(8):
        hits2 += d2.evaluate(_bf(i, user=f"lab\\u{i % 2}", host=1))  # 4 each: below threshold
    assert not [h for h in hits2 if h.rule.id == "R009"]


def _enc(i, sec):
    return {"_id": i, "timestamp": T0 + timedelta(seconds=sec), "endpoint_id": 1, "event_type": "file_modify",
            "process_name": "evil.exe", "user": "lab\\x", "file_ext": ".locked", "command_line": None}


@pytest.mark.parametrize("n,fires", [(19, False), (20, True), (21, True)])
def test_ransomware_threshold_boundary(n, fires):
    d = Detector(RULES)
    hits = [x for i in range(n) for x in d.evaluate(_enc(i, i * 0.1))]
    assert bool([h for h in hits if h.rule.id == "R010"]) is fires


def test_ransomware_slow_encryption_outside_window_does_not_fire():
    d = Detector(RULES)
    hits = [x for i in range(40) for x in d.evaluate(_enc(i, i * 1.0))]  # 1 file/sec: only 11 inside any 10 s
    assert not [h for h in hits if h.rule.id == "R010"]


def test_threshold_rule_fires_once_per_burst():
    d = Detector(RULES)
    hits = [x for i in range(25) for x in d.evaluate(_enc(i, i * 0.05)) if x.rule.id == "R010"]
    assert len(hits) == 1 and len(hits[0].event_ids) == 20


def test_disabled_rule_does_not_fire():
    d = Detector(RULES)
    ev = {"_id": 1, "timestamp": T0, "endpoint_id": 1, "event_type": "process_create", "process_name": "wevtutil.exe",
          "command_line": "wevtutil cl Security", "user": "lab\\x"}
    assert any(h.rule.id == "R011" for h in d.evaluate(ev))
    d.set_enabled("R011", False)
    assert not any(h.rule.id == "R011" for h in d.evaluate(ev))
    d.set_enabled("R999", False)  # unknown id is ignored, not an error


def test_encoded_powershell_regex_variants():
    r = next(x for x in RULES if x.id == "R001")
    base = {"event_type": "process_create", "process_name": "powershell.exe"}
    b = "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA="
    for flag in ("-enc", "-EncodedCommand", "-ec", "-e"):
        assert matches({**base, "command_line": f"powershell {flag} {b}"}, r), flag
    assert not matches({**base, "command_line": "powershell -File a.ps1"}, r)
    assert not matches({**base, "command_line": "powershell -enc short"}, r)       # too short to be a payload
    assert not matches({**base, "process_name": "notepad.exe", "command_line": f"x -enc {b}"}, r)
