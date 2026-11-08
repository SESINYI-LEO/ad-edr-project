"""Endpoint agent: Sysmon/Security XML parsing, offline spool + retry, and the authenticator device."""
import json
import urllib.error
from pathlib import Path

import pytest

from edr_agent import client as client_mod
from edr_agent.config import AgentConfig, load_config
from edr_agent.sysmon import parse_event_xml
from device.authenticator import Authenticator

NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'


def xml(eid, data, provider="Microsoft-Windows-Sysmon", t="2026-10-19T08:00:00.123456789Z"):
    d = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event {NS}><System><Provider Name="{provider}"/><EventID>{eid}</EventID><TimeCreated SystemTime="{t}"/>'
            f'<EventRecordID>7</EventRecordID></System><EventData>{d}</EventData></Event>')


def test_sysmon_process_create():
    e = parse_event_xml(xml(1, {"Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd /c dir", "ParentImage": r"C:\x\explorer.exe",
                                "User": r"LAB\jsmith", "ProcessId": "42"}))
    assert (e["event_type"], e["user"], e["details"]["pid"]) == ("process_create", r"LAB\jsmith", 42)
    assert e["timestamp"] == "2026-10-19T08:00:00.123456+00:00"            # nanoseconds truncated to microseconds


def test_sysmon_network_access_file_registry():
    n = parse_event_xml(xml(3, {"Image": "a.exe", "User": "LAB\\x", "DestinationIp": "8.8.8.8", "DestinationPort": "443", "Protocol": "tcp"}))
    assert n["details"] == {"dest_ip": "8.8.8.8", "dest_port": 443, "protocol": "tcp"}
    a = parse_event_xml(xml(10, {"SourceImage": "m.exe", "TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": "0x1FFFFF", "SourceUser": "LAB\\x"}))
    assert a["event_type"] == "process_access" and a["details"]["granted_access"] == "0x1fffff"
    f = parse_event_xml(xml(11, {"Image": "w.exe", "TargetFilename": r"C:\a\b.docx", "User": "LAB\\x"}))
    assert f["details"]["file_path"] == r"C:\a\b.docx"
    r = parse_event_xml(xml(13, {"Image": "x.exe", "TargetObject": r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\X", "Details": "y", "User": "LAB\\x"}))
    assert r["event_type"] == "registry_set"


def test_security_logon_events():
    f = parse_event_xml(xml(4625, {"TargetUserName": "jsmith", "TargetDomainName": "LAB", "LogonType": "3", "IpAddress": "10.0.0.5"},
                            provider="Microsoft-Windows-Security-Auditing"))
    assert (f["event_type"], f["user"], f["details"]["logon_type"]) == ("logon_failure", r"LAB\jsmith", 3)
    assert parse_event_xml(xml(4624, {"TargetUserName": "x"}, provider="Microsoft-Windows-Security-Auditing"))["event_type"] == "logon_success"


@pytest.mark.parametrize("bad", ["", "<bad", "<Event/>", "not xml at all", xml(1, {}, t="garbage"), xml("abc", {}),
                                 xml(99, {"a": "b"}), xml(5, {}, provider="Other-Provider")])
def test_parser_ignores_malformed_or_unsupported_input(bad):
    assert parse_event_xml(bad) is None


def test_parser_truncates_huge_command_lines():
    e = parse_event_xml(xml(1, {"Image": "a.exe", "CommandLine": "A" * 20000}))
    assert len(e["command_line"]) == 8192


def test_parsed_events_pass_server_validation_and_trigger_detection(client, key):
    from helpers import ingest
    e = parse_event_xml(xml(1, {"Image": r"C:\Windows\System32\wevtutil.exe", "CommandLine": "wevtutil cl Security", "User": r"LAB\tkgosi"},
                            t=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")))
    r = ingest(client, key, [e]).json()
    assert r["accepted"] == 1 and r["alerts_created"] == 1


# ---------------- client / spool ----------------
class FakeServer:
    def __init__(self, fail=0, status=None):
        self.fail, self.status, self.sent = fail, status, []

    def __call__(self, method, path, body=None, headers=None, timeout=10):
        if self.fail:
            self.fail -= 1
            raise urllib.error.URLError("connection refused")
        if self.status:
            raise client_mod.ServerError(self.status, "nope")
        self.sent.extend(body["events"])
        return {"accepted": len(body["events"])}


@pytest.fixture
def cl(tmp_path, monkeypatch):
    monkeypatch.setattr(client_mod.time, "sleep", lambda s: None)
    c = client_mod.Client(AgentConfig(state_dir=str(tmp_path), batch_size=2))
    c.api_key = "edr_x"
    return c


def test_events_are_spooled_when_server_is_down_then_drained(cl, monkeypatch):
    down = FakeServer(fail=99)
    monkeypatch.setattr(cl, "_req", down)
    assert cl.send_with_retry([{"n": 1}, {"n": 2}, {"n": 3}], attempts=3) is False
    assert len(open(cl.cfg.spool_file).readlines()) == 3
    up = FakeServer()
    monkeypatch.setattr(cl, "_req", up)
    assert cl.send_with_retry([{"n": 4}]) is True
    assert [e["n"] for e in up.sent] == [1, 2, 3, 4] and not cl.cfg.spool_file.exists()


def test_permanent_errors_are_not_retried_or_spooled(cl, monkeypatch):
    s = FakeServer(status=401)
    monkeypatch.setattr(cl, "_req", s)
    assert cl.send_with_retry([{"n": 1}]) is False and not cl.cfg.spool_file.exists()


def test_spool_is_bounded(cl):
    cl.cfg.spool_max_events = 5
    cl.spool([{"n": i} for i in range(8)])
    cl.spool([{"n": 99}])
    assert len(open(cl.cfg.spool_file).readlines()) == 5


def test_failed_drain_keeps_spool(cl, monkeypatch):
    cl.spool([{"n": i} for i in range(4)])
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] == 2:
            raise urllib.error.URLError("drop")
        return {}
    monkeypatch.setattr(cl, "_req", flaky)
    with pytest.raises(urllib.error.URLError):
        cl.drain_spool()
    assert cl.cfg.spool_file.exists()


def test_registration_persists_api_key_with_restrictive_permissions(cl, monkeypatch):
    monkeypatch.setattr(cl, "_req", lambda *a, **k: {"api_key": "edr_secret", "endpoint_id": 3})
    cl.api_key = None
    cl.ensure_registered()
    assert json.loads(cl.cfg.key_file.read_text())["api_key"] == "edr_secret"
    assert oct(cl.cfg.key_file.stat().st_mode & 0o777) == "0o600"
    assert client_mod.Client(cl.cfg).api_key == "edr_secret"        # reloaded from disk on restart


def test_config_loading_and_env_override(tmp_path, monkeypatch):
    p = tmp_path / "a.json"
    p.write_text(json.dumps({"server_url": "http://x:1", "batch_size": 7, "unknown": 1}))
    monkeypatch.setenv("EDR_HOSTNAME", "WS-ENV")
    c = load_config(str(p))
    assert (c.server_url, c.batch_size, c.hostname) == ("http://x:1", 7, "WS-ENV")


def test_windows_collector_refuses_to_run_elsewhere(tmp_path):
    from edr_agent.collector import WindowsCollector
    with pytest.raises(RuntimeError):
        WindowsCollector(str(tmp_path)).poll()


def test_isolation_is_logged_off_windows(caplog):
    from edr_agent.main import isolate_host
    with caplog.at_level("WARNING", logger="edr_agent"):
        isolate_host("10.0.0.1")
    assert "would block all traffic" in caplog.text


# ---------------- authenticator ----------------
def test_authenticator_key_persistence_and_qr_parsing(tmp_path):
    a = Authenticator(tmp_path / "k.pem")
    assert Authenticator(tmp_path / "k.pem").public_pem == a.public_pem
    assert oct((tmp_path / "k.pem").stat().st_mode & 0o777) == "0o600"
    assert a.parse_qr("edr://verify?id=12&n=abc_DEF-1") == (12, "abc_DEF-1")
    for bad in ("http://evil/verify?id=1&n=a", "edr://verify?id=x&n=a", "", None, "edr://verify?id=1&n=a b"):
        with pytest.raises(ValueError):
            a.parse_qr(bad)
