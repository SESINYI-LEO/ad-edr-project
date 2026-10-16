import datetime as dt
import os
from pathlib import Path

from tests.conftest import AGENT, SID_KABELO, SID_TSHEPO, send, verified_tx

NOW = dt.datetime.now(dt.timezone.utc)


def ts(offset=0):
    return (NOW + dt.timedelta(seconds=offset)).isoformat()


# ---------- auth & agent ----------
def test_login_failure_is_audited(client, admin):
    assert client.post("/api/auth/login", data={"username": "admin", "password": "wrong"}).status_code == 401
    entries = client.get("/api/audit", headers=admin).json()
    assert any(e["action"] == "login" and e["outcome"] == "denied" for e in entries)


def test_agent_key_required(client):
    r = client.post("/api/telemetry/events", json={"hostname": "x", "event_type": "process"})
    assert r.status_code == 401
    assert client.get("/api/alerts").status_code == 401


def test_malformed_event_rejected(client):
    r = client.post("/api/telemetry/events", json={"hostname": "x", "event_type": "bogus"}, headers=AGENT)
    assert r.status_code == 422


# ---------- detection pipeline ----------
def test_pipeline_enriches_detects_and_prioritises(client, admin):
    r = send(client, timestamp=ts(), command_line="powershell.exe -NoP -Enc SQBFAFgA")
    assert r.status_code == 200 and len(r.json()["alerts"]) == 2  # encoded PS + domain-admin PS
    tickets = client.get("/api/tickets", headers=admin).json()
    top = tickets[0]
    assert top["priority"] in ("high", "critical") and top["priority_score"] >= 70
    assert top["status"] == "prioritised"
    alert = client.get(f"/api/alerts/{top['alert_id']}", headers=admin).json()
    assert alert["events"][0]["user"]["username"] == "tshepo"
    assert alert["events"][0]["user"]["privilege"] == "domain_admin"


def test_identity_raises_priority(client, admin):
    send(client, hostname="ws020", timestamp=ts(1), raw_sid=SID_KABELO, command_line="powershell -enc AAAA")
    send(client, hostname="ws021", timestamp=ts(2), raw_sid=SID_TSHEPO, command_line="powershell -enc BBBB")
    t = {x["hostname"]: x for x in client.get("/api/tickets", headers=admin).json() if x["title"].startswith("Suspicious encoded")}
    assert t["ws021"]["priority_score"] > t["ws020"]["priority_score"]


def test_benign_event_no_alert_and_duplicates_ignored(client):
    r = send(client, event_type="process", process_name="notepad.exe", command_line="notepad.exe a.txt", timestamp=ts(5), raw_sid=SID_KABELO)
    assert r.json()["alerts"] == []
    again = send(client, event_type="process", process_name="notepad.exe", command_line="notepad.exe a.txt", timestamp=ts(5), raw_sid=SID_KABELO)
    assert again.json()["duplicate"] is True and again.json()["event_id"] == r.json()["event_id"]


def test_username_resolution_without_sid(client, admin):
    send(client, event_type="process", hostname="ws030", raw_sid=None, raw_username="CORP\\Naledi", process_name="a.exe", timestamp=ts(6))
    users = {u["username"]: u for u in client.get("/api/ad/users", headers=admin).json()}
    assert users["naledi"]["department"] == "Finance"


def test_correlation_rule_needs_threshold_and_cools_down(client, admin):
    def fail(i):
        return send(client, hostname="ws040", event_type="auth", raw_sid=SID_KABELO, command_line="logon_failed", process_name=f"lsass{i}", timestamp=ts(100 + i))
    assert all(fail(i).json()["alerts"] == [] for i in range(4))
    assert len(fail(4).json()["alerts"]) == 1
    assert fail(5).json()["alerts"] == []  # cooldown: one burst = one alert


# ---------- ticket + incident state charts ----------
def _escalated_incident(client, admin):
    t = next(x for x in client.get("/api/tickets", headers=admin).json() if x["hostname"] == "ws014" and x["status"] == "prioritised")
    assert client.post(f"/api/tickets/{t['id']}/escalate", headers=admin).status_code == 409  # must be under investigation first
    assert client.post(f"/api/tickets/{t['id']}/assign", json={}, headers=admin).json()["status"] == "under_investigation"
    assert client.post(f"/api/tickets/{t['id']}/transition", json={"status": "closed"}, headers=admin).status_code == 409
    r = client.post(f"/api/tickets/{t['id']}/escalate", headers=admin)
    assert r.status_code == 200
    return r.json()["incident_id"]


def test_full_incident_lifecycle(client, admin, analyst):
    inc = _escalated_incident(client, admin)
    detail = client.get(f"/api/incidents/{inc}", headers=admin).json()
    assert detail["status"] == "open" and detail["tickets"][0]["status"] == "escalated"

    # CONTAINED cannot be reached by a manual status change
    assert client.patch(f"/api/incidents/{inc}", json={"status": "resolved"}, headers=admin).status_code == 409
    assert client.patch(f"/api/incidents/{inc}", json={"status": "investigating"}, headers=admin).json()["status"] == "investigating"

    # --- response action preconditions (Section 3.7) ---
    body = {"action": "isolate_endpoint"}
    r = client.post(f"/api/incidents/{inc}/response", json=body, headers=admin)
    assert r.status_code == 403  # no verification
    assert client.get(f"/api/incidents/{inc}", headers=admin).json()["status"] == "investigating"

    tx_a, _ = verified_tx(client, analyst, "response_action")
    r = client.post(f"/api/incidents/{inc}/response", json=body, headers={**analyst, "X-Auth-Transaction": tx_a})
    assert r.status_code == 403  # analysts may not execute response actions

    tx_wrong, status = verified_tx(client, admin, "terminal")
    assert client.post(f"/api/incidents/{inc}/response", json=body, headers={**admin, "X-Auth-Transaction": tx_wrong}).status_code == 403  # wrong purpose

    tx, status = verified_tx(client, admin, "response_action")
    assert status == "verified"
    bad = client.post(f"/api/incidents/{inc}/response", json={"action": "format_c"}, headers={**admin, "X-Auth-Transaction": tx})
    assert bad.status_code == 400  # unapproved action; the verification was not burned
    ok = client.post(f"/api/incidents/{inc}/response", json=body, headers={**admin, "X-Auth-Transaction": tx})
    assert ok.status_code == 200 and ok.json()["status"] == "contained"
    assert "isolate_endpoint" in ok.json()["notes"]
    # post-conditions: endpoint isolated, command queued for the agent, verification single-use, audit written
    assert next(e for e in client.get("/api/endpoints", headers=admin).json() if e["hostname"] == "ws014")["status"] == "isolated"
    cmds = client.get("/api/agent/commands", params={"hostname": "ws014"}, headers=AGENT).json()
    assert cmds[0]["action"] == "isolate_endpoint"
    assert client.post(f"/api/agent/commands/{cmds[0]['id']}/result", json={"status": "done", "result": "ok"}, headers=AGENT).status_code == 200
    assert client.get("/api/agent/commands", params={"hostname": "ws014"}, headers=AGENT).json() == []
    audit = client.get("/api/audit", headers=admin).json()
    assert any(a["action"] == "response_action:isolate_endpoint" and a["outcome"] == "success" for a in audit)
    assert any(a["action"] == "response_action_denied" for a in audit)

    # --- resolve, report gate, close ---
    assert client.patch(f"/api/incidents/{inc}", json={"status": "resolved"}, headers=admin).status_code == 200
    assert client.patch(f"/api/incidents/{inc}", json={"status": "closed"}, headers=admin).status_code == 409  # report first
    rep = client.post(f"/api/incidents/{inc}/report", headers=admin).json()
    assert "tshepo" in rep["content"] and "T1059.001" in rep["content"]
    closed = client.patch(f"/api/incidents/{inc}", json={"status": "closed"}, headers=admin).json()
    assert closed["status"] == "closed" and closed["tickets"][0]["status"] == "resolved"

    m = client.get("/api/metrics", headers=admin).json()
    assert m["mttr_seconds"] is not None and m["mttd_seconds"] is not None


def test_biometric_lockout_and_expiry(client, admin):
    r = client.post("/api/auth/transactions", json={"purpose": "terminal"}, headers=admin).json()
    for _ in range(3):
        v = client.post(f"/api/auth/transactions/{r['id']}/verify", json={"credential": "nope"}).json()
    assert v["status"] == "failed"
    assert client.post(f"/api/auth/transactions/{r['id']}/verify", json={"credential": "demo-fingerprint"}).status_code == 409
    r2 = client.post("/api/auth/transactions", json={"purpose": "terminal"}, headers=admin).json()
    from app.database import SessionLocal
    from app.models import AuthTransaction, utcnow
    import uuid
    with SessionLocal() as db:
        t = db.get(AuthTransaction, uuid.UUID(r2["id"]))
        t.expires_at = utcnow() - dt.timedelta(seconds=1)
        db.commit()
    assert client.post(f"/api/auth/transactions/{r2['id']}/verify", json={"credential": "demo-fingerprint"}).status_code == 409
    assert client.get(f"/api/auth/transactions/{r2['id']}").json()["status"] == "expired"


# ---------- privileged operations ----------
def test_rule_change_needs_verification(client, admin, analyst):
    rule = {"name": "Test rule", "event_type": "file", "severity": "low", "logic": {"all": [{"field": "file_path", "op": "contains", "value": ".locked"}]}}
    assert client.post("/api/rules", json=rule, headers=admin).status_code == 403
    assert client.post("/api/rules", json=rule, headers=analyst).status_code == 403
    tx, _ = verified_tx(client, admin, "rule_change")
    assert client.post("/api/rules", json=rule, headers={**admin, "X-Auth-Transaction": tx}).status_code == 200
    fired = send(client, hostname="ws050", event_type="file", file_path="C:\\docs\\a.locked", raw_sid=SID_KABELO, timestamp=ts(300))
    assert len(fired.json()["alerts"]) == 1  # new rule is live immediately


def test_terminal_validation_and_gate(client, admin):
    assert client.post("/api/terminal/run", json={"tool": "ping", "target": "8.8.8.8; rm -rf /"}, headers=admin).status_code == 400
    assert client.post("/api/terminal/run", json={"tool": "bash", "target": "localhost"}, headers=admin).status_code == 400
    assert client.post("/api/terminal/run", json={"tool": "ping", "target": "127.0.0.1"}, headers=admin).status_code == 403
    tx, _ = verified_tx(client, admin, "terminal")
    r = client.post("/api/terminal/run", json={"tool": "ping", "target": "127.0.0.1"}, headers={**admin, "X-Auth-Transaction": tx})
    assert r.status_code == 200 and "returncode" in r.json()


# ---------- backup & restore ----------
def test_backup_restore_roundtrip_and_tamper_detection(client, admin):
    assert client.post("/api/backups", headers=admin).status_code == 403
    tx, _ = verified_tx(client, admin, "backup_create")
    b = client.post("/api/backups", headers={**admin, "X-Auth-Transaction": tx}).json()
    assert b["status"] == "verified"
    before = len(client.get("/api/alerts", headers=admin).json())
    assert before > 0

    send(client, hostname="ws099", timestamp=ts(900), command_line="powershell -enc ZZZZ")  # new data after the backup
    assert len(client.get("/api/alerts", headers=admin).json()) > before

    tx2, _ = verified_tx(client, admin, "backup_restore")
    r = client.post(f"/api/backups/{b['id']}/restore", headers={**admin, "X-Auth-Transaction": tx2})
    assert r.status_code == 200 and r.json()["restored"]["alerts"] == before
    assert len(client.get("/api/alerts", headers=admin).json()) == before
    assert any(a["action"] == "backup_restored" for a in client.get("/api/audit", headers=admin).json())  # audit survives restore

    from app.config import settings
    f = Path(settings.backup_dir) / b["filename"]
    f.write_bytes(f.read_bytes()[:-20] + b"X" * 20)  # tamper
    assert client.post(f"/api/backups/{b['id']}/verify", headers=admin).json()["status"] == "corrupt"
    tx3, _ = verified_tx(client, admin, "backup_restore")
    assert client.post(f"/api/backups/{b['id']}/restore", headers={**admin, "X-Auth-Transaction": tx3}).status_code == 422
    assert len(client.get("/api/alerts", headers=admin).json()) == before  # nothing was wiped
