"""Black-box API tests: authentication, RBAC, agent enrolment, ingestion, enrichment, tickets and incidents."""
from datetime import timedelta

import pytest

from helpers import (ADMIN, ANALYST, B64, PS, encoded_ps, ev, ingest, login, make_incident, now, register_agent)

API = "/api/v1"


def test_health(client):
    assert client.get(f"{API}/health").json()["status"] == "ok"


# ---------------- authentication ----------------
def test_login_success_returns_token_and_role(client):
    r = client.post(f"{API}/auth/login", json={"username": ADMIN[0], "password": ADMIN[1]})
    assert r.status_code == 200 and r.json()["user"]["role"] == "admin" and r.json()["token_type"] == "bearer"


def test_login_failures_do_not_reveal_whether_user_exists(client):
    a = client.post(f"{API}/auth/login", json={"username": "admin", "password": "wrong-pass-1A"})
    b = client.post(f"{API}/auth/login", json={"username": "ghost", "password": "wrong-pass-1A"})
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_account_locks_after_repeated_failures_even_for_correct_password(client):
    for _ in range(5):
        assert client.post(f"{API}/auth/login", json={"username": "analyst", "password": "bad"}).status_code == 401
    assert client.post(f"{API}/auth/login", json={"username": "analyst", "password": ANALYST[1]}).status_code == 423


def test_active_directory_user_logs_in_with_domain_password(client):
    ok = client.post(f"{API}/auth/login", json={"username": "admin01", "password": "SecAdmin@lab-2026"})
    bad = client.post(f"{API}/auth/login", json={"username": "admin01", "password": "nope"})
    assert ok.status_code == 200 and ok.json()["user"]["auth_source"] == "ad" and bad.status_code == 401


def test_protected_routes_require_a_valid_token(client, admin_h):
    assert client.get(f"{API}/alerts").status_code == 401
    assert client.get(f"{API}/alerts", headers={"Authorization": "Bearer garbage"}).status_code == 401
    assert client.get(f"{API}/alerts", headers={"Authorization": "Basic abc"}).status_code == 401
    assert client.get(f"{API}/alerts", headers=admin_h).status_code == 200


def test_expired_token_is_rejected(client, monkeypatch):
    from server.app import security
    monkeypatch.setattr(security.get_settings(), "token_minutes", -1, raising=False) if False else None
    import jwt
    from server.app.config import get_settings
    t = jwt.encode({"sub": "1", "exp": now() - timedelta(minutes=5)}, get_settings().secret_key, algorithm="HS256")
    assert client.get(f"{API}/alerts", headers={"Authorization": f"Bearer {t}"}).status_code == 401


def test_token_signed_with_other_key_or_none_algorithm_rejected(client):
    import jwt
    forged = jwt.encode({"sub": "1", "exp": now() + timedelta(hours=1)}, "another-secret-key-another-secret-key", algorithm="HS256")
    assert client.get(f"{API}/alerts", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    none_tok = jwt.encode({"sub": "1"}, key=None, algorithm="none")
    assert client.get(f"{API}/alerts", headers={"Authorization": f"Bearer {none_tok}"}).status_code == 401


def test_disabled_user_cannot_use_existing_token(client, admin_h, analyst_h):
    uid = client.get(f"{API}/auth/me", headers=analyst_h).json()["id"]
    assert client.patch(f"{API}/users/{uid}", json={"status": "disabled"}, headers=admin_h).status_code == 200
    assert client.get(f"{API}/auth/me", headers=analyst_h).status_code == 401


# ---------------- RBAC & user management ----------------
def test_analyst_cannot_use_admin_functions(client, analyst_h):
    assert client.get(f"{API}/alerts", headers=analyst_h).status_code == 200
    for method, path, body in [("post", "/users", {"username": "x1x1", "password": "Passw0rd!!x", "role": "admin"}),
                               ("post", "/devices", {"name": "p", "public_key_pem": "x" * 60}),
                               ("get", "/backups", None), ("get", "/tools", None),
                               ("post", "/verify/initiate", {"purpose": "backup:create"})]:
        r = getattr(client, method)(API + path, headers=analyst_h, **({"json": body} if body else {}))
        assert r.status_code == 403, path


def test_user_creation_policy_and_duplicates(client, admin_h):
    mk = lambda **k: client.post(f"{API}/users", headers=admin_h, json={"username": "newuser", "role": "analyst", **k})
    assert mk(password="short").status_code == 422
    assert mk(password="alllowercase123").status_code == 422
    assert mk().status_code == 422                                 # local account needs a password
    assert mk(password="Str0ngPassw0rd").status_code == 201
    assert mk(password="Str0ngPassw0rd").status_code == 409
    assert client.post(f"{API}/users", headers=admin_h, json={"username": "a b", "role": "analyst", "password": "Str0ngPassw0rd"}).status_code == 422
    assert client.post(f"{API}/users", headers=admin_h, json={"username": "okname", "role": "root", "password": "Str0ngPassw0rd"}).status_code == 422


def test_admin_cannot_disable_own_account(client, admin_h):
    me = client.get(f"{API}/auth/me", headers=admin_h).json()["id"]
    assert client.patch(f"{API}/users/{me}", json={"status": "disabled"}, headers=admin_h).status_code == 409


# ---------------- agent enrolment & ingest auth ----------------
def test_agent_registration_requires_enrollment_token(client):
    assert client.post(f"{API}/agent/register", json={"hostname": "WS-X"}, headers={"X-Enrollment-Token": "nope"}).status_code == 401
    assert client.post(f"{API}/agent/register", json={"hostname": "WS-X"}).status_code == 401
    assert client.post(f"{API}/agent/register", json={"hostname": "bad host!"}, headers={"X-Enrollment-Token": "lab-enrollment-token"}).status_code == 422


def test_ingest_requires_valid_api_key_and_reenrolment_rotates_it(client):
    key1, _ = register_agent(client, "WS-R1")
    assert client.post(f"{API}/ingest", json={"events": []}).status_code == 401
    assert client.post(f"{API}/ingest", json={"events": []}, headers={"X-API-Key": "edr_wrong"}).status_code == 401
    assert client.post(f"{API}/ingest", json={"events": []}, headers=key1).status_code == 200
    key2, _ = register_agent(client, "WS-R1")
    assert client.post(f"{API}/ingest", json={"events": []}, headers=key1).status_code == 401  # old key revoked
    assert client.post(f"{API}/ingest", json={"events": []}, headers=key2).status_code == 200


# ---------------- ingestion validation ----------------
@pytest.mark.parametrize("bad,field", [
    ({"event_type": "format_c"}, "event_type"),
    ({"unexpected": 1}, "unexpected"),
    ({"timestamp": "not-a-date"}, "timestamp"),
    ({"user_sid": "S-1-5-21-1)(cn=*"}, "user_sid"),
    ({"details": {"bad key!": 1}}, "details"),
    ({"details": {"k": "x" * 3000}}, "details"),
    ({"details": {f"k{i}": 1 for i in range(40)}}, "details"),
    ({"process_name": "x" * 400}, "process_name"),
])
def test_invalid_events_are_rejected_with_reason(client, key, bad, field):
    e = {**ev(cmd="x"), **bad}
    r = ingest(client, key, [e]).json()
    assert r["rejected"] == 1 and r["accepted"] == 0 and field in r["errors"][0]["field"]


def test_future_and_ancient_timestamps_rejected(client, key):
    r = ingest(client, key, [ev(ts=now() + timedelta(hours=2)), ev(ts=now() - timedelta(days=60))]).json()
    assert r["rejected"] == 2 and r["accepted"] == 0


def test_partial_batch_accepts_valid_events(client, key):
    r = ingest(client, key, [ev(cmd="a"), {"event_type": "nope", "timestamp": now().isoformat()}, ev(cmd="b")]).json()
    assert (r["accepted"], r["rejected"]) == (2, 1)


def test_oversized_batch_rejected(client, key):
    r = client.post(f"{API}/ingest", json={"events": [ev(cmd=str(i)) for i in range(501)]}, headers=key)
    assert r.status_code == 413


def test_duplicate_events_are_ignored_not_double_counted(client, key, admin_h):
    e = encoded_ps()
    assert ingest(client, key, [e]).json()["alerts_created"] == 1
    r = ingest(client, key, [e, e]).json()
    assert r["duplicates"] == 2 and r["accepted"] == 0
    assert len(client.get(f"{API}/alerts", headers=admin_h).json()) == 1


def test_repeat_attack_within_window_is_merged_into_one_alert(client, key, admin_h):
    ingest(client, key, [encoded_ps(ts=now())])
    r = ingest(client, key, [encoded_ps(ts=now() + timedelta(seconds=1))]).json()
    assert r["alerts_created"] == 0 and r["alerts_updated"] == 1
    alerts = client.get(f"{API}/alerts", headers=admin_h).json()
    assert len(alerts) == 1 and alerts[0]["event_count"] == 2
    assert len(client.get(f"{API}/tickets", headers=admin_h).json()) == 1


def test_hostile_strings_are_stored_inertly(client, key, admin_h):
    evil = "'; DROP TABLE alerts;-- <script>alert(1)</script> ${jndi:ldap://x}"
    r = ingest(client, key, [ev(cmd=evil, user="LAB\\jsmith'; --")]).json()
    assert r["accepted"] == 1
    assert client.get(f"{API}/alerts", headers=admin_h).status_code == 200
    ep = client.get(f"{API}/endpoints", headers=admin_h).json()[0]
    assert client.get(f"{API}/endpoints/{ep['id']}/events", headers=admin_h).json()[0]["command_line"] == evil


# ---------------- AD enrichment ----------------
def test_events_are_attributed_to_ad_identity_and_alert_shows_department(client, key, admin_h):
    ingest(client, key, [encoded_ps(r"LAB\jsmith")])
    a = client.get(f"{API}/alerts", headers=admin_h).json()[0]
    assert (a["user"], a["department"], a["privilege_level"]) == ("jsmith", "Finance", "standard")
    d = client.get(f"{API}/alerts/{a['id']}", headers=admin_h).json()
    assert d["identity"]["sid"].startswith("S-1-5-21-") and d["events"][0]["attribution"] == "resolved"
    assert d["events"][0]["identity"]["display_name"] == "John Smith"


def test_attribution_statuses(client, key, admin_h):
    ingest(client, key, [ev(cmd="a", user=r"NT AUTHORITY\SYSTEM"), ev(cmd="b", user=r"LAB\ghostuser"),
                         ev(cmd="c", user=r"LAB\jsmith"), ev(cmd="d", user=r"LAB\jsmith")])
    ep = client.get(f"{API}/endpoints", headers=admin_h).json()[0]
    st = {e["command_line"]: e["attribution"] for e in client.get(f"{API}/endpoints/{ep['id']}/events", headers=admin_h).json()}
    assert st == {"a": "system", "b": "unattributed", "c": "cached", "d": "cached"} or st["a"] == "system" and st["b"] == "unattributed" and {st["c"], st["d"]} <= {"resolved", "cached"}


def test_event_with_sid_resolves_when_name_missing(client, key, admin_h):
    from server.app.ad import Directory
    from server.app.config import get_settings
    sid = Directory(get_settings()).lookup(sam="lmokoena").sid
    ingest(client, key, [{**encoded_ps(user=None), "user_sid": sid}])
    assert client.get(f"{API}/alerts", headers=admin_h).json()[0]["user"] == "lmokoena"


def test_privileged_account_gets_higher_ticket_priority(client, admin_h):
    k1, _ = register_agent(client, "WS-P1")
    k2, _ = register_agent(client, "WS-P2")
    ingest(client, k1, [encoded_ps(r"LAB\jsmith")])
    ingest(client, k2, [encoded_ps(r"LAB\tkgosi")])
    t = {x["user"]: x for x in client.get(f"{API}/tickets", headers=admin_h).json()}
    assert t["tkgosi"]["priority_score"] > t["jsmith"]["priority_score"]
    assert t["tkgosi"]["priority_score"] - t["jsmith"]["priority_score"] == pytest.approx(16.0)


def test_asset_criticality_raises_priority(client, admin_h):
    lo, _ = register_agent(client, "WS-LOW", criticality=1)
    hi, _ = register_agent(client, "SRV-DC01", criticality=5)
    ingest(client, lo, [encoded_ps()])
    ingest(client, hi, [encoded_ps()])
    t = {x["hostname"]: x["priority_score"] for x in client.get(f"{API}/tickets", headers=admin_h).json()}
    assert t["SRV-DC01"] > t["WS-LOW"]


def test_tickets_are_sorted_most_urgent_first(client, key, admin_h):
    ingest(client, key, [ev(cmd="whoami /priv", user=r"LAB\jsmith"), ev(cmd="vssadmin delete shadows /all", user=r"LAB\tkgosi", proc=r"C:\Windows\System32\vssadmin.exe")])
    pr = [t["priority_score"] for t in client.get(f"{API}/tickets", headers=admin_h).json()]
    assert pr == sorted(pr, reverse=True) and len(pr) == 2


# ---------------- ticket workflow ----------------
def test_ticket_lifecycle_enforces_state_machine(client, key, admin_h):
    ingest(client, key, [encoded_ps()])
    t = client.get(f"{API}/tickets", headers=admin_h).json()[0]
    tr = lambda st, **k: client.post(f"{API}/tickets/{t['id']}/transition", json={"status": st, **k}, headers=admin_h)
    assert tr("Under Investigation").status_code == 409            # cannot skip Assigned
    assert tr("Resolved").status_code == 409
    assert tr("Escalated").status_code == 422                      # only through an incident
    assert tr("Assigned", assignee_id=9999).status_code == 422
    assert tr("Assigned").json()["assignee"] == "admin"
    assert tr("Under Investigation").status_code == 200
    assert tr("Resolved").json()["resolved_at"]
    assert tr("Under Investigation").status_code == 200            # reopen
    assert tr("Resolved").status_code == 200 and tr("Closed").status_code == 200
    assert tr("Assigned").status_code == 409                       # closed is final
    assert client.get(f"{API}/alerts/{t['alert_id']}", headers=admin_h).json()["status"] == "closed"


def test_acknowledge_alert(client, key, admin_h, analyst_h):
    ingest(client, key, [encoded_ps()])
    aid = client.get(f"{API}/alerts", headers=admin_h).json()[0]["id"]
    assert client.post(f"{API}/alerts/{aid}/acknowledge", headers=analyst_h).json()["status"] == "acknowledged"
    assert client.post(f"{API}/alerts/9999/acknowledge", headers=analyst_h).status_code == 404


def test_alert_filters(client, key, admin_h):
    ingest(client, key, [encoded_ps(), ev(cmd="wevtutil cl Security", proc=r"C:\Windows\System32\wevtutil.exe")])
    assert {a["severity"] for a in client.get(f"{API}/alerts?severity=high", headers=admin_h).json()} == {"high"}
    assert client.get(f"{API}/alerts?status=closed", headers=admin_h).json() == []


# ---------------- incidents ----------------
def test_incident_requires_ticket_under_investigation(client, key, admin_h):
    ingest(client, key, [encoded_ps()])
    t = client.get(f"{API}/tickets", headers=admin_h).json()[0]
    assert client.post(f"{API}/incidents", json={"ticket_id": t["id"]}, headers=admin_h).status_code == 409
    assert client.post(f"{API}/incidents", json={"ticket_id": 9999}, headers=admin_h).status_code == 404


def test_incident_notes_report_and_close(client, key, admin_h, analyst_h):
    inc = make_incident(client, admin_h, key)
    assert client.get(f"{API}/tickets", headers=admin_h).json()[0]["status"] == "Escalated"
    n = client.post(f"{API}/incidents/{inc['id']}/notes", json={"text": "User reports a strange email."}, headers=analyst_h)
    assert n.status_code == 201 and n.json()["notes"][0]["by"] == "analyst"
    rep = client.get(f"{API}/incidents/{inc['id']}/report", headers=analyst_h).json()
    assert rep["who"][0]["user"] == "jsmith" and rep["who"][0]["department"] == "Finance"
    assert rep["where"] == ["WS-T01"] and rep["what"][0]["technique"] == "T1059.001"
    assert rep["timeline"] and rep["when"]["first_event"]
    closed = client.post(f"{API}/incidents/{inc['id']}/close", headers=analyst_h).json()
    assert closed["status"] == "closed" and closed["tickets"][0]["status"] == "Resolved"
    assert client.post(f"{API}/incidents/{inc['id']}/close", headers=analyst_h).status_code == 409
    assert client.post(f"{API}/incidents/{inc['id']}/notes", json={"text": "late"}, headers=analyst_h).status_code == 409


def test_note_validation(client, key, admin_h):
    inc = make_incident(client, admin_h, key)
    assert client.post(f"{API}/incidents/{inc['id']}/notes", json={"text": ""}, headers=admin_h).status_code == 422
    assert client.post(f"{API}/incidents/{inc['id']}/notes", json={"text": "x" * 2001}, headers=admin_h).status_code == 422


# ---------------- audit trail ----------------
def test_audit_trail_records_key_actions_and_chain_is_valid(client, key, admin_h):
    ingest(client, key, [encoded_ps()])
    client.post(f"{API}/auth/login", json={"username": "admin", "password": "bad"})
    acts = {(a["action"], a["outcome"]) for a in client.get(f"{API}/audit?limit=200", headers=admin_h).json()}
    assert {("auth.login", "success"), ("auth.login", "denied"), ("detection.alert", "success"), ("agent.register", "success")} <= acts
    assert client.get(f"{API}/audit/verify", headers=admin_h).json() == {"ok": True, "checked": len(client.get(f"{API}/audit?limit=500", headers=admin_h).json()), "broken_at": None}


def test_tampering_with_audit_log_is_detected(client, key, admin_h, db):
    from server.app.models import AuditLog
    ingest(client, key, [encoded_ps()])
    row = db.query(AuditLog).filter(AuditLog.action_type == "detection.alert").first()
    row.details = {**row.details, "priority": "Low"}      # an attacker downgrades an alert record
    db.commit()
    res = client.get(f"{API}/audit/verify", headers=admin_h).json()
    assert res["ok"] is False and res["broken_at"] == row.id


def test_deleting_audit_entry_breaks_chain(client, key, admin_h, db):
    from server.app.models import AuditLog
    for i in range(3):
        client.post(f"{API}/auth/login", json={"username": "admin", "password": f"bad{i}"})
    mid = db.query(AuditLog).order_by(AuditLog.id).all()[-2]
    db.delete(mid)
    db.commit()
    assert client.get(f"{API}/audit/verify", headers=admin_h).json()["ok"] is False


# ---------------- dashboard summary / endpoints ----------------
def test_dashboard_summary_and_endpoint_states(client, key, admin_h):
    ingest(client, key, [encoded_ps()])
    s = client.get(f"{API}/dashboard/summary", headers=admin_h).json()
    assert s["endpoints"]["total"] == 1 and s["endpoints"]["online"] == 1
    assert s["alerts_24h"]["high"] == 1 and sum(s["open_tickets"].values()) == 1
    assert s["events_attributed"] == 1 and s["top_users"][0]["user"] == "jsmith" and s["tactics"][0]["tactic"] == "Execution"
    eps = client.get(f"{API}/endpoints", headers=admin_h).json()
    assert eps[0]["open_alerts"] == 1 and eps[0]["state"] == "online"


def test_endpoint_goes_offline_when_silent(client, key, admin_h, db):
    from server.app.models import Endpoint, utcnow
    db.query(Endpoint).update({"last_seen": utcnow() - timedelta(minutes=10)})
    db.commit()
    assert client.get(f"{API}/endpoints", headers=admin_h).json()[0]["state"] == "offline"
    assert client.post(f"{API}/agent/heartbeat", headers=key).status_code == 200
    assert client.get(f"{API}/endpoints", headers=admin_h).json()[0]["state"] == "online"


def test_security_headers_present(client):
    h = client.get(f"{API}/health").headers
    assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY" and "default-src 'self'" in h["content-security-policy"]
