"""QR-assisted biometric verification, protected actions, rule changes, backup/restore and the tools terminal."""
from datetime import timedelta

import pytest

from device.authenticator import Authenticator
from helpers import encoded_ps, enroll, ev, ingest, make_incident, now, verification

API = "/api/v1"


def act(client, h, inc_id, ver_id, kind="isolate_endpoint", target="WS-T01"):
    return client.post(f"{API}/incidents/{inc_id}/actions", headers=h,
                       json={"action_type": kind, "target": target, "verification_id": ver_id})


def audit(client, h, prefix):
    return client.get(f"{API}/audit?limit=200&action={prefix}", headers=h).json()


def test_isolation_succeeds_after_verified_biometric_and_agent_is_told(client, admin_h, key, auth):
    inc = make_incident(client, admin_h, key)
    vid, res = verification(client, admin_h, auth, f"response_action:{inc['id']}:isolate_endpoint")
    assert res == {"ok": True, "stage": "complete", "status": "verified"}
    r = act(client, admin_h, inc["id"], vid)
    assert r.status_code == 201 and r.json()["status"] == "contained"
    assert "isolated" in r.json()["actions"][0]["outcome"]
    assert any("isolate_endpoint" in n["text"] for n in r.json()["notes"])  # design post-condition: note added to the incident
    assert client.post(f"{API}/agent/heartbeat", headers=key).json() == {"status": "isolated", "commands": [{"type": "isolate"}]}
    assert client.get(f"{API}/endpoints", headers=admin_h).json()[0]["state"] == "isolated"
    assert {a["action"] for a in audit(client, admin_h, "")} >= {"verify.initiated", "verify.qr_validated", "verify.verified", "response.executed"}


def test_response_action_without_verification_is_denied_and_audited(client, admin_h, key, auth):
    inc = make_incident(client, admin_h, key)
    r = act(client, admin_h, inc["id"], None)
    assert r.status_code == 403 and "verification required" in r.json()["detail"].lower()
    assert client.get(f"{API}/endpoints", headers=admin_h).json()[0]["state"] != "isolated"
    assert any(a["outcome"] == "denied" and a["action"] == "verify.consume" for a in audit(client, admin_h, "verify"))


def test_biometric_mismatch_blocks_action(client, admin_h, key, auth):
    inc = make_incident(client, admin_h, key)
    vid, res = verification(client, admin_h, auth, f"response_action:{inc['id']}:isolate_endpoint", match=False)
    assert res["ok"] is False and res["status"] == "failed"
    assert act(client, admin_h, inc["id"], vid).status_code == 403
    assert client.get(f"{API}/endpoints", headers=admin_h).json()[0]["state"] != "isolated"


def test_unscanned_pending_verification_is_not_enough(client, admin_h, key, auth):
    inc = make_incident(client, admin_h, key)
    r = client.post(f"{API}/verify/initiate", json={"purpose": f"response_action:{inc['id']}:isolate_endpoint"}, headers=admin_h)
    assert act(client, admin_h, inc["id"], r.json()["id"]).status_code == 403


def test_expired_verification_cannot_be_scanned_or_used(client, admin_h, key, auth, db):
    from server.app.models import BiometricVerification
    inc = make_incident(client, admin_h, key)
    r = client.post(f"{API}/verify/initiate", json={"purpose": f"response_action:{inc['id']}:isolate_endpoint"}, headers=admin_h).json()
    db.query(BiometricVerification).update({"expires_at": now().replace(tzinfo=None) - timedelta(seconds=1)})
    db.commit()
    res = auth.respond(client, r["qr_payload"])
    assert res["ok"] is False and "expired" in res["detail"]
    assert client.get(f"{API}/verify/{r['id']}", headers=admin_h).json()["status"] == "expired"
    assert act(client, admin_h, inc["id"], r["id"]).status_code == 403


def test_verification_is_single_use_replay_rejected(client, admin_h, key, auth):
    inc = make_incident(client, admin_h, key)
    vid, _ = verification(client, admin_h, auth, f"response_action:{inc['id']}:isolate_endpoint")
    assert act(client, admin_h, inc["id"], vid).status_code == 201
    r = act(client, admin_h, inc["id"], vid, kind="release_endpoint")
    assert r.status_code == 403
    r2 = act(client, admin_h, inc["id"], vid)
    assert r2.status_code == 403 and "already used" in r2.json()["detail"]


def test_verification_for_one_operation_cannot_authorise_another(client, admin_h, key, auth):
    inc = make_incident(client, admin_h, key)
    vid, _ = verification(client, admin_h, auth, f"response_action:{inc['id']}:flag_account")
    r = act(client, admin_h, inc["id"], vid, kind="isolate_endpoint")
    assert r.status_code == 403 and "different operation" in r.json()["detail"]
    vid2, _ = verification(client, admin_h, auth, "backup:create")
    assert act(client, admin_h, inc["id"], vid2).status_code == 403


def test_qr_code_never_contains_the_challenge_and_server_stores_no_biometrics(client, admin_h, auth, db):
    from server.app.models import BiometricVerification, DeviceCredential
    r = client.post(f"{API}/verify/initiate", json={"purpose": "backup:create"}, headers=admin_h).json()
    ver = db.get(BiometricVerification, r["id"])
    assert ver.challenge not in r["qr_payload"] and r["qr_payload"].startswith("edr://verify?id=")
    assert r["qr_png"].startswith("data:image/png;base64,")
    assert {c.name for c in DeviceCredential.__table__.columns} == {"id", "user_id", "name", "public_key_pem", "created_at"}
    assert "PUBLIC KEY" in db.query(DeviceCredential).first().public_key_pem


def test_scan_with_wrong_nonce_or_wrong_device_is_denied(client, admin_h, auth, tmp_path, db):
    r = client.post(f"{API}/verify/initiate", json={"purpose": "backup:create"}, headers=admin_h).json()
    vid = r["id"]
    assert client.post(f"{API}/verify/{vid}/scan", json={"nonce": "forged", "device_id": auth.device_id}).status_code == 403
    # a device enrolled by a *different* administrator cannot answer this admin's challenge
    client.post(f"{API}/users", headers=admin_h, json={"username": "second_admin", "password": "Str0ngPassw0rd", "role": "admin"})
    h2 = {"Authorization": "Bearer " + client.post(f"{API}/auth/login", json={"username": "second_admin", "password": "Str0ngPassw0rd"}).json()["access_token"]}
    other = enroll(client, h2, tmp_path, "other-phone")
    nonce = r["qr_payload"].split("&n=")[1]
    assert client.post(f"{API}/verify/{vid}/scan", json={"nonce": nonce, "device_id": other.device_id}).status_code == 403


def test_signature_from_wrong_key_fails_verification(client, admin_h, auth, tmp_path):
    r = client.post(f"{API}/verify/initiate", json={"purpose": "backup:create"}, headers=admin_h).json()
    nonce = r["qr_payload"].split("&n=")[1]
    info = client.post(f"{API}/verify/{r['id']}/scan", json={"nonce": nonce, "device_id": auth.device_id}).json()
    attacker = Authenticator(tmp_path / "attacker.pem")
    msg = f"EDR-VERIFY|{r['id']}|{info['challenge']}|{info['purpose']}|{info['user_id']}".encode()
    res = client.post(f"{API}/verify/{r['id']}/complete", json={"device_id": auth.device_id, "signature": attacker.sign(msg)})
    assert res.json()["status"] == "failed"
    # a valid signature over a *different purpose* is also rejected (purpose is bound into the signed message)
    r2 = client.post(f"{API}/verify/initiate", json={"purpose": "backup:create"}, headers=admin_h).json()
    n2 = r2["qr_payload"].split("&n=")[1]
    i2 = client.post(f"{API}/verify/{r2['id']}/scan", json={"nonce": n2, "device_id": auth.device_id}).json()
    bad = auth.sign(f"EDR-VERIFY|{r2['id']}|{i2['challenge']}|response_action:1:isolate_endpoint|{i2['user_id']}".encode())
    assert client.post(f"{API}/verify/{r2['id']}/complete", json={"device_id": auth.device_id, "signature": bad}).json()["status"] == "failed"


def test_complete_before_scan_and_garbage_signature(client, admin_h, auth):
    r = client.post(f"{API}/verify/initiate", json={"purpose": "backup:create"}, headers=admin_h).json()
    assert client.post(f"{API}/verify/{r['id']}/complete", json={"device_id": auth.device_id, "signature": "AAAA"}).status_code == 409
    nonce = r["qr_payload"].split("&n=")[1]
    client.post(f"{API}/verify/{r['id']}/scan", json={"nonce": nonce, "device_id": auth.device_id})
    assert client.post(f"{API}/verify/{r['id']}/complete", json={"device_id": auth.device_id, "signature": "not base64!!"}).json()["status"] == "failed"


def test_admin_without_enrolled_device_cannot_initiate(client, admin_h):
    assert client.post(f"{API}/verify/initiate", json={"purpose": "backup:create"}, headers=admin_h).status_code == 409


@pytest.mark.parametrize("purpose", ["rm -rf /", "response_action:x:isolate_endpoint", "tool:", "backup:restore:abc", "rule:R1:disable"])
def test_malformed_purposes_rejected(client, admin_h, auth, purpose):
    assert client.post(f"{API}/verify/initiate", json={"purpose": purpose}, headers=admin_h).status_code == 422


def test_verification_status_only_visible_to_owner(client, admin_h, auth, analyst_h):
    r = client.post(f"{API}/verify/initiate", json={"purpose": "backup:create"}, headers=admin_h).json()
    assert client.get(f"{API}/verify/{r['id']}", headers=analyst_h).status_code == 403
    assert client.get(f"{API}/verify/9999", headers=admin_h).status_code == 404


def test_release_and_flag_actions(client, admin_h, key, auth):
    inc = make_incident(client, admin_h, key)
    for kind, tgt in (("isolate_endpoint", "WS-T01"), ("release_endpoint", "WS-T01"), ("flag_account", "jsmith")):
        vid, _ = verification(client, admin_h, auth, f"response_action:{inc['id']}:{kind}")
        assert act(client, admin_h, inc["id"], vid, kind, tgt).status_code == 201
    assert client.get(f"{API}/endpoints", headers=admin_h).json()[0]["state"] == "online"
    vid, _ = verification(client, admin_h, auth, f"response_action:{inc['id']}:isolate_endpoint")
    assert act(client, admin_h, inc["id"], vid, target="NO-SUCH-HOST").status_code == 404


# ---------------- rule management ----------------
def test_disabling_a_rule_needs_verification_and_stops_detection(client, admin_h, key, auth):
    assert client.patch(f"{API}/rules/R001", json={"enabled": False}, headers=admin_h).status_code == 403
    vid, _ = verification(client, admin_h, auth, "rule:R001:disable")
    assert client.patch(f"{API}/rules/R001", json={"enabled": False, "verification_id": vid}, headers=admin_h).status_code == 200
    assert ingest(client, key, [encoded_ps()]).json()["alerts_created"] == 0
    vid, _ = verification(client, admin_h, auth, "rule:R001:enable")
    assert client.patch(f"{API}/rules/R001", json={"enabled": True, "verification_id": vid}, headers=admin_h).status_code == 200
    assert ingest(client, key, [encoded_ps(ts=now() + timedelta(seconds=1))]).json()["alerts_created"] == 1
    assert client.patch(f"{API}/rules/R999", json={"enabled": True}, headers=admin_h).status_code == 404


# ---------------- backup & restore ----------------
def mkbackup(client, h, auth):
    vid, _ = verification(client, h, auth, "backup:create")
    r = client.post(f"{API}/backups", json={"verification_id": vid}, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


def test_backup_requires_verification(client, admin_h, auth):
    assert client.post(f"{API}/backups", json={}, headers=admin_h).status_code == 403


def test_backup_verify_and_restore_round_trip(client, admin_h, key, auth):
    ingest(client, key, [encoded_ps()])
    b = mkbackup(client, admin_h, auth)
    assert client.post(f"{API}/backups/{b['id']}/verify", headers=admin_h).json()["ok"] is True
    before = len(client.get(f"{API}/alerts", headers=admin_h).json())
    ingest(client, key, [ev(cmd="wevtutil cl Security", proc=r"C:\Windows\System32\wevtutil.exe")])
    assert len(client.get(f"{API}/alerts", headers=admin_h).json()) == before + 1
    vid, _ = verification(client, admin_h, auth, f"backup:restore:{b['id']}")
    r = client.post(f"{API}/backups/{b['id']}/restore", json={"verification_id": vid}, headers=admin_h)
    assert r.status_code == 200 and r.json()["audit_chain_ok"] is True
    assert len(client.get(f"{API}/alerts", headers=admin_h).json()) == before         # later data rolled back
    assert client.get(f"{API}/audit/verify", headers=admin_h).json()["ok"] is True
    assert client.get(f"{API}/backups", headers=admin_h).json()[0]["status"] == "restored"
    assert ingest(client, key, [encoded_ps(ts=now() + timedelta(seconds=2))]).status_code == 200  # system usable afterwards


def test_tampered_backup_is_detected_and_restore_refused(client, admin_h, key, auth, db):
    from pathlib import Path
    from server.app.models import Backup
    ingest(client, key, [encoded_ps()])
    b = mkbackup(client, admin_h, auth)
    path = Path(db.get(Backup, b["id"]).location)
    blob = bytearray(path.read_bytes())
    blob[-10] ^= 0xFF
    path.write_bytes(bytes(blob))
    v = client.post(f"{API}/backups/{b['id']}/verify", headers=admin_h)
    assert v.status_code == 422 and "checksum" in v.json()["detail"].lower()
    before = len(client.get(f"{API}/alerts", headers=admin_h).json())
    vid, _ = verification(client, admin_h, auth, f"backup:restore:{b['id']}")
    assert client.post(f"{API}/backups/{b['id']}/restore", json={"verification_id": vid}, headers=admin_h).status_code == 422
    assert len(client.get(f"{API}/alerts", headers=admin_h).json()) == before            # live data untouched
    assert client.get(f"{API}/backups", headers=admin_h).json()[0]["status"] == "corrupt"


def test_missing_backup_file_and_unknown_backup(client, admin_h, auth, db):
    from pathlib import Path
    from server.app.models import Backup
    b = mkbackup(client, admin_h, auth)
    Path(db.get(Backup, b["id"]).location).unlink()
    assert client.post(f"{API}/backups/{b['id']}/verify", headers=admin_h).status_code == 422
    assert client.post(f"{API}/backups/999/verify", headers=admin_h).status_code == 404


def test_backup_file_is_encrypted(client, admin_h, key, auth, db):
    from pathlib import Path
    from server.app.models import Backup
    ingest(client, key, [encoded_ps()])
    b = mkbackup(client, admin_h, auth)
    blob = Path(db.get(Backup, b["id"]).location).read_bytes()
    assert blob.startswith(b"EDRBK1") and b"jsmith" not in blob and b"powershell" not in blob.lower()


# ---------------- security-tool terminal ----------------
def run_tool(client, h, auth, name, args, verified=True):
    vid = verification(client, h, auth, f"tool:{name}")[0] if verified else None
    return client.post(f"{API}/tools/run", json={"name": name, "args": args, "verification_id": vid}, headers=h)


def test_tools_require_verification_and_are_allowlisted(client, admin_h, auth):
    assert client.get(f"{API}/tools", headers=admin_h).json()
    assert run_tool(client, admin_h, auth, "ad_lookup", {"sam": "jsmith"}, verified=False).status_code == 403
    r = run_tool(client, admin_h, auth, "ad_lookup", {"sam": "jsmith"})
    assert r.status_code == 200 and r.json()["result"]["department"] == "Finance"
    for evil in ("bash", "rm", "os_system"):
        assert client.post(f"{API}/tools/run", json={"name": evil, "args": {}}, headers=admin_h).status_code == 404
    assert any(a["action"] == "tool.run" and a["outcome"] == "denied" for a in audit(client, admin_h, "tool"))


@pytest.mark.parametrize("name,args", [("tcp_check", {"host": "a;rm -rf /", "port": 80}), ("tcp_check", {"host": "localhost", "port": 99999}),
                                       ("tcp_check", {"host": "localhost", "port": "x"}), ("dns_resolve", {"host": "$(whoami)"}),
                                       ("ad_lookup", {"sam": "x)(cn=*"}), ("endpoint_status", {"host": "../etc/passwd"})])
def test_tool_arguments_are_validated(client, admin_h, auth, name, args):
    assert run_tool(client, admin_h, auth, name, args).status_code == 422


def test_tool_results(client, admin_h, auth, key):
    assert run_tool(client, admin_h, auth, "system_stats", {}).json()["result"]["endpoints"] == 1
    assert run_tool(client, admin_h, auth, "endpoint_status", {"host": "ws-t01"}).json()["result"]["hostname"] == "WS-T01"
    assert run_tool(client, admin_h, auth, "audit_verify", {}).json()["result"]["ok"] is True
    assert run_tool(client, admin_h, auth, "tcp_check", {"host": "127.0.0.1", "port": 1}).json()["result"]["open"] is False
    assert run_tool(client, admin_h, auth, "dns_resolve", {"host": "localhost"}).json()["result"]["addresses"]
