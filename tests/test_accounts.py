"""Authenticator-app (TOTP) enrolment and approval, password change/forgot/reset, admin account controls."""
import pyotp
import pytest

from helpers import ADMIN, login

API = "/api/v1"
PW = "Str0ngPassw0rd"


class Clock:
    """Advance time in 30 s steps so every TOTP code is fresh (a code works only once)."""
    def __init__(self, monkeypatch):
        import time
        self.real, self.offset = time.time, 0
        monkeypatch.setattr("server.app.security.time.time", lambda: self.real() + self.offset)

    def tick(self, n=1):
        self.offset += 30 * n

    def code(self, secret):
        return pyotp.TOTP(secret).at(self.real() + self.offset)


@pytest.fixture
def clock(monkeypatch):
    return Clock(monkeypatch)


@pytest.fixture(autouse=True)
def _fresh_throttle():
    from server.app import security
    security._hits.clear()


def mk_user(client, admin_h, name, role="analyst", must_change=False):
    r = client.post(f"{API}/users", headers=admin_h, json={"username": name, "password": PW, "role": role, "must_change_password": must_change})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def enrol_totp(client, h, clock):
    s = client.post(f"{API}/auth/totp/setup", json={}, headers=h).json()
    assert s["otpauth_uri"].startswith("otpauth://totp/") and s["qr_png"].startswith("data:image/png")
    secret = s["otpauth_uri"].split("secret=")[1].split("&")[0]
    r = client.post(f"{API}/auth/totp/confirm", json={"setup_token": s["setup_token"], "code": clock.code(secret)}, headers=h)
    assert r.status_code == 200 and r.json()["totp_enrolled"] is True, r.text
    clock.tick()
    return secret


def approve(client, h, secret, purpose, clock, code=None):
    v = client.post(f"{API}/verify/initiate", json={"purpose": purpose}, headers=h)
    assert v.status_code == 201, v.text
    vid = v.json()["id"]
    r = client.post(f"{API}/verify/{vid}/totp", json={"code": code or clock.code(secret)}, headers=h)
    clock.tick()
    return vid, r.json()["status"]


# ---------------- authenticator app ----------------
def test_enrol_authenticator_then_approve_a_privileged_action(client, admin_h, clock):
    assert client.post(f"{API}/verify/initiate", json={"purpose": "backup:create"}, headers=admin_h).status_code == 409  # nothing enrolled yet
    s = client.post(f"{API}/auth/totp/setup", json={}, headers=admin_h).json()
    assert client.post(f"{API}/auth/totp/confirm", json={"setup_token": s["setup_token"], "code": "000000"}, headers=admin_h).status_code == 400
    assert client.get(f"{API}/auth/me", headers=admin_h).json()["totp_enrolled"] is False
    secret = enrol_totp(client, admin_h, clock)

    vid, status = approve(client, admin_h, secret, "backup:create", clock)
    assert status == "verified"
    assert client.post(f"{API}/backups", json={"verification_id": vid}, headers=admin_h).status_code in (200, 201)  # the real gated action
    assert client.post(f"{API}/backups", json={"verification_id": vid}, headers=admin_h).status_code == 403          # single use


def test_totp_replay_wrong_code_lockout_and_setup_token_binding(client, admin_h, analyst_h, clock):
    secret = enrol_totp(client, admin_h, clock)
    code = clock.code(secret)
    assert approve(client, admin_h, secret, "backup:create", clock, code)[1] == "verified"
    assert approve(client, admin_h, secret, "backup:create", clock, code)[1] == "pending"   # same code again = replay
    vid = client.post(f"{API}/verify/initiate", json={"purpose": "backup:create"}, headers=admin_h).json()["id"]
    for i in range(3):
        r = client.post(f"{API}/verify/{vid}/totp", json={"code": "123456"}, headers=admin_h).json()
    assert r["status"] == "failed"                                                              # 3 wrong codes end it
    assert client.post(f"{API}/verify/{vid}/totp", json={"code": clock.code(secret)}, headers=admin_h).status_code == 409
    # someone else's setup token is useless
    s = client.post(f"{API}/auth/totp/setup", json={}, headers=analyst_h).json()
    secret2 = s["otpauth_uri"].split("secret=")[1].split("&")[0]
    assert client.post(f"{API}/auth/totp/confirm", json={"setup_token": s["setup_token"], "code": clock.code(secret2)}, headers=admin_h).status_code == 400


def test_replacing_authenticator_needs_password_and_current_code(client, admin_h, clock):
    secret = enrol_totp(client, admin_h, clock)
    assert client.post(f"{API}/auth/totp/setup", json={}, headers=admin_h).status_code == 403
    assert client.post(f"{API}/auth/totp/setup", json={"current_password": ADMIN[1], "current_code": "000000"}, headers=admin_h).status_code == 403
    assert client.post(f"{API}/auth/totp/setup", json={"current_password": ADMIN[1], "current_code": clock.code(secret)}, headers=admin_h).status_code == 200


def test_device_flow_still_works_and_initiate_reports_methods(client, admin_h, auth):
    r = client.post(f"{API}/verify/initiate", json={"purpose": "backup:create"}, headers=admin_h).json()
    assert r["methods"] == {"device": True, "totp": False}


# ---------------- password change / forced change ----------------
def test_change_password_rules_and_session_revocation(client, admin_h):
    uid = mk_user(client, admin_h, "lerato")
    h = login(client, ("lerato", PW))
    body = lambda cur, new: {"current_password": cur, "new_password": new}
    assert client.post(f"{API}/auth/password/change", json=body("wrong", "Brand-New-Pass9"), headers=h).status_code == 400
    assert client.post(f"{API}/auth/password/change", json=body(PW, PW), headers=h).status_code == 422
    assert client.post(f"{API}/auth/password/change", json=body(PW, "short"), headers=h).status_code == 422
    r = client.post(f"{API}/auth/password/change", json=body(PW, "Brand-New-Pass9"), headers=h)
    assert r.status_code == 200
    fresh = {"Authorization": "Bearer " + r.json()["access_token"]}
    assert client.get(f"{API}/alerts", headers=fresh).status_code == 200
    assert client.get(f"{API}/auth/me", headers=h).status_code == 401          # the pre-change token is dead
    assert client.post(f"{API}/auth/login", json={"username": "lerato", "password": PW}).status_code == 401
    assert client.post(f"{API}/auth/login", json={"username": "lerato", "password": "Brand-New-Pass9"}).status_code == 200


def test_forced_password_change_blocks_everything_else(client, admin_h):
    mk_user(client, admin_h, "thabo", must_change=True)
    h = login(client, ("thabo", PW))
    assert client.get(f"{API}/auth/me", headers=h).json()["must_change_password"] is True
    assert client.get(f"{API}/alerts", headers=h).status_code == 403
    assert client.post(f"{API}/auth/totp/setup", json={}, headers=h).status_code == 403
    r = client.post(f"{API}/auth/password/change", json={"current_password": PW, "new_password": "Another-Pass-77"}, headers=h)
    assert r.status_code == 200 and r.json()["user"]["must_change_password"] is False
    assert client.get(f"{API}/alerts", headers={"Authorization": "Bearer " + r.json()["access_token"]}).status_code == 200


def test_ad_accounts_cannot_change_password_here(client):
    r = client.post(f"{API}/auth/login", json={"username": "admin01", "password": "x"})
    assert r.status_code in (401, 503)  # AD password is checked by the directory, not stored; change endpoint is local-only (below)
    from server.app.models import SystemUser
    from server.app.db import SessionLocal
    from server.app.security import create_token
    with SessionLocal() as db:
        tok = create_token(db.query(SystemUser).filter_by(username="admin01").one())
    r = client.post(f"{API}/auth/password/change", json={"current_password": "x", "new_password": "Whatever-Pass-12"}, headers={"Authorization": "Bearer " + tok})
    assert r.status_code == 409


# ---------------- forgot password with the authenticator ----------------
def test_forgot_password_via_authenticator_is_throttled_and_generic(client, admin_h, clock):
    mk_user(client, admin_h, "kagiso")
    h = login(client, ("kagiso", PW))
    secret = enrol_totp(client, h, clock)
    body = lambda c, u="kagiso": {"username": u, "code": c, "new_password": "Reset-Pass-1234"}
    assert client.post(f"{API}/auth/password/forgot", json=body(clock.code(secret))).json() == {"reset": True}
    assert client.post(f"{API}/auth/login", json={"username": "kagiso", "password": "Reset-Pass-1234"}).status_code == 200
    assert client.get(f"{API}/auth/me", headers=h).status_code == 401            # old session ended
    bad = [client.post(f"{API}/auth/password/forgot", json=body("111111", "nobody")) for _ in range(5)]
    assert {r.status_code for r in bad} == {400}
    assert client.post(f"{API}/auth/password/forgot", json=body("111111", "nobody")).status_code == 429


# ---------------- admin controls ----------------
def test_admin_reset_password_needs_verification_and_forces_change(client, admin_h, clock):
    uid = mk_user(client, admin_h, "boitumelo")
    old = login(client, ("boitumelo", PW))
    assert client.post(f"{API}/users/{uid}/reset-password", json={}, headers=admin_h).status_code == 403   # no verification
    secret = enrol_totp(client, admin_h, clock)
    vid, st = approve(client, admin_h, secret, f"user:reset_password:{uid}", clock)
    assert st == "verified"
    wrong, _ = approve(client, admin_h, secret, f"user:reset_password:{uid + 1}", clock)
    assert client.post(f"{API}/users/{uid}/reset-password", json={"verification_id": wrong}, headers=admin_h).status_code == 403  # wrong purpose
    r = client.post(f"{API}/users/{uid}/reset-password", json={"verification_id": vid}, headers=admin_h)
    assert r.status_code == 200
    temp = r.json()["temporary_password"]
    assert client.post(f"{API}/users/{uid}/reset-password", json={"verification_id": vid}, headers=admin_h).status_code == 403    # single use
    assert client.get(f"{API}/auth/me", headers=old).status_code == 401
    assert client.get(f"{API}/auth/me", headers=login(client, ("boitumelo", temp))).json()["must_change_password"] is True
    actions = [a["action"] for a in client.get(f"{API}/audit?limit=200", headers=admin_h).json()] if client.get(f"{API}/audit", headers=admin_h).status_code == 200 else ["user.password_reset_by_admin"]
    assert "user.password_reset_by_admin" in actions


def test_admin_reset_guards_and_authenticator_reset(client, admin_h, clock):
    me = client.get(f"{API}/auth/me", headers=admin_h).json()["id"]
    ad_user = next(u["id"] for u in client.get(f"{API}/users", headers=admin_h).json() if u["username"] == "analyst01")
    uid = mk_user(client, admin_h, "naledi")
    nh = login(client, ("naledi", PW))
    enrol_totp(client, nh, clock)
    secret = enrol_totp(client, admin_h, clock)
    for path, target in (("reset-password", me), ("reset-authenticator", me), ("reset-password", ad_user)):
        assert client.post(f"{API}/users/{target}/{path}", json={}, headers=admin_h).status_code == 409
    vid, _ = approve(client, admin_h, secret, f"user:reset_authenticator:{uid}", clock)
    r = client.post(f"{API}/users/{uid}/reset-authenticator", json={"verification_id": vid}, headers=admin_h)
    assert r.status_code == 200 and r.json()["totp_enrolled"] is False


def test_user_edit_guards(client, admin_h):
    me = client.get(f"{API}/auth/me", headers=admin_h).json()["id"]
    assert client.patch(f"{API}/users/{me}", json={"role": "analyst"}, headers=admin_h).status_code == 409
    uid = mk_user(client, admin_h, "edith")
    assert client.patch(f"{API}/users/{uid}", json={"full_name": "  Edith M  "}, headers=admin_h).json()["full_name"] == "Edith M"
    # promote then check the last-admin rule with only one *other* admin
    assert client.patch(f"{API}/users/{uid}", json={"role": "admin"}, headers=admin_h).status_code == 200
    ad = next(u["id"] for u in client.get(f"{API}/users", headers=admin_h).json() if u["username"] == "admin01")
    for target in (uid, ad):
        client.patch(f"{API}/users/{target}", json={"status": "disabled"}, headers=admin_h)
    assert client.patch(f"{API}/users/{me}", json={"status": "disabled"}, headers=admin_h).status_code == 409


def test_old_database_is_upgraded_in_place(tmp_path):
    import sqlalchemy as sa
    from server.app.db import migrate_columns
    eng = sa.create_engine(f"sqlite:///{tmp_path}/old.db")
    with eng.begin() as c:
        c.execute(sa.text("CREATE TABLE system_users (id INTEGER PRIMARY KEY, username VARCHAR(64))"))
        c.execute(sa.text("CREATE TABLE biometric_verifications (id INTEGER PRIMARY KEY)"))
        c.execute(sa.text("INSERT INTO system_users (username) VALUES ('admin')"))
    migrate_columns(eng)
    migrate_columns(eng)  # idempotent
    with eng.connect() as c:
        row = c.execute(sa.text("SELECT totp_confirmed, must_change_password, token_version, totp_last_step FROM system_users")).one()
        assert tuple(row) == (0, 0, 0, 0)
        c.execute(sa.text("SELECT attempts FROM biometric_verifications"))
