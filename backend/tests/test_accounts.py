"""Authenticator-app enrolment, password change / reset / forgot, admin user management, and the in-place DB upgrade."""
import datetime as dt
import itertools
import time

import pyotp
import pytest
from sqlalchemy import create_engine, inspect, text

from app.database import Base, add_missing_columns
from app.security import create_access_token
from app.services import totp as totp_svc
from tests.conftest import login, verified_tx

PW = "Start-Pass-1"
_names = itertools.count(1)


@pytest.fixture()
def clock(monkeypatch):
    """A movable clock for the TOTP code check, so tests can ask for 'the next code' without sleeping."""
    state = {"t": time.time()}
    monkeypatch.setattr(totp_svc, "_now", lambda: state["t"])

    class Clock:
        def code(self, secret):
            return pyotp.TOTP(secret).at(state["t"])

        def next_step(self):
            state["t"] += 30

    return Clock()


def new_user(client, admin, role="analyst", must_change=False):
    name = f"u{next(_names)}_{int(time.time() * 1000) % 100000}"
    r = client.post("/api/users", json={"username": name, "password": PW, "role": role, "must_change_password": must_change}, headers=admin)
    assert r.status_code == 200, r.text
    return name, r.json()["id"]


def enroll_authenticator(client, headers, clock, password=PW):
    s = client.post("/api/auth/totp/enroll/start", json={"current_password": password}, headers=headers)
    assert s.status_code == 200, s.text
    secret = s.json()["secret"]
    c = client.post("/api/auth/totp/enroll/confirm", json={"code": clock.code(secret)}, headers=headers)
    assert c.status_code == 200, c.text
    return secret


# ---------------- authenticator enrolment ----------------
def test_enrol_authenticator_and_use_it_for_verification(client, admin, clock):
    name, _ = new_user(client, admin)
    h = login(client, name, PW)

    # no factor yet: a gated transaction cannot even be started
    assert client.post("/api/auth/transactions", json={"purpose": "terminal"}, headers=h).status_code == 409

    # enrolment needs the password
    assert client.post("/api/auth/totp/enroll/start", json={"current_password": "nope"}, headers=h).status_code == 403

    s = client.post("/api/auth/totp/enroll/start", json={"current_password": PW}, headers=h).json()
    assert s["otpauth_uri"].startswith("otpauth://totp/") and "issuer=Sentry" in s["otpauth_uri"] and s["qr_png_base64"]
    assert client.get("/api/auth/me", headers=h).json()["authenticator_enrolled"] is False  # not active until confirmed

    assert client.post("/api/auth/totp/enroll/confirm", json={"code": "000000"}, headers=h).status_code == 400
    ok = client.post("/api/auth/totp/enroll/confirm", json={"code": clock.code(s["secret"])}, headers=h)
    assert ok.status_code == 200 and ok.json()["authenticator_enrolled"] is True

    # the code that confirmed enrolment is burnt; the next one verifies a transaction
    tx = client.post("/api/auth/transactions", json={"purpose": "terminal"}, headers=h).json()
    assert tx["method"] == "authenticator"
    reuse = client.post(f"/api/auth/transactions/{tx['id']}/verify", json={"credential": clock.code(s["secret"])}).json()
    assert reuse["status"] == "pending" and reuse["attempts"] == 1  # replay refused
    clock.next_step()
    good = client.post(f"/api/auth/transactions/{tx['id']}/verify", json={"credential": clock.code(s["secret"])}).json()
    assert good["status"] == "verified"

    # a code works once, even for a different transaction
    tx2 = client.post("/api/auth/transactions", json={"purpose": "terminal"}, headers=h).json()
    again = client.post(f"/api/auth/transactions/{tx2['id']}/verify", json={"credential": clock.code(s["secret"])}).json()
    assert again["status"] == "pending"
    # spaces in "123 456" are tolerated
    clock.next_step()
    spaced = clock.code(s["secret"])
    assert client.post(f"/api/auth/transactions/{tx2['id']}/verify", json={"credential": spaced[:3] + " " + spaced[3:]}).json()["status"] == "verified"


def test_dev_reference_stops_working_once_authenticator_enrolled(client, admin, clock):
    name, _ = new_user(client, admin)
    h = login(client, name, PW)
    assert client.post("/api/auth/biometric/enroll", json={"template": "my-ref", "current_password": "wrong"}, headers=h).status_code == 403
    assert client.post("/api/auth/biometric/enroll", json={"template": "my-ref", "current_password": PW}, headers=h).status_code == 200
    assert verified_tx(client, h, "terminal", "my-ref")[1] == "verified"
    secret = enroll_authenticator(client, h, clock)
    assert client.post("/api/auth/biometric/enroll", json={"template": "x-ref-1", "current_password": PW}, headers=h).status_code == 409
    tx = client.post("/api/auth/transactions", json={"purpose": "terminal"}, headers=h).json()
    assert client.post(f"/api/auth/transactions/{tx['id']}/verify", json={"credential": "my-ref"}).json()["status"] == "pending"
    clock.next_step()
    assert client.post(f"/api/auth/transactions/{tx['id']}/verify", json={"credential": clock.code(secret)}).json()["status"] == "verified"


def test_replacing_and_removing_authenticator_needs_the_current_one(client, admin, clock):
    name, _ = new_user(client, admin)
    h = login(client, name, PW)
    secret = enroll_authenticator(client, h, clock)
    clock.next_step()
    # replacing requires a code from the existing authenticator
    assert client.post("/api/auth/totp/enroll/start", json={"current_password": PW}, headers=h).status_code == 403
    assert client.post("/api/auth/totp/enroll/start", json={"current_password": PW, "current_code": clock.code(secret)}, headers=h).status_code == 200
    clock.next_step()
    # removing requires password + code
    assert client.post("/api/auth/totp/remove", json={"current_password": "bad", "code": clock.code(secret)}, headers=h).status_code == 403
    r = client.post("/api/auth/totp/remove", json={"current_password": PW, "code": clock.code(secret)}, headers=h)
    assert r.status_code == 200 and r.json()["authenticator_enrolled"] is False


# ---------------- change password ----------------
def test_change_password_rejects_old_sessions_and_old_password(client, admin):
    name, _ = new_user(client, admin)
    h = login(client, name, PW)
    old_token = create_access_token(name, "analyst", issued_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=120))
    old = {"Authorization": f"Bearer {old_token}"}
    assert client.get("/api/auth/me", headers=old).status_code == 200  # valid before the change

    assert client.post("/api/auth/password/change", json={"current_password": "wrong", "new_password": "Another-Pass-2"}, headers=h).status_code == 403
    assert client.post("/api/auth/password/change", json={"current_password": PW, "new_password": PW}, headers=h).status_code == 400  # same
    assert client.post("/api/auth/password/change", json={"current_password": PW, "new_password": name}, headers=h).status_code == 400  # = username
    assert client.post("/api/auth/password/change", json={"current_password": PW, "new_password": "short"}, headers=h).status_code == 422

    r = client.post("/api/auth/password/change", json={"current_password": PW, "new_password": "Another-Pass-2"}, headers=h)
    assert r.status_code == 200
    fresh = {"Authorization": f"Bearer {r.json()['access_token']}"}

    assert client.get("/api/auth/me", headers=old).status_code == 401  # older sessions are logged out
    assert client.get("/api/auth/me", headers=fresh).status_code == 200
    assert client.post("/api/auth/login", data={"username": name, "password": PW}).status_code == 401
    assert client.post("/api/auth/login", data={"username": name, "password": "Another-Pass-2"}).status_code == 200


def test_change_password_lockout_after_repeated_failures(client, admin):
    name, _ = new_user(client, admin)
    h = login(client, name, PW)
    codes = [client.post("/api/auth/password/change", json={"current_password": "wrong", "new_password": "Another-Pass-2"}, headers=h).status_code for _ in range(6)]
    assert codes[:5] == [403] * 5 and codes[5] == 429
    # even the right password is refused while locked, but signing in is not affected
    assert client.post("/api/auth/password/change", json={"current_password": PW, "new_password": "Another-Pass-2"}, headers=h).status_code == 429
    assert client.post("/api/auth/login", data={"username": name, "password": PW}).status_code == 200


# ---------------- forgot password ----------------
def test_forgot_password_with_authenticator_code(client, admin, clock):
    name, _ = new_user(client, admin)
    h = login(client, name, PW)
    secret = enroll_authenticator(client, h, clock)
    clock.next_step()

    body = {"username": name, "code": clock.code(secret), "new_password": "Recovered-Pass-3"}
    assert client.post("/api/auth/password/forgot", json={**body, "code": "123456"}).status_code == 400
    assert client.post("/api/auth/password/forgot", json={**body, "username": "ghost"}).status_code == 400  # same error: no username probing
    assert client.post("/api/auth/password/forgot", json={**body, "new_password": PW}).status_code == 400  # not the current password
    assert client.post("/api/auth/password/forgot", json=body).json() == {"reset": True}
    assert client.post("/api/auth/login", data={"username": name, "password": "Recovered-Pass-3"}).status_code == 200
    assert client.post("/api/auth/login", data={"username": name, "password": PW}).status_code == 401
    # the code is single-use
    assert client.post("/api/auth/password/forgot", json={**body, "new_password": "Other-Pass-44"}).status_code == 400


def test_forgot_password_unavailable_without_authenticator_and_lockout(client, admin, clock):
    name, _ = new_user(client, admin)
    assert client.post("/api/auth/password/forgot", json={"username": name, "code": "123456", "new_password": "Whatever-123"}).status_code == 400
    name2, _ = new_user(client, admin)
    h2 = login(client, name2, PW)
    enroll_authenticator(client, h2, clock)
    statuses = [client.post("/api/auth/password/forgot", json={"username": name2, "code": "000000", "new_password": "Whatever-123"}).status_code for _ in range(6)]
    assert statuses[:5] == [400] * 5 and statuses[5] == 429


# ---------------- admin: edit / reset ----------------
def test_admin_reset_password_requires_verification_and_forces_change(client, admin):
    name, uid = new_user(client, admin)
    victim = login(client, name, PW)

    assert client.post(f"/api/users/{uid}/reset-password", json={}, headers=admin).status_code == 403  # no QR + biometric
    tx, status = verified_tx(client, admin, "user_admin")
    assert status == "verified"
    r = client.post(f"/api/users/{uid}/reset-password", json={}, headers={**admin, "X-Auth-Transaction": tx})
    assert r.status_code == 200
    temp = r.json()["temporary_password"]
    assert len(temp) >= 12 and r.json()["must_change_password"] is True
    # single use
    assert client.post(f"/api/users/{uid}/reset-password", json={}, headers={**admin, "X-Auth-Transaction": tx}).status_code == 403

    assert client.get("/api/auth/me", headers=victim).status_code == 401  # their old session is dead
    assert client.post("/api/auth/login", data={"username": name, "password": PW}).status_code == 401

    # temp password signs in, but nothing works until it is changed
    t = login(client, name, temp)
    assert client.get("/api/auth/me", headers=t).json()["must_change_password"] is True
    assert client.get("/api/alerts", headers=t).status_code == 403
    done = client.post("/api/auth/password/change", json={"current_password": temp, "new_password": "My-Own-Pass-9"}, headers=t)
    assert done.status_code == 200 and done.json()["user"]["must_change_password"] is False
    assert client.get("/api/alerts", headers={"Authorization": f"Bearer {done.json()['access_token']}"}).status_code == 200


def test_admin_cannot_reset_own_password_and_analyst_cannot_use_endpoints(client, admin, analyst):
    me = client.get("/api/auth/me", headers=admin).json()
    tx, _ = verified_tx(client, admin, "user_admin")
    assert client.post(f"/api/users/{me['id']}/reset-password", json={}, headers={**admin, "X-Auth-Transaction": tx}).status_code == 400
    assert client.post(f"/api/users/{me['id']}/reset-password", json={}, headers=analyst).status_code == 403
    assert client.patch(f"/api/users/{me['id']}", json={"email": "x@y.z"}, headers=analyst).status_code == 403
    assert client.post("/api/users/not-a-uuid/reset-password", json={}, headers=admin).status_code == 404


def test_admin_edit_user_rules(client, admin):
    name, uid = new_user(client, admin)
    me = client.get("/api/auth/me", headers=admin).json()

    # email only: no verification needed
    r = client.patch(f"/api/users/{uid}", json={"email": "new@corp.local"}, headers=admin)
    assert r.status_code == 200 and r.json()["email"] == "new@corp.local"
    assert client.patch(f"/api/users/{uid}", json={}, headers=admin).status_code == 400

    # role / active changes need verification
    assert client.patch(f"/api/users/{uid}", json={"role": "administrator"}, headers=admin).status_code == 403
    tx, _ = verified_tx(client, admin, "user_admin")
    r = client.patch(f"/api/users/{uid}", json={"role": "administrator"}, headers={**admin, "X-Auth-Transaction": tx})
    assert r.status_code == 200 and r.json()["role"] == "administrator"

    # deactivating ends their sessions
    user_h = login(client, name, PW)
    tx, _ = verified_tx(client, admin, "user_admin")
    assert client.patch(f"/api/users/{uid}", json={"is_active": False}, headers={**admin, "X-Auth-Transaction": tx}).status_code == 200
    assert client.get("/api/auth/me", headers=user_h).status_code == 401

    # you cannot demote or deactivate yourself
    assert client.patch(f"/api/users/{me['id']}", json={"role": "analyst"}, headers=admin).status_code == 400
    assert client.patch(f"/api/users/{me['id']}", json={"is_active": False}, headers=admin).status_code == 400


def test_admin_reset_authenticator(client, admin, clock):
    name, uid = new_user(client, admin)
    h = login(client, name, PW)
    enroll_authenticator(client, h, clock)
    assert client.get("/api/auth/me", headers=h).json()["authenticator_enrolled"] is True
    tx, _ = verified_tx(client, admin, "user_admin")
    r = client.post(f"/api/users/{uid}/reset-authenticator", headers={**admin, "X-Auth-Transaction": tx})
    assert r.status_code == 200 and r.json()["authenticator_enrolled"] is False
    # they can enrol a fresh one
    clock.next_step()
    enroll_authenticator(client, h, clock)


def test_new_user_can_be_forced_to_change_password(client, admin):
    name, _ = new_user(client, admin, must_change=True)
    h = login(client, name, PW)
    assert client.get("/api/auth/me", headers=h).json()["must_change_password"] is True
    assert client.get("/api/tickets", headers=h).status_code == 403


# ---------------- authenticator code unit + DB upgrade ----------------
def test_match_step_window_and_replay(clock):
    secret = pyotp.random_base32()
    code = clock.code(secret)
    step = totp_svc.match_step(secret, code)
    assert step is not None
    assert totp_svc.match_step(secret, code, last_step=step) is None  # replay
    assert totp_svc.match_step(secret, "12345") is None and totp_svc.match_step(secret, "abcdef") is None
    clock.next_step()
    assert totp_svc.match_step(secret, code) == step  # one step old is still inside the drift window
    clock.next_step(); clock.next_step()
    assert totp_svc.match_step(secret, code) is None  # three steps old is too old


def test_add_missing_columns_upgrades_an_old_database(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path}/old.db")
    with eng.begin() as c:  # the users table as it was before authenticator/password-reset support
        c.execute(text("CREATE TABLE users (id CHAR(32) PRIMARY KEY, username VARCHAR(150), email VARCHAR(255), hashed_password VARCHAR(255), "
                       "role VARCHAR(30), is_active BOOLEAN, biometric_template_hash VARCHAR(255), created_at DATETIME)"))
        c.execute(text("INSERT INTO users (id, username, hashed_password, is_active) VALUES ('a', 'old', 'x', 1)"))
    added = add_missing_columns(eng)
    cols = {c["name"] for c in inspect(eng).get_columns("users")}
    assert {"totp_secret_enc", "totp_pending_enc", "totp_last_step", "password_changed_at", "must_change_password",
            "recovery_failures", "recovery_locked_until"} <= cols
    assert "users.totp_secret_enc" in added
    assert add_missing_columns(eng) == []  # idempotent
    with eng.begin() as c:
        assert c.execute(text("SELECT username FROM users")).scalar() == "old"  # data kept
    assert Base.metadata.tables["users"].c.totp_secret_enc.nullable


def test_cli_break_glass(client, admin, clock, capsys):
    from app import cli
    name, _ = new_user(client, admin)
    h = login(client, name, PW)
    enroll_authenticator(client, h, clock)
    assert cli.main(["reset-authenticator", name]) == 0
    assert client.get("/api/auth/me", headers=h).json()["authenticator_enrolled"] is False
    assert cli.main(["reset-password", name]) == 0
    temp = capsys.readouterr().out.split("Temporary password: ")[1].split()[0]
    assert client.get("/api/auth/me", headers=h).status_code == 401
    assert login(client, name, temp)
    assert cli.main(["reset-password", "ghost"]) == 1
    assert cli.main(["reset-password", name, "--password", "short"]) == 1
