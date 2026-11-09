import base64
import io
import re
from datetime import timedelta

import qrcode

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import audit, biometric
from ..ad import Directory, DirectoryUnavailable
from ..config import Settings, get_settings
from ..db import get_db
from ..deps import directory as get_directory
from ..models import BiometricVerification, DeviceCredential, SystemUser, utcnow
from ..security import (
    TOTP_PERIOD, admin_only, any_user, check_totp, clear_hits, create_token, current_user, current_user_any, hash_password,
    new_totp_secret, record_hit, seal, temp_password, throttled, totp_uri, unseal, verify_password,
)

router = APIRouter(prefix="/api/v1")
DUMMY_HASH = hash_password("dummy-password-for-timing", 1000)


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


def ser_user(u: SystemUser) -> dict:
    return {"id": u.id, "username": u.username, "full_name": u.full_name, "role": u.role, "status": u.status,
            "auth_source": u.auth_source, "must_change_password": bool(u.must_change_password),
            "totp_enrolled": bool(u.totp_confirmed)}


def check_password_policy(pw: str):
    if len(pw) < 10 or not re.search(r"[A-Z]", pw) or not re.search(r"[a-z]", pw) or not re.search(r"\d", pw):
        raise HTTPException(422, "Password must be at least 10 characters and include upper-case, lower-case and a digit")


@router.post("/auth/login")
def login(body: LoginIn, db: Session = Depends(get_db), s: Settings = Depends(get_settings),
          directory: Directory = Depends(get_directory)):
    user = db.query(SystemUser).filter(SystemUser.username == body.username).first()
    if user is None:
        verify_password(body.password, DUMMY_HASH)  # equalise timing
        audit.write(db, "auth.login", body.username[:64], None, {"reason": "unknown user"}, "denied")
        db.commit()
        raise HTTPException(401, "Invalid credentials")
    if user.status != "active":
        audit.write(db, "auth.login", user.username, user.id, {"reason": "disabled"}, "denied")
        db.commit()
        raise HTTPException(401, "Invalid credentials")
    if user.locked_until and user.locked_until > utcnow():
        audit.write(db, "auth.login", user.username, user.id, {"reason": "locked"}, "denied")
        db.commit()
        raise HTTPException(423, "Account temporarily locked after repeated failures")
    try:
        ok = (directory.authenticate(user.username, body.password) if user.auth_source == "ad"
              else verify_password(body.password, user.password_hash))
    except DirectoryUnavailable:
        raise HTTPException(503, "Directory service unavailable")
    if not ok:
        user.failed_logins += 1
        if user.failed_logins >= s.max_failed_logins:
            user.locked_until = utcnow() + timedelta(minutes=s.lockout_minutes)
            user.failed_logins = 0
        audit.write(db, "auth.login", user.username, user.id, {"reason": "bad password"}, "denied")
        db.commit()
        raise HTTPException(401, "Invalid credentials")
    user.failed_logins, user.locked_until = 0, None
    audit.write(db, "auth.login", user.username, user.id, {"source": user.auth_source})
    db.commit()
    return {"access_token": create_token(user), "token_type": "bearer", "user": ser_user(user)}


@router.get("/auth/me")
def me(user: SystemUser = Depends(current_user_any)):
    return ser_user(user)


# ---------------- password: change (signed in) and forgot (proved with the authenticator app) ----------------
class PasswordChangeIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class PasswordForgotIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    code: str = Field(min_length=1, max_length=16)
    new_password: str = Field(min_length=1, max_length=256)


def _set_password(user: SystemUser, new_password: str):
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    user.failed_logins, user.locked_until = 0, None
    user.token_version = (user.token_version or 0) + 1  # every older session token stops working


@router.post("/auth/password/change")
def change_password(body: PasswordChangeIn, db: Session = Depends(get_db), user: SystemUser = Depends(current_user_any)):
    if user.auth_source != "local":
        raise HTTPException(409, "This account signs in with Active Directory. Change the password in Windows / AD instead")
    key = f"pwchange:{user.id}"
    if throttled(key):
        raise HTTPException(429, "Too many attempts. Try again in 15 minutes")
    if not verify_password(body.current_password, user.password_hash):
        record_hit(key)
        audit.write(db, "auth.password_change", user.username, user.id, {"reason": "current password wrong"}, "denied")
        db.commit()
        raise HTTPException(400, "Current password is incorrect")
    check_password_policy(body.new_password)
    if verify_password(body.new_password, user.password_hash):
        raise HTTPException(422, "New password must be different from the current one")
    clear_hits(key)
    _set_password(user, body.new_password)
    audit.write(db, "auth.password_changed", user.username, user.id, {})
    db.commit()
    # fresh token so this browser stays signed in while every other session is signed out
    return {"access_token": create_token(user), "token_type": "bearer", "user": ser_user(user)}


@router.post("/auth/password/forgot")
def forgot_password(body: PasswordForgotIn, db: Session = Depends(get_db)):
    """Forgot-password without e-mail: needs the 6-digit code from the account's authenticator app."""
    key = f"pwforgot:{body.username.lower()}"
    if throttled(key):
        raise HTTPException(429, "Too many attempts. Try again in 15 minutes")
    user = db.query(SystemUser).filter(SystemUser.username == body.username).first()
    ok = bool(user and user.status == "active" and user.auth_source == "local" and user.totp_confirmed)
    step = check_totp(unseal(user.totp_secret_enc), body.code, user.totp_last_step or 0) if ok else None
    if step is None:  # same answer for unknown user, no authenticator, wrong code
        record_hit(key)
        audit.write(db, "auth.password_forgot", body.username[:64], user.id if user else None, {"reason": "invalid"}, "denied")
        db.commit()
        raise HTTPException(400, "Username or code is not valid")
    check_password_policy(body.new_password)
    clear_hits(key)
    user.totp_last_step = step
    _set_password(user, body.new_password)
    audit.write(db, "auth.password_reset_self", user.username, user.id, {})
    db.commit()
    return {"reset": True}


# ---------------- authenticator app enrolment (Microsoft Authenticator, Google Authenticator, Authy, ...) ----------------
SETUP_TTL = 600


class TotpSetupIn(BaseModel):
    current_password: str | None = Field(default=None, max_length=256)
    current_code: str | None = Field(default=None, max_length=16)


class TotpConfirmIn(BaseModel):
    setup_token: str = Field(max_length=1024)
    code: str = Field(max_length=16)


@router.post("/auth/totp/setup")
def totp_setup(body: TotpSetupIn, db: Session = Depends(get_db), user: SystemUser = Depends(any_user)):
    """Step 1: new secret + QR. Nothing is stored until step 2 proves the app shows the right code. Replacing an
    existing authenticator needs the current code (and the password for local accounts)."""
    if user.totp_confirmed:
        pw_ok = user.auth_source != "local" or verify_password(body.current_password or "", user.password_hash)
        code_ok = check_totp(unseal(user.totp_secret_enc), body.current_code or "", user.totp_last_step or 0) is not None
        if not (pw_ok and code_ok):
            audit.write(db, "auth.totp_setup", user.username, user.id, {"reason": "re-enrolment check failed"}, "denied")
            db.commit()
            raise HTTPException(403, "To replace your authenticator, enter your current password and a current code from the old one")
    secret = new_totp_secret()
    uri = totp_uri(secret, user.username)
    buf = io.BytesIO()
    qrcode.make(uri, box_size=6, border=2).save(buf, format="PNG")
    audit.write(db, "auth.totp_setup_started", user.username, user.id, {})
    db.commit()
    return {"setup_token": seal(f"{user.id}:{secret}"), "otpauth_uri": uri,
            "qr_png": "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode(),
            "manual_key": " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)), "digits": 6, "period": TOTP_PERIOD}


@router.post("/auth/totp/confirm")
def totp_confirm(body: TotpConfirmIn, db: Session = Depends(get_db), user: SystemUser = Depends(any_user)):
    plain = unseal(body.setup_token, ttl=SETUP_TTL)
    uid, _, secret = (plain or "").partition(":")
    if not plain or uid != str(user.id):
        raise HTTPException(400, "Setup expired - start again")
    step = check_totp(secret, body.code)
    if step is None:
        audit.write(db, "auth.totp_setup", user.username, user.id, {"reason": "first code wrong"}, "denied")
        db.commit()
        raise HTTPException(400, "That code is not right. Check the time on your phone and try the next code")
    user.totp_secret_enc, user.totp_confirmed, user.totp_last_step = seal(secret), True, step
    audit.write(db, "auth.totp_enrolled", user.username, user.id, {})
    db.commit()
    return ser_user(user)


class UserIn(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9._-]{3,64}$")
    full_name: str | None = Field(default=None, max_length=128)
    password: str | None = Field(default=None, max_length=256)
    role: str = Field(pattern="^(admin|analyst)$")
    auth_source: str = Field(default="local", pattern="^(local|ad)$")
    must_change_password: bool = False  # the console ticks this by default: the admin chose the first password


@router.get("/users")
def users(db: Session = Depends(get_db), _=Depends(any_user)):
    return [ser_user(u) for u in db.query(SystemUser).order_by(SystemUser.id)]


@router.post("/users", status_code=201)
def create_user(body: UserIn, db: Session = Depends(get_db), admin=Depends(admin_only)):
    if db.query(SystemUser).filter(SystemUser.username == body.username).first():
        raise HTTPException(409, "Username already exists")
    pw = None
    if body.auth_source == "local":
        if not body.password:
            raise HTTPException(422, "Password required for local accounts")
        check_password_policy(body.password)
        pw = hash_password(body.password)
    u = SystemUser(username=body.username, full_name=body.full_name, password_hash=pw, role=body.role,
                   auth_source=body.auth_source, must_change_password=bool(pw and body.must_change_password))
    db.add(u)
    db.flush()
    audit.write(db, "user.created", admin.username, admin.id, {"user": u.username, "role": u.role})
    db.commit()
    return ser_user(u)


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: dict, db: Session = Depends(get_db), admin=Depends(admin_only)):
    u = db.get(SystemUser, user_id)
    if not u:
        raise HTTPException(404, "User not found")
    if u.id == admin.id and body.get("status") == "disabled":
        raise HTTPException(409, "You cannot disable your own account")
    if u.id == admin.id and body.get("role") == "analyst":
        raise HTTPException(409, "You cannot remove your own administrator role")
    losing_admin = u.role == "admin" and u.status == "active" and (body.get("status") == "disabled" or body.get("role") == "analyst")
    if losing_admin and db.query(func.count(SystemUser.id)).filter(SystemUser.role == "admin", SystemUser.status == "active").scalar() <= 1:
        raise HTTPException(409, "At least one active administrator must remain")
    if body.get("status") in ("active", "disabled"):
        u.status = body["status"]
    if body.get("role") in ("admin", "analyst"):
        u.role = body["role"]
    if isinstance(body.get("full_name"), str):
        u.full_name = body["full_name"].strip()[:128] or None
    audit.write(db, "user.updated", admin.username, admin.id,
                {"user": u.username, "changes": {k: body[k] for k in ("status", "role", "full_name") if k in body}})
    db.commit()
    return ser_user(u)


class VerifiedIn(BaseModel):
    verification_id: int | None = None


def _target(db: Session, user_id: int) -> SystemUser:
    t = db.get(SystemUser, user_id)
    if not t:
        raise HTTPException(404, "User not found")
    return t


@router.post("/users/{user_id}/reset-password")
def admin_reset_password(user_id: int, body: VerifiedIn, db: Session = Depends(get_db), admin=Depends(admin_only),
                         s: Settings = Depends(get_settings)):
    """Forgotten password and no authenticator: set a temporary one (shown once). The user must change it at next sign-in."""
    t = _target(db, user_id)
    if t.id == admin.id:
        raise HTTPException(409, "Use My account > Change password for your own password")
    if t.auth_source != "local":
        raise HTTPException(409, "This account signs in with Active Directory. Reset its password in AD instead")
    try:
        biometric.consume(db, admin, body.verification_id, f"user:reset_password:{t.id}", s)
    except biometric.VerificationError as exc:
        raise _err(exc)
    pw = temp_password()
    _set_password(t, pw)
    t.must_change_password = True
    audit.write(db, "user.password_reset_by_admin", admin.username, admin.id, {"user": t.username})
    db.commit()
    return {"username": t.username, "temporary_password": pw, "must_change_password": True}


@router.post("/users/{user_id}/reset-authenticator")
def admin_reset_authenticator(user_id: int, body: VerifiedIn, db: Session = Depends(get_db), admin=Depends(admin_only),
                              s: Settings = Depends(get_settings)):
    """Lost or replaced phone: removes the user's authenticator app so they can link a new one."""
    t = _target(db, user_id)
    if t.id == admin.id:
        raise HTTPException(409, "Use My account > Replace authenticator for your own account")
    try:
        biometric.consume(db, admin, body.verification_id, f"user:reset_authenticator:{t.id}", s)
    except biometric.VerificationError as exc:
        raise _err(exc)
    t.totp_secret_enc, t.totp_confirmed, t.totp_last_step = None, False, 0
    audit.write(db, "user.authenticator_reset_by_admin", admin.username, admin.id, {"user": t.username})
    db.commit()
    return ser_user(t)


class DeviceIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    public_key_pem: str = Field(min_length=50, max_length=2000)


@router.post("/devices", status_code=201)
def enroll_device(body: DeviceIn, db: Session = Depends(get_db), user: SystemUser = Depends(admin_only)):
    try:
        key = load_pem_public_key(body.public_key_pem.encode())
    except ValueError:
        raise HTTPException(422, "Invalid public key")
    if not isinstance(key, Ed25519PublicKey):
        raise HTTPException(422, "Only Ed25519 keys are supported")
    d = DeviceCredential(user_id=user.id, name=body.name, public_key_pem=body.public_key_pem)
    db.add(d)
    db.flush()
    audit.write(db, "device.enrolled", user.username, user.id, {"device": d.id, "name": d.name})
    db.commit()
    return {"id": d.id, "name": d.name}


@router.get("/devices")
def list_devices(db: Session = Depends(get_db), user: SystemUser = Depends(admin_only)):
    return [{"id": d.id, "name": d.name, "created_at": d.created_at.isoformat() + "Z"}
            for d in db.query(DeviceCredential).filter_by(user_id=user.id)]


class InitiateIn(BaseModel):
    purpose: str = Field(pattern=biometric.PURPOSE_RE)


def ser_ver(v: BiometricVerification, with_qr: bool = False) -> dict:
    d = {"id": v.id, "purpose": v.purpose, "status": v.status, "expires_at": v.expires_at.isoformat() + "Z",
         "verified_at": v.verified_at.isoformat() + "Z" if v.verified_at else None}
    if with_qr:
        p = biometric.qr_payload(v)
        d["qr_payload"], d["qr_png"] = p, biometric.qr_png_data_uri(p)
    return d


def _err(exc: biometric.VerificationError):
    return HTTPException(exc.code, exc.message)


@router.post("/verify/initiate", status_code=201)
def verify_initiate(body: InitiateIn, db: Session = Depends(get_db), user: SystemUser = Depends(admin_only),
                    s: Settings = Depends(get_settings)):
    try:
        v = biometric.initiate(db, user, body.purpose, s)
    except biometric.VerificationError as exc:
        raise _err(exc)
    db.commit()
    return {**ser_ver(v, with_qr=True), "methods": biometric.methods_for(db, user)}


@router.get("/verify/{ver_id}")
def verify_status(ver_id: int, db: Session = Depends(get_db), user: SystemUser = Depends(admin_only)):
    try:
        v = biometric.get(db, ver_id)
    except biometric.VerificationError as exc:
        raise _err(exc)
    if v.user_id != user.id:
        raise HTTPException(404, "Verification not found")
    db.commit()
    return ser_ver(v)


class ScanIn(BaseModel):
    nonce: str = Field(max_length=64)
    device_id: int


@router.post("/verify/{ver_id}/scan")
def verify_scan(ver_id: int, body: ScanIn, db: Session = Depends(get_db)):
    """Called by the enrolled device after scanning the QR code."""
    try:
        v = biometric.scan(db, ver_id, body.nonce, body.device_id)
    except biometric.VerificationError as exc:
        db.commit()
        raise _err(exc)
    db.commit()
    return {"id": v.id, "challenge": v.challenge, "purpose": v.purpose, "user_id": v.user_id, "status": v.status}


class CompleteIn(BaseModel):
    device_id: int
    signature: str = Field(max_length=512)


@router.post("/verify/{ver_id}/complete")
def verify_complete(ver_id: int, body: CompleteIn, db: Session = Depends(get_db)):
    try:
        v = biometric.complete(db, ver_id, body.device_id, body.signature)
    except biometric.VerificationError as exc:
        db.commit()
        raise _err(exc)
    db.commit()
    return ser_ver(v)


class TotpCodeIn(BaseModel):
    code: str = Field(min_length=1, max_length=16)


@router.post("/verify/{ver_id}/totp")
def verify_totp(ver_id: int, body: TotpCodeIn, db: Session = Depends(get_db), user: SystemUser = Depends(admin_only)):
    """Approve a verification with the 6-digit code from the signed-in administrator's authenticator app."""
    try:
        v = biometric.complete_totp(db, user, ver_id, body.code)
    except biometric.VerificationError as exc:
        db.commit()
        raise _err(exc)
    db.commit()
    return ser_ver(v) | {"attempts": v.attempts}


class RejectIn(BaseModel):
    device_id: int


@router.post("/verify/{ver_id}/reject")
def verify_reject(ver_id: int, body: RejectIn, db: Session = Depends(get_db)):
    try:
        v = biometric.reject(db, ver_id, body.device_id)
    except biometric.VerificationError as exc:
        db.commit()
        raise _err(exc)
    db.commit()
    return ser_ver(v)
