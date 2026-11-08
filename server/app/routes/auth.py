import re
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, biometric
from ..ad import Directory, DirectoryUnavailable
from ..config import Settings, get_settings
from ..db import get_db
from ..deps import directory as get_directory
from ..models import BiometricVerification, DeviceCredential, SystemUser, utcnow
from ..security import admin_only, any_user, create_token, current_user, hash_password, verify_password

router = APIRouter(prefix="/api/v1")
DUMMY_HASH = hash_password("dummy-password-for-timing", 1000)


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


def ser_user(u: SystemUser) -> dict:
    return {"id": u.id, "username": u.username, "full_name": u.full_name, "role": u.role, "status": u.status,
            "auth_source": u.auth_source}


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
def me(user: SystemUser = Depends(current_user)):
    return ser_user(user)


class UserIn(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9._-]{3,64}$")
    full_name: str | None = Field(default=None, max_length=128)
    password: str | None = Field(default=None, max_length=256)
    role: str = Field(pattern="^(admin|analyst)$")
    auth_source: str = Field(default="local", pattern="^(local|ad)$")


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
                   auth_source=body.auth_source)
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
    if body.get("status") in ("active", "disabled"):
        u.status = body["status"]
    if body.get("role") in ("admin", "analyst"):
        u.role = body["role"]
    audit.write(db, "user.updated", admin.username, admin.id,
                {"user": u.username, "changes": {k: body[k] for k in ("status", "role") if k in body}})
    db.commit()
    return ser_user(u)


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
    return ser_ver(v, with_qr=True)


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
