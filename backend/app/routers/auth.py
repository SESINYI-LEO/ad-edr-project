import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.deps import client_ip, current_user, current_user_any
from app.models import SystemUser
from app.schemas import EnrollIn, PasswordChange, PasswordForgot, TotpCode, TotpRemove, TotpStart, TxCreate, TxVerify
from app.security import create_access_token, decrypt_text, encrypt_text, verify_secret
from app.services import accounts, audit, auth_tx, totp
from app.routers.common import iso, user_out

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _session(user: SystemUser) -> dict:
    return {"access_token": create_access_token(user.username, user.role.value), "token_type": "bearer", "user": user_out(user)}


@router.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db), ip=Depends(client_ip)):
    user = db.scalar(select(SystemUser).where(SystemUser.username == form.username))
    if not user or not user.is_active or not verify_secret(form.password, user.hashed_password):
        audit.log(db, user, "login", outcome="denied", details=f"username={form.username}", ip=ip, commit=True)
        raise HTTPException(401, "Incorrect username or password")
    audit.log(db, user, "login", ip=ip, commit=True)
    return _session(user)


@router.get("/me")
def me(user=Depends(current_user_any)):
    return user_out(user)


# ---------------- passwords ----------------
@router.post("/password/change")
def change_password(body: PasswordChange, user=Depends(current_user_any), db: Session = Depends(get_db), ip=Depends(client_ip)):
    accounts.check_lock(user)
    if not verify_secret(body.current_password, user.hashed_password):
        accounts.register_failure(db, user, "password_change", ip, "wrong current password")
        raise HTTPException(403, "Current password is incorrect")
    accounts.validate_new_password(user, body.new_password)
    accounts.set_password(user, body.new_password, must_change=False)
    accounts.clear_failures(user)
    audit.log(db, user, "password_changed", ip=ip, commit=True)
    return _session(user)  # fresh token: every older one is now rejected


@router.post("/password/forgot")
def forgot_password(body: PasswordForgot, db: Session = Depends(get_db), ip=Depends(client_ip)):
    """Self-service reset for someone who cannot sign in: proves identity with a code from their enrolled authenticator app.
    Accounts without an authenticator must ask an administrator. The error never says which part was wrong."""
    def generic():
        return HTTPException(400, "Invalid username or authenticator code")

    user = db.scalar(select(SystemUser).where(SystemUser.username == body.username))
    if not user or not user.is_active or not auth_tx.totp_allowed() or not totp.is_enrolled(user):
        audit.log(db, user, "password_reset_self", outcome="denied", details=f"username={body.username}", ip=ip, commit=True)
        raise generic()
    accounts.check_lock(user)
    step = totp.match_step(totp.secret_of(user), body.code, user.totp_last_step or 0)
    if step is None:
        accounts.register_failure(db, user, "password_reset_self", ip, "bad authenticator code")
        raise generic()
    accounts.validate_new_password(user, body.new_password)
    user.totp_last_step = step
    accounts.set_password(user, body.new_password, must_change=False)
    accounts.clear_failures(user)
    audit.log(db, user, "password_reset_self", ip=ip, commit=True)
    return {"reset": True}


# ---------------- authenticator app (Microsoft Authenticator, Google Authenticator, Authy, ...) ----------------
def _need_totp_mode():
    if not auth_tx.totp_allowed():
        raise HTTPException(409, "Authenticator apps are disabled (BIOMETRIC_MODE=simulated)")


@router.post("/totp/enroll/start")
def totp_enroll_start(body: TotpStart, user=Depends(current_user), db: Session = Depends(get_db), ip=Depends(client_ip)):
    """Step 1: returns the QR code to scan. Nothing becomes active until /confirm succeeds, so a half-finished
    enrolment never locks anyone out. Needs the password (a stolen session must not be able to swap the second factor)."""
    _need_totp_mode()
    accounts.check_lock(user)
    if not verify_secret(body.current_password, user.hashed_password):
        accounts.register_failure(db, user, "authenticator_enroll", ip, "wrong password")
        raise HTTPException(403, "Current password is incorrect")
    if totp.is_enrolled(user):
        step = totp.match_step(totp.secret_of(user), body.current_code or "", user.totp_last_step or 0)
        if step is None:
            accounts.register_failure(db, user, "authenticator_enroll", ip, "bad code for existing authenticator")
            raise HTTPException(403, "To replace your authenticator, enter a current code from the existing one")
        user.totp_last_step = step
    accounts.clear_failures(user)
    secret = totp.new_secret()
    user.totp_pending_enc = encrypt_text(secret)
    audit.log(db, user, "authenticator_enroll_started", ip=ip, commit=True)
    uri = totp.provisioning_uri(secret, user.username)
    return {"secret": secret, "otpauth_uri": uri, "qr_png_base64": totp.qr_png_base64(uri),
            "issuer": settings.totp_issuer, "account": user.username}


@router.post("/totp/enroll/confirm")
def totp_enroll_confirm(body: TotpCode, user=Depends(current_user), db: Session = Depends(get_db), ip=Depends(client_ip)):
    """Step 2: the user types the first code their app shows, proving the secret reached the phone."""
    _need_totp_mode()
    pending = decrypt_text(user.totp_pending_enc)
    if not pending:
        raise HTTPException(409, "No enrolment in progress. Start again.")
    accounts.check_lock(user)
    step = totp.match_step(pending, body.code)
    if step is None:
        accounts.register_failure(db, user, "authenticator_enroll", ip, "bad confirmation code")
        raise HTTPException(400, "That code is not valid. Check the code is for this account and your phone's clock is automatic, then try the next code.")
    user.totp_secret_enc = encrypt_text(pending)
    user.totp_pending_enc = None
    user.totp_last_step = step
    user.biometric_template_hash = None  # the dev reference no longer applies once a real authenticator exists
    accounts.clear_failures(user)
    audit.log(db, user, "authenticator_enrolled", ip=ip, commit=True)
    return user_out(user)


@router.post("/totp/remove")
def totp_remove(body: TotpRemove, user=Depends(current_user), db: Session = Depends(get_db), ip=Depends(client_ip)):
    if not totp.is_enrolled(user):
        raise HTTPException(409, "No authenticator is enrolled")
    accounts.check_lock(user)
    ok = verify_secret(body.current_password, user.hashed_password)
    step = totp.match_step(totp.secret_of(user), body.code, user.totp_last_step or 0) if ok else None
    if step is None:
        accounts.register_failure(db, user, "authenticator_remove", ip, "wrong password or code")
        raise HTTPException(403, "Password or authenticator code is incorrect")
    user.totp_secret_enc = user.totp_pending_enc = None
    user.totp_last_step = 0
    accounts.clear_failures(user)
    audit.log(db, user, "authenticator_removed", ip=ip, commit=True)
    return user_out(user)


@router.post("/biometric/enroll")
def enroll(body: EnrollIn, user=Depends(current_user), db: Session = Depends(get_db), ip=Depends(client_ip)):
    """Dev-only: set the simulated biometric reference. Disabled in BIOMETRIC_MODE=totp and once a real authenticator exists."""
    if not auth_tx.simulated_allowed():
        raise HTTPException(409, "Simulated biometric enrolment is disabled; use an authenticator app")
    if totp.is_enrolled(user):
        raise HTTPException(409, "An authenticator app is already enrolled; remove it first")
    accounts.check_lock(user)
    if not verify_secret(body.current_password, user.hashed_password):
        accounts.register_failure(db, user, "biometric_enroll", ip, "wrong password")
        raise HTTPException(403, "Current password is incorrect")
    auth_tx.enroll(db, user, body.template)
    return {"enrolled": True}


# ---------------- QR + biometric transactions ----------------
@router.post("/transactions")
def create_tx(body: TxCreate, user=Depends(current_user), db: Session = Depends(get_db)):
    tx, url, qr_png = auth_tx.create(db, user, body.purpose)
    return {"id": str(tx.id), "purpose": tx.purpose, "status": tx.status.value, "expires_at": iso(tx.expires_at),
            "method": auth_tx.method(user), "verify_url": url, "qr_png_base64": qr_png}


@router.get("/transactions/{tx_id}")
def tx_status(tx_id: str, db: Session = Depends(get_db)):
    try:
        tx = auth_tx.get(db, uuid.UUID(tx_id))
    except ValueError:
        raise HTTPException(404, "Unknown authentication transaction")
    user = db.get(SystemUser, tx.user_id)
    return {"id": str(tx.id), "purpose": tx.purpose, "status": tx.status.value, "expires_at": iso(tx.expires_at),
            "method": auth_tx.method(user)}


@router.post("/transactions/{tx_id}/verify")
def verify_tx(tx_id: str, body: TxVerify, db: Session = Depends(get_db)):
    """Called from the second device after scanning the QR. Public by design: it only accepts the authenticator code."""
    try:
        tx = auth_tx.verify(db, uuid.UUID(tx_id), body.credential)
    except ValueError:
        raise HTTPException(404, "Unknown authentication transaction")
    return {"id": str(tx.id), "status": tx.status.value, "attempts": tx.attempts}
