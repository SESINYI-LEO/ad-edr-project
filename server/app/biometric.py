"""QR-assisted biometric verification protecting privileged operations.

Two interchangeable ways to approve a verification:
  * enrolled DEVICE (Ed25519): scan the QR, biometric unlocks the device key, which signs the server challenge;
  * authenticator APP (TOTP): Microsoft Authenticator / Google Authenticator / Authy..., the 6-digit code is typed in
    (the app's own fingerprint / face lock is what releases the code). Nothing biometric reaches the server either way.

The QR code carries only a transaction id and a one-time nonce. The enrolled device scans it, performs the
biometric check LOCALLY (unlocking a private key held in its secure hardware) and signs a server challenge. The
server stores only the device's PUBLIC key, so no biometric data or template ever reaches the server (the same
model as FIDO2/WebAuthn).
"""
import base64
import io
import secrets
from datetime import timedelta

import qrcode
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from sqlalchemy.orm import Session

from . import audit
from .config import Settings
from .models import BiometricVerification, DeviceCredential, SystemUser, utcnow
from .security import check_totp, unseal

PURPOSE_RE = (r"^(response_action:\d+:(isolate_endpoint|release_endpoint|flag_account)|rule:R\d{3}:(enable|disable)|backup:create|"
              r"backup:restore:\d+|tool:[a-z_]{1,32}|user:(reset_password|reset_authenticator):\d+)$")
MAX_CODE_ATTEMPTS = 3


class VerificationError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def signing_message(ver: BiometricVerification) -> bytes:
    return f"EDR-VERIFY|{ver.id}|{ver.challenge}|{ver.purpose}|{ver.user_id}".encode()


def qr_payload(ver: BiometricVerification) -> str:
    return f"edr://verify?id={ver.id}&n={ver.nonce}"


def qr_png_data_uri(payload: str) -> str:
    img = qrcode.make(payload, box_size=6, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def _refresh(db: Session, ver: BiometricVerification) -> None:
    if ver.status in ("pending", "qr_validated") and utcnow() > ver.expires_at:
        ver.status = "expired"
        audit.write(db, "verify.expired", f"user:{ver.user_id}", ver.user_id, {"verification": ver.id, "purpose": ver.purpose}, "failure")


def methods_for(db: Session, user: SystemUser) -> dict:
    return {"device": db.query(DeviceCredential).filter_by(user_id=user.id).first() is not None,
            "totp": bool(user.totp_confirmed)}


def initiate(db: Session, user: SystemUser, purpose: str, s: Settings) -> BiometricVerification:
    m = methods_for(db, user)
    if not (m["device"] or m["totp"]):
        raise VerificationError(409, "No authenticator enrolled for this account. Link an authenticator app under My account first")
    now = utcnow()
    ver = BiometricVerification(user_id=user.id, purpose=purpose, nonce=secrets.token_urlsafe(24),
                                challenge=secrets.token_urlsafe(32), status="pending", created_at=now,
                                expires_at=now + timedelta(seconds=s.verify_ttl_seconds))
    db.add(ver)
    db.flush()
    audit.write(db, "verify.initiated", user.username, user.id, {"verification": ver.id, "purpose": purpose})
    return ver


def get(db: Session, ver_id: int) -> BiometricVerification:
    ver = db.get(BiometricVerification, ver_id)
    if not ver:
        raise VerificationError(404, "Verification not found")
    _refresh(db, ver)
    return ver


def scan(db: Session, ver_id: int, nonce: str, device_id: int) -> BiometricVerification:
    ver = get(db, ver_id)
    if ver.status != "pending":
        raise VerificationError(409, f"Verification is {ver.status}")
    if not secrets.compare_digest(ver.nonce, nonce or ""):
        audit.write(db, "verify.scan", f"device:{device_id}", ver.user_id, {"verification": ver.id, "reason": "bad nonce"}, "denied")
        raise VerificationError(403, "QR code does not match this transaction")
    dev = db.get(DeviceCredential, device_id)
    if not dev or dev.user_id != ver.user_id:
        audit.write(db, "verify.scan", f"device:{device_id}", ver.user_id, {"verification": ver.id, "reason": "device not enrolled for user"}, "denied")
        raise VerificationError(403, "Device is not enrolled for this account")
    ver.status, ver.device_id = "qr_validated", dev.id
    audit.write(db, "verify.qr_validated", f"device:{dev.id}", ver.user_id, {"verification": ver.id})
    return ver


def complete(db: Session, ver_id: int, device_id: int, signature_b64: str) -> BiometricVerification:
    ver = get(db, ver_id)
    if ver.status != "qr_validated" or ver.device_id != device_id:
        raise VerificationError(409, f"Verification is {ver.status}")
    dev = db.get(DeviceCredential, device_id)
    try:
        key = load_pem_public_key(dev.public_key_pem.encode())
        key.verify(base64.b64decode(signature_b64, validate=True), signing_message(ver))
    except (InvalidSignature, ValueError, TypeError):
        ver.status = "failed"
        audit.write(db, "verify.failed", f"device:{dev.id}", ver.user_id, {"verification": ver.id, "reason": "bad signature"}, "failure")
        return ver
    ver.status, ver.verified_at = "verified", utcnow()
    audit.write(db, "verify.verified", f"device:{dev.id}", ver.user_id, {"verification": ver.id, "purpose": ver.purpose})
    return ver


def complete_totp(db: Session, user: SystemUser, ver_id: int, code: str) -> BiometricVerification:
    """Approve with the 6-digit code from the user's authenticator app (called by the signed-in owner)."""
    ver = get(db, ver_id)
    if ver.user_id != user.id:
        raise VerificationError(404, "Verification not found")
    if ver.status not in ("pending", "qr_validated"):
        raise VerificationError(409, f"Verification is {ver.status}")
    if not user.totp_confirmed:
        raise VerificationError(409, "No authenticator app is linked to this account")
    secret = unseal(user.totp_secret_enc)
    if secret is None:
        raise VerificationError(409, "Authenticator can no longer be read (server key changed). Ask an administrator to reset it")
    step = check_totp(secret, code, user.totp_last_step or 0)
    if step is None:
        ver.attempts = (ver.attempts or 0) + 1
        if ver.attempts >= MAX_CODE_ATTEMPTS:
            ver.status = "failed"
        audit.write(db, "verify.failed" if ver.status == "failed" else "verify.code_wrong", f"user:{user.id}", user.id,
                    {"verification": ver.id, "reason": "wrong authenticator code", "attempts": ver.attempts}, "failure")
        return ver
    user.totp_last_step = step  # this code cannot be replayed
    ver.status, ver.verified_at = "verified", utcnow()
    audit.write(db, "verify.verified", f"user:{user.id}", user.id, {"verification": ver.id, "purpose": ver.purpose, "method": "totp"})
    return ver


def reject(db: Session, ver_id: int, device_id: int) -> BiometricVerification:
    """The device reports that the local biometric check did not match."""
    ver = get(db, ver_id)
    if ver.status != "qr_validated" or ver.device_id != device_id:
        raise VerificationError(409, f"Verification is {ver.status}")
    ver.status = "failed"
    audit.write(db, "verify.failed", f"device:{device_id}", ver.user_id, {"verification": ver.id, "reason": "biometric mismatch"}, "failure")
    return ver


def consume(db: Session, user: SystemUser, ver_id: int | None, purpose: str, s: Settings) -> BiometricVerification:
    """Require a valid, unused, matching verification before a privileged operation. Single use."""
    def deny(msg):
        audit.write(db, "verify.consume", user.username, user.id, {"verification": ver_id, "purpose": purpose, "reason": msg}, "denied")
        db.commit()  # persist the denial even though the request is rejected
        raise VerificationError(403, msg)

    if not ver_id:
        deny("Biometric verification required")
    ver = db.get(BiometricVerification, ver_id)
    if not ver or ver.user_id != user.id:
        deny("Verification not found for this user")
    if ver.status != "verified":
        deny(f"Verification is {ver.status}, not verified")
    if ver.consumed_at is not None:
        deny("Verification already used")
    if ver.purpose != purpose:
        deny("Verification was issued for a different operation")
    if utcnow() - ver.verified_at > timedelta(seconds=s.verify_use_window_seconds):
        deny("Verification has timed out")
    ver.consumed_at = utcnow()
    return ver
