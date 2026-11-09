"""QR-assisted biometric verification (Section 2.1.15/2.1.16). The QR carries only a non-secret transaction id.
The second factor is a 6-digit code from the user's authenticator app (Microsoft Authenticator, Google Authenticator, Authy...),
which the phone protects with its own fingerprint/face lock. For lab use a simulated reference can stand in (BIOMETRIC_MODE)."""
import base64
import io
from datetime import timedelta

import qrcode
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AuthStatus, AuthTransaction, SystemUser, utcnow
from app.security import hash_secret, verify_secret
from app.services import audit, totp


def totp_allowed() -> bool:
    return settings.biometric_mode in ("both", "totp")


def simulated_allowed() -> bool:
    return settings.biometric_mode in ("both", "simulated")


def method(user: SystemUser) -> str:
    """Which kind of credential this user's verification expects: 'authenticator' (6-digit code) or 'reference' (dev)."""
    return "authenticator" if totp_allowed() and totp.is_enrolled(user) else "reference"


def has_factor(user: SystemUser) -> bool:
    if totp_allowed() and totp.is_enrolled(user):
        return True
    return simulated_allowed() and bool(user.biometric_template_hash)


def enroll(db: Session, user: SystemUser, template: str):
    """Dev-only reference enrolment (BIOMETRIC_MODE both|simulated)."""
    user.biometric_template_hash = hash_secret(template)
    audit.log(db, user, "biometric_enrolled", commit=True)


def create(db: Session, user: SystemUser, purpose: str) -> tuple[AuthTransaction, str, str]:
    if not has_factor(user):
        raise HTTPException(409, "No authenticator enrolled for this account. Set one up under Account first.")
    tx = AuthTransaction(user_id=user.id, purpose=purpose, expires_at=utcnow() + timedelta(seconds=settings.auth_tx_ttl_seconds))
    db.add(tx)
    audit.log(db, user, "auth_transaction_created", details=f"purpose={purpose}")
    db.commit()
    url = f"{settings.public_base_url}/verify/{tx.id}"
    buf = io.BytesIO()
    qrcode.make(url).save(buf, format="PNG")
    return tx, url, base64.b64encode(buf.getvalue()).decode()


def _refresh(db: Session, tx: AuthTransaction) -> AuthTransaction:
    if tx.status == AuthStatus.PENDING and tx.expires_at <= utcnow():
        tx.status = AuthStatus.EXPIRED
        db.commit()
    return tx


def get(db: Session, tx_id) -> AuthTransaction:
    tx = db.get(AuthTransaction, tx_id)
    if not tx:
        raise HTTPException(404, "Unknown authentication transaction")
    return _refresh(db, tx)


def _verify_biometric(user: SystemUser, credential: str) -> bool:
    if settings.biometric_mode not in ("both", "totp", "simulated"):
        raise HTTPException(501, f"Unknown BIOMETRIC_MODE '{settings.biometric_mode}' (use both, totp or simulated)")
    if totp_allowed() and totp.is_enrolled(user):
        # Once a real authenticator is enrolled the dev reference is no longer accepted.
        step = totp.match_step(totp.secret_of(user), credential, user.totp_last_step or 0)
        if step is None:
            return False
        user.totp_last_step = step  # committed by verify(); a code is single-use
        return True
    if simulated_allowed():
        return verify_secret(credential, user.biometric_template_hash)
    return False


def verify(db: Session, tx_id, credential: str) -> AuthTransaction:
    tx = get(db, tx_id)
    user = db.get(SystemUser, tx.user_id)
    if tx.status != AuthStatus.PENDING:
        raise HTTPException(409, f"Transaction is {tx.status.value}")
    if _verify_biometric(user, credential):
        tx.status, tx.verified_at = AuthStatus.VERIFIED, utcnow()
        audit.log(db, user, "biometric_verified", details=f"purpose={tx.purpose}")
    else:
        tx.attempts += 1
        if tx.attempts >= settings.auth_tx_max_attempts:
            tx.status = AuthStatus.FAILED
        audit.log(db, user, "biometric_failed", outcome="denied", details=f"purpose={tx.purpose} attempts={tx.attempts}")
    db.commit()
    return tx


def consume(db: Session, user: SystemUser, tx_id, purpose: str, ip: str | None = None) -> AuthTransaction:
    """Precondition check + single-use burn. Raises 403 (and audits) if anything is wrong."""
    def deny(reason: str):
        audit.log(db, user, "auth_gate_denied", outcome="denied", details=f"purpose={purpose}: {reason}", ip=ip, commit=True)
        raise HTTPException(403, f"Verification required: {reason}")

    if not tx_id:
        deny("missing X-Auth-Transaction header")
    try:
        tx = get(db, tx_id)
    except HTTPException:
        deny("unknown transaction")
    if tx.user_id != user.id:
        deny("transaction belongs to a different user")
    if tx.purpose != purpose:
        deny("transaction was issued for a different operation")
    if tx.status != AuthStatus.VERIFIED:
        deny(f"transaction is {tx.status.value}")
    if tx.used:
        deny("transaction already used")
    if tx.verified_at and tx.verified_at + timedelta(seconds=settings.auth_tx_ttl_seconds) <= utcnow():
        deny("verification expired")
    tx.used = True
    db.flush()
    return tx
