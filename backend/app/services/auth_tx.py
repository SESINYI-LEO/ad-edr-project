"""QR-assisted biometric verification (Section 2.1.15/2.1.16). The QR carries only a non-secret transaction id.
Biometric verification happens on the second device; only a protected template hash is ever stored, never raw biometric data."""
import base64
import io
from datetime import timedelta

import qrcode
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AuthStatus, AuthTransaction, SystemUser, utcnow
from app.security import hash_secret, verify_secret
from app.services import audit


def enroll(db: Session, user: SystemUser, template: str):
    user.biometric_template_hash = hash_secret(template)
    audit.log(db, user, "biometric_enrolled", commit=True)


def create(db: Session, user: SystemUser, purpose: str) -> tuple[AuthTransaction, str, str]:
    if not user.biometric_template_hash:
        raise HTTPException(409, "No biometric reference enrolled for this account")
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
    if settings.biometric_mode == "simulated":
        return verify_secret(credential, user.biometric_template_hash)
    raise HTTPException(501, "Only simulated biometric verification is built in; plug a WebAuthn verifier in here for production")


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
