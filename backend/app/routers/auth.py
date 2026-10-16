from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import client_ip, current_user
from app.models import SystemUser
from app.schemas import EnrollIn, TxCreate, TxVerify
from app.security import create_access_token, verify_secret
from app.services import audit, auth_tx
from app.routers.common import iso, user_out

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db), ip=Depends(client_ip)):
    user = db.scalar(select(SystemUser).where(SystemUser.username == form.username))
    if not user or not user.is_active or not verify_secret(form.password, user.hashed_password):
        audit.log(db, user, "login", outcome="denied", details=f"username={form.username}", ip=ip, commit=True)
        raise HTTPException(401, "Incorrect username or password")
    audit.log(db, user, "login", ip=ip, commit=True)
    return {"access_token": create_access_token(user.username, user.role.value), "token_type": "bearer", "user": user_out(user)}


@router.get("/me")
def me(user=Depends(current_user)):
    return user_out(user)


@router.post("/biometric/enroll")
def enroll(body: EnrollIn, user=Depends(current_user), db: Session = Depends(get_db)):
    auth_tx.enroll(db, user, body.template)
    return {"enrolled": True}


@router.post("/transactions")
def create_tx(body: TxCreate, user=Depends(current_user), db: Session = Depends(get_db)):
    tx, url, qr_png = auth_tx.create(db, user, body.purpose)
    return {"id": str(tx.id), "purpose": tx.purpose, "status": tx.status.value, "expires_at": iso(tx.expires_at),
            "verify_url": url, "qr_png_base64": qr_png}


@router.get("/transactions/{tx_id}")
def tx_status(tx_id: str, db: Session = Depends(get_db)):
    import uuid
    try:
        tx = auth_tx.get(db, uuid.UUID(tx_id))
    except ValueError:
        raise HTTPException(404, "Unknown authentication transaction")
    return {"id": str(tx.id), "purpose": tx.purpose, "status": tx.status.value, "expires_at": iso(tx.expires_at)}


@router.post("/transactions/{tx_id}/verify")
def verify_tx(tx_id: str, body: TxVerify, db: Session = Depends(get_db)):
    """Called from the second device after scanning the QR. Public by design: it only accepts the biometric credential."""
    import uuid
    try:
        tx = auth_tx.verify(db, uuid.UUID(tx_id), body.credential)
    except ValueError:
        raise HTTPException(404, "Unknown authentication transaction")
    return {"id": str(tx.id), "status": tx.status.value, "attempts": tx.attempts}
