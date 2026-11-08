import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import admin_only, auth_header, client_ip, current_user
from app.models import ADUser, Role, SystemUser
from app.routers.common import ad_user_out, user_out
from app.schemas import AdminPasswordReset, UserCreate, UserUpdate
from app.security import hash_secret
from app.services import accounts, audit, auth_tx

router = APIRouter(prefix="/api", tags=["users"])


@router.get("/users")
def list_users(user=Depends(current_user), db: Session = Depends(get_db)):
    return [user_out(u) for u in db.scalars(select(SystemUser).order_by(SystemUser.username))]


@router.post("/users")
def create_user(body: UserCreate, admin=Depends(admin_only), db: Session = Depends(get_db)):
    if db.scalar(select(SystemUser).where(SystemUser.username == body.username)):
        raise HTTPException(409, "Username already exists")
    u = SystemUser(username=body.username, email=body.email, hashed_password=hash_secret(body.password), role=Role(body.role),
                   must_change_password=body.must_change_password)
    db.add(u)
    audit.log(db, admin, "user_created", details=f"{body.username} ({body.role})")
    db.commit()
    return user_out(u)


def _target(db: Session, user_id: str) -> SystemUser:
    try:
        u = db.get(SystemUser, uuid.UUID(user_id))
    except ValueError:
        u = None
    if not u:
        raise HTTPException(404, "User not found")
    return u


def _active_admins(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(SystemUser).where(SystemUser.role == Role.ADMINISTRATOR, SystemUser.is_active.is_(True)))


@router.patch("/users/{user_id}")
def update_user(user_id: str, body: UserUpdate, admin=Depends(admin_only), tx=Depends(auth_header), ip=Depends(client_ip),
                db: Session = Depends(get_db)):
    """Edit email / role / active flag. Changing role or active state needs QR + biometric verification."""
    u = _target(db, user_id)
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(400, "Nothing to change")
    new_role = Role(changes["role"]) if changes.get("role") else u.role
    new_active = changes["is_active"] if changes.get("is_active") is not None else u.is_active
    privileged = new_role != u.role or new_active != u.is_active

    if privileged:
        if u.id == admin.id:
            raise HTTPException(400, "You cannot change your own role or deactivate your own account")
        losing_admin = u.role == Role.ADMINISTRATOR and u.is_active and (new_role != Role.ADMINISTRATOR or not new_active)
        if losing_admin and _active_admins(db) <= 1:
            raise HTTPException(400, "At least one active administrator must remain")
        auth_tx.consume(db, admin, tx, "user_admin", ip)

    details = []
    if "email" in changes and changes["email"] is not None and changes["email"] != u.email:
        details.append("email")
        u.email = changes["email"]
    if new_role != u.role:
        details.append(f"role {u.role.value}->{new_role.value}")
        u.role = new_role
    if new_active != u.is_active:
        details.append("activated" if new_active else "deactivated")
        u.is_active = new_active
    audit.log(db, admin, "user_updated", details=f"{u.username}: {', '.join(details) or 'no change'}", ip=ip)
    db.commit()
    return user_out(u)


@router.post("/users/{user_id}/reset-password")
def reset_password(user_id: str, body: AdminPasswordReset, admin=Depends(admin_only), tx=Depends(auth_header), ip=Depends(client_ip),
                   db: Session = Depends(get_db)):
    """Set a new password for another user (generated unless one is supplied). The user must change it at next sign-in,
    all of their existing sessions stop working, and any lockout is cleared. Needs QR + biometric verification."""
    u = _target(db, user_id)
    if u.id == admin.id:
        raise HTTPException(400, "Use Change password for your own account")
    auth_tx.consume(db, admin, tx, "user_admin", ip)
    temp = body.new_password or accounts.temp_password()
    accounts.set_password(u, temp, must_change=True)
    accounts.clear_failures(u)
    audit.log(db, admin, "password_reset_by_admin", details=f"target={u.username}", ip=ip)
    db.commit()
    return {"username": u.username, "temporary_password": temp, "must_change_password": True}


@router.post("/users/{user_id}/reset-authenticator")
def reset_authenticator(user_id: str, admin=Depends(admin_only), tx=Depends(auth_header), ip=Depends(client_ip), db: Session = Depends(get_db)):
    """For a user who lost their phone: removes their authenticator so they can enrol a new one after signing in."""
    u = _target(db, user_id)
    auth_tx.consume(db, admin, tx, "user_admin", ip)
    u.totp_secret_enc = u.totp_pending_enc = None
    u.totp_last_step = 0
    accounts.clear_failures(u)
    audit.log(db, admin, "authenticator_reset_by_admin", details=f"target={u.username}", ip=ip)
    db.commit()
    return user_out(u)


@router.get("/ad/users")
def ad_users(user=Depends(current_user), db: Session = Depends(get_db)):
    return [ad_user_out(u) for u in db.scalars(select(ADUser).order_by(ADUser.username))]
