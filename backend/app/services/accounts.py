"""Password lifecycle helpers shared by the auth and users routers."""
import secrets
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.models import SystemUser, utcnow
from app.security import hash_secret, verify_secret
from app.services import audit

# no 0/O/1/l/I so a temporary password can be read out or typed from a screen without mistakes
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"


def temp_password(length: int = 14) -> str:
    while True:
        pw = "".join(secrets.choice(_ALPHABET) for _ in range(length))
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw):
            return pw


def validate_new_password(user: SystemUser, new: str):
    """Length (8-128) is enforced by the request schemas; these are the account-specific rules."""
    if new.lower() == user.username.lower():
        raise HTTPException(400, "Password must not be the same as the username")
    if verify_secret(new, user.hashed_password):
        raise HTTPException(400, "New password must be different from the current one")


def set_password(user: SystemUser, new: str, must_change: bool = False):
    user.hashed_password = hash_secret(new)
    user.password_changed_at = utcnow()  # invalidates every token issued before now
    user.must_change_password = must_change


# ---- brute-force guard for the endpoints that check a secret for an already-identified account ----
def check_lock(user: SystemUser):
    if user.recovery_locked_until and user.recovery_locked_until > utcnow():
        raise HTTPException(429, f"Too many failed attempts. Try again in {settings.recovery_lockout_minutes} minutes or ask an administrator.")


def register_failure(db: Session, user: SystemUser, action: str, ip: str | None, details: str = ""):
    user.recovery_failures = (user.recovery_failures or 0) + 1
    if user.recovery_failures >= settings.recovery_max_attempts:
        user.recovery_locked_until = utcnow() + timedelta(minutes=settings.recovery_lockout_minutes)
        user.recovery_failures = 0
        details = f"{details} (account locked for {settings.recovery_lockout_minutes} min)".strip()
    audit.log(db, user, action, outcome="denied", details=details, ip=ip, commit=True)


def clear_failures(user: SystemUser):
    user.recovery_failures = 0
    user.recovery_locked_until = None
