"""Password hashing, JWT sessions, API keys and role-based access control."""
import hashlib
import hmac
import os
import secrets
from datetime import timedelta

import jwt
from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import Endpoint, SystemUser, utcnow


def hash_password(password: str, iterations: int | None = None) -> str:
    it = iterations or get_settings().password_iterations
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, it)
    return f"pbkdf2${it}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        _, it, salt, h = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(dk.hex(), h)
    except (ValueError, TypeError):
        return False


def create_token(user: SystemUser) -> str:
    s = get_settings()
    now = utcnow()
    payload = {"sub": str(user.id), "role": user.role, "iat": now, "exp": now + timedelta(minutes=s.token_minutes)}
    return jwt.encode(payload, s.secret_key, algorithm="HS256")


def decode_token(token: str) -> dict:
    return jwt.decode(token, get_settings().secret_key, algorithms=["HS256"])


def current_user(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> SystemUser:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Not authenticated")
    try:
        data = decode_token(authorization.split(" ", 1)[1])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")
    user = db.get(SystemUser, int(data["sub"]))
    if not user or user.status != "active":
        raise HTTPException(401, "Account not active")
    return user


def require_role(*roles: str):
    def dep(user: SystemUser = Depends(current_user)) -> SystemUser:
        if user.role not in roles:
            raise HTTPException(403, "Insufficient privileges")
        return user
    return dep


admin_only = require_role("admin")
any_user = require_role("admin", "analyst")


def new_api_key() -> tuple[str, str]:
    key = "edr_" + secrets.token_urlsafe(32)
    return key, hashlib.sha256(key.encode()).hexdigest()


def current_endpoint(x_api_key: str | None = Header(default=None), db: Session = Depends(get_db)) -> Endpoint:
    if not x_api_key:
        raise HTTPException(401, "Missing API key")
    h = hashlib.sha256(x_api_key.encode()).hexdigest()
    ep = db.query(Endpoint).filter(Endpoint.api_key_hash == h).first()
    if not ep:
        raise HTTPException(401, "Invalid API key")
    return ep
