"""Password hashing, JWT sessions, API keys and role-based access control."""
import base64
import hashlib
import hmac
import os
import secrets
import string
import time
from collections import defaultdict, deque
from datetime import timedelta

import jwt
import pyotp
from cryptography.fernet import Fernet, InvalidToken
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
    payload = {"sub": str(user.id), "role": user.role, "ver": user.token_version or 0, "iat": now,
               "exp": now + timedelta(minutes=s.token_minutes)}
    return jwt.encode(payload, s.secret_key, algorithm="HS256")


def decode_token(token: str) -> dict:
    return jwt.decode(token, get_settings().secret_key, algorithms=["HS256"])


def current_user_any(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> SystemUser:
    """A valid session, even if the account still has to change its password (only the account endpoints use this)."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Not authenticated")
    try:
        data = decode_token(authorization.split(" ", 1)[1])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")
    user = db.get(SystemUser, int(data["sub"]))
    if not user or user.status != "active":
        raise HTTPException(401, "Account not active")
    if data.get("ver", 0) != (user.token_version or 0):
        raise HTTPException(401, "Session ended - please sign in again")  # password was changed/reset since this token was issued
    return user


def current_user(user: SystemUser = Depends(current_user_any)) -> SystemUser:
    if user.must_change_password:
        raise HTTPException(403, "Password change required")
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


# ---------- authenticator app (TOTP, RFC 6238) ----------
TOTP_PERIOD = 30
TOTP_ISSUER = os.environ.get("TOTP_ISSUER", "AD-EDR")


def _fernet() -> Fernet:
    key = hashlib.sha256(("edr-totp-v1|" + get_settings().secret_key).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def seal(text: str) -> str:
    return _fernet().encrypt(text.encode()).decode()


def unseal(token: str | None, ttl: int | None = None) -> str | None:
    """Decrypt, or None if it is missing/tampered/expired (also happens if SECRET_KEY changed since enrolment)."""
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode(), ttl=ttl).decode()
    except InvalidToken:
        return None


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret, interval=TOTP_PERIOD).provisioning_uri(name=username, issuer_name=TOTP_ISSUER)


def check_totp(secret: str | None, code: str, last_step: int = 0) -> int | None:
    """Matched time step (store it as last_step) or None. Allows +/-1 step of clock drift; each step is single-use."""
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if not secret or len(code) != 6:
        return None
    totp = pyotp.TOTP(secret, interval=TOTP_PERIOD)
    now_step = int(time.time() // TOTP_PERIOD)
    for step in (now_step - 1, now_step, now_step + 1):
        if step > last_step and hmac.compare_digest(totp.at(step * TOTP_PERIOD), code):
            return step
    return None


def temp_password() -> str:
    """Random password that satisfies the password policy (10+ chars, upper, lower, digit)."""
    alphabet = string.ascii_letters + string.digits
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(14))
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw):
            return pw


# ---------- small in-memory throttle for guessable endpoints ----------
_hits: dict[str, deque] = defaultdict(deque)


def throttled(key: str, limit: int = 5, window: int = 900) -> bool:
    q = _hits[key]
    cutoff = time.time() - window
    while q and q[0] < cutoff:
        q.popleft()
    return len(q) >= limit


def record_hit(key: str) -> None:
    _hits[key].append(time.time())


def clear_hits(key: str) -> None:
    _hits.pop(key, None)
