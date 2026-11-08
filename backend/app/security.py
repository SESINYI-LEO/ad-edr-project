import base64
import hashlib
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet, InvalidToken
from jose import jwt
from passlib.context import CryptContext

from app.config import settings

_pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def hash_secret(plain: str) -> str:
    return _pwd.hash(plain)


def verify_secret(plain: str, hashed: str | None) -> bool:
    if not hashed:
        return False
    try:
        return _pwd.verify(plain, hashed)
    except Exception:
        return False


def create_access_token(username: str, role: str, issued_at: datetime | None = None) -> str:
    now = issued_at or datetime.now(timezone.utc)
    exp = now + timedelta(minutes=settings.access_token_expire_minutes)
    # iat (sub-second, as RFC 7519 allows) lets the server reject tokens issued before the user's last password change/reset.
    return jwt.encode({"sub": username, "role": role, "iat": now.timestamp(), "exp": exp}, settings.secret_key, algorithm=settings.algorithm)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])


def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(("edr-totp-v1:" + settings.secret_key).encode()).digest())
    return Fernet(key)


def encrypt_text(plain: str) -> str:
    """Reversible encryption for authenticator secrets (keyed from SECRET_KEY; changing SECRET_KEY means re-enrolling)."""
    return _fernet().encrypt(plain.encode()).decode()


def decrypt_text(token: str | None) -> str | None:
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        return None
