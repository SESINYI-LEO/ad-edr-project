from datetime import datetime, timedelta, timezone

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


def create_access_token(username: str, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    return jwt.encode({"sub": username, "role": role, "exp": exp}, settings.secret_key, algorithm=settings.algorithm)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
