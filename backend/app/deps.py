import secrets
import uuid
from datetime import timezone

from fastapi import Depends, Header, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import Role, SystemUser
from app.security import decode_access_token

oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def current_user_any(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> SystemUser:
    """Authenticated user, even if they still owe a password change (used by /me and the change-password endpoint)."""
    err = HTTPException(401, "Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = decode_access_token(token)
    except JWTError:
        raise err
    username = claims.get("sub")
    user = db.scalar(select(SystemUser).where(SystemUser.username == username)) if username else None
    if not user or not user.is_active:
        raise err
    if user.password_changed_at:  # a password change/reset logs out every older session
        changed = user.password_changed_at.replace(tzinfo=timezone.utc).timestamp()
        if float(claims.get("iat", 0)) < changed:
            raise err
    return user


def current_user(user: SystemUser = Depends(current_user_any)) -> SystemUser:
    if user.must_change_password:
        raise HTTPException(403, "Password change required")
    return user


def require_roles(*roles: Role):
    def dep(user: SystemUser = Depends(current_user)) -> SystemUser:
        if user.role not in roles:
            raise HTTPException(403, "Insufficient privileges")
        return user
    return dep


admin_only = require_roles(Role.ADMINISTRATOR)


def agent_key(x_agent_key: str = Header(default="")):
    if not secrets.compare_digest(x_agent_key.encode(), settings.agent_api_key.encode()):
        raise HTTPException(401, "Invalid agent key")


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def auth_header(x_auth_transaction: str | None = Header(default=None)):
    """Raw transaction id from the QR + biometric flow; validated by services.auth_tx.consume()."""
    if not x_auth_transaction:
        return None
    try:
        return uuid.UUID(x_auth_transaction)
    except ValueError:
        return None
