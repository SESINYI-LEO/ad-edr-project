"""Authenticator-app (TOTP, RFC 6238) support. Works with Microsoft Authenticator, Google Authenticator, Authy, 1Password etc.:
they all scan the same otpauth:// QR code. The phone's own fingerprint/face lock protects the app, which is where the
"biometric" part comes from. The server only ever sees a 6-digit code."""
import base64
import hmac
import io
import time

import pyotp
import qrcode

from app.config import settings
from app.models import SystemUser
from app.security import decrypt_text

STEP_SECONDS = 30
WINDOW = 1  # accept the previous/next step too, to tolerate clock drift between the phone and the server


def _now() -> float:  # indirection so tests can move the clock
    return time.time()


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=settings.totp_issuer)


def qr_png_base64(data: str) -> str:
    buf = io.BytesIO()
    qrcode.make(data).save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def secret_of(user: SystemUser) -> str | None:
    return decrypt_text(user.totp_secret_enc)


def is_enrolled(user: SystemUser) -> bool:
    return secret_of(user) is not None


def match_step(secret: str, code: str, last_step: int = 0) -> int | None:
    """Return the 30 s step the code belongs to, or None. A step at or before `last_step` is refused so a code
    (e.g. one read over someone's shoulder) cannot be replayed."""
    digits = "".join(ch for ch in (code or "") if ch.isdigit())  # tolerate "123 456"
    if len(digits) != 6:
        return None
    totp = pyotp.TOTP(secret)
    current = int(_now() // STEP_SECONDS)
    for step in range(current - WINDOW, current + WINDOW + 1):
        if step > last_step and hmac.compare_digest(totp.generate_otp(step), digits):
            return step
    return None
