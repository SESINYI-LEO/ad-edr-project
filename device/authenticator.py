"""Authenticator device (stand-in for the administrator's phone app).

Real deployment: the phone scans the QR code, the OS biometric prompt unlocks a hardware-backed private key, and the
app signs the server challenge. Here the private key is a local Ed25519 key file and the biometric prompt is
simulated by the `biometric_matches` flag, so the server-side protocol (QR nonce -> challenge -> signature) is
exercised exactly as it would be in production. The server stores only the public key.
"""
import base64
import json
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

QR_RE = re.compile(r"^edr://verify\?id=(\d+)&n=([A-Za-z0-9_-]+)$")


class Authenticator:
    def __init__(self, key_path: str | Path):
        self.path = Path(key_path)
        if self.path.exists():
            self.key = serialization.load_pem_private_key(self.path.read_bytes(), password=None)
        else:
            self.key = Ed25519PrivateKey.generate()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_bytes(self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))
            self.path.chmod(0o600)
        self.device_id: int | None = None

    @property
    def public_pem(self) -> str:
        return self.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def sign(self, challenge_msg: bytes) -> str:
        return base64.b64encode(self.key.sign(challenge_msg)).decode()

    @staticmethod
    def parse_qr(payload: str) -> tuple[int, str]:
        m = QR_RE.match(payload or "")
        if not m:
            raise ValueError("Not an EDR verification QR code")
        return int(m.group(1)), m.group(2)

    def respond(self, http, qr_payload: str, biometric_matches: bool = True) -> dict:
        """Scan the QR, run the (simulated) biometric check, and answer the server.

        `http` is any object with post(path, json) -> dict-like response (requests/TestClient style)."""
        ver_id, nonce = self.parse_qr(qr_payload)
        scan = http.post(f"/api/v1/verify/{ver_id}/scan", json={"nonce": nonce, "device_id": self.device_id})
        if scan.status_code != 200:
            return {"ok": False, "stage": "scan", "status": scan.status_code, "detail": scan.json().get("detail")}
        info = scan.json()
        if not biometric_matches:
            r = http.post(f"/api/v1/verify/{ver_id}/reject", json={"device_id": self.device_id})
            return {"ok": False, "stage": "biometric", "status": r.json().get("status")}
        msg = f"EDR-VERIFY|{ver_id}|{info['challenge']}|{info['purpose']}|{info['user_id']}".encode()
        r = http.post(f"/api/v1/verify/{ver_id}/complete", json={"device_id": self.device_id, "signature": self.sign(msg)})
        return {"ok": r.json().get("status") == "verified", "stage": "complete", "status": r.json().get("status")}
