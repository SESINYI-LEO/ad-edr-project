import os
import tempfile

_tmp = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["BACKUP_DIR"] = f"{_tmp}/backups"
os.environ["AGENT_API_KEY"] = "test-agent-key"

import pytest
from fastapi.testclient import TestClient

from app.main import app

AGENT = {"X-Agent-Key": "test-agent-key"}
SID_TSHEPO = "S-1-5-21-1000-2000-3000-1001"  # Domain Admin in the mock directory
SID_KABELO = "S-1-5-21-1000-2000-3000-1003"  # standard user


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


def login(client, user="admin", pw="ChangeMe123!"):
    r = client.post("/api/auth/login", data={"username": user, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="session")
def admin(client):
    return login(client)


@pytest.fixture(scope="session")
def analyst(client):
    return login(client, "analyst")


def verified_tx(client, headers, purpose, credential="demo-fingerprint"):
    """Run the full QR + biometric flow and return the transaction id header."""
    r = client.post("/api/auth/transactions", json={"purpose": purpose}, headers=headers)
    assert r.status_code == 200, r.text
    tx = r.json()
    assert tx["qr_png_base64"] and tx["verify_url"].endswith(tx["id"])
    v = client.post(f"/api/auth/transactions/{tx['id']}/verify", json={"credential": credential})
    assert v.status_code == 200, v.text
    return tx["id"], v.json()["status"]


def send(client, **kw):
    body = {"hostname": "ws014", "event_type": "powershell", "process_name": "powershell.exe", "raw_sid": SID_TSHEPO}
    body.update(kw)
    return client.post("/api/telemetry/events", json=body, headers=AGENT)
