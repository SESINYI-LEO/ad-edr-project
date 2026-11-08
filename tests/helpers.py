import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT, ROOT / "agent"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from device.authenticator import Authenticator  # noqa: E402
from server.app import db as dbm  # noqa: E402
from server.app.config import reset_settings  # noqa: E402
from server.app.main import create_app  # noqa: E402
from server.app.models import Base  # noqa: E402

ADMIN = ("admin", "Admin@EDR-2026!")
ANALYST = ("analyst", "Analyst@EDR-2026!")
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def make_app(tmp_path):
    os.environ.update(PASSWORD_ITERATIONS="1000", BACKUP_DIR=str(tmp_path / "bk"), ALERT_SUPPRESS_SECONDS="60",
                      SECRET_KEY="test-secret-key-test-secret-key-1234", VERIFY_TTL_SECONDS="120", MAX_BATCH="500",
                      AD_MODE="mock", MAX_FAILED_LOGINS="5")
    reset_settings()
    url = os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{tmp_path}/t.db"
    eng = dbm.init_engine(url)
    Base.metadata.drop_all(eng)
    return create_app(url)


def login(client, creds=ADMIN):
    r = client.post("/api/v1/auth/login", json={"username": creds[0], "password": creds[1]})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def register_agent(client, hostname="WS-T01", criticality=3, token="lab-enrollment-token"):
    r = client.post("/api/v1/agent/register", json={"hostname": hostname, "criticality": criticality},
                    headers={"X-Enrollment-Token": token})
    assert r.status_code == 201, r.text
    return {"X-API-Key": r.json()["api_key"]}, r.json()["endpoint_id"]


def now():
    return datetime.now(timezone.utc)


def ev(etype="process_create", user=r"LAB\jsmith", proc=PS, cmd=None, parent=None, ts=None, **details):
    d = {"event_type": etype, "timestamp": (ts or now()).isoformat(), "process_name": proc, "user": user,
         "details": details}
    if cmd is not None:
        d["command_line"] = cmd
    if parent:
        d["parent_process"] = parent
    return d


B64 = "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA=="


def encoded_ps(user=r"LAB\jsmith", ts=None):
    return ev(cmd=f"powershell.exe -enc {B64}", user=user, ts=ts)


def ingest(client, key, events):
    r = client.post("/api/v1/ingest", json={"events": events}, headers=key)
    return r


def enroll(client, h, tmp_path, name="test-phone"):
    auth = Authenticator(tmp_path / f"{name}.pem")
    r = client.post("/api/v1/devices", json={"name": name, "public_key_pem": auth.public_pem}, headers=h)
    assert r.status_code == 201, r.text
    auth.device_id = r.json()["id"]
    return auth


def verification(client, h, auth, purpose, match=True):
    r = client.post("/api/v1/verify/initiate", json={"purpose": purpose}, headers=h)
    assert r.status_code == 201, r.text
    body = r.json()
    res = auth.respond(client, body["qr_payload"], biometric_matches=match)
    return body["id"], res


def make_incident(client, h, key, user=r"LAB\jsmith", hostname="WS-T01"):
    """Raise an alert, walk its ticket to 'Under Investigation' and escalate it. Returns incident json."""
    r = ingest(client, key, [encoded_ps(user)])
    assert r.status_code == 200 and r.json()["alerts_created"] == 1, r.text
    t = client.get("/api/v1/tickets", headers=h).json()[0]
    for st in ("Assigned", "Under Investigation"):
        assert client.post(f"/api/v1/tickets/{t['id']}/transition", json={"status": st}, headers=h).status_code == 200
    inc = client.post("/api/v1/incidents", json={"ticket_id": t["id"]}, headers=h)
    assert inc.status_code == 201, inc.text
    return inc.json()
