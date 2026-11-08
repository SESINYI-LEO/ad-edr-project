"""Time a verified backup, backup verification and restore against a live server (Recoverability NFR)."""
import json, sys, tempfile, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
import requests
from device.authenticator import Authenticator
base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
s = requests.Session()
tok = s.post(base + "/api/v1/auth/login", json={"username": "admin", "password": "Admin@EDR-2026!"}).json()["access_token"]
s.headers["Authorization"] = "Bearer " + tok
class H:
    def post(self, p, json=None): return requests.post(base + p, json=json)
auth = Authenticator(Path(tempfile.mkdtemp()) / "d.pem")
auth.device_id = s.post(base + "/api/v1/devices", json={"name": "rec", "public_key_pem": auth.public_pem}).json()["id"]
def verified(purpose):
    v = s.post(base + "/api/v1/verify/initiate", json={"purpose": purpose}).json(); assert auth.respond(H(), v["qr_payload"], True)["ok"]; return v["id"]
t = time.perf_counter(); b = s.post(base + "/api/v1/backups", json={"verification_id": verified("backup:create")}); b.raise_for_status(); tb = time.perf_counter() - t
bid = b.json()["id"]
t = time.perf_counter(); v = s.post(f"{base}/api/v1/backups/{bid}/verify"); v.raise_for_status(); tv = time.perf_counter() - t
t = time.perf_counter(); r = s.post(f"{base}/api/v1/backups/{bid}/restore", json={"verification_id": verified(f"backup:restore:{bid}")}); r.raise_for_status(); tr = time.perf_counter() - t
out = {"backup_id": bid, "size_bytes": b.json()["size_bytes"], "backup_s": round(tb, 3), "verify_s": round(tv, 3), "restore_s": round(tr, 3), "verify": v.json(), "restore": r.json(),
       "audit_after_restore": s.get(base + "/api/v1/audit/verify").json()}
Path(ROOT / "results/recovery.json").write_text(json.dumps(out, indent=1)); print(json.dumps(out, indent=1))
