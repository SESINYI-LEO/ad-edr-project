"""End-to-end evaluation against a LIVE server over HTTP, using the real agent client and the authenticator simulator.

    python simulation/run_eval.py --base http://127.0.0.1:8000 --out results

Measures: detection (TP/FN/FP, precision/recall), identity attribution accuracy, ingest->alert latency (platform MTTD),
scripted response time (platform MTTR: alert -> ticket -> incident -> biometric-verified isolation -> agent sees isolate),
and ingest throughput / batch latency with benign noise. MTTD/MTTR here are *platform latencies* with a scripted analyst,
NOT human response times.
"""
import argparse, csv, json, statistics, sys, tempfile, time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT, ROOT / "agent"):
    sys.path.insert(0, str(p))

import requests  # noqa: E402
from device.authenticator import Authenticator  # noqa: E402
from edr_agent.client import Client  # noqa: E402
from edr_agent.config import AgentConfig  # noqa: E402
from simulation.scenarios import baseline_noise, build  # noqa: E402


class Http:
    """requests wrapper exposing .post(path, json=) the way Authenticator.respond expects."""
    def __init__(self, base): self.base, self.s, self.h = base, requests.Session(), {}
    def post(self, path, json=None): return self.s.post(self.base + path, json=json, headers=self.h)
    def get(self, path): return self.s.get(self.base + path, headers=self.h)


def pct(xs, p):
    xs = sorted(xs); k = (len(xs) - 1) * p / 100; f = int(k); c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000"); ap.add_argument("--out", default="results")
    ap.add_argument("--admin", default="admin:Admin@EDR-2026!"); ap.add_argument("--respond", type=int, default=12,
                    help="how many attack tickets to drive through incident response (rest left open)")
    ap.add_argument("--noise", type=int, default=10000)
    a = ap.parse_args()
    out = Path(a.out); out.mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="edr_eval_"))
    http = Http(a.base)
    u, p = a.admin.split(":", 1)
    r = http.post("/api/v1/auth/login", json={"username": u, "password": p}); r.raise_for_status()
    http.h = {"Authorization": "Bearer " + r.json()["access_token"]}

    # --- enrol the simulated authenticator device
    auth = Authenticator(work / "device.pem")
    r = requests.post(a.base + "/api/v1/devices", json={"name": "eval-device", "public_key_pem": auth.public_pem}, headers=http.h)
    r.raise_for_status(); auth.device_id = r.json()["id"]

    # --- 1. detection run through the REAL agent client (one enrolled endpoint per scenario)
    scen = build(); results = {}
    for sc in scen:
        cfg = AgentConfig(server_url=a.base, hostname=f"WS-{sc['id']}", state_dir=str(work / sc["id"]))
        c = Client(cfg); c.ensure_registered()
        wall = datetime.now(timezone.utc).replace(tzinfo=None)
        t0 = time.perf_counter(); res = c.send(sc["events"]); rtt = (time.perf_counter() - t0) * 1000
        results[sc["id"]] = {"sc": sc, "res": res, "rtt_ms": rtt, "client": c, "sent_at": wall}
    alerts = http.get("/api/v1/alerts?limit=500").json()
    by_host = {}
    for al in alerts: by_host.setdefault(al["hostname"], []).append(al)

    rows = []; tp = fn = fp = tn = 0
    attr_ok = attr_n = 0
    for sc in scen:
        got = {x["rule_id"] for x in by_host.get(f"WS-{sc['id']}", [])}
        exp = set(sc["expected"]); hit = exp <= got and (not exp or True)
        extra = got - exp
        if sc["kind"] == "attack":
            tp += hit; fn += (not hit)
        else:
            fp += bool(got); tn += (not got)
        exp_user = sc["user"].split("\\")[-1]
        for al in by_host.get(f"WS-{sc['id']}", []):
            if sc["kind"] == "attack" and al["rule_id"] in exp:
                attr_n += 1; attr_ok += (al["user"] == exp_user)
        lat = None
        if got & exp:
            first = min((x for x in by_host[f"WS-{sc['id']}"] if x["rule_id"] in exp), key=lambda x: x["created_at"])
            created = datetime.fromisoformat(first["created_at"].rstrip("Z"))
            lat = (created - results[sc["id"]]["sent_at"]).total_seconds() * 1000
        rows.append({"id": sc["id"], "kind": sc["kind"], "name": sc["name"], "technique": sc["technique"],
                     "expected": ",".join(sorted(exp)), "alerted": ",".join(sorted(got)),
                     "result": ("TP" if hit else "FN") if sc["kind"] == "attack" else ("FP" if got else "TN"),
                     "extra_rules": ",".join(sorted(extra)), "ingest_rtt_ms": round(results[sc["id"]]["rtt_ms"], 1),
                     "send_to_alert_ms": round(lat, 1) if lat is not None else ""})
    rtts = [r["ingest_rtt_ms"] for r in rows if r["kind"] == "attack" and r["result"] == "TP"]
    det = {"attacks": tp + fn, "benign": fp + tn, "TP": tp, "FN": fn, "FP": fp, "TN": tn,
           "precision": round(tp / (tp + fp), 4) if tp + fp else None, "recall": round(tp / (tp + fn), 4),
           "false_positive_rate": round(fp / (fp + tn), 4),
           "attribution_correct": attr_ok, "attribution_total": attr_n, "attribution_accuracy": round(attr_ok / attr_n, 4),
           "detect_latency_ms": {"mean": round(statistics.mean(rtts), 1), "median": round(statistics.median(rtts), 1),
                                 "p95": round(pct(rtts, 95), 1), "max": round(max(rtts), 1)}}

    # --- 2. scripted response (platform MTTR): alert -> ticket workflow -> incident -> QR/biometric -> isolation
    tickets = {t["hostname"]: t for t in sorted(http.get("/api/v1/tickets?limit=500").json(), key=lambda t: -t["priority_score"])}
    mttr, driven = [], 0
    for sc in [s for s in scen if s["kind"] == "attack"][: a.respond]:
        host = f"WS-{sc['id']}"; t = next((x for x in http.get("/api/v1/tickets?limit=500").json() if x["hostname"] == host), None)
        if not t: continue
        alert_created = datetime.fromisoformat(next(x for x in by_host[host] if x["id"] == t["alert_id"])["created_at"].rstrip("Z"))
        for st in ("Assigned", "Under Investigation"):
            http.post(f"/api/v1/tickets/{t['id']}/transition", json={"status": st}).raise_for_status()
        inc = http.post("/api/v1/incidents", json={"ticket_id": t["id"]}); inc.raise_for_status(); inc = inc.json()
        v = http.post("/api/v1/verify/initiate", json={"purpose": f"response_action:{inc['id']}:isolate_endpoint"}); v.raise_for_status(); v = v.json()
        resp = auth.respond(http, v["qr_payload"], True); assert resp["ok"], resp
        act = http.post(f"/api/v1/incidents/{inc['id']}/actions", json={"action_type": "isolate_endpoint", "target": host, "verification_id": v["id"]})
        act.raise_for_status()
        hb = results[sc["id"]]["client"].heartbeat()
        enforced = datetime.now(timezone.utc).replace(tzinfo=None)
        assert hb["commands"] and hb["commands"][0]["type"] == "isolate"
        mttr.append((enforced - alert_created).total_seconds()); driven += 1
    resp_stats = {"incidents_driven": driven, "mean_s": round(statistics.mean(mttr), 3), "median_s": round(statistics.median(mttr), 3),
                  "max_s": round(max(mttr), 3)} if mttr else {}

    # --- 3. negative biometric test: wrong fingerprint must not authorise anything
    v = http.post("/api/v1/verify/initiate", json={"purpose": "backup:create"}).json()
    bad = auth.respond(http, v["qr_payload"], False)
    blocked = http.post("/api/v1/backups", json={"verification_id": v["id"]}).status_code
    unverified = http.post("/api/v1/backups", json={}).status_code

    # --- 4. throughput with benign noise (false positives must stay zero)
    cfg = AgentConfig(server_url=a.base, hostname="WS-NOISE", state_dir=str(work / "noise"), criticality=2)
    c = Client(cfg); c.ensure_registered()
    before = len(http.get("/api/v1/alerts?limit=500").json())
    evs = baseline_noise(a.noise, r"LAB\lmokoena"); batches = [evs[i:i + 500] for i in range(0, len(evs), 500)]
    lats, t0 = [], time.perf_counter()
    for b in batches:
        s = time.perf_counter(); c.send(b); lats.append((time.perf_counter() - s) * 1000)
    el = time.perf_counter() - t0
    after = len(http.get("/api/v1/alerts?limit=500").json())
    thr = {"events": len(evs), "batches": len(batches), "batch_size": 500, "seconds": round(el, 2),
           "events_per_second": round(len(evs) / el, 1), "batch_latency_ms": {"median": round(statistics.median(lats), 1),
           "p95": round(pct(lats, 95), 1), "max": round(max(lats), 1)}, "false_alerts_from_noise": after - before}

    audit = http.get("/api/v1/audit/verify").json()
    summary = {"generated": datetime.now(timezone.utc).isoformat(), "detection": det, "response": resp_stats,
               "biometric_negative": {"wrong_fingerprint_result": bad, "action_with_failed_verification_http": blocked,
                                      "action_without_verification_http": unverified},
               "throughput": thr, "audit_chain": audit}
    (out / "eval_results.json").write_text(json.dumps(summary, indent=2))
    with open(out / "scenario_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
