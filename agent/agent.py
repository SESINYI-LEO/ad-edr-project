#!/usr/bin/env python3
"""
EDR endpoint agent.

  --mode simulate   Generates benign activity (and, with --attack, a scripted chain of *simulated* suspicious events as plain
                    telemetry strings; nothing malicious is executed). Runs anywhere.
  --mode sysmon     Windows only. Reads real Sysmon events (process create, network, file create, registry set) via wevtutil.

In both modes the agent also polls the server for approved response actions (isolate / release / kill process).
Destructive actions only execute on Windows with --enforce; otherwise they are logged as dry-runs.
"""
import argparse
import os
import random
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
IS_WINDOWS = sys.platform.startswith("win")

# SIDs known to the built-in mock AD directory (backend/app/services/ad.py)
SIDS = {"tshepo": "S-1-5-21-1000-2000-3000-1001", "naledi": "S-1-5-21-1000-2000-3000-1002",
        "kabelo": "S-1-5-21-1000-2000-3000-1003", "mpho": "S-1-5-21-1000-2000-3000-1004"}
BENIGN = [("explorer.exe", "explorer.exe"), ("chrome.exe", "chrome.exe --profile-directory=Default"),
          ("notepad.exe", "notepad.exe report.txt"), ("powershell.exe", "powershell.exe Get-Process"), ("excel.exe", "excel.exe budget.xlsx")]


def now():
    return datetime.now(timezone.utc).isoformat()


class Client:
    def __init__(self, server, key, hostname):
        self.server, self.hostname = server.rstrip("/"), hostname
        self.s = requests.Session()
        self.s.headers["X-Agent-Key"] = key

    def send(self, event):
        event = {"hostname": self.hostname, "os_version": sys.platform, "timestamp": now(), **event}
        try:
            r = self.s.post(f"{self.server}/api/telemetry/events", json=event, timeout=10)
            r.raise_for_status()
            j = r.json()
            flag = f"  -> {len(j['alerts'])} alert(s)" if j["alerts"] else ""
            print(f"[{event['event_type']:10}] {event.get('command_line') or event.get('registry_key') or event.get('file_path') or event.get('remote_address') or ''}"[:140] + flag)
        except requests.RequestException as exc:
            print(f"[agent] send failed: {exc}", file=sys.stderr)

    def poll_commands(self, enforce):
        try:
            cmds = self.s.get(f"{self.server}/api/agent/commands", params={"hostname": self.hostname}, timeout=10).json()
        except (requests.RequestException, ValueError):
            return
        for c in cmds if isinstance(cmds, list) else []:
            status, result = run_command(c["action"], c.get("params", {}), self.server, enforce)
            try:
                self.s.post(f"{self.server}/api/agent/commands/{c['id']}/result", json={"status": status, "result": result}, timeout=10)
            except requests.RequestException:
                pass


def _sh(args):
    r = subprocess.run(args, capture_output=True, text=True, timeout=30)
    return r.returncode == 0, (r.stdout + r.stderr).strip()[-400:]


def run_command(action, params, server, enforce):
    live = IS_WINDOWS and enforce
    print(f"[response] {action} {params} ({'ENFORCING' if live else 'dry-run'})")
    if not live:
        return "done", "dry-run: not enforced on this host"
    if action == "kill_process":
        pid = int(params["pid"])
        ok, out = _sh(["taskkill", "/PID", str(pid), "/F"])
        return ("done" if ok else "failed"), out
    if action == "isolate_endpoint":
        ip = socket.gethostbyname(urlparse(server).hostname)
        steps = [["netsh", "advfirewall", "firewall", "add", "rule", "name=EDR-ALLOW-SERVER", "dir=out", "action=allow", f"remoteip={ip}"],
                 ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"]]
    elif action == "release_endpoint":
        steps = [["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"],
                 ["netsh", "advfirewall", "firewall", "delete", "rule", "name=EDR-ALLOW-SERVER"]]
    else:
        return "failed", f"unsupported action {action}"
    for s in steps:
        ok, out = _sh(s)
        if not ok:
            return "failed", out
    return "done", "ok"


# ---------------- simulate mode ----------------
def benign_event():
    name, cmd = random.choice(BENIGN)
    return {"event_type": "powershell" if "powershell" in name else "process", "process_name": name, "command_line": cmd,
            "process_id": random.randint(1000, 9000), "parent_process": "explorer.exe", "raw_sid": random.choice(list(SIDS.values()))}


def attack_chain(user):
    """A scripted sequence of SIMULATED suspicious telemetry for demos/evaluation (MTTD/MTTR). Nothing is executed."""
    sid = SIDS[user]
    yield {"event_type": "powershell", "process_name": "powershell.exe", "process_id": 4820, "parent_process": "winword.exe", "raw_sid": sid,
           "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA=="}
    yield {"event_type": "process", "process_name": "procdump.exe", "process_id": 5120, "parent_process": "powershell.exe", "raw_sid": sid,
           "command_line": "procdump.exe -ma lsass.exe lsass.dmp"}
    yield {"event_type": "registry", "process_name": "reg.exe", "raw_sid": sid,
           "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"}
    yield {"event_type": "network", "process_name": "powershell.exe", "remote_address": "203.0.113.50", "remote_port": 4444, "raw_sid": sid}
    for i in range(6):
        yield {"event_type": "auth", "process_name": "winlogon.exe", "command_line": "logon_failed", "raw_sid": SIDS["kabelo"], "raw_payload": {"n": i}}
        time.sleep(0.2)


def run_simulate(c, a):
    if a.attack:
        for ev in attack_chain(a.attack_user):
            c.send(ev)
            time.sleep(0.5)
        c.poll_commands(a.enforce)
        return
    sent = 0
    while a.count == 0 or sent < a.count:
        c.send(benign_event())
        c.poll_commands(a.enforce)
        sent += 1
        time.sleep(a.interval)


# ---------------- sysmon mode ----------------
def parse_sysmon(xml_text):
    """Convert Sysmon <Event> XML (as returned by wevtutil) into backend event dicts. Pure function, unit-testable anywhere."""
    out = []
    root = ET.fromstring(f"<Events>{xml_text}</Events>")
    for ev in root.findall("e:Event", NS):
        sysel = ev.find("e:System", NS)
        eid = int(sysel.find("e:EventID", NS).text)
        rec = int(sysel.find("e:EventRecordID", NS).text)
        t = sysel.find("e:TimeCreated", NS).get("SystemTime")
        d = {x.get("Name"): (x.text or "") for x in ev.findall("e:EventData/e:Data", NS)}
        image = d.get("Image", "")
        base = {"timestamp": t, "process_name": os.path.basename(image.replace("\\", "/")) or None, "raw_username": d.get("User"), "_rec": rec}
        if eid == 1:
            ps = base["process_name"] and base["process_name"].lower() in ("powershell.exe", "pwsh.exe")
            out.append({**base, "event_type": "powershell" if ps else "process", "command_line": d.get("CommandLine"),
                        "process_id": int(d["ProcessId"]) if d.get("ProcessId", "").isdigit() else None,
                        "parent_process": os.path.basename(d.get("ParentImage", "").replace("\\", "/")) or None})
        elif eid == 3:
            out.append({**base, "event_type": "network", "remote_address": d.get("DestinationIp"),
                        "remote_port": int(d["DestinationPort"]) if d.get("DestinationPort", "").isdigit() else None})
        elif eid == 11:
            out.append({**base, "event_type": "file", "file_path": d.get("TargetFilename")})
        elif eid in (12, 13, 14):
            out.append({**base, "event_type": "registry", "registry_key": d.get("TargetObject")})
        else:
            out.append({**base, "_skip": True})
    return out


def _wevtutil(query, count, reverse=False):
    cmd = ["wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational", f"/q:{query}", "/f:xml", f"/c:{count}", f"/rd:{'true' if reverse else 'false'}"]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout


def run_sysmon(c, a):
    if not IS_WINDOWS:
        sys.exit("sysmon mode only works on Windows with Sysmon installed (use --mode simulate elsewhere)")
    last = 0
    latest = parse_sysmon(_wevtutil("*", 1, reverse=True))
    if latest:
        last = latest[0]["_rec"]  # start from "now"; don't replay history
    print(f"[agent] reading Sysmon from record {last}")
    while True:
        for ev in parse_sysmon(_wevtutil(f"*[System[(EventRecordID>{last})]]", 200)):
            last = max(last, ev.pop("_rec"))
            if not ev.pop("_skip", False):
                c.send(ev)
        c.poll_commands(a.enforce)
        time.sleep(a.interval)


def main():
    p = argparse.ArgumentParser(description="EDR endpoint agent")
    p.add_argument("--server", default=os.getenv("EDR_SERVER", "http://localhost:8000"))
    p.add_argument("--key", default=os.getenv("EDR_AGENT_KEY", "agent-dev-key-change-me"))
    p.add_argument("--hostname", default=socket.gethostname())
    p.add_argument("--mode", choices=["simulate", "sysmon"], default="simulate")
    p.add_argument("--interval", type=float, default=5.0)
    p.add_argument("--count", type=int, default=0, help="simulate mode: stop after N events (0 = forever)")
    p.add_argument("--attack", action="store_true", help="simulate mode: send the scripted suspicious-activity chain once, then exit")
    p.add_argument("--attack-user", default="tshepo", choices=list(SIDS))
    p.add_argument("--enforce", action="store_true", help="actually execute response actions on this Windows host (needs Administrator)")
    a = p.parse_args()
    c = Client(a.server, a.key, a.hostname)
    print(f"[agent] {a.hostname} -> {a.server} mode={a.mode}")
    (run_sysmon if a.mode == "sysmon" else run_simulate)(c, a)


if __name__ == "__main__":
    main()
