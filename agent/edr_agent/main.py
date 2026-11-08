"""EDR endpoint agent entry point.

  python -m edr_agent.main --config agent.json            # Windows: collect Sysmon/Security events
  python -m edr_agent.main --replay events.jsonl          # lab: replay recorded events through the real pipeline
"""
import argparse
import json
import logging
import platform
import subprocess
import time
from datetime import datetime, timezone

from .client import Client, ServerError
from .config import load_config

log = logging.getLogger("edr_agent")


def isolate_host(server_host: str) -> None:
    """Block all traffic except to the EDR server (Windows Firewall)."""
    if platform.system() != "Windows":
        log.warning("ISOLATE command received: would block all traffic except %s (not on Windows)", server_host)
        return
    cmds = [["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"],
            ["netsh", "advfirewall", "firewall", "add", "rule", "name=EDR-Allow-Server", "dir=out", "action=allow",
             f"remoteip={server_host}"]]
    for c in cmds:
        subprocess.run(c, check=False, capture_output=True)
    log.warning("Host isolated; only %s reachable", server_host)


def run(args) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(args.config)
    client = Client(cfg)
    client.ensure_registered()
    if args.replay:
        events = [json.loads(l) for l in open(args.replay) if l.strip()]
        sent = 0
        for i in range(0, len(events), cfg.batch_size):
            chunk = events[i:i + cfg.batch_size]
            if client.send_with_retry(chunk):
                sent += len(chunk)
        log.info("replayed %d/%d events", sent, len(events))
        return 0
    from .collector import WindowsCollector
    col = WindowsCollector(cfg.state_dir)
    last_hb = 0.0
    while True:
        try:
            batch = col.poll()
            for i in range(0, len(batch), cfg.batch_size):
                client.send_with_retry(batch[i:i + cfg.batch_size])
            if time.time() - last_hb >= cfg.heartbeat_seconds:
                hb = client.heartbeat()
                last_hb = time.time()
                if any(c.get("type") == "isolate" for c in hb.get("commands", [])):
                    isolate_host(cfg.server_url.split("//")[-1].split(":")[0])
        except ServerError as e:
            log.error("server error: %s", e)
        time.sleep(cfg.flush_seconds)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config")
    ap.add_argument("--replay")
    raise SystemExit(run(ap.parse_args()))
