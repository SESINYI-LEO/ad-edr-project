"""HTTP client with API-key auth, retry/backoff and an on-disk spool for offline operation."""
import json
import logging
import socket
import time
import urllib.error
import urllib.request

from .config import AgentConfig, os_version

log = logging.getLogger("edr_agent")
AGENT_VERSION = "1.0.0"


class ServerError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body[:200]}")
        self.status = status


class Client:
    def __init__(self, cfg: AgentConfig):
        self.cfg = cfg
        self.api_key: str | None = None
        cfg.key_file.parent.mkdir(parents=True, exist_ok=True)
        if cfg.key_file.exists():
            self.api_key = json.loads(cfg.key_file.read_text()).get("api_key")

    def _req(self, method: str, path: str, body=None, headers=None, timeout=10):
        data = json.dumps(body).encode() if body is not None else None
        h = {"Content-Type": "application/json", **(headers or {})}
        req = urllib.request.Request(self.cfg.server_url.rstrip("/") + path, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise ServerError(e.code, e.read().decode(errors="replace")) from e

    def register(self) -> None:
        res = self._req("POST", "/api/v1/agent/register",
                        {"hostname": self.cfg.hostname, "ip_address": _ip(), "os_version": os_version(),
                         "agent_version": AGENT_VERSION, "criticality": self.cfg.criticality},
                        {"X-Enrollment-Token": self.cfg.enrollment_token})
        self.api_key = res["api_key"]
        self.cfg.key_file.write_text(json.dumps({"api_key": self.api_key, "endpoint_id": res["endpoint_id"]}))
        self.cfg.key_file.chmod(0o600)

    def ensure_registered(self) -> None:
        if not self.api_key:
            self.register()

    def heartbeat(self) -> dict:
        return self._req("POST", "/api/v1/agent/heartbeat", {}, {"X-API-Key": self.api_key})

    def send(self, events: list[dict]) -> dict:
        return self._req("POST", "/api/v1/ingest", {"events": events}, {"X-API-Key": self.api_key}, timeout=30)

    # -- spool -------------------------------------------------------------------
    def spool(self, events: list[dict]) -> None:
        f = self.cfg.spool_file
        existing = sum(1 for _ in open(f)) if f.exists() else 0
        room = max(0, self.cfg.spool_max_events - existing)
        with open(f, "a") as fh:
            for e in events[:room]:
                fh.write(json.dumps(e) + "\n")
        if len(events) > room:
            log.warning("spool full: dropped %d events", len(events) - room)

    def drain_spool(self) -> int:
        f = self.cfg.spool_file
        if not f.exists():
            return 0
        events = [json.loads(line) for line in open(f) if line.strip()]
        sent = 0
        for i in range(0, len(events), self.cfg.batch_size):
            chunk = events[i:i + self.cfg.batch_size]
            self.send(chunk)  # raises on failure; spool kept until all chunks succeed
            sent += len(chunk)
        f.unlink()
        return sent

    def send_with_retry(self, events: list[dict], attempts: int = 4) -> bool:
        delay = 1.0
        for n in range(attempts):
            try:
                self.drain_spool()
                self.send(events)
                return True
            except ServerError as e:
                if e.status in (400, 401, 403, 413, 422):
                    log.error("permanent send failure: %s", e)
                    return False
            except (urllib.error.URLError, OSError, socket.timeout) as e:
                log.warning("send failed (%s), retry %d/%d", e, n + 1, attempts)
            time.sleep(delay)
            delay = min(delay * 2, 30)
        self.spool(events)
        return False


def _ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
