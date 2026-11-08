import json
import os
import platform
import socket
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AgentConfig:
    server_url: str = "http://127.0.0.1:8000"
    enrollment_token: str = "lab-enrollment-token"
    hostname: str = socket.gethostname()
    criticality: int = 3
    state_dir: str = "./agent_state"
    batch_size: int = 100
    flush_seconds: float = 5.0
    heartbeat_seconds: float = 30.0
    spool_max_events: int = 50000
    verify_tls: bool = True

    @property
    def key_file(self) -> Path:
        return Path(self.state_dir) / "api_key.json"

    @property
    def spool_file(self) -> Path:
        return Path(self.state_dir) / "spool.jsonl"


def load_config(path: str | None) -> AgentConfig:
    cfg = AgentConfig()
    if path and os.path.exists(path):
        for k, v in json.load(open(path)).items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
    for env, attr in (("EDR_SERVER", "server_url"), ("EDR_ENROLLMENT_TOKEN", "enrollment_token"), ("EDR_HOSTNAME", "hostname")):
        if os.environ.get(env):
            setattr(cfg, attr, os.environ[env])
    return cfg


def os_version() -> str:
    return f"{platform.system()} {platform.release()} {platform.version()}"[:128]
