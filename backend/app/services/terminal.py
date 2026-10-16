"""Security terminal: fixed allow-list of read-only diagnostics, strictly validated arguments, never a shell."""
import ipaddress
import re
import subprocess
import sys

HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9-]{1,63})*$")
_win = sys.platform.startswith("win")

TOOLS = {
    "ping": lambda h: ["ping", "-n" if _win else "-c", "4", h],
    "dns_lookup": lambda h: ["nslookup", h],
    "traceroute": lambda h: (["tracert", "-h", "15", h] if _win else ["traceroute", "-m", "15", h]),
}


def validate_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        if HOST_RE.match(host) and len(host) <= 253:
            return host
    raise ValueError("Invalid host or IP address")


def run(tool: str, target: str) -> dict:
    if tool not in TOOLS:
        raise ValueError(f"Tool not permitted. Allowed: {sorted(TOOLS)}")
    argv = TOOLS[tool](validate_host(target))
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=30, shell=False)
        return {"returncode": r.returncode, "stdout": r.stdout[-8000:], "stderr": r.stderr[-2000:]}
    except FileNotFoundError:
        return {"returncode": 127, "stdout": "", "stderr": f"'{argv[0]}' is not installed on the server"}
    except subprocess.TimeoutExpired:
        return {"returncode": 124, "stdout": "", "stderr": "timed out after 30s"}
