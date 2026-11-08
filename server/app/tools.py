"""Controlled security-tool terminal: an allowlist of read-only functions. No shell, no arbitrary commands."""
import re
import socket

from sqlalchemy.orm import Session

from . import audit
from .ad import Directory, DirectoryUnavailable
from .models import Alert, Endpoint, TelemetryEvent, Ticket

HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
SAM_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class ToolError(Exception):
    pass


def _host(args):
    h = str(args.get("host", ""))
    if not HOST_RE.match(h):
        raise ToolError("invalid host")
    return h


def tcp_check(db, directory, args):
    host = _host(args)
    try:
        port = int(args.get("port"))
    except (TypeError, ValueError):
        raise ToolError("invalid port")
    if not 1 <= port <= 65535:
        raise ToolError("port out of range")
    try:
        with socket.create_connection((host, port), timeout=3):
            return {"host": host, "port": port, "open": True}
    except OSError as exc:
        return {"host": host, "port": port, "open": False, "reason": exc.__class__.__name__}


def dns_resolve(db, directory, args):
    host = _host(args)
    try:
        return {"host": host, "addresses": sorted({i[4][0] for i in socket.getaddrinfo(host, None)})}
    except socket.gaierror:
        return {"host": host, "addresses": []}


def ad_lookup(db, directory: Directory, args):
    sam = str(args.get("sam", ""))
    if not SAM_RE.match(sam):
        raise ToolError("invalid account name")
    try:
        info = directory.lookup(sam=sam)
    except DirectoryUnavailable:
        raise ToolError("directory unavailable")
    return info.__dict__ if info else {"found": False}


def endpoint_status(db: Session, directory, args):
    h = _host(args)
    ep = db.query(Endpoint).filter(Endpoint.hostname.ilike(h)).first()
    if not ep:
        return {"found": False}
    return {"hostname": ep.hostname, "ip": ep.ip_address, "status": ep.status, "criticality": ep.criticality,
            "last_seen": ep.last_seen.isoformat() if ep.last_seen else None}


def audit_verify(db, directory, args):
    return audit.verify_chain(db)


def system_stats(db: Session, directory, args):
    return {"endpoints": db.query(Endpoint).count(), "events": db.query(TelemetryEvent).count(),
            "alerts": db.query(Alert).count(), "tickets": db.query(Ticket).count()}


TOOLS = {
    "tcp_check": (tcp_check, "Check whether a TCP port is reachable (args: host, port)"),
    "dns_resolve": (dns_resolve, "Resolve a hostname (args: host)"),
    "ad_lookup": (ad_lookup, "Look up an Active Directory account (args: sam)"),
    "endpoint_status": (endpoint_status, "Show an endpoint's status (args: host)"),
    "audit_verify": (audit_verify, "Verify the audit-log hash chain"),
    "system_stats": (system_stats, "Row counts for key tables"),
}


def run_tool(db, directory, name: str, args: dict) -> dict:
    if name not in TOOLS:
        raise ToolError("unknown tool")
    if not isinstance(args, dict):
        raise ToolError("args must be an object")
    return TOOLS[name][0](db, directory, args)
