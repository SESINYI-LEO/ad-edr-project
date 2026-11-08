"""Active Directory identity enrichment (read-only). Mock directory by default; live LDAPS when AD_ENABLED=true."""
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import ADUser, utcnow

DOMAIN_ADMIN_GROUPS = {"Domain Admins", "Enterprise Admins", "Schema Admins"}
ADMIN_GROUPS = {"Server Admins", "Workstation Admins", "IT Admins"}
ELEVATED_GROUPS = {"Help Desk", "Power Users"}

SID_PREFIX = "S-1-5-21-1000-2000-3000-"
MOCK_DIRECTORY = [
    {"sid": SID_PREFIX + "1001", "username": "tshepo", "department": "IT", "groups": ["Domain Admins", "Domain Users"]},
    {"sid": SID_PREFIX + "1002", "username": "naledi", "department": "Finance", "groups": ["Finance", "Domain Users"]},
    {"sid": SID_PREFIX + "1003", "username": "kabelo", "department": "Operations", "groups": ["Domain Users"]},
    {"sid": SID_PREFIX + "1004", "username": "mpho", "department": "HR", "groups": ["Help Desk", "Domain Users"]},
    {"sid": SID_PREFIX + "1005", "username": "svc_backup", "department": "IT", "groups": ["Server Admins", "Domain Users"]},
]


def classify_privilege(groups: list[str]) -> str:
    g = set(groups)
    if g & DOMAIN_ADMIN_GROUPS:
        return "domain_admin"
    if g & ADMIN_GROUPS:
        return "admin"
    if g & ELEVATED_GROUPS:
        return "elevated"
    return "standard"


def _bare(username: str) -> str:
    return username.split("\\")[-1].split("@")[0].strip().lower()


def _mock_lookup(sid: str | None, username: str | None) -> dict | None:
    for u in MOCK_DIRECTORY:
        if (sid and u["sid"] == sid) or (username and u["username"] == _bare(username)):
            return u
    return None


def _live_lookup(sid: str | None, username: str | None) -> dict | None:
    from ldap3 import ALL, SUBTREE, Connection, Server
    from ldap3.utils.conv import escape_filter_chars

    server = Server(settings.ad_server, get_info=ALL)
    conn = Connection(server, user=settings.ad_bind_dn, password=settings.ad_bind_password, auto_bind=True)
    flt = f"(objectSid={escape_filter_chars(sid)})" if sid else f"(sAMAccountName={escape_filter_chars(_bare(username))})"
    conn.search(settings.ad_base_dn, flt, search_scope=SUBTREE, attributes=["sAMAccountName", "department", "memberOf", "objectSid"])
    if not conn.entries:
        return None
    e = conn.entries[0]
    groups = [str(g).split(",")[0].replace("CN=", "") for g in (e.memberOf.values if e.memberOf else [])]
    return {
        "sid": sid or str(e.objectSid), "username": str(e.sAMAccountName).lower(),
        "department": str(e.department) if e.department else None, "groups": groups,
    }


def resolve_identity(db: Session, sid: str | None, username: str | None) -> ADUser | None:
    """Return the ADUser for a SID/username (cached for 1h), creating it on first sight."""
    if not sid and not username:
        return None
    q = select(ADUser)
    cached = db.scalar(q.where(ADUser.sid == sid)) if sid else db.scalar(q.where(ADUser.username == _bare(username)))
    if cached and cached.last_synced > utcnow() - timedelta(hours=1):
        return cached

    try:
        rec = _live_lookup(sid, username) if settings.ad_enabled else _mock_lookup(sid, username)
    except Exception:
        rec = None  # AD unreachable: degrade gracefully, never block telemetry ingestion
    if rec is None:
        if cached:
            return cached
        rec = {"sid": sid or f"unresolved:{_bare(username)}", "username": _bare(username) if username else "unknown",
               "department": None, "groups": []}

    user = cached or db.scalar(select(ADUser).where(ADUser.sid == rec["sid"]))
    if user is None:
        user = ADUser(sid=rec["sid"])
        db.add(user)
    user.username, user.department, user.groups = rec["username"], rec["department"], rec["groups"]
    user.privilege, user.last_synced = classify_privilege(rec["groups"]), utcnow()
    db.flush()
    return user
