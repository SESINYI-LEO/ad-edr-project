"""Active Directory integration over LDAP/LDAPS (ldap3).

Two modes share the same code path:
  * AD_MODE=ldap  - binds to a real domain controller (use LDAPS in production).
  * AD_MODE=mock  - uses ldap3's in-memory MOCK_SYNC server loaded from lab/lab_directory.json,
                    so the identical search/bind/parsing code runs without a domain controller.
"""
import json
import re
import struct
import threading
from dataclasses import dataclass, field
from datetime import timedelta

from ldap3 import ALL, MOCK_SYNC, Connection, Server, SUBTREE
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from sqlalchemy.orm import Session

from .config import Settings
from .models import ADIdentity, utcnow

ADMIN_GROUPS = {"domain admins", "enterprise admins", "administrators", "schema admins"}
ELEVATED_GROUPS = {"server operators", "account operators", "backup operators", "print operators"}
SYSTEM_ACCOUNTS = {"system", "local service", "network service", "anonymous logon", "window manager",
                   "dwm-1", "dwm-2", "umfd-0", "umfd-1"}
SID_RE = re.compile(r"^S-1-\d+(-\d+)+$")


class DirectoryUnavailable(Exception):
    pass


@dataclass
class IdentityInfo:
    sid: str
    sam: str
    display_name: str | None = None
    department: str | None = None
    groups: list = field(default_factory=list)
    privilege_level: str = "standard"
    enabled: bool = True


def sid_from_bytes(raw: bytes) -> str:
    """Decode a binary objectSid into S-1-... form."""
    rev, count = raw[0], raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    subs = struct.unpack("<" + "I" * count, raw[8:8 + 4 * count])
    return "S-%d-%d-%s" % (rev, authority, "-".join(str(s) for s in subs))


def privilege_from_groups(groups: list[str]) -> str:
    g = {x.lower() for x in groups}
    if g & ADMIN_GROUPS:
        return "admin"
    if g & ELEVATED_GROUPS:
        return "elevated"
    return "standard"


def group_name(dn: str) -> str:
    m = re.match(r"(?i)CN=([^,]+)", dn)
    return m.group(1) if m else dn


def parse_account(user: str | None) -> tuple[str | None, str | None]:
    """'LAB\\jsmith' -> ('LAB','jsmith'); 'jsmith@lab.local' -> ('lab.local','jsmith')."""
    if not user:
        return None, None
    user = user.strip()
    if "\\" in user:
        d, s = user.split("\\", 1)
        return d, s
    if "@" in user:
        s, d = user.split("@", 1)
        return d, s
    return None, user


def is_system_account(domain: str | None, sam: str | None) -> bool:
    if not sam:
        return True
    if sam.endswith("$"):  # machine account
        return True
    if (domain or "").upper() in ("NT AUTHORITY", "NT SERVICE", "FONT DRIVER HOST", "WINDOW MANAGER"):
        return True
    return sam.lower() in SYSTEM_ACCOUNTS


class Directory:
    def __init__(self, settings: Settings):
        self.s = settings
        self._lock = threading.Lock()
        self._conn: Connection | None = None

    def _build_mock(self) -> Connection:
        with open(self.s.lab_directory_file, encoding="utf-8") as fh:
            lab = json.load(fh)
        server = Server("mock-dc")
        conn = Connection(server, user=self.s.ad_bind_dn, password=self.s.ad_bind_password,
                          client_strategy=MOCK_SYNC, raise_exceptions=False)
        conn.strategy.add_entry(self.s.ad_bind_dn, {"userPassword": self.s.ad_bind_password,
                                                    "objectClass": "user", "sAMAccountName": "svc_edr"})
        for u in lab["users"]:
            attrs = {"objectClass": "user", "sAMAccountName": u["sam"], "objectSid": u["sid"],
                     "displayName": u["display_name"], "department": u.get("department", ""),
                     "memberOf": [f"CN={g},CN=Users,{self.s.ad_base_dn}" for g in u.get("groups", [])],
                     "userAccountControl": u.get("uac", 512), "userPassword": u["password"]}
            conn.strategy.add_entry(u["dn"], attrs)
        conn.bind()
        return conn

    def _connect(self) -> Connection:
        if self._conn is not None and self._conn.bound:
            return self._conn
        try:
            if self.s.ad_mode == "mock":
                self._conn = self._build_mock()
            else:
                srv = Server(self.s.ad_server, use_ssl=self.s.ad_use_ssl, get_info=ALL, connect_timeout=5)
                self._conn = Connection(srv, user=self.s.ad_bind_dn, password=self.s.ad_bind_password,
                                        auto_bind=True, receive_timeout=8)
        except (LDAPException, OSError, FileNotFoundError, KeyError) as exc:
            self._conn = None
            raise DirectoryUnavailable(str(exc)) from exc
        return self._conn

    def _to_info(self, entry) -> IdentityInfo:
        a = entry["attributes"]

        def one(v):
            return v[0] if isinstance(v, list) and v else v

        raw_sid = one(a.get("objectSid"))
        sid = sid_from_bytes(raw_sid) if isinstance(raw_sid, (bytes, bytearray)) else str(raw_sid)
        groups = [group_name(x) for x in (a.get("memberOf") or [])]
        uac = one(a.get("userAccountControl")) or 512
        return IdentityInfo(sid=sid, sam=str(one(a.get("sAMAccountName"))),
                            display_name=one(a.get("displayName")) or None,
                            department=one(a.get("department")) or None, groups=groups,
                            privilege_level=privilege_from_groups(groups),
                            enabled=not (int(uac) & 0x2))

    def lookup(self, sam: str | None = None, sid: str | None = None) -> IdentityInfo | None:
        if not sam and not sid:
            return None
        if sid and not SID_RE.match(sid):
            return None
        flt = (f"(&(objectClass=user)(objectSid={sid}))" if sid
               else f"(&(objectClass=user)(sAMAccountName={escape_filter_chars(sam)}))")
        with self._lock:
            try:
                conn = self._connect()
                ok = conn.search(self.s.ad_base_dn, flt, SUBTREE,
                                 attributes=["sAMAccountName", "objectSid", "displayName", "department",
                                             "memberOf", "userAccountControl"])
                if not ok or not conn.response:
                    return None
                entries = [e for e in conn.response if e.get("type") == "searchResEntry"]
                return self._to_info(entries[0]) if entries else None
            except LDAPException as exc:
                self._conn = None
                raise DirectoryUnavailable(str(exc)) from exc

    def authenticate(self, sam: str, password: str) -> bool:
        """Verify a user's AD password with an LDAP bind as that user."""
        if not sam or not password:
            return False
        with self._lock:
            try:
                conn = self._connect()
                conn.search(self.s.ad_base_dn, f"(&(objectClass=user)(sAMAccountName={escape_filter_chars(sam)}))",
                            SUBTREE, attributes=["sAMAccountName"])
                ents = [e for e in (conn.response or []) if e.get("type") == "searchResEntry"]
                if not ents:
                    return False
                dn = ents[0]["dn"]
                if self.s.ad_mode == "mock":
                    test = Connection(conn.server, user=dn, password=password, client_strategy=MOCK_SYNC,
                                      raise_exceptions=False)
                    test.strategy.entries = conn.strategy.entries  # share the in-memory directory
                    return bool(test.bind())
                test = Connection(conn.server, user=dn, password=password, raise_exceptions=False)
                try:
                    return bool(test.bind())
                finally:
                    test.unbind()
            except LDAPException as exc:
                self._conn = None
                raise DirectoryUnavailable(str(exc)) from exc


def resolve_identity(db: Session, directory: Directory, user: str | None, sid: str | None,
                     cache_minutes: int) -> tuple[ADIdentity | None, str]:
    """Attribute an endpoint event to an AD identity.

    Returns (identity, status): resolved | cached | system | unattributed | directory_error.
    """
    domain, sam = parse_account(user)
    if is_system_account(domain, sam) and not sid:
        return None, "system"
    cached = None
    if sid:
        cached = db.query(ADIdentity).filter(ADIdentity.sid == sid).first()
    if cached is None and sam:
        cached = db.query(ADIdentity).filter(ADIdentity.sam_account_name.ilike(sam)).first()
    if cached and utcnow() - cached.last_synced < timedelta(minutes=cache_minutes):
        return cached, "cached"
    try:
        info = directory.lookup(sid=sid) if sid else directory.lookup(sam=sam)
        if info is None and sid and sam:
            info = directory.lookup(sam=sam)
    except DirectoryUnavailable:
        return (cached, "cached") if cached else (None, "directory_error")
    if info is None:
        return None, "unattributed"
    ident = db.query(ADIdentity).filter(ADIdentity.sid == info.sid).first() or ADIdentity(sid=info.sid, sam_account_name=info.sam)
    ident.sam_account_name = info.sam
    ident.display_name = info.display_name
    ident.department = info.department
    ident.groups = info.groups
    ident.privilege_level = info.privilege_level
    ident.enabled = info.enabled
    ident.last_synced = utcnow()
    db.add(ident)
    db.flush()
    return ident, "resolved"
