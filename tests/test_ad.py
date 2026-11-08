"""Active Directory module: SID decoding, group->privilege mapping, account parsing, LDAP lookups, identity cache."""
import struct

import pytest

from server.app import ad
from server.app.config import get_settings
from server.app.models import ADIdentity


def _sid_bytes(auth: int, subs: list[int]) -> bytes:
    return bytes([1, len(subs)]) + auth.to_bytes(6, "big") + b"".join(struct.pack("<I", s) for s in subs)


def test_sid_from_bytes_decodes_binary_object_sid():
    raw = _sid_bytes(5, [21, 1004336348, 1177238915, 682003330, 1105])
    assert ad.sid_from_bytes(raw) == "S-1-5-21-1004336348-1177238915-682003330-1105"
    assert ad.sid_from_bytes(_sid_bytes(5, [18])) == "S-1-5-18"


@pytest.mark.parametrize("groups,level", [
    (["Domain Users"], "standard"), ([], "standard"), (["Domain Users", "Domain Admins"], "admin"),
    (["domain admins"], "admin"), (["Backup Operators"], "elevated"), (["Server Operators", "Domain Users"], "elevated"),
    (["Domain Admins", "Backup Operators"], "admin"), (["Marketing"], "standard")])
def test_privilege_from_groups(groups, level):
    assert ad.privilege_from_groups(groups) == level


@pytest.mark.parametrize("raw,expected", [
    (r"LAB\jsmith", ("LAB", "jsmith")), ("jsmith@lab.local", ("lab.local", "jsmith")), ("jsmith", (None, "jsmith")),
    ("  LAB\\jsmith ", ("LAB", "jsmith")), (None, (None, None)), ("", (None, None))])
def test_parse_account(raw, expected):
    assert ad.parse_account(raw) == expected


@pytest.mark.parametrize("dom,sam,sys", [
    ("NT AUTHORITY", "SYSTEM", True), (None, "LOCAL SERVICE", True), ("LAB", "WS-01$", True), ("LAB", "jsmith", False),
    (None, None, True), ("NT SERVICE", "TrustedInstaller", True)])
def test_is_system_account(dom, sam, sys):
    assert ad.is_system_account(dom, sam) is sys


@pytest.fixture
def directory():
    return ad.Directory(get_settings())


def test_lookup_by_account_returns_identity(directory):
    i = directory.lookup(sam="jsmith")
    assert (i.department, i.privilege_level, i.groups) == ("Finance", "standard", ["Domain Users"])
    assert i.sid.startswith("S-1-5-21-") and i.enabled


def test_lookup_by_sid_matches_account_lookup(directory):
    a = directory.lookup(sam="tkgosi")
    b = directory.lookup(sid=a.sid)
    assert b.sam == "tkgosi" and b.privilege_level == "admin"


def test_disabled_account_is_flagged(directory):
    assert directory.lookup(sam="odisabled").enabled is False


@pytest.mark.parametrize("bad", ["nobody", "", "*", "x)(objectClass=*", "jsmith)(|(sAMAccountName=*"])
def test_lookup_unknown_or_injection_returns_none(directory, bad):
    assert directory.lookup(sam=bad) is None  # filter characters are escaped, never interpreted


def test_lookup_rejects_malformed_sid(directory):
    assert directory.lookup(sid="S-1-5-21-1)(cn=*") is None


def test_authenticate_binds_as_user(directory):
    assert directory.authenticate("jsmith", "Fin@nce-2026") is True
    assert directory.authenticate("jsmith", "wrong") is False
    assert directory.authenticate("ghost", "x") is False
    assert directory.authenticate("jsmith", "") is False


def test_resolve_identity_resolved_then_cached(db, directory):
    i1, s1 = ad.resolve_identity(db, directory, r"LAB\jsmith", None, 30)
    i2, s2 = ad.resolve_identity(db, directory, r"LAB\jsmith", None, 30)
    assert (s1, s2) == ("resolved", "cached") and i1.id == i2.id
    assert db.query(ADIdentity).count() == 1


def test_resolve_identity_system_unknown_and_sid_paths(db, directory):
    assert ad.resolve_identity(db, directory, r"NT AUTHORITY\SYSTEM", None, 30) == (None, "system")
    assert ad.resolve_identity(db, directory, r"LAB\nobody", None, 30) == (None, "unattributed")
    real = directory.lookup(sam="mdlamini")
    i, s = ad.resolve_identity(db, directory, None, real.sid, 30)
    assert s == "resolved" and i.sam_account_name == "mdlamini"


def test_directory_outage_falls_back_to_cache_or_marks_error(db, directory, monkeypatch):
    ad.resolve_identity(db, directory, r"LAB\jsmith", None, 30)
    monkeypatch.setattr(ad.Directory, "lookup", lambda *a, **k: (_ for _ in ()).throw(ad.DirectoryUnavailable("down")))
    i, s = ad.resolve_identity(db, directory, r"LAB\jsmith", None, 0)  # cache expired but DC down -> use stale cache
    assert s == "cached" and i.sam_account_name == "jsmith"
    assert ad.resolve_identity(db, directory, r"LAB\kmotsumi", None, 30) == (None, "directory_error")
