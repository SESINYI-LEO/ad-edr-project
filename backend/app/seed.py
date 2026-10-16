"""Idempotent first-run seed: admin + analyst accounts and the starter detection rules."""
from sqlalchemy import select

from app.config import settings
from app.database import SessionLocal
from app.models import DetectionRule, Role, Severity, SystemUser
from app.security import hash_secret

RULES = [
    dict(name="Suspicious encoded PowerShell command", event_type="powershell", severity=Severity.HIGH, mitre_technique="T1059.001",
         description="PowerShell run with an encoded or download-and-execute command line.",
         logic={"all": [{"field": "event_type", "op": "eq", "value": "powershell"},
                        {"field": "command_line", "op": "contains_any", "value": ["-enc", "-encodedcommand", "downloadstring", "iex(", "iex ("]}]}),
    dict(name="Domain admin running PowerShell", event_type="powershell", severity=Severity.CRITICAL, mitre_technique="T1059.001",
         description="A Domain Admin identity launched PowerShell, which warrants extra scrutiny.",
         logic={"all": [{"field": "event_type", "op": "eq", "value": "powershell"}, {"field": "ad_privilege", "op": "eq", "value": "domain_admin"}]}),
    dict(name="Credential store access attempt", event_type="process", severity=Severity.CRITICAL, mitre_technique="T1003",
         description="Process command line references LSASS or well-known credential dumping tooling.",
         logic={"all": [{"field": "event_type", "op": "eq", "value": "process"},
                        {"field": "command_line", "op": "contains_any", "value": ["lsass", "sekurlsa", "procdump", "comsvcs.dll"]}]}),
    dict(name="Registry Run-key persistence", event_type="registry", severity=Severity.HIGH, mitre_technique="T1547.001",
         description="A value was written to an autorun registry key.",
         logic={"all": [{"field": "event_type", "op": "eq", "value": "registry"},
                        {"field": "registry_key", "op": "contains_any", "value": ["\\CurrentVersion\\Run\\", "\\CurrentVersion\\RunOnce\\"]}]}),
    dict(name="Outbound connection on uncommon port", event_type="network", severity=Severity.MEDIUM, mitre_technique="T1571",
         description="A process connected out on a port commonly used for command-and-control.",
         logic={"all": [{"field": "event_type", "op": "eq", "value": "network"}, {"field": "remote_port", "op": "in", "value": [4444, 1337, 6667, 31337]}]}),
    dict(name="Repeated failed logons (possible brute force)", event_type="auth", severity=Severity.HIGH, mitre_technique="T1110",
         description="Five or more failed logons on one endpoint within two minutes.", threshold_count=5, window_seconds=120,
         logic={"all": [{"field": "event_type", "op": "eq", "value": "auth"}, {"field": "command_line", "op": "contains", "value": "logon_failed"}]}),
]


def seed():
    db = SessionLocal()
    try:
        if not db.scalar(select(SystemUser).where(SystemUser.username == "admin")):
            db.add(SystemUser(username="admin", email="admin@edr.local", hashed_password=hash_secret(settings.admin_password),
                              role=Role.ADMINISTRATOR, biometric_template_hash=hash_secret(settings.demo_biometric_secret)))
        if not db.scalar(select(SystemUser).where(SystemUser.username == "analyst")):
            db.add(SystemUser(username="analyst", email="analyst@edr.local", hashed_password=hash_secret(settings.admin_password),
                              role=Role.ANALYST, biometric_template_hash=hash_secret(settings.demo_biometric_secret)))
        for r in RULES:
            if not db.scalar(select(DetectionRule).where(DetectionRule.name == r["name"])):
                db.add(DetectionRule(**r))
        db.commit()
    finally:
        db.close()
