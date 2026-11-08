"""Runtime configuration, read from environment variables (see .env.example)."""
import os
import secrets
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

BASE = Path(__file__).resolve().parent


def _bool(v: str) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    database_url: str
    secret_key: str
    enrollment_token: str
    token_minutes: int
    password_iterations: int
    max_failed_logins: int
    lockout_minutes: int
    ad_mode: str            # "mock" (lab directory via ldap3 MOCK_SYNC) or "ldap" (real domain controller)
    ad_server: str
    ad_base_dn: str
    ad_bind_dn: str
    ad_bind_password: str
    ad_use_ssl: bool
    ad_cache_minutes: int
    lab_directory_file: str
    backup_dir: str
    backup_key: str
    verify_ttl_seconds: int
    verify_use_window_seconds: int
    alert_suppress_seconds: int
    rules_file: str
    frontend_dir: str
    max_batch: int


@lru_cache
def get_settings() -> Settings:
    e = os.environ.get
    return Settings(
        database_url=e("DATABASE_URL", "sqlite:///./edr.db"),
        secret_key=e("SECRET_KEY") or secrets.token_urlsafe(48),
        enrollment_token=e("ENROLLMENT_TOKEN", "lab-enrollment-token"),
        token_minutes=int(e("TOKEN_MINUTES", "60")),
        password_iterations=int(e("PASSWORD_ITERATIONS", "240000")),
        max_failed_logins=int(e("MAX_FAILED_LOGINS", "5")),
        lockout_minutes=int(e("LOCKOUT_MINUTES", "5")),
        ad_mode=e("AD_MODE", "mock"),
        ad_server=e("AD_SERVER", "dc01.lab.local"),
        ad_base_dn=e("AD_BASE_DN", "DC=lab,DC=local"),
        ad_bind_dn=e("AD_BIND_DN", "CN=svc_edr,CN=Users,DC=lab,DC=local"),
        ad_bind_password=e("AD_BIND_PASSWORD", "svc-edr-lab-password"),
        ad_use_ssl=_bool(e("AD_USE_SSL", "true")),
        ad_cache_minutes=int(e("AD_CACHE_MINUTES", "30")),
        lab_directory_file=e("LAB_DIRECTORY_FILE", str(BASE.parent.parent / "lab" / "lab_directory.json")),
        backup_dir=e("BACKUP_DIR", "./backups"),
        backup_key=e("BACKUP_KEY", "lab-backup-passphrase-change-me"),
        verify_ttl_seconds=int(e("VERIFY_TTL_SECONDS", "120")),
        verify_use_window_seconds=int(e("VERIFY_USE_WINDOW_SECONDS", "300")),
        alert_suppress_seconds=int(e("ALERT_SUPPRESS_SECONDS", "60")),
        rules_file=e("RULES_FILE", str(BASE / "rules" / "rules.yaml")),
        frontend_dir=e("FRONTEND_DIR", str(BASE.parent.parent / "frontend" / "dist")),
        max_batch=int(e("MAX_BATCH", "500")),
    )


def reset_settings() -> None:
    get_settings.cache_clear()
