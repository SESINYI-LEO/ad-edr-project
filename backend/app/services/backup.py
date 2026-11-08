"""Backup & restore: DB-agnostic logical export, Fernet-encrypted, SHA-256 integrity, verify-before-restore."""
import base64
import gzip
import hashlib
import json
import uuid
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException
from sqlalchemy import DateTime, Uuid, delete, insert, select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import Base
from app.models import Backup, BackupStatus, utcnow

# users, audit trail, auth transactions and backup metadata are deliberately outside the restore scope
EXCLUDED = {"users", "audit_entries", "auth_transactions", "backups"}


def _tables():
    return [t for t in Base.metadata.sorted_tables if t.name not in EXCLUDED]


def _fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(("backup:" + settings.secret_key).encode()).digest()))


def _enc(v):
    if isinstance(v, datetime):
        return {"__dt__": v.isoformat()}
    if isinstance(v, uuid.UUID):
        return str(v)
    if hasattr(v, "value") and hasattr(v, "name"):
        return v.value
    return v


def create(db: Session, user) -> Backup:
    payload = {"version": 1, "created_at": utcnow().isoformat(), "tables": {}}
    for t in _tables():
        payload["tables"][t.name] = [{k: _enc(v) for k, v in row.items()} for row in db.execute(select(t)).mappings()]
    blob = _fernet().encrypt(gzip.compress(json.dumps(payload).encode()))
    Path(settings.backup_dir).mkdir(parents=True, exist_ok=True)
    name = f"edr_backup_{utcnow():%Y%m%d_%H%M%S}_{uuid.uuid4().hex[:6]}.edrbak"
    (Path(settings.backup_dir) / name).write_bytes(blob)
    b = Backup(created_by=user.id, filename=name, size_bytes=len(blob), sha256=hashlib.sha256(blob).hexdigest())
    db.add(b)
    db.flush()
    return b


def _load(b: Backup) -> dict:
    path = Path(settings.backup_dir) / b.filename
    if not path.exists():
        raise ValueError("backup file missing")
    blob = path.read_bytes()
    if hashlib.sha256(blob).hexdigest() != b.sha256:
        raise ValueError("checksum mismatch")
    try:
        return json.loads(gzip.decompress(_fernet().decrypt(blob)))
    except (InvalidToken, OSError, json.JSONDecodeError):
        raise ValueError("cannot decrypt or parse backup")


def verify(db: Session, b: Backup) -> bool:
    try:
        _load(b)
        b.status = BackupStatus.VERIFIED
    except ValueError:
        b.status = BackupStatus.CORRUPT
    db.commit()
    return b.status == BackupStatus.VERIFIED


def _dec(col, v):
    if v is None:
        return None
    if isinstance(v, dict) and "__dt__" in v:
        return datetime.fromisoformat(v["__dt__"])
    if isinstance(col.type, Uuid) and isinstance(v, str):
        return uuid.UUID(v)
    if isinstance(col.type, DateTime) and isinstance(v, str):
        return datetime.fromisoformat(v)
    return v


def restore(db: Session, b: Backup) -> dict:
    try:
        data = _load(b)  # integrity verified before anything is touched
    except ValueError as exc:
        b.status = BackupStatus.CORRUPT
        db.commit()
        raise HTTPException(422, f"Backup failed verification, nothing restored: {exc}")
    tables = _tables()
    for t in reversed(tables):
        db.execute(delete(t))
    counts = {}
    for t in tables:
        rows = data["tables"].get(t.name, [])
        for row in rows:
            db.execute(insert(t).values({k: _dec(t.c[k], v) for k, v in row.items() if k in t.c}))
        counts[t.name] = len(rows)
    return counts
