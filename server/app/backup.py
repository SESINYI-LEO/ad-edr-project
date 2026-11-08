"""Encrypted, checksummed backup and verified restore of the EDR database."""
import base64
import gzip
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import DateTime, text
from sqlalchemy.orm import Session

from . import audit
from .config import Settings
from .models import Backup, Base, utcnow

MAGIC = b"EDRBK1"
EXCLUDE = {"backups"}


class BackupError(Exception):
    pass


def _tables():
    return [t for t in Base.metadata.sorted_tables if t.name not in EXCLUDE]


def _fernet(passphrase: str, salt: bytes) -> Fernet:
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 200_000, dklen=32)
    return Fernet(base64.urlsafe_b64encode(key))


def _enc(v):
    return v.isoformat() if isinstance(v, datetime) else v


def create_backup(db: Session, user, s: Settings) -> Backup:
    data, counts = {}, {}
    for t in _tables():
        rows = [{k: _enc(v) for k, v in r._mapping.items()} for r in db.execute(t.select())]
        data[t.name], counts[t.name] = rows, len(rows)
    payload = gzip.compress(json.dumps({"version": 1, "created_at": utcnow().isoformat(), "row_counts": counts,
                                        "tables": data}, default=str).encode())
    salt = os.urandom(16)
    blob = MAGIC + salt + _fernet(s.backup_key, salt).encrypt(payload)
    Path(s.backup_dir).mkdir(parents=True, exist_ok=True)
    path = Path(s.backup_dir) / f"edr-backup-{utcnow().strftime('%Y%m%d-%H%M%S-%f')}.bin"
    path.write_bytes(blob)
    rec = Backup(created_by=user.id, location=str(path), checksum=hashlib.sha256(blob).hexdigest(),
                 size_bytes=len(blob), status="complete")
    db.add(rec)
    db.flush()
    audit.write(db, "backup.created", user.username, user.id, {"backup": rec.id, "bytes": len(blob), "rows": sum(counts.values())})
    return rec


def _load(rec: Backup, s: Settings) -> dict:
    path = Path(rec.location)
    if not path.exists():
        raise BackupError("Backup file is missing")
    blob = path.read_bytes()
    if hashlib.sha256(blob).hexdigest() != rec.checksum:
        raise BackupError("Checksum mismatch: backup file has been modified or corrupted")
    if not blob.startswith(MAGIC):
        raise BackupError("Not an EDR backup file")
    salt, token = blob[len(MAGIC):len(MAGIC) + 16], blob[len(MAGIC) + 16:]
    try:
        return json.loads(gzip.decompress(_fernet(s.backup_key, salt).decrypt(token)))
    except (InvalidToken, OSError, ValueError) as exc:
        raise BackupError("Backup could not be decrypted (wrong key or corrupted file)") from exc


def verify_backup(rec: Backup, s: Settings) -> dict:
    d = _load(rec, s)
    return {"ok": True, "tables": len(d["tables"]), "rows": sum(d["row_counts"].values()), "created_at": d["created_at"]}


def restore_backup(db: Session, user, rec: Backup, s: Settings) -> dict:
    try:
        d = _load(rec, s)
    except BackupError:
        rec.status = "corrupt"
        db.commit()
        raise
    tables = _tables()
    rec_id = rec.id
    db.flush()  # persist pending ORM changes (e.g. the consumed verification) before bulk replacing the tables
    for t in reversed(tables):
        db.execute(t.delete())
    for t in tables:
        rows = d["tables"].get(t.name, [])
        dtcols = {c.name for c in t.columns if isinstance(c.type, DateTime)}
        fixed = [{k: (datetime.fromisoformat(v) if k in dtcols and v is not None else v) for k, v in r.items()} for r in rows]
        for i in range(0, len(fixed), 1000):
            db.execute(t.insert(), fixed[i:i + 1000])
    db.expunge_all()  # the ORM identity map is stale after a bulk restore
    if db.bind.dialect.name == "postgresql":
        for t in tables:
            if "id" in t.c and t.c.id.primary_key:
                db.execute(text(f"SELECT setval(pg_get_serial_sequence('{t.name}','id'), COALESCE(MAX(id),1), MAX(id) IS NOT NULL) FROM {t.name}"))
    for t in tables:
        n = db.execute(text(f"SELECT COUNT(*) FROM {t.name}")).scalar()
        if n != d["row_counts"].get(t.name, 0):
            db.rollback()
            raise BackupError(f"Integrity check failed for table {t.name}")
    chain = audit.verify_chain(db)
    if not chain["ok"]:
        db.rollback()
        raise BackupError("Integrity check failed: audit chain broken after restore")
    audit.write(db, "backup.restored", user.username, user.id, {"backup": rec_id, "rows": sum(d["row_counts"].values())})
    db.query(Backup).filter(Backup.id == rec_id).update({"status": "restored"})
    db.commit()
    return {"restored_rows": sum(d["row_counts"].values()), "audit_chain_ok": True}
