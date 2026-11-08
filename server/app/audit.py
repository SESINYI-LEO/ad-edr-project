"""Append-only audit trail. Each entry hashes the previous one, so tampering is detectable."""
import hashlib
import json
import threading

from sqlalchemy import text
from sqlalchemy.orm import Session

from .models import AuditLog, utcnow

GENESIS = "0" * 64
_lock = threading.Lock()


def _digest(prev: str, ts, user_id, actor, action, details, outcome) -> str:
    body = json.dumps({"ts": ts.isoformat(), "uid": user_id, "actor": actor, "action": action,
                       "details": details, "outcome": outcome, "prev": prev},
                      sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def write(db: Session, action: str, actor: str, user_id: int | None = None,
          details: dict | None = None, outcome: str = "success") -> AuditLog:
    """Add an audit entry to the current transaction (caller commits)."""
    details = details or {}
    with _lock:
        if db.bind.dialect.name == "postgresql":
            db.execute(text("SELECT pg_advisory_xact_lock(7001)"))
        last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
        prev = last.entry_hash if last else GENESIS
        ts = utcnow()
        entry = AuditLog(timestamp=ts, user_id=user_id, actor=actor, action_type=action, details=details,
                         outcome=outcome, prev_hash=prev,
                         entry_hash=_digest(prev, ts, user_id, actor, action, details, outcome))
        db.add(entry)
        db.flush()
    return entry


def verify_chain(db: Session) -> dict:
    prev = GENESIS
    n = 0
    for e in db.query(AuditLog).order_by(AuditLog.id):
        n += 1
        expect = _digest(prev, e.timestamp, e.user_id, e.actor, e.action_type, e.details, e.outcome)
        if e.prev_hash != prev or e.entry_hash != expect:
            return {"ok": False, "checked": n, "broken_at": e.id}
        prev = e.entry_hash
    return {"ok": True, "checked": n, "broken_at": None}
