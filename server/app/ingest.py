"""Telemetry ingestion: validate -> normalise -> de-duplicate -> store -> enrich with AD identity -> detect -> alert/ticket."""
import hashlib
import json
import ntpath
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .ad import Directory, resolve_identity
from .config import Settings
from .detection import Detection, Detector
from .models import (ADIdentity, Alert, Endpoint, TelemetryEvent, Ticket, alert_events, utcnow)
from .tickets import compute_priority

EventType = Literal["process_create", "process_access", "file_create", "file_modify", "file_rename", "file_delete",
                    "registry_set", "network_connect", "logon_success", "logon_failure", "powershell_script",
                    "service_install"]
MAX_FUTURE = timedelta(minutes=5)
MAX_AGE = timedelta(days=30)
SID_PATTERN = r"^S-1-\d+(-\d+)+$"
KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")


class IncomingEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_type: EventType
    timestamp: datetime
    process_name: str | None = Field(default=None, max_length=260)
    parent_process: str | None = Field(default=None, max_length=260)
    command_line: str | None = None
    user: str | None = Field(default=None, max_length=256)
    user_sid: str | None = Field(default=None, pattern=SID_PATTERN)
    details: dict[str, str | int | float | bool | None] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _ts(cls, v: datetime) -> datetime:
        if v.tzinfo is not None:
            v = v.astimezone(timezone.utc).replace(tzinfo=None)
        now = utcnow()
        if v > now + MAX_FUTURE:
            raise ValueError("timestamp is in the future")
        if v < now - MAX_AGE:
            raise ValueError("timestamp is too old")
        return v

    @field_validator("command_line")
    @classmethod
    def _cmd(cls, v):
        return v[:8192] if v else v

    @field_validator("details")
    @classmethod
    def _details(cls, v):
        if len(v) > 32:
            raise ValueError("too many detail fields")
        for k, val in v.items():
            if not KEY_RE.match(k):
                raise ValueError(f"bad detail key {k!r}")
            if isinstance(val, str) and len(val) > 2048:
                raise ValueError(f"detail {k} too long")
        return v


def basename(path: str | None) -> str | None:
    if not path:
        return None
    return ntpath.basename(path.replace("/", "\\")).lower() or None


def fingerprint(endpoint_id: int, ev: IncomingEvent) -> str:
    body = json.dumps([endpoint_id, ev.event_type, ev.timestamp.isoformat(), basename(ev.process_name),
                       ev.command_line, ev.user, ev.details], sort_keys=True, default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def engine_view(ev: IncomingEvent, row_id: int, endpoint_id: int) -> dict:
    d: dict[str, Any] = dict(ev.details)
    if "file_ext" not in d and isinstance(d.get("file_path"), str):
        d["file_ext"] = os.path.splitext(ntpath.basename(d["file_path"].replace("/", "\\")).lower())[1]
    if isinstance(d.get("target_process"), str):
        d["target_process"] = basename(d["target_process"])
    d.update({"_id": row_id, "timestamp": ev.timestamp, "endpoint_id": endpoint_id, "event_type": ev.event_type,
              "process_name": basename(ev.process_name), "parent_process": basename(ev.parent_process),
              "command_line": ev.command_line, "user": (ev.user or "").lower() or None})
    return d


def process_batch(db: Session, endpoint: Endpoint, raw_events: list, detector: Detector, directory: Directory,
                  settings: Settings) -> dict:
    result = {"accepted": 0, "duplicates": 0, "rejected": 0, "alerts_created": 0, "alerts_updated": 0, "errors": []}
    valid: list[tuple[IncomingEvent, str]] = []
    for i, raw in enumerate(raw_events):
        try:
            ev = IncomingEvent.model_validate(raw)
        except ValidationError as exc:
            result["rejected"] += 1
            if len(result["errors"]) < 10:
                e = exc.errors()[0]
                result["errors"].append({"index": i, "field": ".".join(str(x) for x in e["loc"]), "error": e["msg"]})
            continue
        valid.append((ev, fingerprint(endpoint.id, ev)))

    existing = set()
    if valid:
        fps = [fp for _, fp in valid]
        for chunk in range(0, len(fps), 500):
            existing |= set(db.scalars(select(TelemetryEvent.fingerprint).where(
                TelemetryEvent.fingerprint.in_(fps[chunk:chunk + 500]))))
    seen: set[str] = set()
    cache: dict = {}
    rows: list[tuple[TelemetryEvent, IncomingEvent]] = []
    for ev, fp in sorted(valid, key=lambda x: x[0].timestamp):
        if fp in existing or fp in seen:
            result["duplicates"] += 1
            continue
        seen.add(fp)
        key = (ev.user, ev.user_sid)
        if key not in cache:
            cache[key] = resolve_identity(db, directory, ev.user, ev.user_sid, settings.ad_cache_minutes)
        ident, status = cache[key]
        row = TelemetryEvent(endpoint_id=endpoint.id, identity_id=ident.id if ident else None,
                             event_type=ev.event_type, timestamp=ev.timestamp,
                             process_name=basename(ev.process_name), parent_process=basename(ev.parent_process),
                             command_line=ev.command_line, user_name=ev.user, details=ev.details,
                             fingerprint=fp, attribution=status)
        db.add(row)
        rows.append((row, ev))
    db.flush()
    result["accepted"] = len(rows)

    for row, ev in rows:
        for det in detector.evaluate(engine_view(ev, row.id, endpoint.id)):
            created = _raise_alert(db, det, endpoint, row, settings)
            result["alerts_created" if created else "alerts_updated"] += 1
    endpoint.last_seen = utcnow()
    db.commit()
    return result


def _raise_alert(db: Session, det: Detection, endpoint: Endpoint, row: TelemetryEvent, settings: Settings) -> bool:
    """Create an alert + ticket, or merge into a recent identical alert (suppression). Returns True if new."""
    rule = det.rule
    now = utcnow()
    since = now - timedelta(seconds=settings.alert_suppress_seconds)
    dup = (db.query(Alert).filter(Alert.rule_id == rule.id, Alert.endpoint_id == endpoint.id,
                                  Alert.user_name == row.user_name, Alert.status != "closed",
                                  Alert.created_at >= since).order_by(Alert.id.desc()).first())
    if dup:
        have = {r[0] for r in db.execute(select(alert_events.c.event_id).where(alert_events.c.alert_id == dup.id))}
        add = [i for i in det.event_ids if i not in have]
        for i in add:
            db.execute(alert_events.insert().values(alert_id=dup.id, event_id=i))
        dup.event_count += len(add)
        return False

    ident = db.get(ADIdentity, row.identity_id) if row.identity_id else None
    others = db.query(Alert.rule_id).filter(Alert.endpoint_id == endpoint.id, Alert.rule_id != rule.id,
                                            Alert.created_at >= now - timedelta(minutes=10)).distinct().count()
    confidence = min(100, rule.confidence + min(others, 2) * 10)
    who = ident.sam_account_name if ident else (row.user_name or "unknown user")
    alert = Alert(rule_id=rule.id, endpoint_id=endpoint.id, identity_id=row.identity_id, user_name=row.user_name,
                  severity=rule.severity, confidence=confidence,
                  summary=f"{rule.name} on {endpoint.hostname} by {who}"[:400], event_count=len(det.event_ids),
                  first_event_time=det.first_time, created_at=now)
    db.add(alert)
    db.flush()
    for i in det.event_ids:
        db.execute(alert_events.insert().values(alert_id=alert.id, event_id=i))
    score, label = compute_priority(rule.severity, confidence, endpoint.criticality,
                                    ident.privilege_level if ident else None)
    db.add(Ticket(alert_id=alert.id, priority=label, priority_score=score, status="New",
                  created_at=now, updated_at=now))
    audit.write(db, "detection.alert", "system", None,
                {"alert_id": alert.id, "rule": rule.id, "technique": rule.technique, "endpoint": endpoint.hostname,
                 "priority": label})
    return True
