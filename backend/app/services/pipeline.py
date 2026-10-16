"""Telemetry ingestion: validate -> dedupe -> AD enrichment -> detect -> alert -> prioritised ticket (Fig 3 / Fig 6)."""
import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (Alert, DetectionRule, Endpoint, EndpointStatus, TelemetryEvent, Ticket, TicketStatus, utcnow)
from app.services import ad
from app.services.detection import event_view, rule_matches, threshold_met
from app.services.scoring import calculate_priority


def _naive_utc(ts: datetime | None) -> datetime:
    if ts is None:
        return utcnow()
    return ts.astimezone(timezone.utc).replace(tzinfo=None) if ts.tzinfo else ts


def get_or_create_endpoint(db: Session, hostname: str, ip: str | None = None, os_version: str | None = None) -> Endpoint:
    ep = db.scalar(select(Endpoint).where(Endpoint.hostname == hostname))
    if ep is None:
        ep = Endpoint(hostname=hostname)
        db.add(ep)
        db.flush()
    ep.last_seen = utcnow()
    if ep.status == EndpointStatus.OFFLINE:
        ep.status = EndpointStatus.ONLINE
    ep.ip_address = ip or ep.ip_address
    ep.os_version = os_version or ep.os_version
    return ep


def ingest(db: Session, p) -> tuple[TelemetryEvent, list[Alert], bool]:
    """Returns (event, new_alerts, is_duplicate)."""
    ep = get_or_create_endpoint(db, p.hostname, p.ip_address, p.os_version)
    ts = _naive_utc(p.timestamp)
    key = "|".join(str(x) for x in (p.hostname, p.event_type, ts.isoformat(), p.process_name, p.process_id, p.command_line,
                                    p.file_path, p.registry_key, p.remote_address, p.remote_port, p.raw_username, p.raw_sid))
    digest = hashlib.sha256(key.encode()).hexdigest()
    dup = db.scalar(select(TelemetryEvent).where(TelemetryEvent.dedupe_hash == digest))
    if dup:
        return dup, [], True

    user = ad.resolve_identity(db, p.raw_sid, p.raw_username)
    event = TelemetryEvent(
        endpoint_id=ep.id, ad_user_id=user.id if user else None, event_type=p.event_type, timestamp=ts,
        process_name=p.process_name, process_id=p.process_id, command_line=p.command_line, parent_process=p.parent_process,
        file_path=p.file_path, registry_key=p.registry_key, remote_address=p.remote_address, remote_port=p.remote_port,
        raw_username=p.raw_username, raw_sid=p.raw_sid, dedupe_hash=digest, raw_payload=p.raw_payload)
    db.add(event)
    db.flush()
    event.ad_user = user

    view = event_view(event)
    alerts: list[Alert] = []
    for rule in db.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True), DetectionRule.event_type == p.event_type)):
        if not rule_matches(rule, view) or not threshold_met(db, rule, event):
            continue
        if rule.threshold_count > 1:  # cooldown so one burst raises one alert, not one per extra event
            cool = utcnow() - timedelta(seconds=max(rule.window_seconds, 1))
            if db.scalar(select(func.count(Alert.id)).where(Alert.rule_id == rule.id, Alert.endpoint_id == ep.id, Alert.created_at >= cool)):
                continue
        alerts.append(_raise_alert(db, rule, ep, event, user))
    db.commit()
    return event, alerts, False


def _raise_alert(db: Session, rule: DetectionRule, ep: Endpoint, event: TelemetryEvent, user) -> Alert:
    alert = Alert(rule_id=rule.id, endpoint_id=ep.id, title=rule.name, description=rule.description, severity=rule.severity,
                  mitre_technique=rule.mitre_technique, confidence=rule.confidence, events=[event])
    db.add(alert)
    db.flush()
    recent = db.scalar(select(func.count(Alert.id)).where(Alert.endpoint_id == ep.id, Alert.created_at >= utcnow() - timedelta(hours=1))) or 0
    score, band = calculate_priority(rule.severity, user.privilege if user else None, ep.criticality, rule.confidence, recent)
    db.add(Ticket(alert_id=alert.id, priority_score=score, priority=band, status=TicketStatus.PRIORITISED))
    return alert
