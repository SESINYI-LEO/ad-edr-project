"""Dashboard data: summary, endpoints, alerts, tickets, rules, events, identities and audit trail."""
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import case, func
from sqlalchemy.orm import Session, joinedload

from .. import audit, biometric
from ..config import Settings, get_settings
from ..db import get_db
from ..deps import detector
from ..detection import Detector
from ..models import (ADIdentity, Alert, AuditLog, DetectionRule, Endpoint, Incident, TelemetryEvent, Ticket, SystemUser, utcnow)
from ..security import admin_only, any_user
from ..serialize import iso, ser_alert, ser_endpoint, ser_event, ser_identity, ser_ticket
from ..tickets import can_transition

router = APIRouter(prefix="/api/v1")
PRIORITY_ORDER = case((Ticket.priority == "Critical", 0), (Ticket.priority == "High", 1),
                      (Ticket.priority == "Medium", 2), else_=3)
SEV_ORDER = ["critical", "high", "medium", "low"]


@router.get("/dashboard/summary")
def summary(db: Session = Depends(get_db), _=Depends(any_user)):
    now = utcnow()
    eps = db.query(Endpoint).all()
    states = {"online": 0, "offline": 0, "isolated": 0}
    from ..serialize import endpoint_state
    for e in eps:
        states[endpoint_state(e)] += 1
    since = now - timedelta(hours=24)
    sev = {s: 0 for s in SEV_ORDER}
    for s, n in db.query(Alert.severity, func.count()).filter(Alert.created_at >= since).group_by(Alert.severity):
        sev[s] = n
    pri = {p: 0 for p in ("Critical", "High", "Medium", "Low")}
    for p, n in db.query(Ticket.priority, func.count()).filter(Ticket.status != "Closed").group_by(Ticket.priority):
        pri[p] = n
    top_hosts = [{"hostname": h, "alerts": n} for h, n in
                 db.query(Endpoint.hostname, func.count(Alert.id)).join(Alert, Alert.endpoint_id == Endpoint.id)
                 .group_by(Endpoint.hostname).order_by(func.count(Alert.id).desc()).limit(5)]
    top_users = [{"user": u, "department": d, "alerts": n} for u, d, n in
                 db.query(ADIdentity.sam_account_name, ADIdentity.department, func.count(Alert.id))
                 .join(Alert, Alert.identity_id == ADIdentity.id)
                 .group_by(ADIdentity.sam_account_name, ADIdentity.department)
                 .order_by(func.count(Alert.id).desc()).limit(5)]
    tactics = [{"tactic": t, "alerts": n} for t, n in
               db.query(DetectionRule.attack_tactic, func.count(Alert.id)).join(Alert, Alert.rule_id == DetectionRule.rule_id)
               .group_by(DetectionRule.attack_tactic).order_by(func.count(Alert.id).desc())]
    total_events = db.query(func.count(TelemetryEvent.id)).scalar()
    attributed = db.query(func.count(TelemetryEvent.id)).filter(TelemetryEvent.identity_id.isnot(None)).scalar()
    recent = db.query(Alert).options(joinedload(Alert.rule), joinedload(Alert.endpoint), joinedload(Alert.identity),
                                     joinedload(Alert.ticket)).order_by(Alert.id.desc()).limit(8).all()
    return {"endpoints": {"total": len(eps), **states}, "alerts_24h": sev, "open_tickets": pri,
            "events_total": total_events, "events_attributed": attributed,
            "open_incidents": db.query(func.count(Incident.id)).filter(Incident.status != "closed").scalar(),
            "top_hosts": top_hosts, "top_users": top_users, "tactics": tactics,
            "recent_alerts": [ser_alert(a) for a in recent]}


@router.get("/endpoints")
def endpoints(db: Session = Depends(get_db), _=Depends(any_user)):
    out = []
    for e in db.query(Endpoint).order_by(Endpoint.hostname):
        d = ser_endpoint(e)
        d["open_alerts"] = db.query(func.count(Alert.id)).filter(Alert.endpoint_id == e.id, Alert.status != "closed").scalar()
        out.append(d)
    return out


@router.get("/endpoints/{ep_id}/events")
def endpoint_events(ep_id: int, limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db), _=Depends(any_user)):
    rows = (db.query(TelemetryEvent).options(joinedload(TelemetryEvent.identity))
            .filter(TelemetryEvent.endpoint_id == ep_id).order_by(TelemetryEvent.timestamp.desc()).limit(limit))
    return [ser_event(e) for e in rows]


@router.get("/alerts")
def alerts(severity: str | None = None, status: str | None = None, limit: int = Query(100, ge=1, le=500),
           db: Session = Depends(get_db), _=Depends(any_user)):
    q = db.query(Alert).options(joinedload(Alert.rule), joinedload(Alert.endpoint), joinedload(Alert.identity),
                                joinedload(Alert.ticket))
    if severity:
        q = q.filter(Alert.severity == severity)
    if status:
        q = q.filter(Alert.status == status)
    return [ser_alert(a) for a in q.order_by(Alert.id.desc()).limit(limit)]


@router.get("/alerts/{alert_id}")
def alert_detail(alert_id: int, db: Session = Depends(get_db), _=Depends(any_user)):
    a = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    return ser_alert(a, detail=True)


@router.post("/alerts/{alert_id}/acknowledge")
def acknowledge(alert_id: int, db: Session = Depends(get_db), user=Depends(any_user)):
    a = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    if a.status == "new":
        a.status = "acknowledged"
        audit.write(db, "alert.acknowledged", user.username, user.id, {"alert": a.id})
        db.commit()
    return ser_alert(a)


@router.get("/tickets")
def tickets(priority: str | None = None, status: str | None = None, limit: int = Query(200, ge=1, le=500),
            db: Session = Depends(get_db), _=Depends(any_user)):
    q = db.query(Ticket).options(joinedload(Ticket.alert).joinedload(Alert.rule), joinedload(Ticket.alert).joinedload(Alert.endpoint),
                                 joinedload(Ticket.alert).joinedload(Alert.identity), joinedload(Ticket.assignee))
    if priority:
        q = q.filter(Ticket.priority == priority)
    if status:
        q = q.filter(Ticket.status == status)
    return [ser_ticket(t) for t in q.order_by(PRIORITY_ORDER, Ticket.priority_score.desc(), Ticket.id).limit(limit)]


class TransitionIn(BaseModel):
    status: str = Field(pattern="^(Assigned|Under Investigation|Resolved|Closed)$")
    assignee_id: int | None = None


@router.post("/tickets/{ticket_id}/transition")
def transition(ticket_id: int, body: TransitionIn, db: Session = Depends(get_db), user=Depends(any_user)):
    t = db.get(Ticket, ticket_id)
    if not t:
        raise HTTPException(404, "Ticket not found")
    if not can_transition(t.status, body.status):
        raise HTTPException(409, f"Cannot move a ticket from '{t.status}' to '{body.status}'")
    if body.status == "Assigned":
        aid = body.assignee_id or user.id
        if not db.get(SystemUser, aid):
            raise HTTPException(422, "Unknown assignee")
        t.assignee_id = aid
    old = t.status
    t.status, t.updated_at = body.status, utcnow()
    if body.status == "Resolved":
        t.resolved_at = utcnow()
    if body.status == "Closed":
        t.alert.status = "closed"
    audit.write(db, "ticket.transition", user.username, user.id, {"ticket": t.id, "from": old, "to": body.status})
    db.commit()
    return ser_ticket(t)


@router.get("/rules")
def rules(db: Session = Depends(get_db), _=Depends(any_user)):
    counts = dict(db.query(Alert.rule_id, func.count()).group_by(Alert.rule_id).all())
    return [{"rule_id": r.rule_id, "name": r.name, "description": r.description, "severity": r.severity,
             "technique": r.attack_technique_id, "tactic": r.attack_tactic, "confidence": r.confidence,
             "enabled": r.enabled, "alerts": counts.get(r.rule_id, 0), "updated_at": iso(r.updated_at)}
            for r in db.query(DetectionRule).order_by(DetectionRule.rule_id)]


class RuleIn(BaseModel):
    enabled: bool
    verification_id: int | None = None


@router.patch("/rules/{rule_id}")
def update_rule(rule_id: str, body: RuleIn, db: Session = Depends(get_db), admin=Depends(admin_only),
                det: Detector = Depends(detector), s: Settings = Depends(get_settings)):
    r = db.get(DetectionRule, rule_id)
    if not r:
        raise HTTPException(404, "Rule not found")
    try:
        biometric.consume(db, admin, body.verification_id, f"rule:{rule_id}:{'enable' if body.enabled else 'disable'}", s)
    except biometric.VerificationError as exc:
        raise HTTPException(exc.code, exc.message)
    r.enabled, r.updated_by, r.updated_at = body.enabled, admin.id, utcnow()
    det.set_enabled(rule_id, body.enabled)
    audit.write(db, "rule.updated", admin.username, admin.id, {"rule": rule_id, "enabled": body.enabled})
    db.commit()
    return {"rule_id": rule_id, "enabled": r.enabled}


@router.get("/identities")
def identities(db: Session = Depends(get_db), _=Depends(any_user)):
    return [ser_identity(i) for i in db.query(ADIdentity).order_by(ADIdentity.sam_account_name)]


@router.get("/audit")
def audit_log(limit: int = Query(100, ge=1, le=500), action: str | None = None, db: Session = Depends(get_db),
              _=Depends(any_user)):
    q = db.query(AuditLog)
    if action:
        q = q.filter(AuditLog.action_type.like(action + "%"))
    return [{"id": a.id, "timestamp": iso(a.timestamp), "actor": a.actor, "action": a.action_type,
             "outcome": a.outcome, "details": a.details, "hash": a.entry_hash[:12]}
            for a in q.order_by(AuditLog.id.desc()).limit(limit)]


@router.get("/audit/verify")
def audit_verify(db: Session = Depends(get_db), _=Depends(any_user)):
    return audit.verify_chain(db)
