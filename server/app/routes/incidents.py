"""Incident management and biometrically protected response actions."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, joinedload

from .. import audit, biometric
from ..config import Settings, get_settings
from ..db import get_db
from ..models import Alert, Endpoint, Incident, ResponseAction, Ticket, utcnow
from ..security import admin_only, any_user
from ..serialize import iso, ser_event, ser_ticket

router = APIRouter(prefix="/api/v1")


def ser_incident(i: Incident, detail: bool = False) -> dict:
    d = {"id": i.id, "title": i.title, "status": i.status, "owner": i.owner.username, "opened_at": iso(i.opened_at),
         "closed_at": iso(i.closed_at), "ticket_count": len(i.tickets), "action_count": len(i.actions)}
    if detail:
        d["notes"] = i.notes
        d["tickets"] = [ser_ticket(t) for t in i.tickets]
        d["actions"] = [{"id": a.id, "action_type": a.action_type, "target": a.target, "requested_at": iso(a.requested_at),
                         "executed_at": iso(a.executed_at), "outcome": a.outcome, "verification_id": a.verification_id}
                        for a in i.actions]
    return d


class IncidentIn(BaseModel):
    ticket_id: int
    title: str | None = Field(default=None, max_length=200)


@router.post("/incidents", status_code=201)
def create_incident(body: IncidentIn, db: Session = Depends(get_db), user=Depends(any_user)):
    t = db.get(Ticket, body.ticket_id)
    if not t:
        raise HTTPException(404, "Ticket not found")
    if t.status != "Under Investigation":
        raise HTTPException(409, "Only a ticket that is 'Under Investigation' can be escalated")
    inc = Incident(title=body.title or t.alert.summary[:200], owner_id=user.id)
    db.add(inc)
    db.flush()
    t.incident_id, t.status, t.updated_at = inc.id, "Escalated", utcnow()
    audit.write(db, "incident.created", user.username, user.id, {"incident": inc.id, "ticket": t.id})
    db.commit()
    return ser_incident(inc, detail=True)


@router.get("/incidents")
def list_incidents(db: Session = Depends(get_db), _=Depends(any_user)):
    return [ser_incident(i) for i in db.query(Incident).options(joinedload(Incident.owner), joinedload(Incident.tickets),
                                                                 joinedload(Incident.actions)).order_by(Incident.id.desc())]


def _get(db, inc_id) -> Incident:
    i = db.get(Incident, inc_id)
    if not i:
        raise HTTPException(404, "Incident not found")
    return i


@router.get("/incidents/{inc_id}")
def get_incident(inc_id: int, db: Session = Depends(get_db), _=Depends(any_user)):
    return ser_incident(_get(db, inc_id), detail=True)


class NoteIn(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


@router.post("/incidents/{inc_id}/notes", status_code=201)
def add_note(inc_id: int, body: NoteIn, db: Session = Depends(get_db), user=Depends(any_user)):
    i = _get(db, inc_id)
    if i.status == "closed":
        raise HTTPException(409, "Incident is closed")
    i.notes = list(i.notes or []) + [{"by": user.username, "at": iso(utcnow()), "text": body.text}]
    audit.write(db, "incident.note", user.username, user.id, {"incident": i.id})
    db.commit()
    return ser_incident(i, detail=True)


class ActionIn(BaseModel):
    action_type: str = Field(pattern="^(isolate_endpoint|release_endpoint|flag_account)$")
    target: str = Field(min_length=1, max_length=128)
    verification_id: int | None = None


@router.post("/incidents/{inc_id}/actions", status_code=201)
def response_action(inc_id: int, body: ActionIn, db: Session = Depends(get_db), admin=Depends(admin_only),
                    s: Settings = Depends(get_settings)):
    i = _get(db, inc_id)
    if i.status == "closed":
        raise HTTPException(409, "Incident is closed")
    ep = None
    if body.action_type in ("isolate_endpoint", "release_endpoint"):
        ep = db.query(Endpoint).filter(Endpoint.hostname == body.target).first()
        if not ep:
            raise HTTPException(404, "Target endpoint not found")
    try:
        ver = biometric.consume(db, admin, body.verification_id, f"response_action:{inc_id}:{body.action_type}", s)
    except biometric.VerificationError as exc:
        raise HTTPException(exc.code, exc.message)
    act = ResponseAction(incident_id=i.id, action_type=body.action_type, target=body.target, requested_by=admin.id,
                         verification_id=ver.id)
    db.add(act)
    if body.action_type == "isolate_endpoint":
        ep.status, act.outcome = "isolated", f"{ep.hostname} network-isolated; agent will enforce on next heartbeat"
        i.status = "contained"
    elif body.action_type == "release_endpoint":
        ep.status, act.outcome = "online", f"{ep.hostname} released from isolation"
    else:
        act.outcome = f"account {body.target} flagged for password reset and review"
    act.executed_at = utcnow()
    i.notes = list(i.notes or []) + [{"by": admin.username, "at": iso(utcnow()),
                                      "text": f"Response action {body.action_type} on {body.target}: {act.outcome} (verification #{ver.id})"}]
    audit.write(db, "response.executed", admin.username, admin.id,
                {"incident": i.id, "action": body.action_type, "target": body.target, "verification": ver.id})
    db.commit()
    return ser_incident(i, detail=True)


@router.post("/incidents/{inc_id}/close")
def close_incident(inc_id: int, db: Session = Depends(get_db), user=Depends(any_user)):
    i = _get(db, inc_id)
    if i.status == "closed":
        raise HTTPException(409, "Incident already closed")
    for t in i.tickets:
        if t.status == "Escalated":
            t.status, t.resolved_at, t.updated_at = "Resolved", utcnow(), utcnow()
    i.status, i.closed_at = "closed", utcnow()
    audit.write(db, "incident.closed", user.username, user.id, {"incident": i.id})
    db.commit()
    return ser_incident(i, detail=True)


@router.get("/incidents/{inc_id}/report")
def report(inc_id: int, db: Session = Depends(get_db), _=Depends(any_user)):
    """Structured incident report: who, what, when, where, with an identity-correlated timeline."""
    i = _get(db, inc_id)
    events, techniques, users, hosts = [], {}, {}, set()
    for t in i.tickets:
        a = t.alert
        techniques[a.rule.attack_technique_id] = {"technique": a.rule.attack_technique_id, "name": a.rule.name,
                                                  "tactic": a.rule.attack_tactic}
        hosts.add(a.endpoint.hostname)
        if a.identity:
            users[a.identity.sam_account_name] = {"user": a.identity.sam_account_name, "name": a.identity.display_name,
                                                  "department": a.identity.department,
                                                  "privilege_level": a.identity.privilege_level, "sid": a.identity.sid}
        for e in a.events:
            ev = ser_event(e)
            ev["hostname"], ev["rule"] = a.endpoint.hostname, a.rule.name
            events.append(ev)
    events.sort(key=lambda e: e["timestamp"])
    return {"incident": ser_incident(i, detail=True), "who": list(users.values()), "where": sorted(hosts),
            "what": list(techniques.values()),
            "when": {"first_event": events[0]["timestamp"] if events else None,
                     "last_event": events[-1]["timestamp"] if events else None, "opened": iso(i.opened_at)},
            "timeline": events}
