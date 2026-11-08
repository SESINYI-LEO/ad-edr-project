import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import client_ip, current_user
from app.models import (Alert, Incident, IncidentStatus, SystemUser, Ticket, TicketStatus, Severity)
from app.routers.common import alert_out, ticket_out
from app.schemas import AssignIn, TicketTransition
from app.services import audit
from app.services.workflow import move_ticket

router = APIRouter(prefix="/api", tags=["alerts"])


@router.get("/alerts")
def list_alerts(limit: int = 200, user=Depends(current_user), db: Session = Depends(get_db)):
    return [alert_out(a) for a in db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(min(limit, 500)))]


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str, user=Depends(current_user), db: Session = Depends(get_db)):
    a = db.get(Alert, uuid.UUID(alert_id))
    if not a:
        raise HTTPException(404, "Alert not found")
    return alert_out(a, with_events=True)


@router.get("/tickets")
def list_tickets(user=Depends(current_user), db: Session = Depends(get_db)):
    """Queue order: highest priority score first."""
    return [ticket_out(t) for t in db.scalars(select(Ticket).order_by(Ticket.priority_score.desc(), Ticket.created_at.desc()).limit(500))]


def _get_ticket(db, ticket_id):
    t = db.get(Ticket, uuid.UUID(ticket_id))
    if not t:
        raise HTTPException(404, "Ticket not found")
    return t


@router.post("/tickets/{ticket_id}/assign")
def assign(ticket_id: str, body: AssignIn, user=Depends(current_user), db: Session = Depends(get_db)):
    t = _get_ticket(db, ticket_id)
    assignee = db.get(SystemUser, uuid.UUID(body.user_id)) if body.user_id else user
    if not assignee:
        raise HTTPException(404, "User not found")
    t.assigned_to = assignee.id
    t.assignee = assignee
    if t.status == TicketStatus.PRIORITISED:
        move_ticket(t, TicketStatus.UNDER_INVESTIGATION)
    audit.log(db, user, "ticket_assigned", details=f"ticket={t.id} to={assignee.username}")
    db.commit()
    return ticket_out(t)


@router.post("/tickets/{ticket_id}/transition")
def transition(ticket_id: str, body: TicketTransition, user=Depends(current_user), db: Session = Depends(get_db)):
    t = _get_ticket(db, ticket_id)
    move_ticket(t, TicketStatus(body.status))
    audit.log(db, user, "ticket_transition", details=f"ticket={t.id} -> {body.status}")
    db.commit()
    return ticket_out(t)


@router.post("/tickets/{ticket_id}/escalate")
def escalate(ticket_id: str, user=Depends(current_user), db: Session = Depends(get_db)):
    """Under Investigation -> Escalated: opens (or joins) an incident for the same endpoint."""
    t = _get_ticket(db, ticket_id)
    move_ticket(t, TicketStatus.ESCALATED)
    ep_id = t.alert.endpoint_id
    inc = db.scalar(select(Incident).where(Incident.endpoint_id == ep_id, Incident.status.not_in([IncidentStatus.CLOSED, IncidentStatus.RESOLVED])))
    if not inc:
        inc = Incident(title=f"{t.alert.title} on {t.alert.endpoint.hostname}", summary=t.alert.description,
                       endpoint_id=ep_id, opened_by=user.id)
        db.add(inc)
        db.flush()
    t.incident_id = inc.id
    audit.log(db, user, "ticket_escalated", details=f"ticket={t.id} incident={inc.id}")
    db.commit()
    return {"ticket": ticket_out(t), "incident_id": str(inc.id)}
