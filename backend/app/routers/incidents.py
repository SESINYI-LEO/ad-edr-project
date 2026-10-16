import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import admin_only, auth_header, client_ip, current_user
from app.models import AgentCommand, Endpoint, EndpointStatus, Incident, IncidentStatus, TicketStatus, utcnow
from app.routers.common import endpoint_out, incident_out
from app.schemas import IncidentCreate, IncidentUpdate, ResponseIn
from app.services import audit, auth_tx, reports
from app.services.response import APPROVED_ACTIONS, execute_response_action
from app.services.workflow import move_incident, move_ticket

router = APIRouter(prefix="/api", tags=["incidents"])


def _get(db, incident_id) -> Incident:
    try:
        i = db.get(Incident, uuid.UUID(incident_id))
    except ValueError:
        i = None
    if not i:
        raise HTTPException(404, "Incident not found")
    return i


@router.get("/incidents")
def list_incidents(user=Depends(current_user), db: Session = Depends(get_db)):
    return [incident_out(i) for i in db.scalars(select(Incident).order_by(Incident.created_at.desc()))]


@router.post("/incidents")
def create_incident(body: IncidentCreate, user=Depends(current_user), db: Session = Depends(get_db)):
    ep = db.get(Endpoint, uuid.UUID(body.endpoint_id)) if body.endpoint_id else None
    i = Incident(title=body.title, summary=body.summary, endpoint_id=ep.id if ep else None, opened_by=user.id)
    db.add(i)
    audit.log(db, user, "incident_created", details=f"incident={i.id} {body.title}")
    db.commit()
    return incident_out(i, detail=True)


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, user=Depends(current_user), db: Session = Depends(get_db)):
    return incident_out(_get(db, incident_id), detail=True)


@router.patch("/incidents/{incident_id}")
def update_incident(incident_id: str, body: IncidentUpdate, user=Depends(current_user), db: Session = Depends(get_db)):
    i = _get(db, incident_id)
    if body.notes is not None:
        i.notes = (i.notes + "\n" if i.notes else "") + f"[{utcnow():%Y-%m-%d %H:%M} UTC] {user.username}: {body.notes}"
    if body.assigned_to:
        i.assigned_to = uuid.UUID(body.assigned_to)
    if body.status:
        new = IncidentStatus(body.status)
        move_incident(i, new, has_report=bool(i.reports))
        if new == IncidentStatus.INVESTIGATING and not i.assigned_to:
            i.assigned_to = user.id
        if new == IncidentStatus.CLOSED:
            i.closed_at = utcnow()
            for t in i.tickets:  # Fig 8(a): escalated ticket becomes Resolved when its incident closes
                if t.status == TicketStatus.ESCALATED:
                    move_ticket(t, TicketStatus.RESOLVED)
        audit.log(db, user, "incident_status", details=f"incident={i.id} -> {new.value}")
    db.commit()
    return incident_out(i, detail=True)


@router.get("/response-actions")
def response_actions(user=Depends(current_user)):
    return APPROVED_ACTIONS


@router.post("/incidents/{incident_id}/response")
def response(incident_id: str, body: ResponseIn, user=Depends(current_user), tx=Depends(auth_header),
             ip=Depends(client_ip), db: Session = Depends(get_db)):
    i = _get(db, incident_id)
    return incident_out(execute_response_action(db, i, user, tx, body.action, body.params, ip), detail=True)


@router.post("/incidents/{incident_id}/report")
def make_report(incident_id: str, user=Depends(current_user), db: Session = Depends(get_db)):
    i = _get(db, incident_id)
    r = reports.build_report(db, i, user)
    db.add(r)
    audit.log(db, user, "report_generated", details=f"incident={i.id}")
    db.commit()
    return {"id": str(r.id), "content": r.content}


@router.post("/endpoints/{endpoint_id}/release")
def release_endpoint(endpoint_id: str, user=Depends(admin_only), tx=Depends(auth_header), ip=Depends(client_ip), db: Session = Depends(get_db)):
    ep = db.get(Endpoint, uuid.UUID(endpoint_id))
    if not ep:
        raise HTTPException(404, "Endpoint not found")
    auth_tx.consume(db, user, tx, "release_endpoint", ip)
    ep.status = EndpointStatus.ONLINE
    db.add(AgentCommand(endpoint_id=ep.id, action="release_endpoint", params={}))
    audit.log(db, user, "endpoint_released", details=f"endpoint={ep.hostname}", ip=ip)
    db.commit()
    return endpoint_out(ep)
