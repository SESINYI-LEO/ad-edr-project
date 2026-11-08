import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import agent_key, current_user
from app.models import AgentCommand, Endpoint
from app.routers.common import endpoint_out, event_out
from app.schemas import CommandResult, EventIn
from app.models import TelemetryEvent
from app.services import pipeline

router = APIRouter(prefix="/api", tags=["telemetry"])


@router.post("/telemetry/events", dependencies=[Depends(agent_key)])
def ingest(body: EventIn, db: Session = Depends(get_db)):
    event, alerts, dup = pipeline.ingest(db, body)
    return {"event_id": str(event.id), "duplicate": dup, "alerts": [str(a.id) for a in alerts]}


@router.get("/events")
def list_events(limit: int = 100, hostname: str | None = None, user=Depends(current_user), db: Session = Depends(get_db)):
    q = select(TelemetryEvent).order_by(TelemetryEvent.timestamp.desc()).limit(min(limit, 500))
    if hostname:
        q = q.join(Endpoint).where(Endpoint.hostname == hostname)
    return [event_out(e) for e in db.scalars(q)]


@router.get("/endpoints")
def list_endpoints(user=Depends(current_user), db: Session = Depends(get_db)):
    return [endpoint_out(e) for e in db.scalars(select(Endpoint).order_by(Endpoint.hostname))]


@router.get("/agent/commands", dependencies=[Depends(agent_key)])
def pending_commands(hostname: str, db: Session = Depends(get_db)):
    ep = db.scalar(select(Endpoint).where(Endpoint.hostname == hostname))
    if not ep:
        return []
    cmds = db.scalars(select(AgentCommand).where(AgentCommand.endpoint_id == ep.id, AgentCommand.status == "pending"))
    return [{"id": str(c.id), "action": c.action, "params": c.params} for c in cmds]


@router.post("/agent/commands/{cmd_id}/result", dependencies=[Depends(agent_key)])
def command_result(cmd_id: str, body: CommandResult, db: Session = Depends(get_db)):
    cmd = db.get(AgentCommand, uuid.UUID(cmd_id))
    if not cmd:
        raise HTTPException(404, "Unknown command")
    cmd.status, cmd.result = body.status, body.result
    db.commit()
    return {"ok": True}
