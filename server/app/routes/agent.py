import hmac
import threading

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit
from ..ad import Directory
from ..config import Settings, get_settings
from ..db import get_db
from ..deps import detector, directory as get_directory
from ..detection import Detector
from ..ingest import process_batch
from ..models import Endpoint, utcnow
from ..security import current_endpoint, new_api_key

router = APIRouter(prefix="/api/v1")
_ingest_lock = threading.Lock()


class RegisterIn(BaseModel):
    hostname: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    ip_address: str | None = Field(default=None, max_length=64)
    os_version: str | None = Field(default=None, max_length=128)
    agent_version: str | None = Field(default=None, max_length=32)
    criticality: int = Field(default=3, ge=1, le=5)


@router.post("/agent/register", status_code=201)
def register(body: RegisterIn, db: Session = Depends(get_db), s: Settings = Depends(get_settings),
             x_enrollment_token: str | None = Header(default=None)):
    if not x_enrollment_token or not hmac.compare_digest(x_enrollment_token, s.enrollment_token):
        audit.write(db, "agent.register", "unknown", None, {"hostname": body.hostname}, "denied")
        db.commit()
        raise HTTPException(401, "Invalid enrollment token")
    key, key_hash = new_api_key()
    ep = db.query(Endpoint).filter(Endpoint.hostname == body.hostname).first()
    if ep:
        ep.api_key_hash = key_hash  # re-enrolment rotates the key
    else:
        ep = Endpoint(hostname=body.hostname, api_key_hash=key_hash)
        db.add(ep)
    ep.ip_address, ep.os_version, ep.agent_version = body.ip_address, body.os_version, body.agent_version
    ep.criticality, ep.last_seen = body.criticality, utcnow()
    db.flush()
    audit.write(db, "agent.register", body.hostname, None, {"endpoint": ep.id})
    db.commit()
    return {"endpoint_id": ep.id, "api_key": key}


@router.post("/agent/heartbeat")
def heartbeat(db: Session = Depends(get_db), ep: Endpoint = Depends(current_endpoint)):
    ep.last_seen = utcnow()
    db.commit()
    return {"status": ep.status, "commands": [{"type": "isolate"}] if ep.status == "isolated" else []}


class IngestIn(BaseModel):
    events: list[dict]


@router.post("/ingest")
def ingest(body: IngestIn, db: Session = Depends(get_db), ep: Endpoint = Depends(current_endpoint),
           s: Settings = Depends(get_settings), det: Detector = Depends(detector),
           directory: Directory = Depends(get_directory)):
    if len(body.events) > s.max_batch:
        raise HTTPException(413, f"Batch too large (max {s.max_batch} events)")
    with _ingest_lock:
        return process_batch(db, ep, body.events, det, directory, s)
