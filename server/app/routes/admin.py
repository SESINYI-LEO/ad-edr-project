"""Backup/restore and the controlled security-tool terminal (both protected by biometric verification)."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, backup as bk, biometric, tools
from ..ad import Directory
from ..config import Settings, get_settings
from ..db import get_db
from ..deps import detector, directory as get_directory
from ..detection import Detector
from ..models import Backup, DetectionRule
from ..security import admin_only
from ..serialize import iso

router = APIRouter(prefix="/api/v1")


def ser_backup(b: Backup) -> dict:
    return {"id": b.id, "created_at": iso(b.created_at), "size_bytes": b.size_bytes, "checksum": b.checksum[:16],
            "status": b.status}


class VerIn(BaseModel):
    verification_id: int | None = None


@router.get("/backups")
def list_backups(db: Session = Depends(get_db), _=Depends(admin_only)):
    return [ser_backup(b) for b in db.query(Backup).order_by(Backup.id.desc())]


@router.post("/backups", status_code=201)
def create_backup(body: VerIn, db: Session = Depends(get_db), admin=Depends(admin_only), s: Settings = Depends(get_settings)):
    try:
        biometric.consume(db, admin, body.verification_id, "backup:create", s)
    except biometric.VerificationError as exc:
        raise HTTPException(exc.code, exc.message)
    rec = bk.create_backup(db, admin, s)
    db.commit()
    return ser_backup(rec)


@router.post("/backups/{backup_id}/verify")
def verify_backup(backup_id: int, db: Session = Depends(get_db), admin=Depends(admin_only), s: Settings = Depends(get_settings)):
    rec = db.get(Backup, backup_id)
    if not rec:
        raise HTTPException(404, "Backup not found")
    try:
        res = bk.verify_backup(rec, s)
    except bk.BackupError as exc:
        rec.status = "corrupt"
        audit.write(db, "backup.verify", admin.username, admin.id, {"backup": rec.id, "error": str(exc)}, "failure")
        db.commit()
        raise HTTPException(422, str(exc))
    audit.write(db, "backup.verify", admin.username, admin.id, {"backup": rec.id, **res})
    db.commit()
    return res


@router.post("/backups/{backup_id}/restore")
def restore_backup(backup_id: int, body: VerIn, db: Session = Depends(get_db), admin=Depends(admin_only),
                   s: Settings = Depends(get_settings), det: Detector = Depends(detector)):
    rec = db.get(Backup, backup_id)
    if not rec:
        raise HTTPException(404, "Backup not found")
    try:
        biometric.consume(db, admin, body.verification_id, f"backup:restore:{backup_id}", s)
    except biometric.VerificationError as exc:
        raise HTTPException(exc.code, exc.message)
    try:
        res = bk.restore_backup(db, admin, rec, s)
    except bk.BackupError as exc:
        db.rollback()
        raise HTTPException(422, str(exc))
    for r in db.query(DetectionRule):  # re-sync the live detector with restored rule states
        det.set_enabled(r.rule_id, r.enabled)
    return res


@router.get("/tools")
def list_tools(_=Depends(admin_only)):
    return [{"name": n, "description": d} for n, (_, d) in tools.TOOLS.items()]


class ToolIn(BaseModel):
    name: str = Field(pattern="^[a-z_]{1,32}$")
    args: dict = Field(default_factory=dict)
    verification_id: int | None = None


@router.post("/tools/run")
def run_tool(body: ToolIn, db: Session = Depends(get_db), admin=Depends(admin_only), s: Settings = Depends(get_settings),
             directory: Directory = Depends(get_directory)):
    if body.name not in tools.TOOLS:
        audit.write(db, "tool.run", admin.username, admin.id, {"tool": body.name}, "denied")
        db.commit()
        raise HTTPException(404, "Unknown tool")
    try:
        biometric.consume(db, admin, body.verification_id, f"tool:{body.name}", s)
    except biometric.VerificationError as exc:
        raise HTTPException(exc.code, exc.message)
    try:
        result = tools.run_tool(db, directory, body.name, body.args)
    except tools.ToolError as exc:
        audit.write(db, "tool.run", admin.username, admin.id, {"tool": body.name, "args": body.args, "error": str(exc)}, "failure")
        db.commit()
        raise HTTPException(422, str(exc))
    audit.write(db, "tool.run", admin.username, admin.id, {"tool": body.name, "args": body.args})
    db.commit()
    return {"tool": body.name, "result": result}
