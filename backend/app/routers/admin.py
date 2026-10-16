import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import admin_only, auth_header, client_ip, current_user
from app.models import AuditEntry, Backup, DetectionRule, Severity
from app.routers.common import audit_out, backup_out, rule_out
from app.schemas import RuleIn, RuleToggle, ToolRun
from app.services import audit, auth_tx, backup as backup_svc, metrics, terminal

router = APIRouter(prefix="/api", tags=["admin"])


# ---- Detection rules (modification needs QR + biometric) ----
@router.get("/rules")
def list_rules(user=Depends(current_user), db: Session = Depends(get_db)):
    return [rule_out(r) for r in db.scalars(select(DetectionRule).order_by(DetectionRule.name))]


@router.post("/rules")
def create_rule(body: RuleIn, user=Depends(admin_only), tx=Depends(auth_header), ip=Depends(client_ip), db: Session = Depends(get_db)):
    if db.scalar(select(DetectionRule).where(DetectionRule.name == body.name)):
        raise HTTPException(409, "A rule with this name already exists")
    auth_tx.consume(db, user, tx, "rule_change", ip)
    r = DetectionRule(**{**body.model_dump(), "severity": Severity(body.severity)})
    db.add(r)
    audit.log(db, user, "rule_created", details=body.name, ip=ip)
    db.commit()
    return rule_out(r)


@router.patch("/rules/{rule_id}")
def toggle_rule(rule_id: str, body: RuleToggle, user=Depends(admin_only), tx=Depends(auth_header), ip=Depends(client_ip), db: Session = Depends(get_db)):
    r = db.get(DetectionRule, uuid.UUID(rule_id))
    if not r:
        raise HTTPException(404, "Rule not found")
    auth_tx.consume(db, user, tx, "rule_change", ip)
    r.enabled = body.enabled
    audit.log(db, user, "rule_toggled", details=f"{r.name} enabled={body.enabled}", ip=ip)
    db.commit()
    return rule_out(r)


# ---- Audit + metrics ----
@router.get("/audit")
def audit_trail(limit: int = 200, user=Depends(current_user), db: Session = Depends(get_db)):
    return [audit_out(a) for a in db.scalars(select(AuditEntry).order_by(AuditEntry.timestamp.desc()).limit(min(limit, 1000)))]


@router.get("/metrics")
def get_metrics(user=Depends(current_user), db: Session = Depends(get_db)):
    return metrics.compute(db)


# ---- Backup & restore ----
@router.get("/backups")
def list_backups(user=Depends(admin_only), db: Session = Depends(get_db)):
    return [backup_out(b) for b in db.scalars(select(Backup).order_by(Backup.created_at.desc()))]


@router.post("/backups")
def create_backup(user=Depends(admin_only), tx=Depends(auth_header), ip=Depends(client_ip), db: Session = Depends(get_db)):
    auth_tx.consume(db, user, tx, "backup_create", ip)
    b = backup_svc.create(db, user)
    audit.log(db, user, "backup_created", details=b.filename, ip=ip)
    db.commit()
    backup_svc.verify(db, b)  # verify immediately: creating a backup is not proof it can be restored
    return backup_out(b)


def _backup(db, backup_id) -> Backup:
    b = db.get(Backup, uuid.UUID(backup_id))
    if not b:
        raise HTTPException(404, "Backup not found")
    return b


@router.post("/backups/{backup_id}/verify")
def verify_backup(backup_id: str, user=Depends(admin_only), db: Session = Depends(get_db)):
    b = _backup(db, backup_id)
    backup_svc.verify(db, b)
    audit.log(db, user, "backup_verified", outcome="success" if b.status.value == "verified" else "failed", details=b.filename, commit=True)
    return backup_out(b)


@router.post("/backups/{backup_id}/restore")
def restore_backup(backup_id: str, user=Depends(admin_only), tx=Depends(auth_header), ip=Depends(client_ip), db: Session = Depends(get_db)):
    b = _backup(db, backup_id)
    auth_tx.consume(db, user, tx, "backup_restore", ip)
    counts = backup_svc.restore(db, b)
    audit.log(db, user, "backup_restored", details=b.filename, ip=ip)
    db.commit()
    return {"restored": counts}


# ---- Security terminal ----
@router.get("/terminal/tools")
def tools(user=Depends(admin_only)):
    return sorted(terminal.TOOLS)


@router.post("/terminal/run")
def run_tool(body: ToolRun, user=Depends(admin_only), tx=Depends(auth_header), ip=Depends(client_ip), db: Session = Depends(get_db)):
    try:
        terminal.validate_host(body.target)
        if body.tool not in terminal.TOOLS:
            raise ValueError(f"Tool not permitted. Allowed: {sorted(terminal.TOOLS)}")
    except ValueError as exc:
        audit.log(db, user, "terminal_rejected", outcome="denied", details=f"{body.tool} {body.target}: {exc}", ip=ip, commit=True)
        raise HTTPException(400, str(exc))
    auth_tx.consume(db, user, tx, "terminal", ip)
    result = terminal.run(body.tool, body.target)
    audit.log(db, user, "terminal_run", details=f"{body.tool} {body.target} rc={result['returncode']}", ip=ip, commit=True)
    return result
