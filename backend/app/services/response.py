"""EDRSystem::executeResponseAction - preconditions/postconditions from Section 3.7."""
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import AgentCommand, EndpointStatus, Incident, IncidentStatus, Role, SystemUser, utcnow
from app.services import audit, auth_tx

APPROVED_ACTIONS = {
    "isolate_endpoint": "Block the endpoint's network access (except to the EDR server)",
    "kill_process": "Terminate a process on the endpoint (params.pid)",
    "disable_ad_account": "Request disabling of the AD account (recorded for the AD administrator; EDR never writes to AD)",
}


def execute_response_action(db: Session, incident: Incident, user: SystemUser, tx_id, action: str, params: dict, ip=None) -> Incident:
    def deny(code: int, msg: str):
        audit.log(db, user, "response_action_denied", outcome="denied", details=f"incident={incident.id} action={action}: {msg}", ip=ip, commit=True)
        raise HTTPException(code, msg)

    # --- Preconditions ---
    if incident.status != IncidentStatus.INVESTIGATING:
        deny(409, f"Incident must be 'investigating' (is '{incident.status.value}')")
    if user.role != Role.ADMINISTRATOR:
        deny(403, "Only an Administrator may execute response actions")
    if action not in APPROVED_ACTIONS:
        deny(400, f"Action must be one of {sorted(APPROVED_ACTIONS)}")
    if action in ("isolate_endpoint", "kill_process") and not incident.endpoint_id:
        deny(400, "Incident has no affected endpoint")
    if action == "kill_process":
        try:
            params = {"pid": int(params.get("pid"))}
        except (TypeError, ValueError):
            deny(400, "kill_process requires an integer params.pid")
    auth_tx.consume(db, user, tx_id, "response_action", ip)  # QR + biometric, single use

    # --- Postconditions ---
    if action == "isolate_endpoint":
        incident.endpoint.status = EndpointStatus.ISOLATED
        db.add(AgentCommand(endpoint_id=incident.endpoint_id, action=action, params={}))
    elif action == "kill_process":
        db.add(AgentCommand(endpoint_id=incident.endpoint_id, action=action, params=params))
    incident.status = IncidentStatus.CONTAINED
    incident.notes += f"\n[{utcnow():%Y-%m-%d %H:%M} UTC] {user.username} executed '{action}' {params or ''} (biometric verified)"
    audit.log(db, user, f"response_action:{action}", details=f"incident={incident.id} params={params}", ip=ip)
    db.commit()
    return incident
