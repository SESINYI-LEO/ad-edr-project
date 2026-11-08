from datetime import datetime

from .models import Alert, Endpoint, Ticket, TelemetryEvent, ADIdentity, utcnow

ONLINE_SECONDS = 120


def iso(d: datetime | None):
    return d.isoformat() + "Z" if d else None


def endpoint_state(ep: Endpoint) -> str:
    if ep.status == "isolated":
        return "isolated"
    if ep.last_seen and (utcnow() - ep.last_seen).total_seconds() <= ONLINE_SECONDS:
        return "online"
    return "offline"


def ser_endpoint(ep: Endpoint) -> dict:
    return {"id": ep.id, "hostname": ep.hostname, "ip_address": ep.ip_address, "os_version": ep.os_version,
            "agent_version": ep.agent_version, "criticality": ep.criticality, "state": endpoint_state(ep),
            "last_seen": iso(ep.last_seen), "registered_at": iso(ep.registered_at)}


def ser_identity(i: ADIdentity | None) -> dict | None:
    if not i:
        return None
    return {"id": i.id, "sid": i.sid, "sam_account_name": i.sam_account_name, "display_name": i.display_name,
            "department": i.department, "groups": i.groups, "privilege_level": i.privilege_level, "enabled": i.enabled}


def ser_event(e: TelemetryEvent) -> dict:
    return {"id": e.id, "endpoint_id": e.endpoint_id, "event_type": e.event_type, "timestamp": iso(e.timestamp),
            "process_name": e.process_name, "parent_process": e.parent_process, "command_line": e.command_line,
            "user_name": e.user_name, "details": e.details, "attribution": e.attribution,
            "identity": ser_identity(e.identity)}


def ser_alert(a: Alert, detail: bool = False) -> dict:
    d = {"id": a.id, "rule_id": a.rule_id, "rule_name": a.rule.name, "technique": a.rule.attack_technique_id,
         "tactic": a.rule.attack_tactic, "endpoint_id": a.endpoint_id, "hostname": a.endpoint.hostname,
         "user": a.identity.sam_account_name if a.identity else a.user_name,
         "department": a.identity.department if a.identity else None,
         "privilege_level": a.identity.privilege_level if a.identity else None,
         "severity": a.severity, "confidence": a.confidence, "status": a.status, "summary": a.summary,
         "event_count": a.event_count, "first_event_time": iso(a.first_event_time), "created_at": iso(a.created_at),
         "ticket_id": a.ticket.id if a.ticket else None, "priority": a.ticket.priority if a.ticket else None}
    if detail:
        d["description"] = a.rule.description
        d["identity"] = ser_identity(a.identity)
        d["events"] = [ser_event(e) for e in a.events]
    return d


def ser_ticket(t: Ticket) -> dict:
    a = t.alert
    return {"id": t.id, "alert_id": t.alert_id, "priority": t.priority, "priority_score": t.priority_score,
            "status": t.status, "assignee": t.assignee.username if t.assignee else None, "assignee_id": t.assignee_id,
            "incident_id": t.incident_id, "created_at": iso(t.created_at), "updated_at": iso(t.updated_at),
            "resolved_at": iso(t.resolved_at), "summary": a.summary, "severity": a.severity,
            "rule_name": a.rule.name, "technique": a.rule.attack_technique_id, "hostname": a.endpoint.hostname,
            "user": a.identity.sam_account_name if a.identity else a.user_name}
