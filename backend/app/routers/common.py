"""JSON serialisers shared by routers."""


def iso(d):
    return d.isoformat() if d else None


def user_out(u):
    return {"id": str(u.id), "username": u.username, "role": u.role.value, "is_active": u.is_active,
            "biometric_enrolled": bool(u.biometric_template_hash), "created_at": iso(u.created_at)}


def endpoint_out(e):
    return {"id": str(e.id), "hostname": e.hostname, "ip_address": e.ip_address, "os_version": e.os_version, "domain": e.domain,
            "criticality": e.criticality.value, "status": e.status.value, "last_seen": iso(e.last_seen)}


def ad_user_out(u):
    return {"id": str(u.id), "sid": u.sid, "username": u.username, "department": u.department,
            "groups": u.groups, "privilege": u.privilege, "last_synced": iso(u.last_synced)}


def event_out(e):
    return {"id": str(e.id), "hostname": e.endpoint.hostname if e.endpoint else None, "event_type": e.event_type,
            "timestamp": iso(e.timestamp), "process_name": e.process_name, "process_id": e.process_id,
            "command_line": e.command_line, "parent_process": e.parent_process, "file_path": e.file_path,
            "registry_key": e.registry_key, "remote_address": e.remote_address, "remote_port": e.remote_port,
            "user": ad_user_out(e.ad_user) if e.ad_user else None, "raw_username": e.raw_username}


def alert_out(a, with_events=False):
    out = {"id": str(a.id), "title": a.title, "description": a.description, "severity": a.severity.value,
           "mitre_technique": a.mitre_technique, "confidence": a.confidence, "hostname": a.endpoint.hostname,
           "endpoint_id": str(a.endpoint_id), "created_at": iso(a.created_at),
           "ticket_id": str(a.ticket.id) if a.ticket else None}
    if with_events:
        out["events"] = [event_out(e) for e in sorted(a.events, key=lambda x: x.timestamp)]
    return out


def ticket_out(t):
    a = t.alert
    return {"id": str(t.id), "alert_id": str(t.alert_id), "title": a.title, "hostname": a.endpoint.hostname,
            "mitre_technique": a.mitre_technique, "severity": a.severity.value, "priority": t.priority.value,
            "priority_score": t.priority_score, "status": t.status.value, "incident_id": str(t.incident_id) if t.incident_id else None,
            "assigned_to": t.assignee.username if t.assignee else None, "created_at": iso(t.created_at)}


def incident_out(i, detail=False):
    out = {"id": str(i.id), "title": i.title, "summary": i.summary, "status": i.status.value,
           "hostname": i.endpoint.hostname if i.endpoint else None, "endpoint_id": str(i.endpoint_id) if i.endpoint_id else None,
           "created_at": iso(i.created_at), "closed_at": iso(i.closed_at), "ticket_count": len(i.tickets),
           "report_count": len(i.reports)}
    if detail:
        out["notes"] = i.notes
        out["tickets"] = [ticket_out(t) for t in i.tickets]
        out["reports"] = [{"id": str(r.id), "created_at": iso(r.created_at), "content": r.content} for r in sorted(i.reports, key=lambda r: r.created_at, reverse=True)]
    return out


def rule_out(r):
    return {"id": str(r.id), "name": r.name, "description": r.description, "event_type": r.event_type, "severity": r.severity.value,
            "mitre_technique": r.mitre_technique, "confidence": r.confidence, "logic": r.logic,
            "threshold_count": r.threshold_count, "window_seconds": r.window_seconds, "enabled": r.enabled}


def audit_out(a):
    return {"id": str(a.id), "username": a.username, "action": a.action, "outcome": a.outcome, "details": a.details,
            "ip_address": a.ip_address, "timestamp": iso(a.timestamp)}


def backup_out(b):
    return {"id": str(b.id), "filename": b.filename, "size_bytes": b.size_bytes, "sha256": b.sha256,
            "status": b.status.value, "created_at": iso(b.created_at)}
