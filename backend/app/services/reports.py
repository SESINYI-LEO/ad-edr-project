from sqlalchemy.orm import Session

from app.models import AuditEntry, Incident, IncidentReport, utcnow
from sqlalchemy import select


def build_report(db: Session, incident: Incident, user) -> IncidentReport:
    L = [f"# Incident Report: {incident.title}", "",
         f"- **Incident ID:** {incident.id}", f"- **Status:** {incident.status.value}",
         f"- **Affected endpoint:** {incident.endpoint.hostname if incident.endpoint else 'n/a'}",
         f"- **Opened:** {incident.created_at:%Y-%m-%d %H:%M} UTC",
         f"- **Report generated:** {utcnow():%Y-%m-%d %H:%M} UTC by {user.username}", "",
         "## Summary", incident.summary or "_No summary recorded._", "", "## Linked tickets and alerts"]
    for t in incident.tickets:
        a = t.alert
        L += [f"### {a.title}  ({t.priority.value.upper()}, score {t.priority_score}/100)",
              f"- ATT&CK technique: {a.mitre_technique or 'n/a'}; confidence {round(a.confidence * 100)}%; ticket status {t.status.value}"]
        for e in sorted(a.events, key=lambda x: x.timestamp):
            who = f"{e.ad_user.username} ({e.ad_user.privilege}, {e.ad_user.department})" if e.ad_user else "unattributed"
            what = e.command_line or e.registry_key or e.file_path or e.remote_address or e.process_name
            L.append(f"  - {e.timestamp:%H:%M:%S} UTC | {e.event_type} | {who} | {what}")
        L.append("")
    L += ["## Investigation notes", incident.notes or "_None._", "", "## Related audit trail"]
    for ent in db.scalars(select(AuditEntry).where(AuditEntry.details.contains(str(incident.id))).order_by(AuditEntry.timestamp)):
        L.append(f"- {ent.timestamp:%Y-%m-%d %H:%M:%S} | {ent.username} | {ent.action} | {ent.outcome}")
    return IncidentReport(incident_id=incident.id, generated_by=user.id, content="\n".join(L))
