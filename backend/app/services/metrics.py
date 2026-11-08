from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Alert, Endpoint, EndpointStatus, Incident, IncidentStatus, TelemetryEvent, Ticket, TicketStatus


def _avg(xs):
    return round(sum(xs) / len(xs), 2) if xs else None


def compute(db: Session) -> dict:
    # MTTD: event occurrence -> alert raised.  MTTR: incident opened -> closed.
    mttd = []
    for a in db.scalars(select(Alert)).all():
        if a.events:
            mttd.append((a.created_at - min(e.timestamp for e in a.events)).total_seconds())
    mttr = [(i.closed_at - i.created_at).total_seconds() for i in db.scalars(select(Incident).where(Incident.closed_at.is_not(None)))]
    by_sev = dict(db.execute(select(Alert.severity, func.count()).group_by(Alert.severity)).all())
    return {
        "events_total": db.scalar(select(func.count(TelemetryEvent.id))) or 0,
        "alerts_total": db.scalar(select(func.count(Alert.id))) or 0,
        "alerts_by_severity": {k.value: v for k, v in by_sev.items()},
        "endpoints_total": db.scalar(select(func.count(Endpoint.id))) or 0,
        "endpoints_online": db.scalar(select(func.count(Endpoint.id)).where(Endpoint.status == EndpointStatus.ONLINE)) or 0,
        "endpoints_isolated": db.scalar(select(func.count(Endpoint.id)).where(Endpoint.status == EndpointStatus.ISOLATED)) or 0,
        "tickets_open": db.scalar(select(func.count(Ticket.id)).where(Ticket.status.not_in([TicketStatus.CLOSED, TicketStatus.FALSE_POSITIVE, TicketStatus.RESOLVED]))) or 0,
        "incidents_active": db.scalar(select(func.count(Incident.id)).where(Incident.status != IncidentStatus.CLOSED)) or 0,
        "mttd_seconds": _avg(mttd), "mttr_seconds": _avg(mttr),
    }
