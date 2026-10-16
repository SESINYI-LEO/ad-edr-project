"""State machines from the Chapter 3 state charts (Fig 8)."""
from fastapi import HTTPException

from app.models import IncidentStatus as I
from app.models import TicketStatus as T

TICKET_TRANSITIONS = {
    T.NEW: {T.PRIORITISED},
    T.PRIORITISED: {T.UNDER_INVESTIGATION},
    T.UNDER_INVESTIGATION: {T.FALSE_POSITIVE, T.RESOLVED, T.ESCALATED},
    T.ESCALATED: {T.RESOLVED},
    T.RESOLVED: {T.CLOSED},
    T.CLOSED: set(), T.FALSE_POSITIVE: set(),
}
# CONTAINED is reachable only through a verified response action (see response.py), never by a manual status change.
INCIDENT_TRANSITIONS = {
    I.OPEN: {I.INVESTIGATING, I.CLOSED},
    I.INVESTIGATING: {I.CLOSED},
    I.CONTAINED: {I.RESOLVED},
    I.RESOLVED: {I.CLOSED},
    I.CLOSED: set(),
}


def move_ticket(ticket, new: T):
    if new not in TICKET_TRANSITIONS[ticket.status]:
        raise HTTPException(409, f"Ticket cannot move from '{ticket.status.value}' to '{new.value}'")
    ticket.status = new


def move_incident(incident, new: I, has_report: bool = False):
    if new not in INCIDENT_TRANSITIONS[incident.status]:
        raise HTTPException(409, f"Incident cannot move from '{incident.status.value}' to '{new.value}'")
    if incident.status == I.RESOLVED and new == I.CLOSED and not has_report:
        raise HTTPException(409, "Generate the incident report before closing a resolved incident")
    incident.status = new
