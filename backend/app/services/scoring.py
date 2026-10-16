"""Priority Score = severity + identity risk + asset criticality + confidence + frequency (0-100)."""
from app.models import Criticality, Severity

SEVERITY_PTS = {Severity.LOW: 10, Severity.MEDIUM: 25, Severity.HIGH: 35, Severity.CRITICAL: 40}
PRIVILEGE_PTS = {"standard": 5, "elevated": 10, "admin": 15, "domain_admin": 20}
CRITICALITY_PTS = {Criticality.LOW: 5, Criticality.MEDIUM: 10, Criticality.HIGH: 15, Criticality.CRITICAL: 20}


def frequency_points(n: int) -> int:
    return 10 if n >= 10 else 7 if n >= 5 else 4 if n >= 2 else 0


def calculate_priority(severity: Severity, privilege: str | None, criticality: Criticality,
                       confidence: float, recent_alerts: int) -> tuple[int, Severity]:
    total = (SEVERITY_PTS[severity] + PRIVILEGE_PTS.get(privilege or "standard", 5) + CRITICALITY_PTS[criticality]
             + round(confidence * 10) + frequency_points(recent_alerts))
    total = max(0, min(100, total))
    band = Severity.CRITICAL if total >= 90 else Severity.HIGH if total >= 70 else Severity.MEDIUM if total >= 40 else Severity.LOW
    return total, band
