"""Risk-based ticket prioritisation and the ticket lifecycle (state chart, Fig 8a in Chapter 3)."""
SEVERITY_SCORE = {"low": 25, "medium": 50, "high": 75, "critical": 100}
PRIVILEGE_SCORE = {"standard": 20, "elevated": 60, "admin": 100, "unknown": 40}
W_SEVERITY, W_CONFIDENCE, W_ASSET, W_PRIVILEGE = 0.40, 0.20, 0.20, 0.20
THRESHOLDS = ((75, "Critical"), (55, "High"), (35, "Medium"), (0, "Low"))

TRANSITIONS = {
    "New": {"Assigned"},
    "Assigned": {"Under Investigation"},
    "Under Investigation": {"Escalated", "Resolved"},
    "Escalated": {"Resolved"},
    "Resolved": {"Closed", "Under Investigation"},
    "Closed": set(),
}


def compute_priority(severity: str, confidence: int, asset_criticality: int, privilege: str | None) -> tuple[float, str]:
    """Weighted risk score 0-100 -> Critical/High/Medium/Low."""
    if severity not in SEVERITY_SCORE:
        raise ValueError("unknown severity")
    conf = max(0, min(100, confidence))
    asset = max(1, min(5, asset_criticality)) * 20
    priv = PRIVILEGE_SCORE.get(privilege or "unknown", PRIVILEGE_SCORE["unknown"])
    score = (W_SEVERITY * SEVERITY_SCORE[severity] + W_CONFIDENCE * conf + W_ASSET * asset + W_PRIVILEGE * priv)
    score = round(score, 1)
    for floor, label in THRESHOLDS:
        if score >= floor:
            return score, label
    return score, "Low"


def can_transition(current: str, new: str) -> bool:
    return new in TRANSITIONS.get(current, set())
