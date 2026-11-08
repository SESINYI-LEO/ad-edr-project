"""Rule-based behaviour detection engine. Rules hold a declarative JSON condition tree evaluated against a flat event view."""
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import DetectionRule, TelemetryEvent

VIEW_FIELDS = ["event_type", "process_name", "process_id", "command_line", "parent_process", "file_path",
               "registry_key", "remote_address", "remote_port", "raw_username"]


def event_view(event: TelemetryEvent) -> dict[str, Any]:
    v = {f: getattr(event, f) for f in VIEW_FIELDS}
    u = event.ad_user
    v.update(ad_username=u.username if u else None, ad_department=u.department if u else None,
             ad_privilege=u.privilege if u else None, ad_groups=",".join(u.groups) if u else None)
    return v


def eval_condition(view: dict, cond: dict) -> bool:
    if "all" in cond:
        return all(eval_condition(view, c) for c in cond["all"])
    if "any" in cond:
        return any(eval_condition(view, c) for c in cond["any"])
    if "not" in cond:
        return not eval_condition(view, cond["not"])
    actual, op, exp = view.get(cond["field"]), cond["op"], cond.get("value")
    if actual is None:
        return False
    if op == "eq":
        return actual == exp
    if op == "neq":
        return actual != exp
    s = str(actual).lower()
    if op == "contains":
        return str(exp).lower() in s
    if op == "contains_any":
        return any(str(x).lower() in s for x in exp)
    if op == "in":
        return actual in exp
    if op == "gt":
        return actual > exp
    if op == "lt":
        return actual < exp
    raise ValueError(f"unsupported operator: {op}")


def rule_matches(rule: DetectionRule, view: dict) -> bool:
    if not rule.enabled or rule.event_type != view["event_type"]:
        return False
    try:
        return eval_condition(view, rule.logic)
    except (KeyError, ValueError, TypeError):
        return False  # a malformed rule must not blind the whole engine


def threshold_met(db: Session, rule: DetectionRule, event: TelemetryEvent) -> bool:
    """Correlation: >= threshold_count matching events from the same endpoint inside the window."""
    if rule.threshold_count <= 1:
        return True
    since = event.timestamp - timedelta(seconds=rule.window_seconds)
    recent = db.scalars(select(TelemetryEvent).where(
        TelemetryEvent.endpoint_id == event.endpoint_id, TelemetryEvent.event_type == rule.event_type,
        TelemetryEvent.timestamp >= since, TelemetryEvent.timestamp <= event.timestamp)).all()
    return sum(1 for e in recent if rule_matches(rule, event_view(e))) >= rule.threshold_count
