"""Rule-based behaviour detection engine (rules are data; see rules/rules.yaml)."""
import ipaddress
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache

import yaml

SEVERITIES = ("low", "medium", "high", "critical")
OPS = {"eq", "ne", "in", "not_in", "regex", "contains_any", "gte", "lte", "is_public_ip"}


@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str
    technique: str
    tactic: str
    confidence: int
    conditions: list
    threshold: dict | None = None
    enabled: bool = True


@dataclass
class Detection:
    rule: Rule
    event_ids: list
    first_time: datetime
    group: tuple = ()


def load_rules(path: str) -> list[Rule]:
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    rules = []
    for r in raw:
        if r["severity"] not in SEVERITIES:
            raise ValueError(f"{r['id']}: bad severity {r['severity']}")
        for c in r["conditions"]:
            if c["op"] not in OPS:
                raise ValueError(f"{r['id']}: unknown op {c['op']}")
        rules.append(Rule(id=r["id"], name=r["name"], description=r.get("description", ""), severity=r["severity"],
                          technique=r["technique"], tactic=r["tactic"], confidence=int(r["confidence"]),
                          conditions=r["conditions"], threshold=r.get("threshold")))
    return rules


@lru_cache(maxsize=512)
def _rx(pattern: str):
    return re.compile(pattern, re.IGNORECASE)


def _is_public(ip) -> bool:
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)


def check(ev: dict, cond: dict) -> bool:
    """Evaluate one condition against a normalised event. A missing field never matches."""
    val = ev.get(cond["field"])
    if val is None:
        return False
    op, want = cond["op"], cond.get("value")
    if op == "is_public_ip":
        return _is_public(val) == bool(want)
    if op in ("gte", "lte"):
        try:
            v = float(int(val, 16)) if isinstance(val, str) and val.lower().startswith("0x") else float(val)
        except (TypeError, ValueError):
            return False
        return v >= float(want) if op == "gte" else v <= float(want)
    s = str(val).lower()
    if op == "eq":
        return s == str(want).lower()
    if op == "ne":
        return s != str(want).lower()
    if op == "in":
        return s in {str(x).lower() for x in want}
    if op == "not_in":
        return s not in {str(x).lower() for x in want}
    if op == "regex":
        return bool(_rx(want).search(str(val)))
    if op == "contains_any":
        return any(str(x).lower() in s for x in want)
    return False


def matches(ev: dict, rule: Rule) -> bool:
    return all(check(ev, c) for c in rule.conditions)


class Detector:
    """Evaluates events against enabled rules; keeps sliding windows for threshold rules."""

    def __init__(self, rules: list[Rule]):
        self.rules = {r.id: r for r in rules}
        self.windows: dict = defaultdict(deque)

    def set_enabled(self, rule_id: str, enabled: bool):
        if rule_id in self.rules:
            self.rules[rule_id].enabled = enabled

    def evaluate(self, ev: dict) -> list[Detection]:
        out = []
        ts: datetime = ev["timestamp"]
        for rule in self.rules.values():
            if not rule.enabled or not matches(ev, rule):
                continue
            if rule.threshold is None:
                out.append(Detection(rule, [ev["_id"]], ts))
                continue
            t = rule.threshold
            key = (rule.id,) + tuple(ev.get(f) for f in t["group_by"])
            win = self.windows[key]
            win.append((ts, ev["_id"]))
            while win and (ts - win[0][0]).total_seconds() > t["window_seconds"]:
                win.popleft()
            if len(win) >= t["count"]:
                out.append(Detection(rule, [i for _, i in win], win[0][0], key[1:]))
                win.clear()  # fire once per burst
        return out
