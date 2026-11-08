"""Ticket prioritisation (property-based over the whole input space) and lifecycle state machine."""
import itertools

import pytest

from server.app.tickets import (PRIVILEGE_SCORE, SEVERITY_SCORE, THRESHOLDS, TRANSITIONS, can_transition,
                                compute_priority)

SEV = list(SEVERITY_SCORE)
PRIV = ["standard", "elevated", "admin", None]
LEVELS = ["Low", "Medium", "High", "Critical"]


def test_label_always_matches_threshold_over_entire_input_space():
    n = 0
    for sev, conf, asset, priv in itertools.product(SEV, range(0, 101, 5), range(1, 6), PRIV):
        score, label = compute_priority(sev, conf, asset, priv)
        expected = next(l for floor, l in THRESHOLDS if score >= floor)
        assert label == expected and 0 <= score <= 100
        n += 1
    assert n == 4 * 21 * 5 * 4


@pytest.mark.parametrize("conf,label", [(45, "High"), (40, "Medium")])  # score 55.0 vs 54.0 (boundary)
def test_high_boundary(conf, label):
    assert compute_priority("high", conf, 3, "standard")[1] == label


@pytest.mark.parametrize("conf,label", [(35, "Medium"), (30, "Low")])  # score 35.0 vs 34.0
def test_medium_boundary(conf, label):
    assert compute_priority("medium", conf, 1, "standard")[1] == label


def test_priority_is_monotonic_in_each_factor():
    base = dict(severity="medium", confidence=50, asset_criticality=3, privilege="standard")
    s0 = compute_priority(**base)[0]
    assert compute_priority(**{**base, "severity": "critical"})[0] > s0
    assert compute_priority(**{**base, "confidence": 90})[0] > s0
    assert compute_priority(**{**base, "asset_criticality": 5})[0] > s0
    assert compute_priority(**{**base, "privilege": "admin"})[0] > s0


def test_admin_account_outranks_standard_user_for_same_alert():
    a = compute_priority("high", 70, 3, "admin")[0]
    s = compute_priority("high", 70, 3, "standard")[0]
    assert a - s == pytest.approx(16.0)  # 0.2 * (100 - 20)


def test_inputs_are_clamped_and_validated():
    assert compute_priority("low", -50, 0, "standard") == compute_priority("low", 0, 1, "standard")
    assert compute_priority("low", 999, 99, "standard") == compute_priority("low", 100, 5, "standard")
    assert compute_priority("low", 10, 1, "martian")[0] == compute_priority("low", 10, 1, None)[0]
    with pytest.raises(ValueError):
        compute_priority("urgent", 50, 3, "standard")


ALL = list(TRANSITIONS)


@pytest.mark.parametrize("cur,new", [(c, n) for c in ALL for n in ALL])
def test_state_machine_exhaustive(cur, new):
    legal = {("New", "Assigned"), ("Assigned", "Under Investigation"), ("Under Investigation", "Escalated"),
             ("Under Investigation", "Resolved"), ("Escalated", "Resolved"), ("Resolved", "Closed"),
             ("Resolved", "Under Investigation")}
    assert can_transition(cur, new) is ((cur, new) in legal)


def test_unknown_state_has_no_transitions():
    assert can_transition("Bogus", "New") is False and can_transition("New", "Bogus") is False
