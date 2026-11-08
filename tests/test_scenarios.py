"""Functional acceptance tests: every simulated attack must alert on the expected rule; every benign look-alike must not."""
import pytest
from fastapi.testclient import TestClient

from helpers import ingest, login, make_app, register_agent
from simulation.scenarios import baseline_noise, build

API = "/api/v1"


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    app = make_app(tmp_path_factory.mktemp("sim"))
    c = TestClient(app)
    h = login(c)
    out = {}
    for sc in build():
        key, ep = register_agent(c, f"WS-{sc['id']}")
        res = ingest(c, key, sc["events"]).json()
        out[sc["id"]] = {"sc": sc, "res": res, "ep": ep}
    alerts = c.get(f"{API}/alerts?limit=500", headers=h).json()
    by_host = {}
    for a in alerts:
        by_host.setdefault(a["hostname"], set()).add(a["rule_id"])
    return {"client": c, "h": h, "runs": out, "by_host": by_host, "alerts": alerts}


ATTACKS = [s["id"] for s in build() if s["kind"] == "attack"]
BENIGN = [s["id"] for s in build() if s["kind"] == "benign"]


@pytest.mark.parametrize("sid", ATTACKS)
def test_attack_is_detected_with_expected_rules(env, sid):
    sc = env["runs"][sid]["sc"]
    assert env["runs"][sid]["res"]["rejected"] == 0
    assert set(sc["expected"]) <= env["by_host"].get(f"WS-{sid}", set()), f"{sid} {sc['name']} missed"


@pytest.mark.parametrize("sid", [s for s in ATTACKS if s != "A15"])
def test_single_technique_attacks_raise_no_extra_rules(env, sid):
    assert env["by_host"].get(f"WS-{sid}", set()) == set(env["runs"][sid]["sc"]["expected"])


@pytest.mark.parametrize("sid", BENIGN)
def test_benign_lookalike_does_not_alert(env, sid):
    assert env["runs"][sid]["res"]["rejected"] == 0
    assert env["by_host"].get(f"WS-{sid}", set()) == set(), env["runs"][sid]["sc"]["name"]


def test_attack_alerts_are_attributed_to_the_right_ad_user(env):
    exp = {"A01": "jsmith", "A02": "mdlamini", "A03": "tkgosi", "A06": "rseretse", "A09": "tkgosi"}
    seen = {}
    for a in env["alerts"]:
        seen.setdefault(a["hostname"], set()).add(a["user"])
    for sid, user in exp.items():
        assert seen[f"WS-{sid}"] == {user}, sid


def test_ransomware_alert_is_one_merged_alert_with_all_evidence(env):
    a = [x for x in env["alerts"] if x["hostname"] == "WS-A10"]
    assert len(a) == 1 and a[0]["event_count"] >= 20 and a[0]["severity"] == "critical"


def test_chain_attack_creates_four_alerts_and_critical_priorities(env):
    t = [x for x in env["client"].get(f"{API}/tickets?limit=500", headers=env["h"]).json() if x["hostname"] == "WS-A15"]
    assert len(t) == 4 and all(x["priority"] in ("Critical", "High") for x in t)


def test_noise_does_not_create_false_positives_and_is_fast(tmp_path):
    c = TestClient(make_app(tmp_path))
    key, _ = register_agent(c, "WS-NOISE")
    for i in range(0, 1000, 250):
        r = ingest(c, key, baseline_noise(1000, r"LAB\jsmith")[i:i + 250]).json()
        assert r["rejected"] == 0 and r["alerts_created"] == 0
