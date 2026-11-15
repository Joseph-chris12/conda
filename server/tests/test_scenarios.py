"""Uji end-to-end: keluaran tools/simulator.py -> Engine. Memastikan tiap skenario
memicu PERSIS aturan yang dimaksud dan skenario normal tidak memicu apa pun."""
import json
import subprocess
import sys
from collections import Counter

import pytest

from server.db import Database
from server.engine import Engine

from .helpers import alerts_of
from server.sources import SIMULATOR


def run_scenario(cfg, scenario, *extra):
    out = subprocess.run([sys.executable, "-I", SIMULATOR, "--scenario", scenario, "--fast", *extra],
                         capture_output=True, text=True, timeout=120, check=True).stdout
    engine = Engine(cfg, Database(":memory:"), send_cmd=lambda c: None)
    alerts, states = [], set()
    for ln in out.splitlines():
        for ev in engine.handle_line(ln):
            if ev["t"] == "alert":
                alerts.append(ev)
            elif ev["t"] == "node_status":
                states.add((ev["node"], ev["state"]))
    return alerts, states, engine


@pytest.mark.parametrize("scenario,expected_rule", [
    ("evil_twin", "evil_twin"),
    ("downgrade", "sec_downgrade"),
    ("lookalike", "ssid_lookalike"),
    ("rogue", "rogue_ap"),
    ("deauth", "deauth_flood"),
    ("tracker", "ble_tracker"),
])
def test_scenario_fires_exactly_its_rule(cfg, scenario, expected_rule):
    alerts, _, _ = run_scenario(cfg, scenario)
    assert alerts, "tidak ada alert"
    assert {a["rule"] for a in alerts} == {expected_rule}, Counter(a["rule"] for a in alerts)


def test_normal_traffic_is_alert_free_for_5_minutes(cfg):
    alerts, states, _ = run_scenario(cfg, "normal", "--duration", "300")
    assert alerts == [], [(a["rule"], a["detail"]) for a in alerts]
    assert {s for _, s in states} <= {"ok"}


def test_tracker_scenario_finds_all_three_kinds(cfg):
    alerts, _, _ = run_scenario(cfg, "tracker")
    assert {a["evidence"]["kind"] for a in alerts} == {"apple_findmy", "samsung_smarttag", "tile"}


def test_node_lost_scenario_loses_and_recovers_last_node(cfg):
    alerts, states, engine = run_scenario(cfg, "node_lost")
    assert {a["rule"] for a in alerts} == {"node_lost"}
    assert sorted(a["severity"] for a in alerts) == ["high", "low"]          # hilang + pulih
    assert ("N3", "lost") in states and engine.nodes["N3"]["state"] == "ok"


def test_deauth_scenario_reaches_critical_and_all_nodes_hear_it(cfg):
    alerts, _, _ = run_scenario(cfg, "deauth")
    assert "critical" in {a["severity"] for a in alerts}
    assert {n for a in alerts for n in a["evidence"]["nodes"]} == {"N1", "N2", "N3"}


def test_full_demo_triggers_all_seven_rules_and_nothing_else(cfg):
    alerts, _, _ = run_scenario(cfg, "full_demo")
    assert {a["rule"] for a in alerts} == {
        "evil_twin", "sec_downgrade", "ssid_lookalike", "deauth_flood", "rogue_ap", "ble_tracker", "node_lost"}
