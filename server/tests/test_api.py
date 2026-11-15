"""Tes REST + WebSocket lewat TestClient (tanpa jaringan/serial sungguhan)."""
import json
import shutil

import pytest
from fastapi.testclient import TestClient

from server.app import create_app
from server.config import DEFAULT_CONFIG_DIR

from .helpers import ATTACKER, OFFICIAL_BSSID, ap, ap_msg, hb_msg, line


class FakeSource:
    name = "fake"

    def __init__(self):
        self.cmds = []

    def start(self, on_line):
        pass

    def write(self, cmd):
        self.cmds.append(cmd)

    def stop(self):
        pass


@pytest.fixture
def env(tmp_path):
    cfgdir = tmp_path / "config"
    shutil.copytree(DEFAULT_CONFIG_DIR, cfgdir)
    src = FakeSource()
    app = create_app(str(cfgdir), str(tmp_path / "t.db"), src)
    with TestClient(app) as client:
        yield client, app, src, cfgdir


def recv_until(ws, t, limit=30):
    for _ in range(limit):
        m = ws.receive_json()
        if m["t"] == t:
            return m
    raise AssertionError("tidak menerima pesan %s" % t)


def test_ws_sends_snapshot_first(env):
    client, *_ = env
    with client.websocket_connect("/ws") as ws:
        snap = ws.receive_json()
    assert snap["t"] == "snapshot"
    assert [n["node"] for n in snap["nodes"]] == ["N1", "N2", "N3"]
    assert snap["floorplan"]["width"] == 800 and snap["aps"] == [] and snap["alerts"] == []
    assert {w["ssid"] for w in snap["whitelist"]} == {"SATUAN-01", "SATUAN-02", "LOGISTIK-NET"}


def test_pushed_line_becomes_ws_alert_and_command(env):
    client, app, src, _ = env
    with client.websocket_connect("/ws") as ws:
        ws.receive_json()
        app.state.push(line(ap_msg([ap("SATUAN-01", ATTACKER, sec="OPEN")])))
        alert = recv_until(ws, "alert")
        assert alert["rule"] == "evil_twin" and alert["severity"] == "critical"
        status = recv_until(ws, "node_status")
        assert status["node"] == "N1" and status["state"] == "alert"
    assert src.cmds and src.cmds[0]["level"] == 3 and src.cmds[0]["node"] == "N1"


def test_rest_state_health_and_alert_history(env):
    client, app, *_ = env
    with client.websocket_connect("/ws") as ws:
        ws.receive_json()
        app.state.push(line(ap_msg([ap("SATUAN-01", ATTACKER)])))
        recv_until(ws, "alert")
    assert client.get("/api/health").json()["source"] == "fake"
    state = client.get("/api/state").json()
    assert state["alerts"][0]["rule"] == "evil_twin" and any(a["bssid"] == ATTACKER for a in state["aps"])
    assert client.get("/api/alerts?limit=5").json()[0]["bssid"] == ATTACKER


def test_ack_alert(env):
    client, app, *_ = env
    with client.websocket_connect("/ws") as ws:
        ws.receive_json()
        app.state.push(line(ap_msg([ap("SATUAN-01", ATTACKER)])))
        aid = recv_until(ws, "alert")["id"]
        assert client.post("/api/alerts/%d/ack" % aid).json() == {"ok": True}
        assert recv_until(ws, "alert_ack")["id"] == aid
    assert client.get("/api/alerts").json()[0]["acked"] is True
    assert client.post("/api/alerts/9999/ack").status_code == 404


def test_promote_updates_file_and_broadcasts(env):
    client, app, _, cfgdir = env
    with client.websocket_connect("/ws") as ws:
        ws.receive_json()
        app.state.push(line(ap_msg([ap("SATUAN-01", ATTACKER, sec="WPA2")])))
        recv_until(ws, "alert")
        r = client.post("/api/whitelist/promote", json={"bssid": ATTACKER})
        assert r.status_code == 200
        cfg_ev = recv_until(ws, "config_changed")
        assert ATTACKER in [b for w in cfg_ev["whitelist"] if w["ssid"] == "SATUAN-01" for b in w["bssids"]]
    saved = json.load(open(cfgdir / "whitelist.json"))
    assert ATTACKER in [b for a in saved["aps"] for b in a["bssids"]]


def test_promote_validation_error_is_400(env):
    client, *_ = env
    r = client.post("/api/whitelist/promote", json={"bssid": "zz", "ssid": "X"})
    assert r.status_code == 400


def test_ignore_endpoint(env):
    client, _, _, cfgdir = env
    assert client.post("/api/whitelist/ignore", json={"bssid": "02:ca:fe:00:00:07"}).status_code == 200
    assert "02:ca:fe:00:00:07" in json.load(open(cfgdir / "whitelist.json"))["ignored_bssids"]


def test_alarm_clear_sends_off(env):
    client, app, src, _ = env
    assert client.post("/api/alarm/clear").json() == {"ok": True}
    assert src.cmds[-1] == {"cmd": "alert", "node": "all", "level": 0, "ttl_s": 0}


def test_garbage_line_does_not_break_pipeline(env):
    client, app, *_ = env
    with client.websocket_connect("/ws") as ws:
        ws.receive_json()
        app.state.push("garbage {{{")
        app.state.push(line(hb_msg("N1")))
        assert recv_until(ws, "node_status")["node"] == "N1"


def test_record_file_is_replayable(tmp_path):
    cfgdir = tmp_path / "config"
    shutil.copytree(DEFAULT_CONFIG_DIR, cfgdir)
    rec = tmp_path / "rec.jsonl"
    app = create_app(str(cfgdir), ":memory:", FakeSource(), str(rec))
    with TestClient(app) as client:
        with client.websocket_connect("/ws") as ws:
            ws.receive_json()
            app.state.push(line(ap_msg([ap("SATUAN-01", ATTACKER)])))
            recv_until(ws, "alert")
    rows = [json.loads(l) for l in rec.read_text().splitlines()]
    assert rows[0]["t"] == "snapshot" and rows[0]["at"] == 0 or rows[0]["at"] < 1
    assert any(r["t"] == "alert" for r in rows) and all("at" in r for r in rows)
    assert [r["at"] for r in rows] == sorted(r["at"] for r in rows)
