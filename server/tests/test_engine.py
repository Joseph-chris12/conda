"""Tes perilaku engine: prioritas aturan, cooldown, status node, perintah alarm, inventaris."""
import json

from .helpers import (ATTACKER, OFFICIAL_BSSID, ap, ap_msg, alerts_of, ble_item, ble_msg,
                      deauth_item, deauth_msg, hb_msg, line, threat_alerts)

STRANGER = "02:ca:fe:00:00:07"


def rules_of(events):
    return [a["rule"] for a in alerts_of(events)]


def node_states(events):
    return {e["node"]: e["state"] for e in events if e["t"] == "node_status"}


# ---------------------------------------------------------------- prioritas
def test_evil_twin_open_fires_only_evil_twin(engine):
    ev = engine.handle(ap_msg([ap("SATUAN-01", ATTACKER, sec="OPEN", rssi=-40)]))
    assert rules_of(ev) == ["evil_twin"]          # bukan dobel dengan sec_downgrade/rogue_ap


def test_strong_lookalike_does_not_also_fire_rogue(engine):
    ev = engine.handle(ap_msg([ap("SATUAN_01", ATTACKER, rssi=-45)]))
    assert rules_of(ev) == ["ssid_lookalike"]


def test_official_open_fires_downgrade_only(engine):
    ev = engine.handle(ap_msg([ap("SATUAN-01", OFFICIAL_BSSID, sec="OPEN")]))
    assert rules_of(ev) == ["sec_downgrade"]


def test_normal_traffic_is_silent(engine):
    aps = [ap("SATUAN-01", OFFICIAL_BSSID, sec="WPA2", rssi=-40),
           ap("Indihome-4F2A", "5c:f4:ab:42:4f:2a", rssi=-80),
           ap("", "b0:95:75:11:22:33", rssi=-85)]
    ev = engine.handle(ap_msg(aps))
    ev += engine.handle(deauth_msg([deauth_item(deauth=2)], ts=1001))
    ev += engine.handle(ble_msg([ble_item(company="004c", mtype="10")], ts=1002))
    assert alerts_of(ev) == []


# ----------------------------------------------------------------- cooldown
def test_cooldown_suppresses_repeats_then_allows_again(engine):
    cd = engine.cfg.rule("evil_twin")["cooldown_s"]
    msg = lambda ts: ap_msg([ap("SATUAN-01", ATTACKER)], ts=ts)
    assert len(threat_alerts(engine.handle(msg(1000)))) == 1
    assert len(threat_alerts(engine.handle(msg(1000 + cd - 1)))) == 0
    assert len(threat_alerts(engine.handle(msg(1000 + cd)))) == 1


def test_cooldown_is_per_key(engine):
    engine.handle(ap_msg([ap("SATUAN-01", ATTACKER)]))
    ev = engine.handle(ap_msg([ap("SATUAN-01", "aa:bb:cc:dd:ee:02")], ts=1001))
    assert rules_of(ev) == ["evil_twin"]          # BSSID berbeda -> alert terpisah


def test_alert_has_protocol_fields_and_is_persisted(engine):
    a = alerts_of(engine.handle(ap_msg([ap("SATUAN-01", ATTACKER)], node="N1", ts=1234.5)))[0]
    for k in ("id", "ts", "rule", "severity", "title", "detail", "node", "bssid", "ssid", "evidence"):
        assert k in a
    assert a["ts"] == 1234.5 and a["evidence"]["nodes"] == ["N1"]
    assert engine.db.recent_alerts(1)[0]["id"] == a["id"]


def test_evidence_collects_all_reporting_nodes(engine):
    engine.handle(ap_msg([ap("SATUAN-01", ATTACKER)], node="N1", ts=1000))
    engine.handle(ap_msg([ap("SATUAN-01", ATTACKER)], node="N3", ts=1001))
    ev = engine.handle(ap_msg([ap("SATUAN-01", ATTACKER)], node="N2", ts=1000 + 61))
    assert threat_alerts(ev)[0]["evidence"]["nodes"] == ["N1", "N2", "N3"]


# -------------------------------------------------------------- status node
def test_node_state_alert_then_returns_to_ok_after_ttl(engine):
    ttl = engine.cfg.thresholds["alert_ttl_s"]
    ev = engine.handle(ap_msg([ap("SATUAN-01", ATTACKER)], node="N1", ts=1000))
    assert node_states(ev)["N1"] == "alert"
    ev = engine.handle(hb_msg("N1", ts=1000 + ttl + 1))
    assert node_states(ev)["N1"] == "ok"


def test_medium_alert_gives_warn_state(engine):
    ev = engine.handle(ap_msg([ap("FREE-WIFI", STRANGER, rssi=-40)], node="N2"))
    assert node_states(ev)["N2"] == "warn"


def test_unknown_until_first_message(engine):
    assert engine.nodes["N2"]["state"] == "unknown"
    ev = engine.handle(hb_msg("N2", ts=1000))
    assert node_states(ev)["N2"] == "ok"


def test_condition_stays_active_during_cooldown(engine):
    """Walau alert baru ditahan cooldown, node tetap 'alert' selama ancaman masih terlihat."""
    for i in range(0, 120, 6):
        engine.handle(ap_msg([ap("SATUAN-01", ATTACKER)], ts=1000 + i))
    assert engine.nodes["N1"]["state"] == "alert"


# ---------------------------------------------------------------- node lost
def test_node_lost_and_recovery(engine):
    lost_after = engine.cfg.thresholds["node_lost_s"]
    for nid in ("N1", "N2", "N3"):
        engine.handle(hb_msg(nid, ts=1000))
    # N1 & N2 terus melapor, N3 diam
    ev = []
    for t in range(1006, 1050, 6):
        ev += engine.handle(hb_msg("N1", ts=t))
        ev += engine.handle(hb_msg("N2", ts=t))
    lost = [a for a in alerts_of(ev) if a["rule"] == "node_lost"]
    assert len(lost) == 1 and lost[0]["node"] == "N3" and lost[0]["severity"] == "high"
    assert engine.nodes["N3"]["state"] == "lost"
    assert 1000 + lost_after < lost[0]["ts"] <= 1000 + lost_after + engine.cfg.thresholds["node_check_interval_s"] + 6

    ev = engine.handle(hb_msg("N3", ts=1060))               # N3 hidup lagi
    rec = alerts_of(ev)
    assert len(rec) == 1 and rec[0]["severity"] == "low" and "pulih" in rec[0]["title"]
    assert node_states(ev)["N3"] == "ok"


def test_never_seen_node_is_lost_after_grace(engine):
    engine.handle(hb_msg("N1", ts=1000))                    # N2/N3 tidak pernah melapor
    ev = engine.handle(hb_msg("N1", ts=1040))
    assert {a["node"] for a in alerts_of(ev) if a["rule"] == "node_lost"} == {"N2", "N3"}


def test_tick_detects_silence_without_incoming_messages(engine):
    for nid in ("N1", "N2", "N3"):
        engine.handle(hb_msg(nid, ts=1000))
    ev = engine.tick(1031)
    assert {a["node"] for a in alerts_of(ev)} == {"N1", "N2", "N3"}


def test_unknown_node_is_ignored(engine):
    ev = engine.handle(ap_msg([ap("SATUAN-01", ATTACKER)], node="N99"))
    assert ev == [] and engine.stats["unknown_node_lines"] == 1


# ---------------------------------------------------------------- perintah
def test_critical_alert_commands_reporting_node(engine, sent):
    engine.handle(ap_msg([ap("SATUAN-01", ATTACKER)], node="N1", ts=1000))
    assert sent == [{"cmd": "alert", "node": "N1", "level": 3, "ttl_s": engine.cfg.thresholds["alert_command_ttl_s"]}]


def test_medium_alert_is_level_1_and_high_is_level_2(engine, sent):
    engine.handle(ap_msg([ap("FREE-WIFI", STRANGER, rssi=-40)], node="N2", ts=1000))
    assert sent[-1]["level"] == 1 and sent[-1]["node"] == "N2"
    engine.handle(deauth_msg([deauth_item(deauth=20)], node="N3", ts=1001))
    assert sent[-1]["level"] == 2 and sent[-1]["node"] == "N3"


def test_command_is_refreshed_before_ttl_but_not_every_message(engine, sent):
    ttl = engine.cfg.thresholds["alert_command_ttl_s"]
    engine.handle(ap_msg([ap("SATUAN-01", ATTACKER)], ts=1000))
    engine.handle(ap_msg([ap("SATUAN-01", ATTACKER)], ts=1002))
    assert len(sent) == 1                                   # belum perlu diperbarui
    engine.handle(ap_msg([ap("SATUAN-01", ATTACKER)], ts=1000 + ttl / 2 + 1))
    assert len(sent) == 2                                   # menjelang TTL: perbarui


def test_node_lost_commands_other_nodes_not_the_lost_one(engine, sent):
    for nid in ("N1", "N2", "N3"):
        engine.handle(hb_msg(nid, ts=1000))
    for t in range(1006, 1042, 6):                          # N1 & N2 terus melapor, N3 diam
        engine.handle(hb_msg("N1", ts=t))
        engine.handle(hb_msg("N2", ts=t))
    assert engine.nodes["N3"]["state"] == "lost"
    cmds = {c["node"] for c in sent}
    assert "N3" not in cmds and {"N1", "N2"} <= cmds


def test_severity_escalation_bypasses_cooldown(engine):
    ev = engine.handle(deauth_msg([deauth_item(deauth=15)], ts=1000))
    assert [a["severity"] for a in alerts_of(ev)] == ["high"]
    ev = engine.handle(deauth_msg([deauth_item(deauth=16)], ts=1002))
    assert alerts_of(ev) == []                              # masih high -> ditahan cooldown
    ev = engine.handle(deauth_msg([deauth_item(deauth=50)], ts=1004))
    assert [a["severity"] for a in alerts_of(ev)] == ["critical"]   # naik -> dilaporkan
    ev = engine.handle(deauth_msg([deauth_item(deauth=15)], ts=1006))
    assert alerts_of(ev) == []                              # turun kembali -> tidak


def test_clear_alarms_sends_off_to_all(engine, sent):
    engine.handle(ap_msg([ap("SATUAN-01", ATTACKER)]))
    engine.clear_alarms()
    assert sent[-1] == {"cmd": "alert", "node": "all", "level": 0, "ttl_s": 0}
    assert engine.nodes["N1"]["state"] == "ok"


# --------------------------------------------------------------- inventaris
def test_inventory_status_unknown_official_suspect(engine):
    engine.handle(ap_msg([ap("SATUAN-01", OFFICIAL_BSSID, sec="WPA2", rssi=-40),
                          ap("Indihome-4F2A", "5c:f4:ab:42:4f:2a", rssi=-80),
                          ap("SATUAN-01", ATTACKER, rssi=-45)]))
    st = {a["bssid"]: a["status"] for a in engine.snapshot()["aps"]}
    assert st[OFFICIAL_BSSID] == "official"
    assert st["5c:f4:ab:42:4f:2a"] == "unknown"
    assert st[ATTACKER] == "suspect"


def test_ap_update_emitted_for_new_ap_and_security_change_only(engine):
    ev = engine.handle(ap_msg([ap("SATUAN-01", OFFICIAL_BSSID, sec="WPA2", rssi=-40)], ts=1000))
    assert [e["t"] for e in ev].count("ap_update") == 1
    ev = engine.handle(ap_msg([ap("SATUAN-01", OFFICIAL_BSSID, sec="WPA2", rssi=-41)], ts=1006))
    assert [e for e in ev if e["t"] == "ap_update"] == []          # tidak ada perubahan berarti
    ev = engine.handle(ap_msg([ap("SATUAN-01", OFFICIAL_BSSID, sec="OPEN", rssi=-41)], ts=1012))
    assert [e for e in ev if e["t"] == "ap_update" and e["sec"] == "OPEN"]


def test_best_rssi_across_nodes(engine):
    engine.handle(ap_msg([ap("X-AP", STRANGER, rssi=-80)], node="N1", ts=1000))
    engine.handle(ap_msg([ap("X-AP", STRANGER, rssi=-60)], node="N3", ts=1001))
    a = [x for x in engine.snapshot()["aps"] if x["bssid"] == STRANGER][0]
    assert a["rssi_best"] == -60 and a["node_best"] == "N3"


def test_ble_inventory_contains_trackers_only(engine):
    engine.handle(ble_msg([ble_item(company="004c", mtype="10", addr="aa:aa:aa:aa:aa:01"),
                           ble_item(addr="c7:4a:91:3e:5b:21")]))
    ble = engine.snapshot()["ble"]
    assert [b["addr"] for b in ble] == ["c7:4a:91:3e:5b:21"] and ble[0]["kind"] == "apple_findmy"
    assert engine.stats["ble_other"] == 1


def test_tracker_alert_after_three_cycles_end_to_end(engine):
    ev = []
    for c in range(1, 4):
        ev += engine.handle(ble_msg([ble_item(rssi=-68)], node="N2", ts=1000 + 6 * c, cycle=c))
    assert rules_of(ev) == ["ble_tracker"]


# --------------------------------------------------------- operator & ketahanan
def test_promote_makes_ap_official_and_clears_its_alert(engine, cfg):
    engine.handle(ap_msg([ap("SATUAN-01", ATTACKER, sec="WPA2")], ts=1000))
    assert engine.nodes["N1"]["state"] == "alert"
    ev = engine.promote(ATTACKER)
    assert any(e["t"] == "config_changed" for e in ev)
    assert ATTACKER in cfg.whitelist.ssids["SATUAN-01"]["bssids"]
    assert engine.nodes["N1"]["state"] == "ok"
    ev = engine.handle(ap_msg([ap("SATUAN-01", ATTACKER, sec="WPA2")], ts=1100))
    assert threat_alerts(ev) == []
    saved = json.load(open(cfg.dir + "/whitelist.json"))                # tersimpan ke file
    assert ATTACKER in [b for a in saved["aps"] for b in a["bssids"]]


def test_promote_new_ssid_adds_entry_with_observed_security(engine, cfg):
    engine.handle(ap_msg([ap("FREE-WIFI", STRANGER, rssi=-40, sec="WPA2")]))
    engine.promote(STRANGER)
    assert cfg.whitelist.ssids["FREE-WIFI"]["security"] == {"WPA2"}


def test_promote_rejects_bad_input(engine):
    import pytest
    with pytest.raises(ValueError):
        engine.promote("not-a-mac", "X")
    with pytest.raises(ValueError):
        engine.promote(STRANGER, "")


def test_ignore_silences_rogue(engine):
    engine.handle(ap_msg([ap("FREE-WIFI", STRANGER, rssi=-40)], ts=1000))
    engine.ignore(STRANGER)
    ev = engine.handle(ap_msg([ap("FREE-WIFI", STRANGER, rssi=-40)], ts=1200))
    assert threat_alerts(ev) == []


def test_bad_lines_do_not_crash(engine):
    for raw in ("", "   ", "not json", "[1,2]", '{"v":2,"t":"ap"}', '{"v":1}',
                '{"v":1,"t":"ap","node":"N1","aps":[{"ssid":"x"}]}',     # AP tidak lengkap
                "I (123) wifi: firmware debug log"):
        assert engine.handle_line(raw) == [] or True
    assert engine.stats["bad_lines"] >= 5
    assert alerts_of(engine.handle_line(line(ap_msg([ap("SATUAN-01", ATTACKER)])))) != []   # tetap hidup


def test_server_stamps_ts_when_missing(engine):
    msg = ap_msg([ap("SATUAN-01", ATTACKER)])
    del msg["ts"]
    a = alerts_of(engine.handle(msg))[0]
    assert a["ts"] == 1000.0                                   # clock palsu di fixture


def test_inventory_survives_restart(cfg, tmp_path):
    from server.db import Database
    from server.engine import Engine
    path = str(tmp_path / "r.db")
    e1 = Engine(cfg, Database(path), clock=lambda: 1000.0)
    e1.handle(ap_msg([ap("SATUAN-01", ATTACKER)], ts=1000))
    e2 = Engine(cfg, Database(path), clock=lambda: 2000.0)
    assert ATTACKER in [a["bssid"] for a in e2.snapshot()["aps"]]
    assert e2.snapshot()["alerts"][0]["rule"] == "evil_twin"


# ---------------------------------------------------------------- MAC cacat (byte hilang di serial)
def test_malformed_bssid_is_dropped_not_a_ghost_ap(engine):
    good = ap("Kantor", "02:aa:bb:cc:dd:01", rssi=-80)
    ghost = ap("Kantor", "02:aa:bb:cc:dd01", rssi=-40)      # titik dua hilang: JSON tetap valid
    engine.handle(ap_msg([good, ghost]))
    assert list(engine.aps) == ["02:aa:bb:cc:dd:01"]
    assert engine.stats["bad_items"] == 1


def test_malformed_mac_in_deauth_and_ble_is_dropped(engine):
    ev = engine.handle(deauth_msg([deauth_item(bssid="d8:07:b6:10:0001", deauth=50)]))
    assert threat_alerts(ev) == []
    ev = engine.handle(ble_msg([ble_item(addr="c7:4a:91:3e:5b")]))
    assert engine.stats["bad_items"] == 2
    assert not engine.ble


def test_uppercase_and_dash_mac_is_normalised(engine):
    engine.handle(ap_msg([ap("Kantor", "02-AA-BB-CC-DD-02", rssi=-80)]))
    assert "02:aa:bb:cc:dd:02" in engine.aps
