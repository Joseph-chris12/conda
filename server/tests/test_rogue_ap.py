from server.rules import rogue_ap

from .helpers import ATTACKER, OFFICIAL_BSSID, ap

STRANGER = "02:ca:fe:00:00:07"


def test_strong_unknown_ap_is_medium(cfg):
    f = rogue_ap.check(ap("FREE-WIFI", STRANGER, rssi=-42, sec="OPEN"), "N2", cfg)
    assert f and f["rule"] == "rogue_ap" and f["severity"] == "medium" and f["node"] == "N2"


def test_rssi_threshold_boundary(cfg):
    assert rogue_ap.check(ap("FREE-WIFI", STRANGER, rssi=-55), "N1", cfg)        # tepat di ambang
    assert rogue_ap.check(ap("FREE-WIFI", STRANGER, rssi=-56), "N1", cfg) is None


def test_weak_neighbor_is_silent(cfg):
    assert rogue_ap.check(ap("Indihome-4F2A", "5c:f4:ab:42:4f:2a", rssi=-80), "N1", cfg) is None


def test_official_bssid_is_silent(cfg):
    assert rogue_ap.check(ap("SATUAN-01", OFFICIAL_BSSID, rssi=-30), "N1", cfg) is None


def test_ignored_bssid_is_silent(cfg):
    cfg.ignore(STRANGER)
    assert rogue_ap.check(ap("FREE-WIFI", STRANGER, rssi=-30), "N1", cfg) is None


def test_official_ssid_foreign_bssid_is_evil_twin_domain(cfg):
    assert rogue_ap.check(ap("SATUAN-01", ATTACKER, rssi=-30), "N1", cfg) is None


def test_lookalike_is_not_double_reported(cfg):
    assert rogue_ap.check(ap("SATUAN_01", ATTACKER, rssi=-30), "N1", cfg) is None


def test_hidden_strong_ap_is_reported(cfg):
    f = rogue_ap.check(ap("", STRANGER, rssi=-40), "N1", cfg)
    assert f and f["ssid"] is None and f["evidence"]["hidden"] is True


def test_threshold_from_config(cfg):
    cfg.thresholds["rules"]["rogue_ap"]["min_rssi_dbm"] = -90
    assert rogue_ap.check(ap("Indihome-4F2A", "5c:f4:ab:42:4f:2a", rssi=-80), "N1", cfg)


def test_disabled_rule(cfg):
    cfg.thresholds["rules"]["rogue_ap"]["enabled"] = False
    assert rogue_ap.check(ap("FREE-WIFI", STRANGER, rssi=-30), "N1", cfg) is None
