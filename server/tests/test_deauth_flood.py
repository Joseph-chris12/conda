from server.rules import deauth_flood

from .helpers import ATTACKER, OFFICIAL_BSSID, deauth_item


def test_below_warn_threshold_is_silent(cfg):
    assert deauth_flood.check(deauth_item(deauth=9), "N1", cfg) is None
    assert deauth_flood.check(deauth_item(deauth=5, disassoc=4), "N1", cfg) is None


def test_warn_threshold_is_high(cfg):
    f = deauth_flood.check(deauth_item(deauth=10), "N1", cfg)
    assert f and f["rule"] == "deauth_flood" and f["severity"] == "high"


def test_deauth_and_disassoc_are_summed(cfg):
    f = deauth_flood.check(deauth_item(deauth=6, disassoc=4), "N1", cfg)
    assert f and f["evidence"]["total"] == 10


def test_crit_threshold_is_critical(cfg):
    assert deauth_flood.check(deauth_item(deauth=39), "N1", cfg)["severity"] == "high"
    assert deauth_flood.check(deauth_item(deauth=40), "N1", cfg)["severity"] == "critical"
    assert deauth_flood.check(deauth_item(deauth=30, disassoc=10), "N1", cfg)["severity"] == "critical"


def test_official_target_is_marked(cfg):
    f = deauth_flood.check(deauth_item(bssid=OFFICIAL_BSSID, deauth=20), "N1", cfg)
    assert f["evidence"]["official"] is True and "AP RESMI" in f["detail"]
    g = deauth_flood.check(deauth_item(bssid=ATTACKER, deauth=20), "N1", cfg)
    assert g["evidence"]["official"] is False


def test_thresholds_come_from_config(cfg):
    cfg.thresholds["rules"]["deauth_flood"]["warn_frames"] = 3
    assert deauth_flood.check(deauth_item(deauth=3), "N1", cfg)


def test_disabled_rule(cfg):
    cfg.thresholds["rules"]["deauth_flood"]["enabled"] = False
    assert deauth_flood.check(deauth_item(deauth=100), "N1", cfg) is None
