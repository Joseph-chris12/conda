from server.rules import evil_twin

from .helpers import ATTACKER, OFFICIAL_BSSID, OFFICIAL_BSSID_2, ap


def test_unknown_bssid_with_official_ssid_is_critical(cfg):
    f = evil_twin.check(ap("SATUAN-01", ATTACKER, sec="WPA2"), "N1", cfg)
    assert f and f["rule"] == "evil_twin" and f["severity"] == "critical"
    assert f["bssid"] == ATTACKER and f["key"] == ATTACKER and f["node"] == "N1"


def test_open_evil_twin_mentions_open_in_evidence(cfg):
    f = evil_twin.check(ap("SATUAN-01", ATTACKER, sec="OPEN"), "N1", cfg)
    assert f["evidence"]["sec"] == "OPEN" and "TERBUKA" in f["detail"]


def test_official_bssids_are_fine_including_second_radio(cfg):
    assert evil_twin.check(ap("SATUAN-01", OFFICIAL_BSSID), "N1", cfg) is None
    assert evil_twin.check(ap("SATUAN-01", OFFICIAL_BSSID_2), "N1", cfg) is None


def test_other_ssid_is_not_evil_twin(cfg):
    assert evil_twin.check(ap("Indihome-4F2A", ATTACKER), "N1", cfg) is None


def test_ssid_match_is_case_sensitive(cfg):
    # 'satuan-01' bukan SSID resmi persis -> urusan ssid_lookalike, bukan evil_twin
    assert evil_twin.check(ap("satuan-01", ATTACKER), "N1", cfg) is None


def test_hidden_ssid_never_matches(cfg):
    assert evil_twin.check(ap("", ATTACKER), "N1", cfg) is None


def test_disabled_rule(cfg):
    cfg.thresholds["rules"]["evil_twin"]["enabled"] = False
    assert evil_twin.check(ap("SATUAN-01", ATTACKER), "N1", cfg) is None
