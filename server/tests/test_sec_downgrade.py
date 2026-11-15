from server.rules import sec_downgrade

from .helpers import ATTACKER, LOGISTIK_BSSID, OFFICIAL_BSSID, ap


def test_official_bssid_open_is_critical(cfg):
    f = sec_downgrade.check(ap("SATUAN-01", OFFICIAL_BSSID, sec="OPEN"), "N1", cfg)
    assert f and f["rule"] == "sec_downgrade" and f["severity"] == "critical"
    assert f["evidence"]["sec"] == "OPEN" and "WPA2" in f["evidence"]["expected"]


def test_official_bssid_other_mismatch_is_high(cfg):
    f = sec_downgrade.check(ap("LOGISTIK-NET", LOGISTIK_BSSID, sec="WEP"), "N1", cfg)
    assert f and f["severity"] == "high"


def test_allowed_security_variants_pass(cfg):
    for sec in ("WPA2", "WPA3_TRANSITION", "WPA3"):
        assert sec_downgrade.check(ap("SATUAN-01", OFFICIAL_BSSID, sec=sec), "N1", cfg) is None


def test_unknown_security_is_not_judged(cfg):
    assert sec_downgrade.check(ap("SATUAN-01", OFFICIAL_BSSID, sec="UNKNOWN"), "N1", cfg) is None


def test_foreign_bssid_is_left_to_evil_twin(cfg):
    # BSSID asing + Open: tidak boleh dobel dengan evil_twin
    assert sec_downgrade.check(ap("SATUAN-01", ATTACKER, sec="OPEN"), "N1", cfg) is None


def test_non_official_ssid_ignored(cfg):
    assert sec_downgrade.check(ap("Warung", "c8:3a:35:11:90:7e", sec="OPEN"), "N1", cfg) is None
