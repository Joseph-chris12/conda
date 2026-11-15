import pytest

from server.rules import ssid_lookalike
from server.rules.ssid_lookalike import levenshtein

from .helpers import ATTACKER, OFFICIAL_BSSID, ap


@pytest.mark.parametrize("a,b,d", [
    ("", "", 0), ("abc", "", 3), ("", "abc", 3), ("SATUAN-01", "SATUAN_01", 1),
    ("kitten", "sitting", 3), ("abc", "abc", 0), ("flaw", "lawn", 2),
])
def test_levenshtein(a, b, d):
    assert levenshtein(a, b) == d


@pytest.mark.parametrize("ssid", ["SATUAN_01", "SATUAN-O1", "SATUAN-0", "SATUAN01", "satuan-01", "SATUAN--01"])
def test_lookalikes_detected(cfg, ssid):
    f = ssid_lookalike.check(ap(ssid, ATTACKER), "N1", cfg)
    assert f and f["rule"] == "ssid_lookalike" and f["severity"] == "high"
    assert f["evidence"]["official"] == "SATUAN-01"


def test_identical_ssid_is_not_lookalike(cfg):
    assert ssid_lookalike.check(ap("SATUAN-01", ATTACKER), "N1", cfg) is None


def test_other_official_ssid_not_flagged(cfg):
    # SATUAN-02 resmi, meski hanya berjarak 1 dari SATUAN-01
    assert ssid_lookalike.check(ap("SATUAN-02", ATTACKER), "N1", cfg) is None


def test_far_ssid_not_flagged(cfg):
    assert ssid_lookalike.check(ap("Indihome-4F2A", ATTACKER), "N1", cfg) is None


def test_official_bssid_not_flagged(cfg):
    assert ssid_lookalike.check(ap("SATUAN_01", OFFICIAL_BSSID), "N1", cfg) is None


def test_hidden_and_too_short_ssids_ignored(cfg):
    assert ssid_lookalike.check(ap("", ATTACKER), "N1", cfg) is None
    cfg.thresholds["rules"]["ssid_lookalike"]["min_ssid_len"] = 20
    assert ssid_lookalike.check(ap("SATUAN_01", ATTACKER), "N1", cfg) is None


def test_max_distance_is_configurable(cfg):
    cfg.thresholds["rules"]["ssid_lookalike"]["max_distance"] = 0
    assert ssid_lookalike.check(ap("SATUAN_01", ATTACKER), "N1", cfg) is None
    assert ssid_lookalike.check(ap("satuan-01", ATTACKER), "N1", cfg)  # jarak 0 setelah lower()


def test_disabled_rule(cfg):
    cfg.thresholds["rules"]["ssid_lookalike"]["enabled"] = False
    assert ssid_lookalike.check(ap("SATUAN_01", ATTACKER), "N1", cfg) is None
