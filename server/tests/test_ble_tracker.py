from server.rules import ble_tracker
from server.rules.ble_tracker import Tracks, classify

from .helpers import ble_item

ADDR = "c7:4a:91:3e:5b:21"


def observe(cfg, tracks, item, node="N2", cycle=1, ts=1000.0, kind=None):
    """Meniru jalur engine: klasifikasi -> hitung -> evaluasi."""
    kind = kind or classify(item, cfg)
    count = tracks.update(kind, item["addr"], node, cycle, item["rssi"], ts, cfg)
    return ble_tracker.check({"addr": item["addr"], "kind": kind, "rssi": item["rssi"], "count": count}, node, cfg)


# ---- klasifikasi tanda tangan ----
def test_classify_apple_find_my(cfg):
    assert classify(ble_item(company="004c", mtype="12"), cfg) == "apple_findmy"


def test_classify_samsung_and_tile(cfg):
    assert classify(ble_item(company=None, mtype=None, svc="fd5a"), cfg) == "samsung_smarttag"
    assert classify(ble_item(company=None, mtype=None, svc="feed"), cfg) == "tile"


def test_regular_apple_device_is_not_a_tracker(cfg):
    for mtype in ("10", "0c", "0f", "09"):
        assert classify(ble_item(company="004c", mtype=mtype), cfg) is None


def test_other_vendors_ignored(cfg):
    assert classify(ble_item(company="0006", mtype="01"), cfg) is None
    assert classify(ble_item(company=None, mtype=None, svc="fe2c"), cfg) is None


# ---- persistensi dan ambang ----
def test_needs_min_reports_across_cycles(cfg):
    t = Tracks()
    item = ble_item(addr=ADDR, rssi=-70)
    assert observe(cfg, t, item, cycle=1) is None
    assert observe(cfg, t, item, cycle=2) is None
    f = observe(cfg, t, item, cycle=3)
    assert f and f["rule"] == "ble_tracker" and f["severity"] == "medium"
    assert f["evidence"]["kind"] == "apple_findmy" and f["evidence"]["reports"] == 3


def test_same_cycle_counts_once(cfg):
    t = Tracks()
    item = ble_item(addr=ADDR)
    for _ in range(5):
        assert observe(cfg, t, item, cycle=1) is None


def test_two_nodes_in_same_cycle_both_count(cfg):
    t = Tracks()
    item = ble_item(addr=ADDR)
    observe(cfg, t, item, node="N1", cycle=1)
    observe(cfg, t, item, node="N2", cycle=1)
    assert observe(cfg, t, item, node="N3", cycle=1)       # 3 node berbeda = 3 laporan


def test_weak_signal_does_not_accumulate(cfg):
    t = Tracks()
    weak = ble_item(addr=ADDR, rssi=-90)
    for c in range(1, 10):
        assert observe(cfg, t, weak, cycle=c) is None
    strong = ble_item(addr=ADDR, rssi=-70)
    assert observe(cfg, t, strong, cycle=10) is None        # baru hitungan ke-1


def test_close_tracker_is_high(cfg):
    t = Tracks()
    item = ble_item(addr=ADDR, rssi=-55)
    observe(cfg, t, item, cycle=1)
    observe(cfg, t, item, cycle=2)
    f = observe(cfg, t, item, cycle=3)
    assert f["severity"] == "high" and f["evidence"]["close"] is True


def test_known_tracker_is_silent(cfg):
    cfg.whitelist.known_trackers.add(ADDR)
    t = Tracks()
    item = ble_item(addr=ADDR)
    for c in range(1, 6):
        assert observe(cfg, t, item, cycle=c) is None


def test_count_resets_after_stale_gap(cfg):
    t = Tracks()
    item = ble_item(addr=ADDR)
    observe(cfg, t, item, cycle=1, ts=1000)
    observe(cfg, t, item, cycle=2, ts=1006)
    stale = cfg.thresholds["inventory"]["ble_stale_s"]
    assert observe(cfg, t, item, cycle=3, ts=1006 + stale + 1) is None   # hitungan mulai dari awal


def test_rotated_mac_is_a_new_device(cfg):
    t = Tracks()
    a, b = ble_item(addr=ADDR), ble_item(addr="c7:4a:91:3e:5b:99")
    observe(cfg, t, a, cycle=1); observe(cfg, t, a, cycle=2)
    assert observe(cfg, t, b, cycle=3) is None


def test_disabled_rule(cfg):
    cfg.thresholds["rules"]["ble_tracker"]["enabled"] = False
    t = Tracks()
    item = ble_item(addr=ADDR)
    for c in range(1, 6):
        assert observe(cfg, t, item, cycle=c) is None
