"""R6 — Pelacak BLE asing (Apple Find My, Samsung SmartTag, Tile).

Node hanya melaporkan advertiser mentah; pencocokan tanda tangan ada di sini
(config/thresholds.json -> ble_signatures) sehingga bisa diubah tanpa flash ulang.

Pelacak sering berganti MAC, jadi identitas dihitung per (jenis, alamat) dan
sebuah pelacak baru dilaporkan setelah terlihat di >= `min_reports` siklus
node yang berbeda dengan sinyal cukup kuat.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from .base import make_finding

NAME = "ble_tracker"


def classify(item: Dict[str, Any], cfg) -> Optional[str]:
    """Nama jenis pelacak bila `item` cocok dengan salah satu tanda tangan, selain itu None."""
    for kind, sig in cfg.thresholds["ble_signatures"].items():
        fields = [k for k in ("company", "mtype", "svc") if k in sig]
        if fields and all(item.get(k) == sig[k] for k in fields):
            return kind
    return None


class Tracks:
    """Hitungan penampakan per (jenis, alamat) lintas siklus."""

    def __init__(self):
        self._t: Dict[tuple, Dict[str, Any]] = {}

    def update(self, kind, addr, node, cycle, rssi, ts, cfg) -> int:
        rc = cfg.rule(NAME)
        stale = cfg.thresholds.get("inventory", {}).get("ble_stale_s", 300)
        e = self._t.get((kind, addr))
        if e is None or ts - e["last_ts"] > stale:
            e = {"count": 0, "cycles": {}, "last_ts": ts}
            self._t[(kind, addr)] = e
        e["last_ts"] = ts
        # tiap (node, siklus) dihitung sekali, dan hanya bila sinyalnya cukup kuat
        if rssi >= rc["min_rssi_dbm"] and e["cycles"].get(node) != cycle:
            e["cycles"][node] = cycle
            e["count"] += 1
        return e["count"]


def check(dev, node, cfg):
    """`dev`: {addr, kind, rssi, count} (count dari Tracks.update)."""
    rc = cfg.rule(NAME)
    if not rc["enabled"]:
        return None
    if dev["addr"] in cfg.whitelist.known_trackers:
        return None
    if dev["count"] < rc["min_reports"] or dev["rssi"] < rc["min_rssi_dbm"]:
        return None
    label = cfg.thresholds["ble_signatures"][dev["kind"]].get("label", dev["kind"])
    close = dev["rssi"] >= rc["close_rssi_dbm"]
    return make_finding(
        NAME, rc["severity_close"] if close else rc["severity"],
        "Pelacak BLE asing: %s" % label,
        "%s (%s) terlihat %d siklus, %s dBm di %s%s" % (
            label, dev["addr"], dev["count"], dev["rssi"], node, " — SANGAT DEKAT" if close else ""),
        key="%s:%s" % (dev["kind"], dev["addr"]), node=node,
        evidence={"kind": dev["kind"], "addr": dev["addr"], "rssi": dev["rssi"],
                  "reports": dev["count"], "close": close})
