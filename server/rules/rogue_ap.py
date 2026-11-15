"""R5 — Rogue AP: AP tak dikenal dengan sinyal kuat (indikasi berada di dalam area).

Tidak berlaku bila AP sudah masuk kategori lain (SSID resmi → evil_twin,
SSID mirip → ssid_lookalike), sudah resmi, atau diabaikan operator.
"""
from __future__ import annotations

from .base import make_finding
from .ssid_lookalike import find_lookalike

NAME = "rogue_ap"


def check(ap, node, cfg):
    rc = cfg.rule(NAME)
    if not rc["enabled"]:
        return None
    wl = cfg.whitelist
    if ap["rssi"] < rc["min_rssi_dbm"]:
        return None
    if ap["bssid"] in wl.bssids or ap["bssid"] in wl.ignored:
        return None
    if ap["ssid"] in wl.ssids or find_lookalike(ap["ssid"], cfg):
        return None
    name = ap["ssid"] or "(SSID tersembunyi)"
    return make_finding(
        NAME, rc["severity"],
        "AP tak dikenal: %s" % name,
        "AP %s BSSID %s berdaya kuat (%s dBm, kanal %s, %s) dan tidak terdaftar" % (
            name, ap["bssid"], ap["rssi"], ap["ch"], ap["sec"]),
        key=ap["bssid"], node=node, bssid=ap["bssid"], ssid=ap["ssid"] or None,
        evidence={"ch": ap["ch"], "rssi": ap["rssi"], "sec": ap["sec"], "hidden": not ap["ssid"]})
