"""R1 — Evil twin: SSID resmi dipancarkan BSSID yang tidak terdaftar."""
from __future__ import annotations

from .base import make_finding

NAME = "evil_twin"


def check(ap, node, cfg):
    rc = cfg.rule(NAME)
    if not rc["enabled"]:
        return None
    entry = cfg.whitelist.ssids.get(ap["ssid"])        # peka huruf besar/kecil
    if entry is None or ap["bssid"] in entry["bssids"]:
        return None
    note = " TERBUKA (tanpa enkripsi)" if ap["sec"] == "OPEN" else ""
    return make_finding(
        NAME, rc["severity"],
        "Evil twin: %s" % ap["ssid"],
        "SSID resmi '%s' dipancarkan BSSID tak terdaftar %s (kanal %s, %s dBm, %s)%s" % (
            ap["ssid"], ap["bssid"], ap["ch"], ap["rssi"], ap["sec"], note),
        key=ap["bssid"], node=node, bssid=ap["bssid"], ssid=ap["ssid"],
        evidence={"ch": ap["ch"], "rssi": ap["rssi"], "sec": ap["sec"],
                  "official_bssids": sorted(entry["bssids"])})
