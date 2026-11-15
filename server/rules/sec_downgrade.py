"""R2 — Downgrade keamanan: BSSID resmi tampil dengan keamanan yang tidak diizinkan.

Hanya BSSID yang terdaftar yang dinilai di sini; BSSID asing dengan SSID resmi
ditangani `evil_twin` (supaya satu AP tidak memicu dua alert). Keamanan
`UNKNOWN` (parser node gagal mengenali) tidak dinilai agar tidak menimbulkan
alarm palsu.
"""
from __future__ import annotations

from .base import make_finding

NAME = "sec_downgrade"


def check(ap, node, cfg):
    rc = cfg.rule(NAME)
    if not rc["enabled"]:
        return None
    entry = cfg.whitelist.ssids.get(ap["ssid"])
    if entry is None or ap["bssid"] not in entry["bssids"]:
        return None
    sec = ap["sec"]
    if sec == "UNKNOWN" or sec in entry["security"]:
        return None
    is_open = sec == "OPEN"
    return make_finding(
        NAME, rc["severity_open"] if is_open else rc["severity_other"],
        "Downgrade keamanan: %s" % ap["ssid"],
        "AP resmi %s (%s) kini tampil sebagai %s; seharusnya %s" % (
            ap["bssid"], ap["ssid"], sec, "/".join(sorted(entry["security"]))),
        key=ap["bssid"], node=node, bssid=ap["bssid"], ssid=ap["ssid"],
        evidence={"ch": ap["ch"], "rssi": ap["rssi"], "sec": sec,
                  "expected": sorted(entry["security"])})
