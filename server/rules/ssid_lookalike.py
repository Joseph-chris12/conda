"""R3 — SSID mirip SSID resmi (typosquatting), mis. SATUAN-01 vs SATUAN_01."""
from __future__ import annotations

from typing import Optional, Tuple

from .base import make_finding

NAME = "ssid_lookalike"


def levenshtein(a: str, b: str) -> int:
    """Jarak edit (sisip/hapus/ganti), DP dua baris."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def find_lookalike(ssid: str, cfg) -> Optional[Tuple[str, int]]:
    """(ssid_resmi, jarak) terdekat bila `ssid` mirip tetapi tidak identik; selain itu None.
    Dipakai juga oleh rogue_ap untuk tidak melaporkan ganda."""
    rc = cfg.rule(NAME)
    wl = cfg.whitelist
    if not ssid or ssid in wl.ssids or len(ssid) < rc["min_ssid_len"]:
        return None
    best = None
    for official in wl.ssids:
        d = levenshtein(ssid.lower(), official.lower())
        if d <= rc["max_distance"] and (best is None or d < best[1]):
            best = (official, d)
    return best


def check(ap, node, cfg):
    rc = cfg.rule(NAME)
    if not rc["enabled"] or ap["bssid"] in cfg.whitelist.bssids:
        return None
    hit = find_lookalike(ap["ssid"], cfg)
    if hit is None:
        return None
    official, dist = hit
    return make_finding(
        NAME, rc["severity"],
        "SSID mirip: %s ~ %s" % (ap["ssid"], official),
        "SSID '%s' (BSSID %s, kanal %s, %s dBm, %s) mirip SSID resmi '%s' (jarak edit %d)" % (
            ap["ssid"], ap["bssid"], ap["ch"], ap["rssi"], ap["sec"], official, dist),
        key=ap["bssid"], node=node, bssid=ap["bssid"], ssid=ap["ssid"],
        evidence={"official": official, "distance": dist, "ch": ap["ch"], "rssi": ap["rssi"], "sec": ap["sec"]})
