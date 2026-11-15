"""R4 — Serangan deauth/disassoc: lonjakan frame per BSSID dalam satu laporan node."""
from __future__ import annotations

from .base import make_finding

NAME = "deauth_flood"


def check(item, node, cfg):
    """`item`: {bssid, ch, deauth, disassoc, rssi, bcast} dari paket type=deauth."""
    rc = cfg.rule(NAME)
    if not rc["enabled"]:
        return None
    total = item["deauth"] + item["disassoc"]
    if total < rc["warn_frames"]:
        return None
    sev = "critical" if total >= rc["crit_frames"] else "high"
    official = item["bssid"] in cfg.whitelist.bssids
    return make_finding(
        NAME, sev,
        "Deauth flood: %s" % item["bssid"],
        "%d frame deauth/disassoc (%d+%d) untuk BSSID %s%s pada kanal %s, %s dBm%s" % (
            total, item["deauth"], item["disassoc"], item["bssid"],
            " (AP RESMI)" if official else "", item["ch"], item["rssi"],
            ", ditujukan ke broadcast" if item.get("bcast") else ""),
        key=item["bssid"], node=node, bssid=item["bssid"],
        evidence={"deauth": item["deauth"], "disassoc": item["disassoc"], "total": total,
                  "ch": item["ch"], "rssi": item["rssi"], "bcast": bool(item.get("bcast")),
                  "official": official})
