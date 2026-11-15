"""R7 — Node hilang: tidak ada paket apa pun > `node_lost_s` detik
(dicabut, dirusak, atau di-jamming)."""
from __future__ import annotations

from .base import make_finding

NAME = "node_lost"


def check(node_id, silent_s, cfg):
    rc = cfg.rule(NAME)
    if not rc["enabled"] or silent_s <= cfg.thresholds["node_lost_s"]:
        return None
    name = cfg.nodes.get(node_id, {}).get("name", node_id)
    return make_finding(
        NAME, rc["severity"],
        "Node hilang: %s" % node_id,
        "Node %s (%s) tidak melapor selama %d detik — kemungkinan dicabut, dirusak, atau di-jamming" % (
            node_id, name, int(silent_s)),
        key=node_id, node=node_id,
        evidence={"silent_s": int(silent_s), "name": name},
        cmd_nodes=["all"])
