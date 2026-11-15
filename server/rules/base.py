"""Bentuk hasil temuan (finding) yang dihasilkan semua aturan."""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def make_finding(rule: str, severity: str, title: str, detail: str, key: str, node: str,
                 bssid: Optional[str] = None, ssid: Optional[str] = None,
                 evidence: Optional[Dict[str, Any]] = None,
                 cmd_nodes: Optional[List[str]] = None) -> Dict[str, Any]:
    """`key` dipakai untuk cooldown dan pelacakan kondisi aktif.
    `cmd_nodes`: node yang diperintah menyalakan alarm (default: node pelapor;
    ["all"] = semua node yang masih hidup)."""
    return {
        "rule": rule, "severity": severity, "title": title, "detail": detail,
        "key": key, "node": node, "bssid": bssid, "ssid": ssid,
        "evidence": evidence or {}, "cmd_nodes": cmd_nodes or [node],
    }
