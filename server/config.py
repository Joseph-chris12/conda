"""Pemuatan konfigurasi (whitelist, ambang, node) dari file JSON.

Tidak ada nilai yang di-hardcode di kode deteksi: semuanya berasal dari
config/*.json sehingga aturan bisa diubah tanpa flash ulang firmware.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Set

SEV_LEVEL = {"low": 0, "medium": 1, "high": 2, "critical": 3}
VALID_SEC = {"OPEN", "WEP", "WPA", "WPA2", "WPA3_TRANSITION", "WPA3", "ENTERPRISE", "UNKNOWN"}
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")

DEFAULT_CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config")


class ConfigError(Exception):
    """Berkas konfigurasi hilang atau tidak valid."""


_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def norm_mac(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


def is_mac(mac: object) -> bool:
    """True bila `mac` berbentuk aa:bb:cc:dd:ee:ff (juga menerima huruf besar dan tanda '-')."""
    return isinstance(mac, str) and _MAC_RE.match(norm_mac(mac)) is not None


def _load(path: str) -> Dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise ConfigError("Berkas konfigurasi tidak ditemukan: %s" % path)
    except ValueError as e:
        raise ConfigError("JSON tidak valid di %s: %s" % (path, e))


class Whitelist:
    """Tampilan terindeks dari whitelist.json."""

    def __init__(self, data: Dict[str, Any]):
        self.data = data
        # ssid -> {"bssids": set, "security": set}  (entri ber-SSID sama digabung)
        self.ssids: Dict[str, Dict[str, Set[str]]] = {}
        self.bssids: Set[str] = set()
        for ap in data.get("aps", []):
            entry = self.ssids.setdefault(ap["ssid"], {"bssids": set(), "security": set()})
            for b in ap["bssids"]:
                entry["bssids"].add(norm_mac(b))
                self.bssids.add(norm_mac(b))
            entry["security"].update(ap["security"])
        self.ignored: Set[str] = {norm_mac(b) for b in data.get("ignored_bssids", [])}
        self.known_trackers: Set[str] = {norm_mac(b) for b in data.get("known_trackers", [])}

    def public(self) -> List[Dict[str, Any]]:
        return [{"ssid": s, "bssids": sorted(e["bssids"]), "security": sorted(e["security"])}
                for s, e in sorted(self.ssids.items())]


class Config:
    def __init__(self, cfg_dir: Optional[str] = None):
        self.dir = os.path.abspath(cfg_dir or DEFAULT_CONFIG_DIR)
        self.reload()

    def reload(self) -> None:
        self.thresholds = _load(os.path.join(self.dir, "thresholds.json"))
        self.nodes_cfg = _load(os.path.join(self.dir, "nodes.json"))
        self.whitelist = Whitelist(_load(self._wl_path))
        self.nodes = {n["id"]: n for n in self.nodes_cfg["nodes"]}
        for key in ("node_lost_s", "alert_ttl_s", "alert_command_ttl_s", "node_check_interval_s", "rules", "ble_signatures"):
            if key not in self.thresholds:
                raise ConfigError("thresholds.json: kunci '%s' tidak ada" % key)

    @property
    def _wl_path(self) -> str:
        return os.path.join(self.dir, "whitelist.json")

    def rule(self, name: str) -> Dict[str, Any]:
        try:
            return self.thresholds["rules"][name]
        except KeyError:
            raise ConfigError("thresholds.json: aturan '%s' tidak ada" % name)

    # ---- perubahan whitelist oleh operator (tombol "jadikan resmi") ----
    def _write_whitelist(self) -> None:
        data = self.whitelist.data
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".whitelist.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.write("\n")
            os.replace(tmp, self._wl_path)      # atomik: tidak ada file setengah jadi
        except Exception:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        self.whitelist = Whitelist(data)

    def promote(self, bssid: str, ssid: str, security: Iterable[str]) -> None:
        bssid = norm_mac(bssid)
        security = list(security)
        if not MAC_RE.match(bssid):
            raise ValueError("BSSID tidak valid: %s" % bssid)
        if not ssid:
            raise ValueError("SSID kosong (AP tersembunyi tidak bisa dijadikan resmi tanpa SSID)")
        bad = [s for s in security if s not in VALID_SEC]
        if bad or not security:
            raise ValueError("Jenis keamanan tidak valid: %s" % (bad or "kosong"))
        data = self.whitelist.data
        for ap in data["aps"]:
            if ap["ssid"] == ssid:
                if bssid not in [norm_mac(b) for b in ap["bssids"]]:
                    ap["bssids"].append(bssid)
                for s in security:
                    if s not in ap["security"]:
                        ap["security"].append(s)
                break
        else:
            data["aps"].append({"ssid": ssid, "bssids": [bssid], "security": security,
                                "note": "Ditambahkan operator lewat dashboard"})
        data["ignored_bssids"] = [b for b in data.get("ignored_bssids", []) if norm_mac(b) != bssid]
        self._write_whitelist()

    def ignore(self, bssid: str) -> None:
        bssid = norm_mac(bssid)
        if not MAC_RE.match(bssid):
            raise ValueError("BSSID tidak valid: %s" % bssid)
        ign = self.whitelist.data.setdefault("ignored_bssids", [])
        if bssid not in [norm_mac(b) for b in ign]:
            ign.append(bssid)
            self._write_whitelist()
