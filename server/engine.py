"""Mesin deteksi: menerima baris JSON dari gateway, menjalankan aturan,
memelihara inventaris/status node, dan menghasilkan event untuk dashboard.

Engine bersifat sinkron dan tidak tahu soal jaringan/serial; I/O ada di
app.py dan sources.py. Semua waktu memakai `ts` pada pesan bila ada
(simulator/tes/replay) sehingga hasilnya deterministik.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional

from . import rules
from .config import SEV_LEVEL, Config, is_mac, norm_mac
from .db import Database
from .rules import ble_tracker, node_lost

log = logging.getLogger("conda.engine")

Event = Dict[str, Any]
_FIX_ALERT_RULES = ("evil_twin", "rogue_ap", "ssid_lookalike", "sec_downgrade")
_BEST_WINDOW_S = 30        # RSSI terbaik dihitung dari laporan node 30 detik terakhir
_RSSI_EMIT_DELTA = 4       # selisih RSSI minimal agar dikirim ulang ke dashboard
_DB_WRITE_EVERY_S = 15


class Engine:
    def __init__(self, cfg: Config, db: Database,
                 send_cmd: Optional[Callable[[Dict[str, Any]], None]] = None,
                 clock: Callable[[], float] = time.time):
        self.cfg, self.db, self.send_cmd, self.clock = cfg, db, send_cmd, clock
        self.start_ts = clock()
        self._virtual = False          # True bila pesan terakhir membawa `ts` sendiri
        self.latest_ts = self.start_ts
        self._first_msg = True
        self._last_node_check = 0.0

        self.nodes: Dict[str, Dict[str, Any]] = {}
        for nid, n in cfg.nodes.items():
            self.nodes[nid] = {"node": nid, "name": n.get("name", nid), "x": n.get("x"), "y": n.get("y"),
                               "state": "unknown", "last_seen": None, "uptime_s": None, "heap_kb": None,
                               "lost": False}
        self.aps: Dict[str, Dict[str, Any]] = {}
        self.ble: Dict[str, Dict[str, Any]] = {}
        self.tracks = ble_tracker.Tracks()
        self.last_fire: Dict[tuple, tuple] = {}            # (rule, key) -> (ts, level) alert terakhir
        self.active: Dict[tuple, Dict[str, Any]] = {}      # kondisi yang sedang berlangsung
        self.cmd_sent: Dict[str, tuple] = {}               # node -> (level, ts)
        self.unknown_nodes: set = set()
        self.stats = {"lines": 0, "bad_lines": 0, "bad_items": 0, "unknown_node_lines": 0, "ble_other": 0}
        self._rehydrate()

    # ------------------------------------------------------------------ util
    def _rehydrate(self) -> None:
        """Muat inventaris dari SQLite agar tidak kosong setelah restart."""
        for r in self.db.load_aps():
            r.update(hidden=bool(r["hidden"]), per_node={}, status="unknown", _db_ts=0.0)
            self.aps[r["bssid"]] = r
        for r in self.db.load_ble():
            r.update(_db_ts=0.0)
            self.ble[r["addr"]] = r
        for a in self.aps.values():
            a["status"] = self._ap_status(a["bssid"])

    def _now(self) -> float:
        return self.latest_ts if self._virtual else self.clock()

    @staticmethod
    def _best(per_node: Dict[str, tuple], now: float):
        recent = {n: v for n, v in per_node.items() if now - v[1] <= _BEST_WINDOW_S}
        pool = recent or per_node
        if not pool:
            return None, None
        node, (rssi, _) = max(pool.items(), key=lambda kv: kv[1][0])
        return rssi, node

    # ------------------------------------------------------------ public views
    def _node_event(self, nid: str) -> Event:
        n = self.nodes[nid]
        return {"t": "node_status", **{k: v for k, v in n.items() if k != "lost"}}

    @staticmethod
    def _ap_public(a: Dict[str, Any]) -> Dict[str, Any]:
        keys = ("ssid", "bssid", "ch", "sec", "hidden", "rssi_best", "node_best", "first_seen", "last_seen", "status")
        return {k: a.get(k) for k in keys}

    def _ble_public(self, b: Dict[str, Any]) -> Dict[str, Any]:
        sig = self.cfg.thresholds["ble_signatures"].get(b["kind"], {})
        return {"addr": b["addr"], "kind": b["kind"], "label": sig.get("label", b["kind"]),
                "rssi_best": b["rssi_best"], "node_best": b["node_best"], "first_seen": b["first_seen"],
                "last_seen": b["last_seen"], "reports": b["reports"],
                "foreign": b["addr"] not in self.cfg.whitelist.known_trackers}

    def snapshot(self) -> Event:
        return {
            "t": "snapshot", "server_ts": self._now(),
            "nodes": [{k: v for k, v in self._node_event(n).items() if k != "t"} for n in self.nodes],
            "aps": sorted((self._ap_public(a) for a in self.aps.values()), key=lambda a: -(a["last_seen"] or 0)),
            "ble": sorted((self._ble_public(b) for b in self.ble.values()), key=lambda b: -(b["last_seen"] or 0)),
            "alerts": self.db.recent_alerts(50),
            "floorplan": self.cfg.nodes_cfg["floorplan"],
            "whitelist": self.cfg.whitelist.public(),
            "stats": dict(self.stats),
        }

    # ---------------------------------------------------------------- ingest
    def handle_line(self, raw: str) -> List[Event]:
        raw = raw.strip()
        if not raw:
            return []
        try:
            msg = json.loads(raw)
        except ValueError:
            self.stats["bad_lines"] += 1       # log debug firmware biasa muncul di serial
            log.debug("baris non-JSON diabaikan: %.80s", raw)
            return []
        if not isinstance(msg, dict) or msg.get("v") != 1 or "t" not in msg:
            self.stats["bad_lines"] += 1
            return []
        try:
            return self.handle(msg)
        except Exception:                      # satu pesan rusak tidak boleh menjatuhkan server
            self.stats["bad_lines"] += 1
            log.exception("gagal memproses pesan: %.200s", raw)
            return []

    def handle(self, msg: Dict[str, Any]) -> List[Event]:
        ts = msg.get("ts")
        self._virtual = ts is not None
        if ts is None:
            ts = self.clock()
        if self._first_msg and self._virtual:
            self.start_ts = ts                 # masa tenggang node dihitung dari awal rekaman
        self._first_msg = False
        self.latest_ts = ts
        self.stats["lines"] += 1

        events: List[Event] = []
        mtype = msg["t"]
        if mtype == "gw":
            log.info("gateway: %s", {k: v for k, v in msg.items() if k not in ("v", "t")})
            return events

        nid = msg.get("node")
        if nid not in self.nodes:
            self.stats["unknown_node_lines"] += 1
            if nid not in self.unknown_nodes:
                self.unknown_nodes.add(nid)
                log.warning("node tak dikenal %r diabaikan (tidak ada di nodes.json)", nid)
            return events

        self._drop_bad_macs(msg)
        self._touch_node(nid, msg, ts, events)
        if mtype == "ap":
            self._on_ap(msg, nid, ts, events)
        elif mtype == "deauth":
            for item in msg.get("items", []):
                f = rules.deauth_flood.check(item, nid, self.cfg)
                if f:
                    self._fire(f, ts, events)
        elif mtype == "ble":
            self._on_ble(msg, nid, ts, events)
        elif mtype != "hb":
            log.debug("tipe pesan tak dikenal: %s", mtype)

        if ts - self._last_node_check >= self.cfg.thresholds["node_check_interval_s"]:
            self._check_nodes(ts, events)
        self._refresh(ts, events)
        if mtype == "hb" and not any(e["t"] == "node_status" and e["node"] == nid for e in events):
            events.append(self._node_event(nid))
        return events

    def _drop_bad_macs(self, msg: Dict[str, Any]) -> None:
        """Buang item ber-MAC cacat. Byte hilang di jalur serial bisa menghasilkan JSON yang tetap valid tetapi
        berisi MAC rusak (mis. 'da:279a'); tanpa ini ia menjadi AP/perangkat hantu dan memicu alert palsu."""
        for key, field in (("aps", "bssid"), ("items", "bssid"), ("items", "addr")):
            items = msg.get(key)
            if not isinstance(items, list):
                continue
            keep = []
            for it in items:
                if not isinstance(it, dict) or field not in it:
                    keep.append(it)
                elif is_mac(it[field]):
                    it[field] = norm_mac(it[field])
                    keep.append(it)
                else:
                    self.stats["bad_items"] += 1
                    log.debug("item dengan %s cacat dibuang: %.60r", field, it.get(field))
            msg[key] = keep

    def tick(self, now: Optional[float] = None) -> List[Event]:
        """Dipanggil berkala: mendeteksi node yang diam (tidak ada pesan masuk)."""
        now = self._now() if now is None else now
        events: List[Event] = []
        self._check_nodes(now, events)
        self._refresh(now, events)
        return events

    # ----------------------------------------------------------------- nodes
    def _touch_node(self, nid: str, msg: Dict[str, Any], ts: float, events: List[Event]) -> None:
        n = self.nodes[nid]
        n["last_seen"] = ts
        if msg["t"] == "hb":
            n["uptime_s"], n["heap_kb"] = msg.get("uptime_s"), msg.get("heap_kb")
        if n["lost"]:                          # node kembali melapor
            n["lost"] = False
            self.active.pop(("node_lost", nid), None)
            self.cmd_sent.pop(nid, None)
            alert = self._store_alert({
                "ts": ts, "rule": "node_lost", "severity": "low", "title": "Node pulih: %s" % nid,
                "detail": "Node %s (%s) kembali melapor" % (nid, n["name"]), "node": nid,
                "bssid": None, "ssid": None, "evidence": {"recovered": True}})
            events.append(alert)

    def _check_nodes(self, ts: float, events: List[Event]) -> None:
        self._last_node_check = ts
        for nid, n in self.nodes.items():
            if n["lost"]:
                continue
            ref = n["last_seen"] if n["last_seen"] is not None else self.start_ts
            f = node_lost.check(nid, ts - ref, self.cfg)
            if f:
                n["lost"] = True
                self._fire(f, ts, events)

    # ------------------------------------------------------------- AP / BLE
    def _on_ap(self, msg, nid, ts, events) -> None:
        for ap in msg.get("aps", []):
            ap.setdefault("hidden", ap.get("ssid", "") == "")
            for rule in rules.AP_RULES:
                f = rule.check(ap, nid, self.cfg)
                if f:
                    self._fire(f, ts, events)
            self._upsert_ap(ap, nid, ts, events)

    def _upsert_ap(self, ap, nid, ts, events) -> None:
        b = ap["bssid"]
        rec = self.aps.get(b)
        new = rec is None
        if new:
            rec = {"bssid": b, "first_seen": ts, "per_node": {}, "status": "unknown",
                   "rssi_best": None, "node_best": None, "_db_ts": 0.0}
            self.aps[b] = rec
        changed = new or any(rec.get(k) != ap[k] for k in ("ssid", "ch", "sec"))
        rec.update(ssid=ap["ssid"], ch=ap["ch"], sec=ap["sec"], hidden=bool(ap.get("hidden")), last_seen=ts)
        rec["per_node"][nid] = (ap["rssi"], ts)
        best, node_best = self._best(rec["per_node"], ts)
        delta = rec["rssi_best"] is None or abs(best - rec["rssi_best"]) >= _RSSI_EMIT_DELTA
        rec["rssi_best"], rec["node_best"] = best, node_best
        status = self._ap_status(b)
        changed = changed or status != rec["status"]
        rec["status"] = status
        if changed or delta:
            events.append({"t": "ap_update", **self._ap_public(rec)})
        if changed or ts - rec["_db_ts"] >= _DB_WRITE_EVERY_S:
            rec["_db_ts"] = ts
            self.db.upsert_ap(rec)

    def _ap_status(self, bssid: str) -> str:
        if any(e.get("bssid") == bssid for e in self.active.values()):
            return "suspect"
        return "official" if bssid in self.cfg.whitelist.bssids else "unknown"

    def _on_ble(self, msg, nid, ts, events) -> None:
        cycle = msg.get("cycle")
        for item in msg.get("items", []):
            kind = ble_tracker.classify(item, self.cfg)
            if kind is None:
                self.stats["ble_other"] += 1
                continue
            addr = norm_mac(item["addr"])
            count = self.tracks.update(kind, addr, nid, cycle, item["rssi"], ts, self.cfg)
            rec = self.ble.get(addr)
            if rec is None:
                rec = {"addr": addr, "kind": kind, "first_seen": ts, "per_node": {}, "_db_ts": 0.0}
                self.ble[addr] = rec
            rec.setdefault("per_node", {})[nid] = (item["rssi"], ts)
            rec["rssi_best"], rec["node_best"] = self._best(rec["per_node"], ts)
            rec.update(kind=kind, last_seen=ts, reports=count)
            events.append({"t": "ble_update", **self._ble_public(rec)})
            if ts - rec["_db_ts"] >= _DB_WRITE_EVERY_S:
                rec["_db_ts"] = ts
                self.db.upsert_ble(rec)
            f = ble_tracker.check({"addr": addr, "kind": kind, "rssi": item["rssi"], "count": count}, nid, self.cfg)
            if f:
                self._fire(f, ts, events)

    # ---------------------------------------------------------------- alerts
    def _store_alert(self, alert: Dict[str, Any]) -> Event:
        alert["id"] = self.db.insert_alert(alert)
        alert["acked"] = False
        return {"t": "alert", **alert}

    def _fire(self, f: Dict[str, Any], ts: float, events: List[Event]) -> None:
        """Catat kondisi aktif (selalu) dan keluarkan alert (kecuali masih cooldown)."""
        k = (f["rule"], f["key"])
        prev = self.active.get(k)
        nodes = set(prev["nodes"]) if prev else set()
        nodes.add(f["node"])
        self.active[k] = {"rule": f["rule"], "severity": f["severity"], "nodes": nodes, "ts": ts,
                          "bssid": f.get("bssid"), "cmd_nodes": set(f["cmd_nodes"])}
        last = self.last_fire.get(k)
        level = SEV_LEVEL[f["severity"]]
        # cooldown menahan alert berulang, tetapi kenaikan severity (mis. deauth high -> critical)
        # harus tetap dilaporkan
        if last is None or ts - last[0] >= self.cfg.rule(f["rule"])["cooldown_s"] or level > last[1]:
            self.last_fire[k] = (ts, level)
            evidence = dict(f["evidence"], nodes=sorted(nodes))
            events.append(self._store_alert({
                "ts": ts, "rule": f["rule"], "severity": f["severity"], "title": f["title"],
                "detail": f["detail"], "node": f["node"], "bssid": f.get("bssid"),
                "ssid": f.get("ssid"), "evidence": evidence}))
        self._command(f["cmd_nodes"], ts)

    def _command(self, targets: List[str], ts: float) -> None:
        """Nyalakan LED/buzzer di node sesuai severity tertinggi yang aktif untuknya."""
        if self.send_cmd is None:
            return
        ttl = self.cfg.thresholds["alert_command_ttl_s"]
        real = [n for n, v in self.nodes.items() if not v["lost"]] if "all" in targets else targets
        for nid in real:
            if nid not in self.nodes or self.nodes[nid]["lost"]:
                continue
            level = max([SEV_LEVEL[e["severity"]] for e in self.active.values()
                         if nid in e["cmd_nodes"] or "all" in e["cmd_nodes"]] or [0])
            last = self.cmd_sent.get(nid)
            if level > 0 and (last is None or last[0] != level or ts - last[1] >= ttl / 2):
                self.cmd_sent[nid] = (level, ts)
                try:
                    self.send_cmd({"cmd": "alert", "node": nid, "level": level, "ttl_s": ttl})
                except Exception:
                    log.exception("gagal mengirim perintah ke gateway")

    # ----------------------------------------------------------- state refresh
    def _refresh(self, ts: float, events: List[Event]) -> None:
        ttl = self.cfg.thresholds["alert_ttl_s"]
        for k in [k for k, e in self.active.items() if ts - e["ts"] > ttl]:
            del self.active[k]
        for nid, n in self.nodes.items():
            if n["lost"]:
                state = "lost"
            elif n["last_seen"] is None:
                state = "unknown"
            else:
                lv = max([SEV_LEVEL[e["severity"]] for e in self.active.values() if nid in e["nodes"]] or [0])
                state = "alert" if lv >= SEV_LEVEL["high"] else "warn" if lv == SEV_LEVEL["medium"] else "ok"
            if state != n["state"]:
                n["state"] = state
                events.append(self._node_event(nid))
        for a in self.aps.values():
            st = self._ap_status(a["bssid"])
            if st != a["status"]:
                a["status"] = st
                events.append({"t": "ap_update", **self._ap_public(a)})

    # ------------------------------------------------------- aksi operator
    def promote(self, bssid: str, ssid: Optional[str] = None, security: Optional[List[str]] = None) -> List[Event]:
        bssid = norm_mac(bssid)
        rec = self.aps.get(bssid)
        ssid = ssid if ssid is not None else (rec["ssid"] if rec else "")
        if security is None:
            security = [rec["sec"]] if rec and rec["sec"] != "UNKNOWN" else ["WPA2"]
        self.cfg.promote(bssid, ssid, security)
        for k in [k for k, e in self.active.items() if e["rule"] in _FIX_ALERT_RULES and e.get("bssid") == bssid]:
            del self.active[k]
        events: List[Event] = [{"t": "config_changed", "whitelist": self.cfg.whitelist.public()}]
        self._refresh(self._now(), events)
        return events

    def ignore(self, bssid: str) -> List[Event]:
        bssid = norm_mac(bssid)
        self.cfg.ignore(bssid)
        for k in [k for k, e in self.active.items() if e["rule"] == "rogue_ap" and e.get("bssid") == bssid]:
            del self.active[k]
        events: List[Event] = [{"t": "config_changed", "whitelist": self.cfg.whitelist.public()}]
        self._refresh(self._now(), events)
        return events

    def ack(self, alert_id: int) -> bool:
        return self.db.ack_alert(alert_id)

    def clear_alarms(self) -> List[Event]:
        """Padamkan alarm fisik di semua node dan bersihkan kondisi aktif.
        Bila ancamannya masih ada, kondisi akan muncul lagi pada laporan berikutnya."""
        self.active.clear()
        self.cmd_sent.clear()
        if self.send_cmd is not None:
            self.send_cmd({"cmd": "alert", "node": "all", "level": 0, "ttl_s": 0})
        events: List[Event] = []
        self._refresh(self._now(), events)
        return events
