"""Penyimpanan SQLite: riwayat alert, inventaris AP, dan perangkat BLE."""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any, Dict, List

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    rule      TEXT NOT NULL,
    severity  TEXT NOT NULL,
    title     TEXT NOT NULL,
    detail    TEXT NOT NULL,
    node      TEXT,
    bssid     TEXT,
    ssid      TEXT,
    evidence  TEXT NOT NULL DEFAULT '{}',
    acked     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS aps (
    bssid      TEXT PRIMARY KEY,
    ssid       TEXT NOT NULL,
    ch         INTEGER,
    sec        TEXT,
    hidden     INTEGER NOT NULL DEFAULT 0,
    rssi_best  INTEGER,
    node_best  TEXT,
    first_seen REAL,
    last_seen  REAL
);
CREATE TABLE IF NOT EXISTS ble (
    addr       TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    rssi_best  INTEGER,
    node_best  TEXT,
    reports    INTEGER,
    first_seen REAL,
    last_seen  REAL
);
"""


class Database:
    def __init__(self, path: str = ":memory:"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            if path != ":memory:":
                self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def close(self) -> None:
        with self.lock:
            self.conn.close()

    # ---------------- alerts ----------------
    def insert_alert(self, a: Dict[str, Any]) -> int:
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO alerts(ts,rule,severity,title,detail,node,bssid,ssid,evidence) VALUES (?,?,?,?,?,?,?,?,?)",
                (a["ts"], a["rule"], a["severity"], a["title"], a["detail"], a.get("node"),
                 a.get("bssid"), a.get("ssid"), json.dumps(a.get("evidence", {}), ensure_ascii=False)))
            self.conn.commit()
            return int(cur.lastrowid)

    @staticmethod
    def _alert_row(r: sqlite3.Row) -> Dict[str, Any]:
        d = dict(r)
        d["evidence"] = json.loads(d["evidence"])
        d["acked"] = bool(d["acked"])
        return d

    def recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [self._alert_row(r) for r in rows]

    def ack_alert(self, alert_id: int) -> bool:
        with self.lock:
            cur = self.conn.execute("UPDATE alerts SET acked=1 WHERE id=?", (alert_id,))
            self.conn.commit()
            return cur.rowcount > 0

    # ---------------- inventaris ----------------
    def upsert_ap(self, r: Dict[str, Any]) -> None:
        with self.lock:
            self.conn.execute(
                """INSERT INTO aps(bssid,ssid,ch,sec,hidden,rssi_best,node_best,first_seen,last_seen)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(bssid) DO UPDATE SET ssid=excluded.ssid, ch=excluded.ch, sec=excluded.sec,
                     hidden=excluded.hidden, rssi_best=excluded.rssi_best, node_best=excluded.node_best,
                     last_seen=excluded.last_seen""",
                (r["bssid"], r["ssid"], r["ch"], r["sec"], int(bool(r.get("hidden"))), r["rssi_best"],
                 r["node_best"], r["first_seen"], r["last_seen"]))
            self.conn.commit()

    def load_aps(self) -> List[Dict[str, Any]]:
        with self.lock:
            return [dict(r) for r in self.conn.execute("SELECT * FROM aps")]

    def upsert_ble(self, r: Dict[str, Any]) -> None:
        with self.lock:
            self.conn.execute(
                """INSERT INTO ble(addr,kind,rssi_best,node_best,reports,first_seen,last_seen)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(addr) DO UPDATE SET kind=excluded.kind, rssi_best=excluded.rssi_best,
                     node_best=excluded.node_best, reports=excluded.reports, last_seen=excluded.last_seen""",
                (r["addr"], r["kind"], r["rssi_best"], r["node_best"], r["reports"], r["first_seen"], r["last_seen"]))
            self.conn.commit()

    def load_ble(self) -> List[Dict[str, Any]]:
        with self.lock:
            return [dict(r) for r in self.conn.execute("SELECT * FROM ble")]
