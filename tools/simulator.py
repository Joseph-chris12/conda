#!/usr/bin/env python3
"""CONDA — simulator gateway.

Memancarkan JSON per baris persis seperti firmware gateway asli (lihat
docs/protokol.md §3), sehingga server dan dashboard bisa dikembangkan tanpa
hardware. 100% pasif/offline: ini hanya mencetak teks ke stdout, tidak
menyentuh radio atau jaringan.

Contoh:
    python3 tools/simulator.py --list
    python3 tools/simulator.py --scenario full_demo            # waktu nyata
    python3 tools/simulator.py --scenario evil_twin --speed 5  # 5x lebih cepat
    python3 tools/simulator.py --scenario full_demo --fast --with-ts > data/samples/raw.jsonl

Hanya standar library Python (3.8+).

Server boleh menulis perintah ke stdin simulator
(`{"cmd":"alert","node":"N1","level":3,"ttl_s":20}`); simulator membalas
`cmd_ack` dan menyalakan flag led_red/buzzer di heartbeat node terkait,
seperti gateway + node sungguhan.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
import threading
import time

# --------------------------------------------------------------------------
# Konstanta protokol (docs/protokol.md §1)
# --------------------------------------------------------------------------
PAYLOAD_MAX = 250 - 6        # ESP-NOW 250 byte dikurangi header 6 byte
AP_REC_FIXED = 10            # bssid6 ch1 rssi1 sec1 ssid_len1
DEAUTH_REC = 13
BLE_REC = 14
BLE_MAX_REPORT = 48          # sama dengan konstanta firmware node
RX_FLOOR_DBM = -92           # di bawah ini frame dianggap tidak terdengar
GW_UPTIME_OFFSET_MS = 120_000  # gateway "sudah menyala" 2 menit saat simulasi mulai

DEFAULT_CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config")

# --------------------------------------------------------------------------
# Skenario
# --------------------------------------------------------------------------
# (jenis_event, mulai_relatif_detik, selesai_relatif_detik). Waktu relatif
# terhadap --attack-at untuk skenario tunggal.
SINGLE = {
    "normal":    [],
    "evil_twin": [("evil_twin", 0, 45)],
    "downgrade": [("downgrade", 0, 45)],
    "lookalike": [("lookalike", 0, 45)],
    "deauth":    [("deauth", 0, 25)],
    "rogue":     [("rogue", 0, 45)],
    "tracker":   [("tracker", 0, 60)],
    "node_lost": [("node_lost", 0, 50)],
}

# Urutan penuh untuk demo: waktu ABSOLUT sejak simulasi dimulai.
FULL_DEMO = [
    ("evil_twin", 30, 75),
    ("deauth", 90, 115),
    ("tracker", 130, 190),
    ("node_lost", 200, 250),
    ("downgrade", 270, 315),
    ("lookalike", 330, 375),
    ("rogue", 390, 435),
]

DESCRIPTIONS = {
    "normal":    "Lalu lintas wajar: AP resmi, AP tetangga lemah, BLE latar. Tidak boleh memicu alert apa pun.",
    "evil_twin": "SSID SATUAN-01 dipancarkan BSSID asing, terbuka, sinyal kuat di dekat N1.",
    "downgrade": "BSSID resmi SATUAN-01 mendadak tampil sebagai Open.",
    "lookalike": "AP 'SATUAN_01' (garis bawah) dengan BSSID asing.",
    "deauth":    "Banjir frame deauth/disassoc ke BSSID resmi SATUAN-01, terdengar di semua node.",
    "rogue":     "AP asing 'FREE-WIFI' berdaya kuat di dekat N2.",
    "tracker":   "Apple Find My (N2), lalu Samsung SmartTag (N3), lalu Tile (N1) muncul bertahap.",
    "node_lost": "Node terakhir berhenti melapor 50 detik (dicabut/dirusak/di-jamming), lalu reboot.",
    "full_demo": "Semua skenario di atas berurutan (±7,5 menit).",
}


class Event:
    def __init__(self, kind, start, end):
        self.kind, self.start, self.end = kind, float(start), float(end)

    def active(self, t):
        return self.start <= t < self.end


# --------------------------------------------------------------------------
# Dunia simulasi
# --------------------------------------------------------------------------
def rand_mac(rng, static_random=False):
    b = [rng.randrange(256) for _ in range(6)]
    if static_random:        # dua bit teratas 11 = static random address BLE
        b[0] |= 0xC0
    return ":".join("%02x" % x for x in b)


class World:
    def __init__(self, cfg_dir, seed):
        self.rng = random.Random(seed)
        with open(os.path.join(cfg_dir, "whitelist.json"), encoding="utf-8") as f:
            wl = json.load(f)
        with open(os.path.join(cfg_dir, "nodes.json"), encoding="utf-8") as f:
            nd = json.load(f)

        self.floor = (nd["floorplan"]["width"], nd["floorplan"]["height"])
        self.nodes = [(n["id"], (n["x"], n["y"])) for n in nd["nodes"]]
        self.node_ids = [n[0] for n in self.nodes]
        self.node_pos = dict(self.nodes)

        # AP resmi: diletakkan dekat salah satu node
        self.legit = []
        chans = [1, 6, 11]
        for i, ap in enumerate(wl["aps"]):
            home = self.nodes[i % len(self.nodes)][1]
            sec = ap["security"][i % len(ap["security"])]  # bervariasi agar inventaris tampak beragam
            for j, bssid in enumerate(ap["bssids"]):
                self.legit.append({
                    "ssid": ap["ssid"], "bssid": bssid, "ch": chans[(i + j) % 3], "sec": sec,
                    "pos": (home[0] + self.rng.uniform(-40, 40), home[1] + self.rng.uniform(-40, 40)),
                })
        self.legit_by_ssid = {}
        for ap in self.legit:
            self.legit_by_ssid.setdefault(ap["ssid"], []).append(ap)

        # AP tetangga (di luar markas): lemah di semua node, tidak boleh memicu rogue_ap
        neigh_defs = [
            ("Indihome-4F2A", "5c:f4:ab:42:4f:2a", 1, "WPA2"),
            ("TP-Link_5E3C", "50:c7:bf:8d:5e:3c", 6, "WPA2"),
            ("Warung-Bu-Sri", "c8:3a:35:11:90:7e", 11, "WPA2"),
            ("Tenda_A1B2C3", "c8:3a:35:a1:b2:c3", 3, "WPA2"),
            ("", "b0:95:75:11:22:33", 11, "WPA2"),                  # SSID tersembunyi
            ("Kopi-Kenangan-Guest", "f8:1a:67:00:aa:55", 9, "OPEN"),  # terbuka tapi jauh/lemah
        ]
        self.neigh = []
        for ssid, bssid, ch, sec in neigh_defs:
            base = {nid: self.rng.randint(-93, -70) for nid in self.node_ids}
            self.neigh.append({"ssid": ssid, "bssid": bssid, "ch": ch, "sec": sec, "base": base})

        # Perangkat BLE latar (ponsel, jam tangan, dsb.) — bukan pelacak
        self.ble_bg = []
        mk = [("004c", "10"), ("004c", "0c"), ("004c", "0f"), ("004c", "09"),
              ("0006", "01"), (None, None), ("0075", "42")]
        for k in range(14):
            company, mtype = mk[k % len(mk)]
            svc = "fe2c" if (company is None and k % 2 == 0) else None
            self.ble_bg.append({
                "addr": rand_mac(self.rng, True), "atype": "random",
                "company": company, "mtype": mtype, "svc": svc,
                "info": self.rng.randrange(256),
                "pos": (self.rng.uniform(0, self.floor[0]), self.rng.uniform(0, self.floor[1])),
            })

        # state per node
        self.cycle = {nid: 0 for nid in self.node_ids}
        self.boot_t = {nid: -3600.0 for nid in self.node_ids}
        self.was_down = {nid: False for nid in self.node_ids}

    # ---- propagasi sederhana: RSSI turun linear terhadap jarak ----
    def rssi(self, pos, nid, tx=-38.0, k=0.12, sigma=2.0):
        d = math.dist(pos, self.node_pos[nid])
        r = int(round(tx - k * d + self.rng.gauss(0, sigma)))
        return r if r >= RX_FLOOR_DBM else None



# --------------------------------------------------------------------------
# Penyusun laporan per (node, siklus)
# --------------------------------------------------------------------------
def pack_aps(aps):
    """Kemas AP ke paket sesuai batas byte seperti firmware node (greedy)."""
    packets, cur, size = [], [], 0
    for ap in aps:
        rec = AP_REC_FIXED + len(ap["ssid"].encode("utf-8"))
        if cur and size + rec > PAYLOAD_MAX:
            packets.append(cur)
            cur, size = [], 0
        cur.append(ap)
        size += rec
    if cur:
        packets.append(cur)
    return packets


def chunks(seq, per):
    return [seq[i:i + per] for i in range(0, len(seq), per)]


def build_report(world, nid, t, events, alert_level_fn):
    """Kembalikan daftar (offset_detik, dict_baris) untuk satu siklus satu node."""
    rng = world.rng
    act = {}
    for e in events:
        if e.active(t):
            act[e.kind] = e

    # --- node hilang: tidak ada paket sama sekali ---
    lost = act.get("node_lost")
    if lost and nid == world.node_ids[-1]:
        world.was_down[nid] = True
        return []
    if world.was_down[nid]:                      # baru pulih => reboot
        world.was_down[nid] = False
        world.boot_t[nid] = t
        world.cycle[nid] = 0

    world.cycle[nid] = (world.cycle[nid] + 1) & 0xFFFF
    lines = []

    # ---------------- AP ----------------
    aps = []
    for ap in world.legit:
        sec = ap["sec"]
        if "downgrade" in act and ap["ssid"] == "SATUAN-01" and ap is world.legit_by_ssid["SATUAN-01"][0]:
            sec = "OPEN"
        r = world.rssi(ap["pos"], nid)
        if r is not None:
            aps.append({"ssid": ap["ssid"], "bssid": ap["bssid"], "ch": ap["ch"], "rssi": r, "sec": sec})
    for n in world.neigh:
        if rng.random() < 0.85:
            r = n["base"][nid] + rng.randint(-2, 2)
            if r >= RX_FLOOR_DBM:
                entry = {"ssid": n["ssid"], "bssid": n["bssid"], "ch": n["ch"], "rssi": r, "sec": n["sec"]}
                if n["ssid"] == "":
                    entry["hidden"] = True
                aps.append(entry)

    def attacker_ap(ssid, bssid, ch, sec, pos):
        r = world.rssi(pos, nid, tx=-36.0)
        if r is not None:
            aps.append({"ssid": ssid, "bssid": bssid, "ch": ch, "rssi": r, "sec": sec})

    if "evil_twin" in act:
        attacker_ap("SATUAN-01", "aa:bb:cc:dd:ee:01", 6, "OPEN", (170, 150))   # dekat N1
    if "lookalike" in act:
        attacker_ap("SATUAN_01", "aa:bb:cc:dd:ee:02", 11, "WPA2", (430, 170))
    if "rogue" in act:
        attacker_ap("FREE-WIFI", "02:ca:fe:00:00:07", 1, "OPEN", (440, 140))

    for pk in pack_aps(aps):
        lines.append({"t": "ap", "aps": pk})

    # ---------------- DEAUTH ----------------
    items = []
    if "deauth" in act:
        target = world.legit_by_ssid["SATUAN-01"][0]
        pos = (150, 100)
        r = world.rssi(pos, nid, tx=-36.0)
        if r is not None:
            factor = max(0.0, min(1.0, (r + 90) / 45.0))
            total = int(max(0, rng.gauss(45, 8) * factor))
            if total > 0:
                dis = int(total * 0.1)
                items.append({"bssid": target["bssid"], "ch": target["ch"], "deauth": total - dis,
                              "disassoc": dis, "rssi": r, "bcast": rng.random() < 0.8})
    elif rng.random() < 0.05:                    # derau normal: 1–3 frame, jauh di bawah ambang
        ap = rng.choice(world.legit)
        items.append({"bssid": ap["bssid"], "ch": ap["ch"], "deauth": rng.randint(1, 3), "disassoc": 0,
                      "rssi": rng.randint(-75, -55), "bcast": False})
    for pk in chunks(items, (PAYLOAD_MAX) // DEAUTH_REC):
        lines.append({"t": "deauth", "items": pk})

    # ---------------- BLE ----------------
    ble = []
    for d in world.ble_bg:
        if rng.random() < 0.7:
            r = world.rssi(d["pos"], nid, tx=-45.0, k=0.15, sigma=4.0)
            if r is not None:
                ble.append({"addr": d["addr"], "atype": d["atype"], "rssi": r, "company": d["company"],
                            "mtype": d["mtype"], "svc": d["svc"], "info": d["info"]})
    trk = act.get("tracker")
    if trk:
        rel = t - trk.start
        devs = [  # (mulai_rel, addr, company, mtype, svc, info, pos)
            (0, "c7:4a:91:3e:5b:21", "004c", "12", None, 16, (440, 150)),   # Apple Find My dekat N2
            (20, "e8:3a:12:77:90:ab", None, None, "fd5a", 0, (310, 380)),   # SmartTag dekat N3
            (35, "f1:00:5c:2d:c4:09", None, None, "feed", 0, (150, 140)),   # Tile dekat N1
        ]
        for start, addr, company, mtype, svc, info, pos in devs:
            if rel >= start and rng.random() < 0.9:
                r = world.rssi(pos, nid, tx=-45.0, k=0.15, sigma=3.0)
                if r is not None:
                    ble.append({"addr": addr, "atype": "random", "rssi": r, "company": company,
                                "mtype": mtype, "svc": svc, "info": info})
    ble.sort(key=lambda x: -x["rssi"])
    ble = ble[:BLE_MAX_REPORT]
    for pk in chunks(ble, PAYLOAD_MAX // BLE_REC):
        lines.append({"t": "ble", "items": pk})

    # ---------------- HEARTBEAT ----------------
    lvl = alert_level_fn(nid)
    lines.append({
        "t": "hb", "uptime_s": int(t - world.boot_t[nid]) if world.boot_t[nid] > -3600 else 3600 + int(t),
        "heap_kb": 182 + rng.randint(-3, 3), "cycle_ms": 5800 + rng.randint(-150, 150), "fw": 1,
        "led_red": lvl > 0, "buzzer": lvl >= 2,
    })
    return [(0.05 * i, ln) for i, ln in enumerate(lines)]


# --------------------------------------------------------------------------
# Penjadwal & keluaran
# --------------------------------------------------------------------------
class Emitter:
    """Menulis baris JSON ke stdout dengan aman terhadap banyak thread."""

    def __init__(self, out):
        self.out, self.lock = out, threading.Lock()

    def emit(self, obj):
        data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n"
        with self.lock:
            self.out.write(data)
            self.out.flush()


def main(argv=None):
    p = argparse.ArgumentParser(description="Simulator gateway CONDA (pengganti gateway ESP32).")
    p.add_argument("--scenario", default="full_demo", choices=sorted(list(SINGLE) + ["full_demo"]))
    p.add_argument("--list", action="store_true", help="tampilkan daftar skenario lalu keluar")
    p.add_argument("--speed", type=float, default=1.0, help="kelipatan kecepatan waktu nyata (default 1)")
    p.add_argument("--fast", action="store_true", help="tanpa menunggu (untuk membuat rekaman/tes); otomatis --with-ts")
    p.add_argument("--with-ts", action="store_true", help="sertakan `ts` epoch pada tiap baris (default: server yang mengisi)")
    p.add_argument("--start-ts", type=float, default=None, help="epoch awal untuk --with-ts (default: sekarang)")
    p.add_argument("--cycle", type=float, default=5.8, help="detik per siklus node (default 5.8)")
    p.add_argument("--attack-at", type=float, default=15.0, help="detik sebelum serangan pada skenario tunggal (default 15)")
    p.add_argument("--duration", type=float, default=None, help="lama simulasi (detik virtual); default = panjang skenario")
    p.add_argument("--forever", action="store_true", help="lanjut dengan lalu lintas normal tanpa batas")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--config-dir", default=DEFAULT_CONFIG_DIR)
    a = p.parse_args(argv)

    if a.list:
        for name in sorted(list(SINGLE) + ["full_demo"]):
            print("%-10s %s" % (name, DESCRIPTIONS[name]))
        return 0

    if a.fast:
        a.with_ts = True
    if a.speed <= 0:
        p.error("--speed harus > 0")

    if a.scenario == "full_demo":
        events = [Event(k, s, e) for k, s, e in FULL_DEMO]
    else:
        events = [Event(k, a.attack_at + s, a.attack_at + e) for k, s, e in SINGLE[a.scenario]]
    end_of_events = max([e.end for e in events], default=0.0)
    duration = a.duration if a.duration is not None else max(60.0, end_of_events + 20.0)

    world = World(a.config_dir, a.seed)
    n_nodes = len(world.nodes)
    out = Emitter(sys.stdout)
    start_ts = a.start_ts if a.start_ts is not None else time.time()

    # ---- status LED/buzzer yang ditetapkan perintah server ----
    alert_state = {}            # nid -> (level, kedaluwarsa_detik_virtual)
    now_v = [0.0]
    state_lock = threading.Lock()

    def alert_level(nid):
        with state_lock:
            lvl, exp = alert_state.get(nid, (0, 0))
            return lvl if (lvl > 0 and now_v[0] < exp) else 0

    def stdin_reader():
        for raw in sys.stdin:
            raw = raw.strip()
            if not raw:
                continue
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if msg.get("cmd") != "alert":
                continue
            node, level = msg.get("node", "all"), int(msg.get("level", 0))
            ttl = float(msg.get("ttl_s", 20))
            targets = world.node_ids if node in ("all", "ALL") else [node]
            with state_lock:
                for nid in targets:
                    alert_state[nid] = (level, now_v[0] + ttl)
            out.emit({"v": 1, "t": "gw", "event": "cmd_ack", "node": node, "level": level,
                      "gw_ms": int(now_v[0] * 1000) + GW_UPTIME_OFFSET_MS})

    if not a.fast and not sys.stdin.isatty():
        threading.Thread(target=stdin_reader, daemon=True).start()

    # ---- ringkasan ke stderr (stdout dijaga hanya berisi JSON) ----
    sys.stderr.write("[sim] skenario=%s node=%s durasi=%ss kecepatan=%s%s\n" % (
        a.scenario, ",".join(world.node_ids), "∞" if a.forever else int(duration), a.speed, " (fast)" if a.fast else ""))
    for e in events:
        sys.stderr.write("[sim]   t=%5.0f–%-5.0f %s\n" % (e.start, e.end, e.kind))

    def stamp(line, t, nid=None, cycle=None):
        d = {"v": 1, "t": line["t"]}
        if nid is not None:
            d["node"] = nid
            d["cycle"] = cycle
        d["gw_ms"] = int(t * 1000) + GW_UPTIME_OFFSET_MS
        if nid is not None:
            d["src"] = "24:6f:28:aa:bb:%02x" % (world.node_ids.index(nid) + 1)
        if a.with_ts:
            d["ts"] = round(start_ts + t, 3)
        for k, v in line.items():
            if k != "t":
                d[k] = v
        return d

    wall0 = time.monotonic()

    def wait_until(t):
        if a.fast:
            return
        delay = wall0 + t / a.speed - time.monotonic()
        if delay > 0:
            time.sleep(delay)

    try:
        out.emit(stamp({"t": "gw", "event": "boot", "fw": 1, "channel": 1}, 0.0))
        c = 0
        while a.forever or c * a.cycle < duration:
            batch = []
            for idx, (nid, _) in enumerate(world.nodes):
                t0 = c * a.cycle + idx * (a.cycle / n_nodes) + world.rng.uniform(-0.25, 0.25) + 0.5
                for off, line in build_report(world, nid, t0, events, alert_level):
                    batch.append((t0 + off, nid, line))
            batch.sort(key=lambda x: x[0])
            for t, nid, line in batch:
                wait_until(t)
                now_v[0] = t
                out.emit(stamp(line, t, nid, world.cycle[nid]))
            c += 1
    except (BrokenPipeError, KeyboardInterrupt):
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
