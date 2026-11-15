#!/usr/bin/env python3
"""Membuat rekaman replay (data/samples/*.jsonl) tanpa hardware dan tanpa menunggu.

Menjalankan simulator dalam mode --fast (waktu virtual), memasukkan keluarannya ke Engine
yang sama dengan server, lalu menulis tiap event WebSocket dengan field `at` (detik sejak awal).
Format: docs/protokol.md §7.

    python tools/make_sample.py                              # data/samples/demo.jsonl (full_demo)
    python tools/make_sample.py --scenario evil_twin --out data/samples/evil_twin.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, ROOT)

from server.config import Config          # noqa: E402
from server.db import Database            # noqa: E402
from server.engine import Engine          # noqa: E402

START_TS = 1_700_000_000.0                # epoch tetap supaya rekaman deterministik


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Buat rekaman replay dari simulator")
    p.add_argument("--scenario", default="full_demo")
    p.add_argument("--out", default=os.path.join(ROOT, "data", "samples", "demo.jsonl"))
    p.add_argument("--seed", type=int, default=7)
    a = p.parse_args(argv)

    sim = os.path.join(ROOT, "tools", "simulator.py")
    raw = subprocess.run(
        [sys.executable, "-I", sim, "--scenario", a.scenario, "--fast", "--start-ts", str(START_TS), "--seed", str(a.seed)],
        capture_output=True, text=True, check=True).stdout

    engine = Engine(Config(), Database(":memory:"), clock=lambda: START_TS)
    rows = [dict(engine.snapshot(), at=0.0)]
    for line in raw.splitlines():
        try:
            ts = json.loads(line).get("ts", START_TS)
        except ValueError:
            continue
        at = round(ts - START_TS, 3)
        for ev in engine.handle_line(line):
            rows.append(dict(ev, at=at))

    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n")
    alerts = [r for r in rows if r["t"] == "alert"]
    print("%s: %d event, %d alert, durasi %.0f detik, %d KB" % (
        a.out, len(rows), len(alerts), rows[-1]["at"], os.path.getsize(a.out) // 1024))
    return 0


if __name__ == "__main__":
    sys.exit(main())
