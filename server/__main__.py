"""Titik masuk CLI: `python -m server --sim full_demo` (lihat --help)."""
from __future__ import annotations

import argparse
import logging
import sys

from .app import DEFAULT_DB, create_app
from .config import ConfigError
from .sources import SerialSource, StdinSource, SubprocessSource


def pick_free_port(host: str, first: int, tries: int = 20):
    """Port TCP bebas pertama mulai dari `first`, atau None. Memeriksa dengan bind sungguhan pada `host`
    (dan pada semua antarmuka bila host lokal), karena proses lain bisa memegang port yang sama di IPv6."""
    import socket
    for port in range(first, first + tries):
        ok = True
        for fam, addr in ((socket.AF_INET, host or "127.0.0.1"), (socket.AF_INET6, "::")):
            s = socket.socket(fam, socket.SOCK_STREAM)
            try:
                s.bind((addr, port))
            except OSError as e:
                if fam == socket.AF_INET or e.errno in (48, 98, 10048):     # IPv6 tak tersedia bukan alasan menolak
                    ok = False
            finally:
                s.close()
            if not ok:
                break
        if ok:
            return port
    return None


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m server", description="Server deteksi CONDA")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--serial", metavar="PORT", nargs="?", const="auto",
                     help="baca dari gateway ESP32 di port serial (default: auto-deteksi)")
    src.add_argument("--sim", metavar="SKENARIO", nargs="?", const="full_demo",
                     help="jalankan tools/simulator.py sebagai pengganti gateway (default: full_demo)")
    src.add_argument("--stdin", action="store_true", help="baca JSON dari stdin")
    p.add_argument("--sim-speed", type=float, default=1.0, help="kecepatan simulator (default 1)")
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument("--host", default="127.0.0.1", help="gunakan 0.0.0.0 agar dashboard bisa dibuka dari laptop lain")
    p.add_argument("--port", type=int, default=None,
                   help="port HTTP (default: 8000, atau yang bebas berikutnya bila 8000 terpakai)")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--fresh", action="store_true", help="hapus database sebelum mulai")
    p.add_argument("--record", metavar="FILE", help="rekam event WebSocket ke JSONL (untuk mode replay)")
    p.add_argument("--config-dir", default=None)
    p.add_argument("--log-level", default="INFO")
    a = p.parse_args(argv)

    logging.basicConfig(level=a.log_level.upper(), format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    if a.serial is not None:
        source = SerialSource(a.serial, a.baud)
    elif a.sim is not None:
        source = SubprocessSource(a.sim, a.sim_speed)
    elif a.stdin:
        source = StdinSource()
    else:
        source = None

    import uvicorn
    port = a.port
    if port is None:                       # tidak ditentukan: pakai 8000, atau cari yang bebas
        port = pick_free_port(a.host, 8000)
        if port is None:
            print("Tidak ada port bebas di 8000-8019; tentukan sendiri dengan --port", file=sys.stderr)
            return 2
        if port != 8000:
            print("Port 8000 sedang dipakai proses lain; memakai port %d." % port, file=sys.stderr)
    try:
        app = create_app(a.config_dir, a.db, source, a.record, a.fresh)
    except ConfigError as e:
        print("Konfigurasi bermasalah: %s" % e, file=sys.stderr)
        return 2
    print("\n  Dasbor CONDA:  http://%s:%d\n" % ("127.0.0.1" if a.host in ("0.0.0.0", "") else a.host, port), flush=True)
    uvicorn.run(app, host=a.host, port=port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
