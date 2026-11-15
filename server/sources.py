"""Sumber baris data: gateway USB serial, simulator (subprocess), atau stdin."""
from __future__ import annotations

import glob
import json
import logging
import os
import subprocess
import sys
import threading
import time
from typing import Callable, Optional

log = logging.getLogger("conda.source")

SIMULATOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools", "simulator.py")


class LineSource:
    """Antarmuka: `start(on_line)` memanggil `on_line(str)` dari thread lain;
    `write(dict)` mengirim perintah ke gateway."""
    name = "none"

    def start(self, on_line: Callable[[str], None]) -> None:  # pragma: no cover - antarmuka
        pass

    def write(self, cmd: dict) -> None:
        pass

    def stop(self) -> None:
        pass


def find_serial_port() -> Optional[str]:
    """Cari port USB-serial ESP32 (macOS: cu.usbserial*/cu.SLAB*/cu.wchusbserial*; Linux: ttyUSB*/ttyACM*)."""
    patterns = ["/dev/cu.usbserial*", "/dev/cu.SLAB_USBtoUART*", "/dev/cu.wchusbserial*",
                "/dev/cu.usbmodem*", "/dev/ttyUSB*", "/dev/ttyACM*"]
    for p in patterns:
        found = sorted(glob.glob(p))
        if found:
            return found[0]
    return None


class SerialSource(LineSource):
    def __init__(self, port: str = "auto", baud: int = 115200):
        self.port, self.baud = port, baud
        self.name = "serial:%s" % port
        self._stop = threading.Event()
        self._ser = None
        self._wlock = threading.Lock()

    def start(self, on_line):
        threading.Thread(target=self._run, args=(on_line,), daemon=True, name="serial-reader").start()

    def _run(self, on_line):
        import serial  # impor di sini agar tes tanpa pyserial tetap jalan
        while not self._stop.is_set():
            port = find_serial_port() if self.port == "auto" else self.port
            if not port:
                log.warning("port serial gateway belum ditemukan; mencoba lagi...")
                self._stop.wait(2)
                continue
            try:
                with serial.Serial(port, self.baud, timeout=1) as ser:
                    self._ser = ser
                    log.info("terhubung ke gateway di %s @ %d", port, self.baud)
                    self._drain_open_burst(ser)
                    while not self._stop.is_set():
                        raw = ser.readline()
                        if raw:
                            on_line(raw.decode("utf-8", "replace"))
            except (serial.SerialException, OSError) as e:
                log.warning("serial terputus (%s); mencoba lagi dalam 2 detik", e)
            finally:
                self._ser = None
            self._stop.wait(2)

    @staticmethod
    def _drain_open_burst(ser, min_s: float = 0.8, quiet_s: float = 0.5, max_s: float = 10.0) -> None:
        """Buang data sesaat setelah port dibuka, sampai aliran tenang. Driver USB-serial (CP210x di macOS)
        kadang menyemburkan fragmen basi yang diulang-ulang selama beberapa detik sejak port dibuka (terukur:
        ±4 detik, >60.000 'baris' non-JSON, tidak selalu terjadi). Data nyata yang ikut terbuang paling banyak
        satu siklus node. Baris pertama sesudahnya bisa terpotong; parser membuangnya seperti baris rusak lain."""
        t0 = time.monotonic()
        last = t0
        ser.reset_input_buffer()
        while True:
            now = time.monotonic()
            if now - t0 >= max_s:              # dicek lebih dulu: aliran yang tak pernah berhenti tak boleh menahan kita
                log.warning("aliran serial tak kunjung tenang setelah %.1f detik; lanjut membaca", max_s)
                break
            n = ser.in_waiting
            if n:
                ser.read(n)
                last = now
            elif now - t0 >= min_s and now - last >= quiet_s:
                break
            else:
                time.sleep(0.02)
        ser.reset_input_buffer()
        ser.readline()                     # buang sisa baris yang mungkin terpotong

    def write(self, cmd):
        with self._wlock:
            if self._ser is not None:
                self._ser.write((json.dumps(cmd, separators=(",", ":")) + "\n").encode())

    def stop(self):
        self._stop.set()


class SubprocessSource(LineSource):
    """Menjalankan tools/simulator.py sebagai pengganti gateway."""

    def __init__(self, scenario: str = "full_demo", speed: float = 1.0, extra=()):
        self.argv = [sys.executable, "-u", SIMULATOR, "--scenario", scenario, "--speed", str(speed),
                     "--forever", *extra]
        self.name = "sim:%s" % scenario
        self.proc: Optional[subprocess.Popen] = None

    def start(self, on_line):
        self.proc = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True, bufsize=1)
        threading.Thread(target=self._run, args=(on_line,), daemon=True, name="sim-reader").start()

    def _run(self, on_line):
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            on_line(line)
        log.info("simulator berhenti")

    def write(self, cmd):
        if self.proc and self.proc.stdin and self.proc.poll() is None:
            try:
                self.proc.stdin.write(json.dumps(cmd, separators=(",", ":")) + "\n")
                self.proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()


class StdinSource(LineSource):
    """Membaca baris dari stdin, mis. `python tools/simulator.py | python -m server --stdin`.
    Perintah ke gateway tidak bisa dikirim lewat mode ini."""
    name = "stdin"

    def start(self, on_line):
        def run():
            for line in sys.stdin:
                on_line(line)
            log.info("stdin habis")
        threading.Thread(target=run, daemon=True, name="stdin-reader").start()
