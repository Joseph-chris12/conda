"""Pembaca serial: semburan basi saat port dibuka harus dibuang sampai aliran tenang."""
from server.sources import SerialSource


class FakeSerial:
    """Port palsu: menyemburkan `burst_polls` pembacaan data basi, lalu hening."""

    def __init__(self, burst_polls):
        self.left = burst_polls
        self.read_bytes = 0
        self.resets = 0
        self.lines_read = 0

    @property
    def in_waiting(self):
        if self.left > 0:
            self.left -= 1
            return 4096
        return 0

    def read(self, n):
        self.read_bytes += n
        return b"}\n" * (n // 2)

    def reset_input_buffer(self):
        self.resets += 1

    def readline(self):
        self.lines_read += 1
        return b""


def test_drain_consumes_whole_burst_then_stops():
    ser = FakeSerial(burst_polls=40)
    SerialSource._drain_open_burst(ser, min_s=0.05, quiet_s=0.05, max_s=2.0)
    assert ser.left == 0                      # seluruh semburan terbaca dan dibuang
    assert ser.read_bytes == 40 * 4096
    assert ser.resets >= 2 and ser.lines_read == 1


def test_drain_returns_quickly_on_quiet_port():
    ser = FakeSerial(burst_polls=0)
    SerialSource._drain_open_burst(ser, min_s=0.05, quiet_s=0.05, max_s=2.0)
    assert ser.read_bytes == 0


def test_drain_gives_up_on_endless_stream():
    ser = FakeSerial(burst_polls=10 ** 9)     # tak pernah tenang
    SerialSource._drain_open_burst(ser, min_s=0.01, quiet_s=0.05, max_s=0.2)
    assert ser.read_bytes > 0                 # kembali setelah batas atas, tidak menggantung


def test_pick_free_port_skips_busy_port():
    import socket
    from server.__main__ import pick_free_port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    busy = s.getsockname()[1]
    try:
        got = pick_free_port("127.0.0.1", busy)
        assert got is not None and got != busy
    finally:
        s.close()
