"""Aturan deteksi CONDA. Tiap modul = satu aturan, fungsi `check(...)` murni
sehingga mudah diuji. Semantik lengkap: docs/protokol.md §5."""
from . import (ble_tracker, deauth_flood, evil_twin, node_lost, rogue_ap,
               sec_downgrade, ssid_lookalike)

# Aturan yang dievaluasi untuk tiap AP pada paket `ap`. Urutan tidak penting:
# kondisinya saling eksklusif (lihat docstring tiap modul).
AP_RULES = (evil_twin, sec_downgrade, ssid_lookalike, rogue_ap)

RULE_NAMES = (evil_twin.NAME, sec_downgrade.NAME, ssid_lookalike.NAME, deauth_flood.NAME,
              rogue_ap.NAME, ble_tracker.NAME, node_lost.NAME)
