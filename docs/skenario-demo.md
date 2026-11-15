# Skenario demo CONDA

Naskah peragaan ±8 menit. Tiga jalur, dari yang paling aman ke yang paling meyakinkan:

1. **Replay** — tanpa server, tanpa perangkat; untuk juri yang hanya membuka tautan.
2. **Simulator** — server sungguhan + data sintetis; alarm suara dan alur aksi operator berjalan penuh.
3. **Perangkat keras** — node ESP32 sungguhan + kondisi uji yang dibuat tim di lab sendiri.

> Seluruh pengujian serangan dilakukan **manual di lab milik tim**. CONDA dan simulatornya tidak memancarkan serangan apa pun.

## Persiapan (5 menit sebelum tampil)

1. `./.venv/bin/python -m pytest -q` → `122 passed`.
2. Jalankan server (pilih satu):
   - Simulator: `./.venv/bin/python -m server --sim full_demo --fresh`
   - Perangkat keras: `./.venv/bin/python -m server --serial --fresh`
3. Buka http://127.0.0.1:8000, **klik sekali di halaman** (izin suara), nyalakan volume.
4. Siapkan cadangan: tab kedua dengan `?mode=replay&file=demo.jsonl` bila server atau perangkat bermasalah.

## Alur simulator `full_demo` (waktu dari awal)

| Detik | Kejadian | Yang terlihat | Yang dijelaskan |
|---|---|---|---|
| 0 | Lalu lintas normal | Semua node hijau, AP resmi, BLE latar | CONDA tidak mengganggu — nol alarm palsu |
| ±32 | **Evil twin** `SATUAN-01` | Alert *critical*, N1 merah, sirene 2 nada | SSID resmi dipancarkan BSSID asing, terbuka, dekat N1 |
| ±91 → 99 | **Banjir deauth** | *high* lalu naik ke *critical* | Eskalasi severity menembus cooldown |
| ±142 → 175 | **Pelacak BLE** Apple → Samsung → Tile | Peringatan medium → high | Format iklan Find My / SmartTag / Tile; node terkuat = lokasi kasar |
| ±227 → 254 | **Node hilang** N3, lalu pulih | *high*, node abu-abu, node lain ikut berbunyi; lalu *low* "node pulih" | Sensor dicabut/dijamming tidak lolos diam-diam |
| ±271 | **Downgrade keamanan** | *critical* — BSSID resmi mendadak Open | Deteksi tanpa perlu SSID baru |
| ±331 | **SSID mirip** `SATUAN_01` | *high* | Levenshtein ≤ 2 |
| ±391 | **Rogue AP** `FREE-WIFI` | *medium* | AP asing berdaya kuat |

Skenario tunggal untuk demo singkat: `--sim evil_twin`, `--sim deauth`, `--sim tracker`, dst. (`tools/simulator.py --list`).
Percepat: `--sim-speed 3` (tetapi `node_lost` memakai jam server sehingga tidak akan terpicu pada kecepatan > 1).

### Aksi operator untuk diperagakan
- **Tandai dilihat** pada sebuah alert.
- **Jadikan resmi** pada AP asing → dialog konfirmasi (menjadikan evil twin resmi = melegitimasi penyerang), whitelist tertulis ke `config/whitelist.json`.
- **Abaikan** AP tetangga.
- **Matikan alarm** → semua node padam.

> Setelah memeragakan "Jadikan resmi" pada server sungguhan, kembalikan `config/whitelist.json` ke keadaan semula.

## Kondisi uji di lab (perangkat keras) — dibuat manual oleh tim

Semua memakai perangkat milik tim di ruang tertutup; CONDA hanya mengamati.

| Deteksi | Cara membuat kondisi (manual) | Harapan |
|---|---|---|
| `evil_twin` / `ssid_lookalike` | Aktifkan hotspot ponsel/router cadangan **milik tim** dengan SSID sama (atau `SATUAN_01`) dengan BSSID yang tidak di whitelist | Alert dalam 1–2 siklus (±6–12 detik) |
| `sec_downgrade` | Pada AP lab yang ada di whitelist, ubah keamanan ke Open sebentar | Alert *critical* |
| `rogue_ap` | Dekatkan hotspot ponsel dengan SSID lain ke node | Alert *medium* bila ≥ −55 dBm |
| `ble_tracker` | Dekatkan AirTag/SmartTag/Tile asli milik tim ke node, tunggu ≥ 3 siklus | Alert *medium/high* |
| `node_lost` | Cabut daya salah satu node | Alert *high* setelah 30 detik |
| `deauth_flood` | **Tidak** dibuat dengan alat serangan. Cukup peragakan di simulator/replay; bila tim punya lingkungan lab terisolasi yang sah, lakukan di sana atas tanggung jawab tim | — |

Sebelum uji perangkat keras: ganti BSSID contoh di `config/whitelist.json`, dan pastikan node tampil **Normal**
(bukan "Menunggu laporan") di dasbor. Jika tautan ESP-NOW belum pernah diuji, lakukan satu kali uji jarak (node di ruangan
yang akan dipakai) sebelum hari demo.

## Rekam sesi nyata untuk replay

```bash
./.venv/bin/python -m server --serial --fresh --record data/samples/lab.jsonl
```

Lalu buka `http://127.0.0.1:8000/?mode=replay&file=lab.jsonl` atau `python tools/build_static.py` untuk situs statis.

## Bila ada yang gagal saat demo

| Masalah | Tindakan |
|---|---|
| Papan tidak terdeteksi | Pindah ke `--sim full_demo` — dasbor dan alurnya identik |
| Server error | Buka tab replay cadangan |
| Tidak ada internet / Wi-Fi | Tidak masalah; seluruh sistem offline |
| Suara tidak keluar | Klik halaman sekali; periksa volume dan izin situs |
