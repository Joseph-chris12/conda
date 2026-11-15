# CONDA — Sensor Pemantau Ancaman Wi-Fi & Bluetooth untuk Area Markas

> Sensor *pasif* 2.4 GHz berbiaya rendah yang berjaga di udara area markas: mengenali jaringan palsu,
> serangan deauth, dan pelacak BLE asing, lalu memberi peringatan lokal (LED + buzzer) dan di dasbor komando.

Kartika Cyber Hackathon 2026 (PUSSIBERAD × CODEPOLITAN) · Kategori **Penangkalan** · Tim **Elit Siber Protokol**

**Coba tanpa perangkat keras (±2 menit):** lihat [Cara menjalankan](#cara-menjalankan) → "Mode replay" atau "Mode simulator".

---

## 1. Latar belakang

Jaringan nirkabel markas dilindungi kata sandi, tetapi hampir tidak ada yang *melihat* apa yang terjadi di udara:

- **Evil twin / rogue AP** — penyerang memancarkan SSID yang sama dengan jaringan resmi (atau mirip, mis. `SATUAN_01`),
  personel tersambung tanpa sadar, dan lalu lintasnya terbaca.
- **Penurunan keamanan** — AP resmi mendadak tampil tanpa enkripsi (Open) atau turun ke mode lemah.
- **Serangan deauth** — banjir frame pemutus koneksi, dipakai untuk memaksa klien pindah ke AP palsu atau mengganggu layanan.
- **Pelacak BLE** (AirTag, SmartTag, Tile) yang diselipkan ke kendaraan, tas, atau perlengkapan untuk memantau pergerakan.
- **Sensor yang dicabut/dirusak** — sistem pemantau yang diam-diam mati sama bahayanya dengan serangannya sendiri.

Perangkat pemantau komersial (WIDS/WIPS) mahal, butuh AP khusus, dan kerap terhubung ke layanan cloud — tidak cocok untuk
lingkungan militer yang terisolasi. CONDA mengambil jalan lain: **node ESP32 seharga puluhan ribu rupiah**, server tunggal di
laptop, **berjalan 100% offline**.

## 2. Prinsip rancangan

| Prinsip | Wujudnya |
|---|---|
| **Pasif sepenuhnya** | Node hanya *mendengarkan* (mode promiscuous + scan BLE pasif). Tidak ada kode yang mengirim deauth, beacon palsu, jamming, atau serangan apa pun. Satu-satunya pemancaran adalah laporan ESP-NOW ke gateway. Pengujian serangan dilakukan manual oleh tim di lab sendiri. |
| **Offline** | Tidak ada CDN, API cloud, atau telemetri. Dasbor memakai JavaScript murni; semua dependensi dapat dipasang dari berkas wheel lokal ([docs/instalasi.md](docs/instalasi.md)). |
| **Node bodoh, server pintar** | Node hanya mengumpulkan data mentah. Seluruh logika deteksi ada di server, sehingga aturan dan ambang bisa diubah tanpa flash ulang firmware. |
| **Konfigurasi terpisah dari kode** | Daftar AP resmi, ambang, tanda tangan BLE, dan posisi node ada di `config/*.json`. |
| **Teruji** | 130 unit/integrasi test (satu berkas per aturan) + simulator yang mendemonstrasikan tiap skenario. |

## 3. Arsitektur

```
 ┌─────────────┐  ESP-NOW (kanal 1)  ┌──────────────┐  USB serial   ┌────────────────────────────┐
 │ Node N1..N3 │ ───────────────────▶│  Gateway     │ ─ JSON/baris ▶│ Server Python (FastAPI)    │
 │ ESP32       │                     │  ESP32       │               │  • aturan deteksi          │
 │ Wi-Fi sniff │◀── perintah alarm ──│  (di laptop) │◀─ perintah ───│  • SQLite  • WebSocket     │
 │ + BLE scan  │                     └──────────────┘               └─────────────┬──────────────┘
 │ LED + buzzer│                                                                  │ WebSocket /ws
 └─────────────┘                                                    ┌─────────────▼──────────────┐
                                                                    │ Dasbor web (HTML/JS murni) │
                                                                    │ denah • tabel AP/BLE • feed│
                                                                    │ alarm suara • mode replay  │
                                                                    └────────────────────────────┘
```

Ringkasnya: ESP32 **Node** memindai udara → **Gateway** ESP32 menerima lewat ESP-NOW dan meneruskannya sebagai satu baris JSON
per paket lewat USB → **Server** menjalankan aturan deteksi, menyimpan ke SQLite, dan mendorong hasil ke **Dasbor** lewat WebSocket.
Saat ada ancaman, server memerintahkan node terdekat menyalakan LED merah dan buzzer.

Detail: [docs/arsitektur.md](docs/arsitektur.md) · Spesifikasi protokol & aturan: [docs/protokol.md](docs/protokol.md)

### Siklus kerja node (±5,3 detik)

1. **Scan Wi-Fi** — hop kanal 1–13 (±150 ms/kanal): baca beacon/probe-response (SSID, BSSID, kanal, RSSI, jenis enkripsi dari RSN/WPA IE) dan hitung frame deauth/disassoc per BSSID.
2. **Scan BLE** pasif ±3 detik (NimBLE): alamat, RSSI, *manufacturer data*, UUID layanan.
3. **Lapor** — kembali ke kanal gateway, kirim paket AP/DEAUTH/BLE + heartbeat via ESP-NOW, lalu dengar perintah alarm ±300 ms.

### Deteksi

| Aturan | Memicu bila | Severity |
|---|---|---|
| `evil_twin` | SSID resmi dipancarkan BSSID yang tidak terdaftar | critical |
| `sec_downgrade` | BSSID resmi tampil dengan enkripsi di luar yang diizinkan (Open → critical) | critical/high |
| `ssid_lookalike` | SSID mirip SSID resmi (jarak Levenshtein ≤ 2), BSSID asing | high |
| `deauth_flood` | frame deauth/disassoc ≥ 10 (high) atau ≥ 40 (critical) per laporan | high/critical |
| `rogue_ap` | AP tak dikenal dengan sinyal kuat (≥ −55 dBm) | medium |
| `ble_tracker` | Perangkat berformat Apple Find My / Samsung SmartTag / Tile terlihat berulang | medium/high |
| `node_lost` | Node diam > 30 detik (dicabut, rusak, atau di-jamming) | high |

Semantik lengkap (cooldown, eskalasi severity, kasus tepi) ada di [docs/protokol.md §5](docs/protokol.md).

### Respons

| Level | Tindakan di node |
|---|---|
| medium | LED merah menyala |
| high | LED merah + buzzer putus-putus |
| critical | LED merah + buzzer terus-menerus |

Saat sebuah node dinyatakan hilang, server memerintahkan node lain yang masih hidup untuk memberi peringatan. Dasbor
membunyikan alarm suara (WebAudio, tanpa berkas audio eksternal) yang sepadan dengan severity.

## 4. Struktur repositori

```
conda/
├── config/          whitelist.json · thresholds.json · nodes.json (denah & posisi node)
├── docs/            protokol.md · arsitektur.md · instalasi.md · skenario-demo.md
├── firmware/
│   ├── common/      conda_proto.h  (format paket bersama node & gateway)
│   ├── gateway/     PlatformIO: ESP-NOW → serial JSON, serial → perintah alarm
│   └── node/        PlatformIO: sniffer Wi-Fi + scan BLE + alarm (env node1..node3)
├── server/          FastAPI, mesin aturan, SQLite, sumber data (serial/simulator), test
├── dashboard/       index.html · app.js · style.css (tanpa dependensi)
├── tools/           simulator.py · make_sample.py · build_static.py
└── data/samples/    demo.jsonl (rekaman untuk mode replay)
```

## 5. Persiapan

Butuh **Python 3.9+**. Dari folder `conda/`:

```bash
python3 -m venv .venv
```

```bash
./.venv/bin/pip install -r requirements.txt
```

Tanpa internet: lihat bagian "Pemasangan offline" di [docs/instalasi.md](docs/instalasi.md).

Uji bahwa semuanya sehat:

```bash
./.venv/bin/python -m pytest -q
```

Hasil yang diharapkan: `130 passed`.

## 6. Cara menjalankan

### a. Mode simulator (tanpa ESP32) — demo penuh dengan alarm suara

```bash
./.venv/bin/python -m server --sim full_demo --fresh
```

Buka **http://127.0.0.1:8000**. Klik di halaman sekali agar browser mengizinkan suara. Simulator memutar semua skenario
berurutan (±7,5 menit): lalu lintas normal → evil twin → deauth → pelacak BLE → node hilang → penurunan keamanan → SSID mirip → rogue AP.
Skenario tunggal: `--sim evil_twin` (daftar: `./.venv/bin/python tools/simulator.py --list`).

### b. Mode perangkat keras (gateway + node ESP32)

1. Flash gateway dan node — langkah rinci di [docs/instalasi.md](docs/instalasi.md).
2. Colokkan gateway ke laptop, lalu:

```bash
./.venv/bin/python -m server --serial --fresh
```

Port terdeteksi otomatis; paksa dengan `--serial /dev/cu.usbserial-0001` (macOS) atau `--serial COM5` (Windows).
Server menyambung ulang sendiri bila kabel tercabut.

**Hanya punya satu ESP32?** Flash node dengan env `node1usb` (mode USB-langsung: node juga mencetak JSON berformat gateway ke
USB), lalu `./.venv/bin/python -m server --serial --config-dir config/lab-1node --fresh`. Lihat
[docs/instalasi.md](docs/instalasi.md#mode-usb-langsung-satu-papan-tanpa-gateway--untuk-uji-dan-demo).

### c. Mode replay (untuk juri / tanpa server)

Dasbor yang sama memutar ulang rekaman `data/samples/demo.jsonl` dengan kontrol jeda, kecepatan, dan lompat ke kejadian.

- **Lewat server:** `./.venv/bin/python -m server --sim normal` lalu buka `http://127.0.0.1:8000/?mode=replay&file=demo.jsonl`
- **Situs statis** (GitHub Pages, hosting apa pun, atau buka berkas): 

```bash
./.venv/bin/python tools/build_static.py
```

  Unggah isi folder `dist/`. Di `*.github.io` dan saat dibuka sebagai `file://`, dasbor otomatis masuk mode replay.
  Cek lokal: `cd dist && python3 -m http.server 9000` → `http://127.0.0.1:9000/?mode=replay&file=demo.jsonl`.

Membuat ulang rekaman setelah mengubah aturan: `./.venv/bin/python tools/make_sample.py`.

### d. Sebelum demo — wajib

Ganti BSSID contoh di `config/whitelist.json` dengan BSSID AP lab yang sebenarnya (tiap radio, band, dan SSID virtual memiliki
BSSID sendiri; daftarkan semuanya). Tanpa ini AP resmi Anda akan dianggap *rogue*. Alternatif: biarkan CONDA belajar — di
dasbor, tombol **Jadikan resmi** pada tabel AP menambahkan entri ke whitelist (dengan konfirmasi).

Skrip peragaan lengkap: [docs/skenario-demo.md](docs/skenario-demo.md).

## 7. Dasbor

- **Denah** dengan posisi node, berwarna sesuai status (hijau normal, kuning/oranye waspada, merah ancaman, abu-abu hilang).
- **Feed peringatan** berurut waktu, dengan bukti (BSSID, kanal, RSSI, node pelapor) dan tombol *Tandai dilihat*.
- **Tabel AP** (resmi / tak dikenal / mencurigakan) dengan aksi **Jadikan resmi** dan **Abaikan**.
- **Tabel perangkat BLE** dengan penanda "berformat pelacak".
- **Alarm suara** per severity; **Matikan alarm** mengirim perintah padam ke semua node.
- Teks dari udara (SSID dsb.) selalu dirender sebagai teks murni — SSID berisi `<script>` tidak dapat menyuntik kode.

## 8. Status pengujian (jujur)

| Bagian | Status |
|---|---|
| Aturan deteksi, mesin, REST/WebSocket | ✅ 130 test lulus, termasuk integrasi tiap skenario simulator |
| Dasbor live & replay | ✅ diuji di browser dengan simulator |
| Firmware node: scan Wi-Fi + BLE di ESP32 | ✅ diuji di perangkat (5–6 AP, 15–18 perangkat BLE per siklus, heap stabil ±146 KB) |
| Firmware gateway: serial JSON, perintah, ack | ✅ diuji di perangkat; server tersambung lewat USB |
| Layar I2C di node (LCD 0x27 terdeteksi & diinisialisasi; OLED SSD1306 belum diuji) | ⚠️ tampilan LCD menunggu konfirmasi visual |
| Node (mode USB-langsung) → server nyata: AP, BLE, heartbeat, perintah alarm + `cmd_ack` | ✅ diuji di perangkat dengan data udara sungguhan (0 dari 44 baris rusak setelah perbaikan; 3 run berturut-turut bersih) |
| LED/buzzer dan tampilan alarm di layar saat perintah masuk | ⚠️ perintah diterima dan di-ack; efek fisiknya belum dilihat (LED/buzzer belum terpasang) |
| **Tautan ESP-NOW node → gateway** | ⚠️ **belum diuji end-to-end** (tersedia satu papan saat pengembangan; kode dikompilasi untuk gateway & node1–3) |
| **Alarm di node dari perintah server** | ⚠️ belum diuji end-to-end (bergantung pada tautan di atas) |
| **Deteksi pelacak BLE asli** | ⚠️ tanda tangan dibuktikan di test; belum diverifikasi dengan AirTag/SmartTag/Tile fisik |
| Serangan nyata (evil twin, deauth) di lab | ⚠️ belum; dilakukan manual oleh tim |

## 9. Keterbatasan

- **Hanya 2.4 GHz** (kanal 1–13). ESP32 klasik tidak melihat 5/6 GHz; serangan di band itu tidak terdeteksi.
- **MAC pelacak berganti-ganti.** AirTag/SmartTag merotasi alamat; CONDA mengenali *format* iklan, bukan identitas perangkat, sehingga satu pelacak bisa tampil sebagai beberapa entri.
- **Tanda tangan tidak pasti.** UUID Samsung `0xFD5A` juga muncul dari ponsel Galaxy dengan SmartThings Find; tipe Apple `0x12` dipakai pula oleh aksesori Find My pihak ketiga. Hasilnya: "perangkat berformat pelacak".
- **Lokasi hanya kasar** — dari RSSI antar-node (node terkuat), bukan triangulasi presisi.
- **Deauth terhitung hanya saat dwell** (±150 ms per kanal per siklus ±6 detik); serangan sangat singkat bisa terlewat, ambang dinyatakan per laporan.
- **ESP-NOW tidak terautentikasi.** Penyerang di kanal 1 dapat memalsukan laporan atau perintah alarm. Rencana: HMAC pada tiap paket.
- **BLE dibatasi 48 perangkat per siklus** (RSSI terkuat dulu) dan hanya UUID 16-bit pertama yang dilaporkan.
- **Satu gateway, satu kanal ESP-NOW** (kanal 1) — cakupan bergantung pada jarak node ke gateway.
- Bukan pengganti WIPS komersial; ini detektor tingkat awal berbiaya rendah.

## 10. Peta jalan

1. **ESP32-C5** (dual-band 2.4/5 GHz) untuk menutup celah 5 GHz.
2. **Node PoE** (kabel ethernet) sebagai pengganti ESP-NOW: lebih andal dan dapat diautentikasi, tanpa batas jarak ke gateway.
3. **Autentikasi paket** (HMAC/enkripsi ESP-NOW) agar laporan dan perintah tidak dapat dipalsukan.
4. **Integrasi SIEM** (syslog/CEF) agar alert CONDA masuk ke pusat pemantauan yang sudah ada.
5. **Estimasi lokasi ancaman** dari RSSI multi-node (layar status di node sudah ada: LCD I2C teruji, OLED SSD1306 belum diuji).
6. **Korelasi lintas siklus** untuk pelacak BLE (mis. pola iklan, bukan alamat).

## 11. Pengujian serangan (kebijakan tim)

CONDA **tidak** menyertakan alat serangan apa pun. Untuk membuktikan deteksi di perangkat keras, tim membuat kondisi uji
**di lab sendiri, secara manual** (mis. AP kedua dengan SSID yang sama untuk evil twin; tag BLE asli untuk pelacak). Simulator
hanya menghasilkan *data laporan* sintetis ke server, tidak memancarkan apa pun ke udara.

## 12. Atribusi pustaka pihak ketiga

| Komponen | Lisensi | Dipakai untuk |
|---|---|---|
| [FastAPI](https://github.com/fastapi/fastapi) (+ Starlette, Pydantic) | MIT / BSD-3 | REST & WebSocket server |
| [Uvicorn](https://github.com/encode/uvicorn) | BSD-3 | server ASGI |
| [pyserial](https://github.com/pyserial/pyserial) | BSD-3 | membaca gateway lewat USB |
| [pytest](https://github.com/pytest-dev/pytest), [httpx](https://github.com/encode/httpx) | MIT / BSD-3 | pengujian |
| [SQLite](https://www.sqlite.org/) (via modul `sqlite3` Python) | domain publik | penyimpanan |
| [NimBLE-Arduino](https://github.com/h2zero/NimBLE-Arduino) 1.4.3 | Apache-2.0 | scan BLE di node |
| [Arduino-ESP32](https://github.com/espressif/arduino-esp32) / [ESP-IDF](https://github.com/espressif/esp-idf) | LGPL-2.1 / Apache-2.0 | Wi-Fi promiscuous, ESP-NOW |
| [Adafruit SSD1306](https://github.com/adafruit/Adafruit_SSD1306) 2.5.9, [Adafruit GFX](https://github.com/adafruit/Adafruit-GFX-Library) 1.11.9 (+ Adafruit BusIO) | BSD | layar OLED opsional di node |
| [PlatformIO](https://platformio.org/) (platform `espressif32` 6.9.0) | Apache-2.0 | toolchain build firmware |

Levenshtein, parser IE 802.11, dan seluruh kode CONDA ditulis sendiri oleh tim. Dasbor tidak memuat pustaka eksternal apa pun.

## 13. Dokumentasi

- [docs/arsitektur.md](docs/arsitektur.md) — alur data, komponen, keputusan rancangan
- [docs/protokol.md](docs/protokol.md) — format paket, JSON, WebSocket, REST, semantik aturan
- [docs/instalasi.md](docs/instalasi.md) — perangkat keras, pengkabelan, flash firmware, instalasi offline
- [docs/skenario-demo.md](docs/skenario-demo.md) — naskah peragaan & cara membuat kondisi uji secara aman
