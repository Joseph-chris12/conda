# Instalasi CONDA

## 1. Perangkat keras

| Jumlah | Barang | Catatan |
|---|---|---|
| 1 | ESP32 DevKit V1 (WROOM-32) | **Gateway**, ditancapkan ke laptop server lewat USB |
| 3 | ESP32 DevKit V1 (WROOM-32) | **Node** N1–N3 (minimal 1 untuk uji) |
| 3 | LED hijau + 3 LED merah + resistor 220 Ω | satu pasang per node |
| 3 | Buzzer aktif 3,3–5 V | satu per node |
| 3 | Catu daya USB 5 V (power bank/adaptor) | node bisa dinyalakan dari mana saja |
| — | Kabel micro-USB **data** (bukan hanya pengisi daya) | |

ESP32 klasik hanya 2.4 GHz. Driver USB-serial: CP210x atau CH340 (macOS/Linux umumnya sudah ada; Windows perlu driver).

### Pengkabelan node

| Komponen | Pin ESP32 | Keterangan |
|---|---|---|
| LED hijau (anode, lewat 220 Ω) | GPIO25 | indikator hidup/siklus |
| LED merah (anode, lewat 220 Ω) | GPIO26 | peringatan |
| Buzzer aktif (+) | GPIO27 | HIGH = bunyi |
| Katoda LED, buzzer (−) | GND | |

Buzzer aktif kecil yang menarik ≤ ±12 mA aman langsung dari GPIO; untuk buzzer lebih besar pakai transistor NPN.
Gateway tidak memerlukan komponen tambahan (LED bawaan GPIO2 berkedip saat menerima paket).
**Layar opsional (I2C, SDA = GPIO21, SCL = GPIO22, VCC 5 V atau 3,3 V sesuai modul, GND).** Saat boot node memindai bus I2C
dan memilih sendiri:

| Terdeteksi | Layar | Catatan |
|---|---|---|
| 0x27 / 0x3F (dan 0x20–0x26) | LCD karakter HD44780 dengan backpack PCF8574 | bawaan 16×2; untuk 20×4 tambahkan `-DLCD_COLS=20 -DLCD_ROWS=4` di `build_flags` |
| 0x3C / 0x3D | OLED SSD1306 128×64 | `-DOLED_HEIGHT=32` untuk layar 32 piksel; **belum diuji di perangkat** |
| tidak ada | — | node berjalan normal tanpa layar |

Layar menampilkan ID node + nomor siklus, jumlah AP/BLE/deauth, fase (scan Wi-Fi kanal N / scan BLE / lapor), waktu sejak
perintah terakhir dari gateway (indikator tautan), uptime, heap, dan status alarm. LCD 16×2 bergantian halaman tiap ±2 detik;
saat alarm baris bawah selalu menampilkan "ALARM". Bila layar kosong/hanya kotak, putar potensiometer kontras di belakang modul.
Hasil pindai I2C tercetak di serial saat boot (`[CONDA] pindai I2C: 0x27`).

## 2. Server (Python 3.9+)

```bash
cd conda
python3 -m venv .venv
```

```bash
./.venv/bin/pip install -r requirements.txt
```

```bash
./.venv/bin/python -m pytest -q
```

Hasil yang diharapkan: `130 passed`. Server tidak butuh internet saat berjalan.

### Pemasangan offline (lingkungan terisolasi)

Siapkan di komputer **yang berinternet dan satu OS/arsitektur/versi Python** dengan laptop sasaran:

```bash
./.venv/bin/pip download -r requirements.txt -d wheels
```

Salin folder `wheels/` ke laptop sasaran, lalu:

```bash
python3 -m venv .venv
```

```bash
./.venv/bin/pip install --no-index --find-links wheels -r requirements.txt
```

## 3. Firmware (PlatformIO)

PlatformIO diunduh dari internet **sekali** (toolchain ±1 GB). Setelah satu kali build online, folder `~/.platformio`
(Windows: `%USERPROFILE%\.platformio`) berisi semuanya; salin ke komputer offline untuk build tanpa internet.

```bash
./.venv/bin/pip install platformio
```

Versi platform (`espressif32@6.9.0`) dan library (`NimBLE-Arduino@1.4.3`) **dipaku** — jangan diubah tanpa menguji ulang
(tanda tangan callback ESP-NOW berbeda antar versi Arduino core).

Cari port papan:

```bash
./.venv/bin/pio device list
```

### Flash gateway

```bash
cd firmware/gateway
../../.venv/bin/pio run -t upload --upload-port <PORT_GATEWAY>
```

Uji: `../../.venv/bin/pio device monitor -b 115200` — harus muncul baris JSON `{"v":1,"t":"gw",...,"event":"boot",...}`.

### Flash node (satu env per node)

```bash
cd firmware/node
../../.venv/bin/pio run -e node1 -t upload --upload-port <PORT_NODE1>
```

Ulangi dengan `node2` dan `node3` untuk papan lain. ID node menentukan label di dasbor dan harus ada di `config/nodes.json`.
Uji: `../../.venv/bin/pio device monitor -b 115200` — tiap ±5,3 detik muncul baris `[N1] siklus ...: AP=.. deauth=.. frame BLE=..`.

Bila upload macet di "Connecting...", tahan tombol **BOOT** pada papan sampai proses mulai.

### Mode USB-langsung (satu papan, tanpa gateway) — untuk uji dan demo

Bila hanya ada satu ESP32, bangun node dengan env `node1usb`. Papan itu tetap memindai Wi-Fi/BLE dan mengirim ESP-NOW seperti
biasa, **tetapi juga** mencetak paket yang sama sebagai baris JSON berformat gateway ke USB dan menerima perintah alarm dari
server lewat USB. Server tidak perlu diubah.

```bash
cd firmware/node
../../.venv/bin/pio run -e node1usb -t upload --upload-port <PORT>
```

Jalankan server dengan konfigurasi satu node (supaya N2/N3 tidak dianggap hilang):

```bash
cd ../..
./.venv/bin/python -m server --serial --config-dir config/lab-1node --fresh
```

Catatan:
- Di mode ini serial hanya berisi JSON; log teks manusia dibungkam (layar LCD tetap menampilkan status). Jangan membuka
  `pio device monitor` bersamaan dengan server — dua pembaca di satu port saling mencuri byte dan merusak baris.
- `config/lab-1node/whitelist.json` awalnya kosong: semua AP sekitar tampil "tak dikenal" dan AP kuat memicu `rogue_ap`.
  Tandai AP milikmu dengan **Jadikan resmi**, atau **Abaikan** untuk AP tetangga.
- Ini mode uji, bukan arsitektur produksi. Untuk penerapan gunakan node (`node1..3`) + gateway.

> Gateway dan node memakai **kanal ESP-NOW yang sama** (`CONDA_CHANNEL=1` di `platformio.ini`). Ubah di keduanya bila perlu.

## 4. Konfigurasi

| Berkas | Isi | Kapan diubah |
|---|---|---|
| `config/whitelist.json` | AP resmi: SSID, semua BSSID, enkripsi yang diizinkan | **Wajib** sebelum demo/penerapan |
| `config/nodes.json` | ID node, nama, posisi di denah | Saat menambah/memindah node |
| `config/thresholds.json` | Ambang tiap aturan, cooldown, TTL, tanda tangan BLE | Penyetelan sensitivitas |

Server membaca berkas ini saat start (restart setelah mengubahnya, kecuali whitelist yang diubah lewat tombol di dasbor).
Setiap radio/band/SSID virtual pada AP memiliki BSSID sendiri — daftarkan semuanya, bila tidak AP resmi tampil sebagai *rogue*.

## 5. Menjalankan

```bash
./.venv/bin/python -m server --serial --fresh
```

Buka http://127.0.0.1:8000. Opsi: `--serial <PORT>`, `--host 0.0.0.0` (dasbor dari laptop lain; hanya di jaringan tertutup),
`--port`, `--db`, `--record file.jsonl` (rekam untuk mode replay), `--config-dir`.

## 6. Pemecahan masalah

| Gejala | Penyebab umum |
|---|---|
| Server: "port serial gateway belum ditemukan; mencoba lagi..." | Kabel hanya pengisi daya; driver belum terpasang; port dipakai `pio device monitor` (tutup dulu) |
| Node tetap "Menunggu laporan" | Gateway/node beda `CONDA_CHANNEL`; node terlalu jauh dari gateway; ID node tak ada di `nodes.json` |
| Semua AP tampil "tak dikenal"/rogue | Whitelist masih berisi BSSID contoh |
| Tidak ada suara alarm | Browser butuh satu klik di halaman dulu; cek volume |
| Upload gagal "Connecting......" | Tahan tombol BOOT; ganti kabel |
| Dasbor kosong tanpa server | Itu mode live — gunakan `?mode=replay` |
| Statistik `bad_lines` meledak (puluhan ribu) tepat setelah server tersambung | Driver USB-serial (CP210x/macOS) kadang menyemburkan fragmen basi beberapa detik saat port dibuka. Server sudah membuangnya otomatis sampai aliran tenang; tidak mengganggu data |
| Beberapa baris JSON kehilangan karakter (mode USB-langsung) | Pancaran radio ESP-NOW tepat saat ekor baris masih keluar dari UART menjatuhkan byte. Sudah ditangani dengan `Serial.flush()` sebelum radio memancar (rusak ±12% → 0 dari 44 baris). Jangan buka monitor serial lain bersamaan dengan server |
| Server menerima AP dengan BSSID aneh (mis. `da:279a`) | Sudah ditolak oleh validasi MAC di server; hitungannya ada di `bad_items` pada `/api/health` |
