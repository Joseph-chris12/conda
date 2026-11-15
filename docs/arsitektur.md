# Arsitektur CONDA

Dokumen ini menjelaskan *mengapa* CONDA dibangun seperti sekarang. Format byte dan semantik aturan yang tepat ada di
[protokol.md](protokol.md).

## 1. Alur data

```
Node (ESP32)                Gateway (ESP32)             Server (Python)                Dasbor
────────────                ───────────────             ───────────────                ──────
sniff Wi-Fi 1..13
scan BLE
  │  paket biner ≤250 B
  ├──── ESP-NOW (kanal 1) ─▶ terima, antre (FreeRTOS)
                              decode → 1 baris JSON ──▶ parse → Engine.handle()
                                                         ├─ aturan deteksi (fungsi murni)
                                                         ├─ cooldown / eskalasi
                                                         ├─ status node (ok/warn/alert/lost)
                                                         ├─ SQLite (alerts, aps, ble)
                                                         └─ WebSocket /ws ───────────────▶ render
  ◀── CmdPkt (siaran 3×) ── {"cmd":"alert",...} ◀──────── perintah alarm
LED merah + buzzer
```

### Mengapa ESP-NOW, bukan Wi-Fi biasa

Node memakai radio Wi-Fi-nya untuk *mendengarkan* udara (promiscuous) sambil berpindah kanal, sehingga tidak bisa sekaligus
tersambung ke AP. ESP-NOW tidak memerlukan asosiasi AP: node pindah ke kanal tetap (1), mengirim laporan, lalu kembali
memindai. Ini juga membuat sistem tidak bergantung pada jaringan yang justru sedang dipantau. Konsekuensinya: tidak ada ACK
pada siaran, sehingga perintah alarm dikirim 3× dan di-*refresh* server berkala.

### Mengapa gateway terpisah

Server berjalan di laptop biasa, yang tidak punya radio ESP-NOW. Gateway adalah ESP32 polos yang hanya menjadi jembatan
ESP-NOW ⇄ serial. Ia sengaja tidak punya logika deteksi dan tidak punya jam dinding: server yang memberi cap waktu (`ts`)
saat baris tiba.

## 2. Komponen

### Firmware node ([firmware/node/src/main.cpp](../firmware/node/src/main.cpp))
- Callback sniffer mem-parse frame manajemen: beacon/probe-response → tabel AP (64 entri; SSID, BSSID, kanal, RSSI,
  enkripsi dari RSN IE tag 48 / WPA vendor IE 221 / bit Privacy); deauth/disassoc → penghitung per BSSID (16 entri).
- `scanBle()` — NimBLE pasif, ≤48 perangkat per siklus, diurutkan RSSI terkuat.
- Laporan dipecah ke paket ≤250 B (AP 5, DEAUTH 18, BLE 17 record per paket pada kasus terburuk) + heartbeat.
- `alarmTask` terpisah mengatur LED/buzzer dan padam sendiri bila TTL perintah habis (gateway/server hilang ≠ buzzer
  menyala selamanya).
- Pasif: tidak memanggil fungsi pengiriman frame 802.11 mentah. Pemancaran hanya ESP-NOW.

### Firmware gateway ([firmware/gateway/src/main.cpp](../firmware/gateway/src/main.cpp))
- Callback ESP-NOW hanya mengantre paket (tidak boleh memblok); task terpisah men-decode dan mencetak JSON.
- SSID dari udara di-escape sehingga JSON selalu valid walau SSID berisi karakter kontrol.
- Parser perintah serial → siaran `CmdPkt` 3×, membalas `cmd_ack`; mencetak statistik tiap 30 detik.

### Server ([server/](../server))
| Berkas | Peran |
|---|---|
| `sources.py` | Sumber data: `SerialSource` (auto-deteksi port, sambung ulang), `SubprocessSource` (simulator), `StdinSource` |
| `engine.py` | Pintu masuk semua event: validasi, inventaris AP/BLE, panggil aturan, cooldown, status node, perintah alarm, persistensi |
| `rules/*.py` | Satu berkas per aturan; fungsi murni `check(...)` → daftar temuan. Mudah diuji tanpa I/O |
| `config.py` | Memuat/menyimpan `config/*.json`; whitelist ditulis atomik (tulis-rename) |
| `db.py` | SQLite (alerts, aps, ble); riwayat dimuat ulang saat server restart |
| `app.py` | FastAPI: `/ws`, REST, dan berkas statis dasbor |

Keputusan penting di mesin:
- **Cooldown per (aturan, kunci)** menahan alert berulang, tetapi **kenaikan severity** menembusnya (deauth high → critical).
- **Kondisi aktif**: selama ancaman masih terlihat, node tetap berstatus `alert`/`warn` walau alert barunya ditahan.
- **Waktu virtual**: aturan memakai `ts` pesan bila ada, sehingga test dan replay deterministik. `node_lost` pada live memakai
  jam server; karenanya `--sim-speed` > 1 tidak memicunya.
- **Node tak dikenal** (ID di luar `nodes.json`) diabaikan dan dicatat — mencegah data dari node palsu.
- **Kegagalan tidak fatal**: baris tak valid hanya dicatat; server tidak crash.

### Dasbor ([dashboard/](../dashboard))
- JavaScript murni, tanpa CDN/framework. Satu jalur render untuk mode live (WebSocket) dan replay (JSONL).
- Semua teks yang berasal dari udara dimasukkan lewat `textContent` — kebal XSS dari SSID jahat.
- Baris tabel ber-*key* sehingga tombol tetap bisa diklik walau data terus berubah.
- Pembaruan digabung (batching 50 ms); alarm memakai WebAudio, tanpa berkas suara.

## 3. Respons ancaman

`level` perintah: medium → 1 (LED), high → 2 (LED + buzzer putus-putus), critical → 3 (LED + buzzer terus). Perintah
dikirim ke node yang melaporkan ancaman dan di-refresh tiap `alert_command_ttl_s / 2`. Bila sebuah node hilang
(`node_lost`), semua node lain yang masih hidup diperintah memberi peringatan. Operator dapat memadamkan semuanya dari dasbor.

## 4. Batas kepercayaan dan keamanan

| Sumber data | Dipercaya? | Penanganan |
|---|---|---|
| Frame di udara (SSID, BSSID) | Tidak | Dibatasi panjang di node, di-escape di gateway, `textContent` di dasbor |
| Paket ESP-NOW | Belum diautentikasi | Validasi versi/panjang/tipe; node tak dikenal diabaikan; **risiko tersisa**: pemalsuan oleh pihak di kanal yang sama (rencana HMAC) |
| Baris serial | Semi | Parse defensif, baris rusak dibuang |
| REST (aksi operator) | Operator di jaringan lokal | Server default hanya `127.0.0.1`; `--host 0.0.0.0` hanya bila perlu, di jaringan tertutup |

Tidak ada koneksi keluar dari server maupun dasbor. Tidak ada telemetri.

## 5. Ketergantungan radio ESP32 (penyederhanaan yang dipilih)

Wi-Fi promiscuous, BLE, dan ESP-NOW berbagi satu radio 2.4 GHz. Mengaktifkannya bersamaan menurunkan kinerja ketiganya.
CONDA memilih **pembagian waktu** (scan Wi-Fi → scan BLE → lapor) alih-alih konkurensi: lebih sederhana, deterministik, dan
cukup untuk siklus ±5,3 detik. Harganya: cakupan tiap kanal hanya ±150 ms per siklus (lihat keterbatasan di README).
