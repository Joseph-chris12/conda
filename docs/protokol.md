# CONDA — Spesifikasi Protokol Pesan (v1)

Dokumen ini adalah **kontrak** antara firmware, simulator, server, dan dashboard.
Kalau ada yang berubah, ubah dokumen ini dulu.

```
Node ESP32 ──ESP-NOW (biner)──▶ Gateway ESP32 ──USB serial (JSON/baris)──▶ Server Python ──WebSocket (JSON)──▶ Dashboard
          ◀──ESP-NOW (perintah)──          ◀──serial (perintah JSON/baris)──        ◀──REST (aksi operator)──
```

Prinsip:
- **Node hanya mengumpulkan data mentah.** Semua keputusan "ini ancaman atau bukan" ada di server (lihat §5).
- **Pasif.** Tidak ada pesan yang menyuruh node mengirim frame 802.11 apa pun selain ESP-NOW ke gateway.
- Semua angka multi-byte di paket biner memakai **little-endian**.

---

## 1. Node → Gateway (ESP-NOW, biner)

Semua paket diawali **header 6 byte**, diikuti `count` record bertipe sama.
Batas ESP-NOW 250 byte per paket; node mengemas record secara greedy dan mengirim beberapa paket bila perlu.

| Offset | Ukuran | Field | Keterangan |
|---|---|---|---|
| 0 | u8 | `ver` | Versi protokol, saat ini `1` |
| 1 | u8 | `type` | `1`=AP, `2`=DEAUTH, `3`=BLE, `4`=HB (heartbeat) |
| 2 | u8 | `node` | ID numerik node (1..250). Di JSON menjadi `"N<id>"` |
| 3 | u8 | `count` | Jumlah record di paket ini |
| 4 | u16 | `cycle` | Nomor siklus scan node (naik 1 tiap ±6 detik, melingkar). Menempati offset 4–5 |

### type=1 AP — record variabel, 10 + `ssid_len` byte (maks 42)

| Ukuran | Field | Keterangan |
|---|---|---|
| 6 | `bssid` | Alamat MAC AP |
| 1 | `ch` | Kanal 1–13 (dari DS Parameter Set, bukan kanal tempat frame diterima) |
| 1 | `rssi` | i8, dBm |
| 1 | `sec` | Kode keamanan, lihat tabel di bawah |
| 1 | `ssid_len` | 0–32. `0` = SSID tersembunyi |
| n | `ssid` | Byte UTF-8, tanpa terminator |

Kode `sec`:

| Kode | Nama JSON | Cara node menentukan |
|---|---|---|
| 0 | `OPEN` | Bit Privacy di Capability = 0, tanpa RSN/WPA IE |
| 1 | `WEP` | Bit Privacy = 1, tanpa RSN/WPA IE |
| 2 | `WPA` | Hanya WPA IE vendor (tag 221, OUI 00:50:F2 tipe 1) |
| 3 | `WPA2` | RSN IE (tag 48), AKM PSK (00:0F:AC:2 / :6) |
| 4 | `WPA3_TRANSITION` | RSN IE dengan AKM PSK **dan** SAE |
| 5 | `WPA3` | RSN IE, hanya AKM SAE (00:0F:AC:8) |
| 6 | `ENTERPRISE` | RSN IE, AKM 802.1X (00:0F:AC:1 / :5) |
| 7 | `UNKNOWN` | Selain di atas |

Maks 5 record AP per paket pada kasus terburuk (6 + 5×42 = 216 byte).

### type=2 DEAUTH — record tetap 13 byte

Dihitung node selama jendela scan satu siklus, per BSSID (addr3 frame).

| Ukuran | Field | Keterangan |
|---|---|---|
| 6 | `bssid` | BSSID yang dilaporkan di frame |
| 1 | `ch` | Kanal tempat frame ditangkap |
| 2 | `deauth` | u16, jumlah frame deauthentication |
| 2 | `disassoc` | u16, jumlah frame disassociation |
| 1 | `rssi` | i8, rata-rata RSSI frame |
| 1 | `flags` | bit0 = ada frame yang ditujukan ke broadcast (ff:ff:ff:ff:ff:ff) |

Hanya BSSID dengan `deauth+disassoc > 0` yang dilaporkan. Maks 18 record per paket.

### type=3 BLE — record tetap 14 byte

Node melaporkan advertiser BLE **mentah** (maks `BLE_MAX_REPORT`=48 per siklus, diurut RSSI terkuat, deduplikasi per MAC). Node **tidak** mengklasifikasi; pencocokan tanda tangan pelacak ada di server (`config/thresholds.json`).

| Ukuran | Field | Keterangan |
|---|---|---|
| 6 | `addr` | Alamat BLE |
| 1 | `atype` | Tipe alamat NimBLE: 0=public, 1=random, 2=RPA-public, 3=RPA-random |
| 1 | `rssi` | i8, dBm |
| 2 | `company` | Company ID dari manufacturer data, `0xFFFF` = tidak ada |
| 1 | `mtype` | Byte pertama payload manufacturer data setelah company ID (`mdata[0]`), 0 bila tidak ada |
| 2 | `svc` | UUID 16-bit pertama (service UUID atau service data), `0` bila tidak ada |
| 1 | `info` | `mdata[2]` bila ada, selain itu 0. (Apple Find My: byte status) |

Maks 17 record per paket (6 + 17×14 = 244 byte).

### type=4 HB (heartbeat) — satu record 10 byte

Dikirim tiap siklus, juga bila tidak ada AP/BLE/deauth. Ini yang menjadi dasar deteksi node hilang.

| Ukuran | Field | Keterangan |
|---|---|---|
| 4 | `uptime_s` | u32 |
| 2 | `heap_kb` | u16, free heap dalam KB |
| 2 | `cycle_ms` | u16, durasi siklus terakhir |
| 1 | `fw` | Versi firmware |
| 1 | `flags` | bit0 = LED merah menyala, bit1 = buzzer aktif |

---

## 2. Gateway → Node (ESP-NOW, perintah)

Dikirim **broadcast** (node memfilter berdasarkan `node`). Node membuka jendela terima ±300 ms setelah mengirim laporan, jadi perintah sampai paling lambat satu siklus.

| Offset | Ukuran | Field | Keterangan |
|---|---|---|---|
| 0 | u8 | `ver` | `1` |
| 1 | u8 | `type` | `0x80` = ALERT_CMD |
| 2 | u8 | `node` | ID node tujuan, `0xFF` = semua |
| 3 | u8 | `level` | `0`=padam, `1`=LED merah, `2`=LED + buzzer putus-putus, `3`=LED + buzzer terus |
| 4 | u8 | `ttl_s` | Detik sampai node memadamkan sendiri bila tidak ada perintah baru (fail-safe) |

Pemetaan severity → level: `medium`→1, `high`→2, `critical`→3.

---

## 3. Gateway → Server (serial 115200 8N1, satu JSON per baris)

Gateway mendekode paket biner menjadi JSON. Setiap baris punya `v` (versi) dan `t` (tipe).

**Soal timestamp.** ESP32 tanpa RTC/NTP tidak punya jam dinding. Maka gateway menambahkan `gw_ms` (milidetik sejak boot), dan **server menambahkan `ts`** (epoch detik, float) saat baris diterima. Bila baris sudah memuat `ts` (simulator, tes, replay), server memakainya apa adanya.

Field umum untuk `t` ∈ {`ap`,`deauth`,`ble`,`hb`}: `node` ("N1"), `cycle`, `gw_ms`, `src` (MAC pengirim ESP-NOW).

```json
{"v":1,"t":"ap","node":"N1","cycle":42,"gw_ms":183201,"src":"24:6f:28:aa:bb:01",
 "aps":[{"ssid":"SATUAN-01","bssid":"d8:07:b6:10:00:01","ch":6,"rssi":-52,"sec":"WPA2"},
        {"ssid":"","bssid":"b0:95:75:11:22:33","ch":11,"rssi":-80,"sec":"WPA2","hidden":true}]}

{"v":1,"t":"deauth","node":"N1","cycle":42,"gw_ms":183202,
 "items":[{"bssid":"d8:07:b6:10:00:01","ch":6,"deauth":38,"disassoc":2,"rssi":-60,"bcast":true}]}

{"v":1,"t":"ble","node":"N2","cycle":42,"gw_ms":183240,
 "items":[{"addr":"c1:22:33:44:55:66","atype":"random","rssi":-70,
           "company":"004c","mtype":"12","svc":null,"info":16}]}

{"v":1,"t":"hb","node":"N2","cycle":42,"gw_ms":183250,
 "uptime_s":3600,"heap_kb":182,"cycle_ms":5800,"fw":1,"led_red":false,"buzzer":false}

{"v":1,"t":"gw","gw_ms":1200,"event":"boot","fw":1,"channel":1}
```

Aturan format JSON:
- MAC: huruf kecil, dipisah `:`.
- `company`, `mtype`, `svc`: string hex huruf kecil tanpa `0x` (`"004c"`, `"12"`, `"fd5a"`), atau `null` bila tidak ada.
- `atype`: `"public"|"random"|"rpa_public"|"rpa_random"`.
- `sec`: nama dari tabel §1.
- `hidden: true` bila `ssid_len` = 0 (field `ssid` = `""`).
- Baris `gw` adalah status gateway (`boot`, `cmd_ack`, `error`); tidak dipakai aturan deteksi, hanya ditampilkan/di-log.
- Baris yang tidak bisa di-parse diabaikan dan dicatat di log (jangan sampai membuat server crash).

### Server → Gateway (perintah)

```json
{"cmd":"alert","node":"N2","level":3,"ttl_s":20}
{"cmd":"alert","node":"all","level":0,"ttl_s":0}
```

Gateway menerjemahkan ke paket §2 dan membalas `{"v":1,"t":"gw","event":"cmd_ack","node":"N2","level":3}`.

---

## 4. Server → Dashboard (WebSocket `/ws`, JSON)

Server mendorong pesan; dashboard hanya menerima (aksi operator lewat REST, §6).
Semua pesan: `{"t": "<tipe>", ...}`.

| `t` | Kapan | Isi |
|---|---|---|
| `snapshot` | Sekali saat koneksi dibuka | `nodes`, `aps`, `ble`, `alerts` (50 terakhir), `floorplan`, `server_ts` |
| `node_status` | Status node berubah / heartbeat | `node`, `name`, `x`, `y`, `state` (`unknown`/`ok`/`warn`/`alert`/`lost`), `last_seen`, `uptime_s`, `heap_kb` |
| `alert_ack` | Operator menandai alert dilihat | `id` |
| `alert` | Aturan terpicu | objek alert (di bawah) |
| `ap_update` | AP baru/berubah | objek AP inventaris |
| `ble_update` | Perangkat BLE baru/berubah | objek BLE |
| `config_changed` | Whitelist diubah operator | `whitelist` |

Objek **alert**:

```json
{"t":"alert","id":17,"ts":1731512345.12,"rule":"evil_twin","severity":"critical",
 "title":"Evil twin: SATUAN-01",
 "detail":"SSID resmi 'SATUAN-01' dipancarkan BSSID tak terdaftar aa:bb:cc:dd:ee:ff (kanal 6, -48 dBm)",
 "node":"N1","bssid":"aa:bb:cc:dd:ee:ff","ssid":"SATUAN-01",
 "evidence":{"ch":6,"rssi":-48,"sec":"OPEN","nodes":["N1","N3"]}}
```

`severity` ∈ `low` | `medium` | `high` | `critical`. `rule` ∈ nama aturan §5.

Objek **AP inventaris**: `{ssid, bssid, ch, sec, rssi_best, node_best, first_seen, last_seen, status}` dengan `status` ∈ `official` | `unknown` | `suspect` (suspect = sedang terkena alert).

Objek **BLE**: `{addr, kind, rssi_best, node_best, first_seen, last_seen, reports, foreign}`; `kind` ∈ `apple_findmy` | `samsung_smarttag` | `tile` | `other`.

Status node: `ok` (hijau), `warn` (alert medium aktif), `alert` (high/critical aktif), `lost` (abu-abu/berkedip). Alert dianggap aktif selama `alert_ttl_s` sejak terakhir terpicu.

---

## 5. Aturan deteksi (semantik tepat — acuan unit test)

Semua ambang ada di `config/thresholds.json`, daftar AP resmi di `config/whitelist.json`.
Setiap aturan punya `cooldown_s` per kunci (mis. per BSSID) agar feed tidak banjir.

| ID | Kondisi | Severity | Kunci cooldown |
|---|---|---|---|
| `evil_twin` | `ssid` persis sama (peka huruf besar/kecil) dengan SSID di whitelist **dan** `bssid` tidak ada di daftar BSSID entri itu | `critical` | `bssid` |
| `sec_downgrade` | `bssid` ada di whitelist, `ssid` cocok, tetapi `sec` tidak ada di daftar `security` yang diizinkan entri itu. `OPEN` → `critical`, lainnya → `high` | lihat kiri | `bssid` |
| `ssid_lookalike` | SSID **tidak** identik dengan SSID resmi mana pun, panjang ≥ `min_ssid_len`, dan jarak Levenshtein ≤ `max_distance` ke salah satu SSID resmi (perbandingan setelah `lower()`); BSSID tidak ada di whitelist | `high` | `bssid` |
| `deauth_flood` | `deauth+disassoc` untuk satu BSSID dalam satu laporan node ≥ `warn_frames` (`high`) atau ≥ `crit_frames` (`critical`) | `high`/`critical` | `bssid` |
| `rogue_ap` | `bssid` & `ssid` tak ada di whitelist (dan bukan evil twin/lookalike), tidak di `ignored_bssids`, RSSI ≥ `min_rssi_dbm` di salah satu node | `medium` | `bssid` |
| `ble_tracker` | Perangkat BLE cocok tanda tangan di `ble_signatures`, tidak ada di `known_trackers`, terlihat ≥ `min_reports` laporan dengan RSSI ≥ `min_rssi_dbm`. RSSI ≥ `close_rssi_dbm` → `high`, selain itu `medium` | `medium`/`high` | `kind`+`addr` |
| `node_lost` | Node di `nodes.json` tidak mengirim paket apa pun > `node_lost_s` (default 30 s). Dicek tiap 5 detik. Saat pulih: pesan `node_status` kembali `ok` + alert `low` "node pulih" | `high` | `node` |

Catatan penting:
- Satu BSSID yang sekaligus tak terdaftar dan Open dilaporkan sebagai **`evil_twin`** saja (bukti `sec` ikut dicantumkan), bukan dobel dengan `sec_downgrade`.
- Node dengan ID di luar `nodes.json` diabaikan dan dicatat di log (mencegah node palsu mengotori data).
- AP dengan SSID tersembunyi tidak dicocokkan SSID; hanya dikenai `rogue_ap`.
- Keamanan `UNKNOWN` (node gagal mengenali) tidak dinilai oleh `sec_downgrade`, agar tidak menimbulkan alarm palsu.
- **Cooldown** menahan alert berulang untuk kunci yang sama, tetapi **kenaikan severity** (mis. deauth `high` → `critical`) tetap dilaporkan. Selama ancaman masih terlihat, status node tetap `alert`/`warn` walau alert barunya ditahan cooldown.
- Waktu pada aturan memakai `ts` pesan bila ada; bila tidak, jam server. Karena itu `node_lost` pada mode live mengukur diam dalam waktu nyata server (`--sim-speed` > 1 tidak akan memicunya).

---

## 6. REST API (aksi operator & data awal)

| Method | Path | Fungsi |
|---|---|---|
| GET | `/api/state` | Sama dengan isi `snapshot` |
| POST | `/api/whitelist/promote` | Body `{"bssid":"..","ssid":"..","security":[..]}` — **jadikan resmi**; menulis ke `config/whitelist.json`. Dashboard wajib meminta konfirmasi (menjadikan evil twin resmi = melegitimasi penyerang) |
| POST | `/api/whitelist/ignore` | Body `{"bssid":".."}` — masuk `ignored_bssids` |
| POST | `/api/alerts/{id}/ack` | Tandai alert sudah dilihat |
| POST | `/api/alarm/clear` | Padamkan alert di semua node |
| GET | `/` | Dashboard statis |

---

## 7. Mode replay

Rekaman di `data/samples/*.jsonl` berisi **pesan WebSocket server** (§4), satu per baris, dengan field tambahan `"at": <detik sejak awal rekaman>`. Dashboard mode replay (`?mode=replay&file=<nama>`) memutar baris itu sesuai `at`, memakai kode render yang sama dengan mode live. Rekaman dibuat dengan `tools/simulator.py` → server `--record`.

---

## 8. Keterbatasan yang melekat pada format

- Hanya 2.4 GHz (kanal 1–13).
- Penghitungan deauth hanya mencakup waktu dwell di kanal tersebut (±150 ms dari tiap siklus ±6 detik), jadi ambang dinyatakan per laporan, bukan per detik.
- MAC pelacak BLE berganti-ganti; identitas pelacak tidak stabil antar siklus.
- Samsung service UUID 0xFD5A juga bisa muncul dari ponsel Galaxy dengan SmartThings Find aktif; Apple type 0x12 juga dipakai aksesori pihak ketiga yang kompatibel Find My. Hasilnya adalah "perangkat berformat pelacak", bukan identifikasi pasti.
- Lokasi hanya perkiraan kasar berdasar RSSI antar-node.
