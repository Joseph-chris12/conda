# Naskah demo CONDA

Panduan tampil untuk Kartika Cyber Hackathon 2026 · Tim **Elit Siber Protokol**. Dua versi:

| Versi | Lama | Cara | Kapan dipakai |
|---|---|---|---|
| **Panjang** | ±8 menit | Simulator live, kecepatan 1× | Presentasi penuh, ada alarm suara dan aksi operator |
| **Ringkas** | ±4 menit | Mode replay, kecepatan 2× | Waktu terbatas, atau server/perangkat bermasalah |

> Seluruh pengujian serangan dilakukan **manual di lab milik tim**. CONDA dan simulatornya tidak memancarkan serangan apa pun.

---

## 1. Pesan kunci (hafalkan, 30 detik)

> "Jaringan markas dilindungi kata sandi, tapi tidak ada yang *mengawasi udara*-nya. CONDA adalah sensor **pasif** 2.4 GHz
> berbiaya rendah: ia hanya mendengarkan, mengenali jaringan palsu, serangan deauth, dan pelacak BLE asing, lalu menyalakan
> alarm lokal dan di dasbor komando. Seluruh sistem **berjalan offline**, dan semua logika deteksi ada di server sehingga aturan
> bisa diubah tanpa menyentuh perangkat."

Tiga hal yang ingin diingat juri:
1. **Relevan:** ancaman nirkabel di area markas (evil twin, deauth, pelacak) yang tak terlihat oleh keamanan biasa.
2. **Layak:** node ESP32 murah, satu server di laptop, tanpa cloud.
3. **Teruji:** 130 test otomatis, simulator tiap skenario, dan perangkat keras sungguhan yang sudah mengirim data udara nyata.

---

## 2. Persiapan

### Malam sebelumnya
- [ ] `git pull`, lalu `./.venv/bin/python -m pytest -q` → harus `130 passed`.
- [ ] Ganti BSSID contoh di `config/whitelist.json` dengan BSSID AP lab (atau kosongkan dan pakai alur di bagian 5).
- [ ] Uji semua jalur sekali: simulator, replay, dan (bila ada papan) mode perangkat keras.
- [ ] Siapkan **dua tab** peramban: tab A untuk jalur utama, tab B untuk replay cadangan.
- [ ] Jangan memindah kabel USB papan setelah dites. Port bisa berubah nama dan macet (lihat bagian 7).

### 10 menit sebelum tampil
1. Tutup program lain yang memakai port 8000 atau port serial (monitor serial, server lama). Cek: `lsof -nP -iTCP:8000 -sTCP:LISTEN`.
2. Jalankan jalur yang dipilih:

| Jalur | Perintah |
|---|---|
| **Simulator** (utama) | `./.venv/bin/python -m server --sim full_demo --fresh` |
| **Perangkat keras, satu papan** | `./.venv/bin/python -m server --serial --config-dir config/lab-1node --fresh` |
| **Replay** (cadangan) | `./.venv/bin/python -m server --sim normal` lalu buka `/?mode=replay&file=demo.jsonl` |

3. Buka alamat yang **tercetak di terminal** (`Dasbor CONDA: http://127.0.0.1:<port>`). Bila port 8000 terpakai, server memilih port bebas berikutnya.
4. **Klik sekali di halaman**, lalu tekan **Suara: aktifkan**. Tanpa ini peramban menahan bunyi alarm.
5. Naikkan volume, lalu bunyikan satu alarm uji. Pastikan terdengar di ruangan.
6. Perbesar jendela peramban penuh layar (denah dan feed harus terlihat bersamaan).

---

## 3. Naskah versi panjang (simulator live, ±8 menit)

Waktu dihitung dari server mulai. Hitung detik sendiri di kepala; tidak perlu persis.

### Pembuka — 0:00 · lalu lintas normal (±30 detik)
**Tunjuk:** denah dengan tiga node hijau, tabel AP, kartu ringkasan.
**Ucapkan:** "Ini area markas dengan tiga node CONDA: Pos Jaga, Ruang Komando, dan Aula. Semua hijau. Di tabel ini AP resmi dan
AP tetangga yang lemah. Perhatikan: **tidak ada alarm palsu**. Lalu lintas normal tidak memicu apa pun, dan itu kami uji
otomatis selama lima menit simulasi."

### 1. Evil twin — ±0:30 (critical)
**Terjadi:** sirene dua nada, spanduk merah di atas, node N1 merah, alert baru di feed.
**Tunjuk:** feed alert → bukti (BSSID, kanal, sinyal, node pelapor); tabel AP → baris merah "mencurigakan".
**Ucapkan:** "Seseorang memancarkan SSID resmi `SATUAN-01` dari perangkat yang BSSID-nya tidak terdaftar, terbuka tanpa enkripsi,
dan sinyalnya kuat di dekat Pos Jaga. Personel yang tersambung lalu lintasnya bisa dibaca. CONDA mengenalinya karena
SSID cocok dengan daftar resmi tetapi BSSID-nya asing."

### 2. Banjir deauth — ±1:30 (high lalu critical)
**Terjadi:** peringatan naik dari *high* ke *critical* beberapa detik kemudian; bunyi berubah dari tiga bip menjadi sirene.
**Ucapkan:** "Frame pemutus koneksi dibanjirkan ke AP resmi. Ini taktik untuk memaksa klien pindah ke AP palsu tadi. Perhatikan
eskalasinya: ketika serangan membesar, tingkat bahaya ikut naik meski alert serupa baru saja berbunyi."

### 3. Pelacak BLE — ±2:20 sampai 3:00 (medium → high)
**Terjadi:** tiga peringatan berturut-turut: Apple Find My di N2, Samsung SmartTag di N3, Tile di N1.
**Tunjuk:** tabel "Perangkat BLE terdeteksi"; kolom node terkuat.
**Ucapkan:** "Pelacak yang diselipkan ke kendaraan atau tas. CONDA mengenali *format iklan*-nya dan menyebut node dengan sinyal terkuat
sebagai perkiraan lokasi kasar. Kami jujur soal batasnya: alamat pelacak berputar, jadi ini deteksi *jenis perangkat*, bukan
identitas pasti."

### 4. Node hilang — ±3:45 (high), pulih ±4:15
**Terjadi:** N3 menjadi abu-abu; node lain ikut memberi peringatan; sekitar 30 detik kemudian alert *low* "node pulih".
**Ucapkan:** "Sensor yang dicabut, dirusak, atau di-jamming tidak boleh mati diam-diam. Bila sebuah node berhenti melapor lebih
dari 30 detik, node lain langsung diperintahkan bunyi."

### 5. Penurunan keamanan — ±4:30 (critical)
**Ucapkan:** "Tidak ada SSID baru. AP *resmi* kita tiba-tiba tampil terbuka tanpa enkripsi. Ini ciri AP dibajak atau dikonfigurasi
ulang. Kami mendeteksinya karena membandingkan dengan keamanan yang diizinkan di daftar resmi."

### 6. SSID mirip — ±5:30 (high)
**Ucapkan:** "`SATUAN_01` dengan garis bawah, bukan `SATUAN-01`. Jarak penyuntingan satu karakter. Mudah terlewat mata manusia, tidak
terlewat CONDA."

### 7. Rogue AP — ±6:30 (medium)
**Ucapkan:** "AP asing `FREE-WIFI` dengan daya kuat di dekat Ruang Komando. Tingkatnya *medium* karena belum tentu berbahaya, tapi
tidak seharusnya ada."

### Aksi operator — ±7:00 (peragakan 1 menit)
Peragakan **secara berurutan**:
1. **Tandai dilihat** pada sebuah alert → alert berubah menjadi "Sudah dilihat".
2. **Jadikan resmi** pada AP asing → muncul **dialog konfirmasi**. Ucapkan: "Menjadikan evil twin resmi sama dengan
   melegitimasi penyerang, jadi sistem meminta konfirmasi." Tekan **Batal** (kecuali sedang mendemokan whitelist).
3. **Abaikan** pada AP tetangga.
4. **Padamkan alarm** → alarm di semua node padam.

### Penutup — ±7:45
**Ucapkan:** "Semua ini berjalan offline di satu laptop, dengan node seharga puluhan ribu rupiah per unit (perkiraan). Pasif sepenuhnya: tidak ada
satu baris kode pun yang mengirim serangan. Terima kasih."

---

## 4. Naskah versi ringkas (replay 2×, ±4 menit)

Buka `/?mode=replay&file=demo.jsonl` dan pilih kecepatan **2×**. Bilah replay punya tombol **Jeda/Putar**, pilihan kecepatan, dan
penggeser posisi. Garis warna kecil di atas penggeser menandai alert (merah *critical*, oranye *high*, kuning *medium*); arahkan kursor
untuk melihat judulnya. Rekaman berulang otomatis.

Poin yang cukup diucapkan, satu kalimat per kejadian: evil twin → deauth → pelacak → node hilang → downgrade → SSID mirip → rogue AP.

Penting untuk dikatakan: "**Ini rekaman data uji, bukan sensor langsung.**" Tombol aksi operator di mode replay hanya menampilkan
pemberitahuan, tidak mengubah apa pun. Menggeser penggeser membangun ulang tampilan tanpa bunyi; bunyi hanya saat diputar.

---

## 5. Peragaan perangkat keras (opsional, bila port papan sehat)

Hanya lakukan bila sudah dicoba malam sebelumnya. Jika ragu, lewati dan katakan apa adanya (bagian 6).

**Mode USB-langsung:** satu papan berperan sebagai node sekaligus jembatan ke server (tanpa gateway). Flash dengan env `node1usb`
(lihat [instalasi.md](instalasi.md)), lalu jalankan server dengan `--serial --config-dir config/lab-1node`.

**Yang bisa dilihat penonton:** angka `AP:` dan `BLE:` di LCD naik-turun sesuai udara sekitar; dasbor menampilkan SSID nyata;
node berubah warna saat ada alert.

**Uji evil twin dengan satu ponsel** (tanpa serangan, hanya mengamati hotspot milik sendiri):
1. Buat konfigurasi uji di luar repo: salin `config/lab-1node/` ke folder sementara, lalu isi `whitelist.json` dengan satu entri
   `{"ssid": "LAB-CONDA", "bssids": ["02:00:00:00:00:01"], "security": ["WPA2"]}` (BSSID palsu).
2. Jalankan server dengan `--config-dir <folder-sementara>`.
3. Nyalakan hotspot ponsel bernama `LAB-CONDA`, WPA2, **band 2.4 GHz**, dekat papan.
4. Dalam 1–2 siklus (±6–12 detik) muncul alert **evil twin**: SSID resmi, BSSID tidak cocok.

Variasi dengan hotspot yang sama: ubah namanya menjadi `LAB_CONDA` → *SSID mirip*; daftarkan BSSID asli hotspot lalu setel hotspot ke
terbuka → *penurunan keamanan* (hanya sebagian ponsel Android yang mengizinkan hotspot tanpa kata sandi; iPhone tidak).

> BSSID hotspot ponsel dapat berubah tiap dinyalakan. Itu normal; ulangi pendaftaran bila perlu.

| Deteksi | Kondisi uji (manual, perangkat milik tim) | Harapan |
|---|---|---|
| `evil_twin` / `ssid_lookalike` | Hotspot dengan SSID yang sama/mirip, BSSID tak terdaftar | ±6–12 detik |
| `sec_downgrade` | AP terdaftar diubah menjadi terbuka sebentar | *critical* |
| `rogue_ap` | Hotspot ber-SSID lain, dekat node (≥ −55 dBm) | *medium* |
| `ble_tracker` | AirTag/SmartTag/Tile milik tim didekatkan, tunggu ≥ 3 siklus | *medium/high* |
| `node_lost` | Cabut daya salah satu node (butuh lebih dari satu node) | *high* setelah 30 detik |
| `deauth_flood` | **Tidak** dibuat dengan alat serangan: peragakan hanya di simulator/replay | — |

---

## 6. Apa yang nyata dan apa yang simulasi (katakan terus terang)

Juri menghargai kejujuran, dan pertanyaan ini hampir pasti muncul. Jawaban singkat:

| Bagian | Status |
|---|---|
| Aturan deteksi dan server | **Teruji otomatis:** 130 test, tiap skenario simulator memicu aturan yang benar |
| Dasbor, alarm suara, replay | **Teruji** di peramban |
| Node ESP32 memindai Wi-Fi dan BLE | **Nyata:** diuji di perangkat dengan udara sungguhan |
| Node → server → perintah alarm → balasan | **Nyata** lewat mode USB-langsung (satu papan) |
| Pelacak BLE terdeteksi dari data nyata | Format Apple Find My **terklasifikasi dari udara nyata** (sumber perangkatnya belum diverifikasi sebagai pelacak sungguhan); Samsung dan Tile terbukti di test |
| Tautan radio ESP-NOW antar-papan | **Belum diuji** (hanya ada satu papan); kode dikompilasi |
| Banyak node bersamaan | **Simulator** |
| LED dan buzzer fisik | **Belum diuji** (komponen belum terpasang); logika dan perintah sudah |
| Serangan nyata di lab | **Belum** dilakukan di perangkat keras |

Kalimat yang aman: *"Deteksi sudah terbukti di simulator dan dengan data udara nyata dari satu node. Tautan radio multi-node adalah
langkah berikutnya."*

**Hindari mengatakan:** "100% akurat", "mendeteksi AirTag pasti", "menjangkau semua frekuensi", "sudah diuji multi-node",
"mencegah serangan" (CONDA **mendeteksi dan memperingatkan**, tidak memblokir).

---

## 7. Pertanyaan juri yang mungkin muncul

| Pertanyaan | Jawaban |
|---|---|
| **Kenapa pasif? Kenapa tidak memblokir serangan?** | Pasif itu pilihan sadar: aman dan legal dioperasikan, tidak mengganggu jaringan sendiri. Memblokir (deauth balik) justru melanggar aturan dan berisiko. CONDA fokus pada *deteksi cepat dan peringatan*. |
| **Kenapa hanya 2.4 GHz?** | Keterbatasan ESP32 klasik. Ini ditulis jelas di README. Peta jalan: ESP32-C5 yang dual-band 2.4/5 GHz. |
| **Bagaimana dengan alarm palsu?** | Lalu lintas normal diuji 5 menit tanpa alarm. Ambang bisa disetel di `config/thresholds.json`, dan operator bisa menandai AP resmi atau mengabaikan AP tetangga. |
| **Apakah laporan antar-node bisa dipalsukan?** | Ya, ESP-NOW tidak terautentikasi, dan ini tercatat sebagai keterbatasan. Rencana: HMAC pada tiap paket. Node tak dikenal diabaikan server. |
| **Pelacak berganti alamat, bagaimana?** | Betul. Kami mendeteksi *format iklan*, bukan identitas. Hasilnya "perangkat berformat pelacak", dengan lokasi kasar dari node terkuat. |
| **Bisa diintegrasikan ke SIEM?** | Belum; ada di peta jalan (syslog/CEF). Data sudah terstruktur: REST dan WebSocket JSON. |
| **Kenapa semua logika di server, bukan di node?** | Aturan bisa diubah tanpa flash ulang; node tetap sederhana dan murah; satu tempat untuk diuji (130 test). |
| **Bagaimana dengan privasi / legalitas?** | Hanya membaca frame manajemen publik (beacon) dan iklan BLE; tidak membaca isi lalu lintas. Tidak ada kode pengirim serangan. |
| **Berapa biaya?** | Node ESP32 DevKit, kisaran puluhan ribu rupiah per unit (perkiraan, bergantung toko), ditambah satu laptop sebagai server. |
| **Kenapa offline?** | Lingkungan militer terisolasi: tanpa CDN, API cloud, atau telemetri. Dependensi dapat dipasang dari berkas lokal. |

---

## 8. Bila ada yang gagal saat demo

| Masalah | Tindakan |
|---|---|
| Papan tidak terdeteksi atau port macet | Jangan dipaksa di depan juri. Pindah ke `--sim full_demo`; dasbor dan alurnya identik. Bila port macet (`Invalid argument`), cabut dari **sisi laptop** lalu colok ke port lain; server menyambung sendiri. |
| Server error / port 8000 terpakai | Server memilih port bebas sendiri; buka alamat yang tercetak. Cadangan: tab replay. |
| Tab dasbor kosong | Itu mode live tanpa server. Buka `?mode=replay&file=demo.jsonl`. |
| Suara tidak keluar | Klik halaman sekali, tekan **Suara: aktifkan**, periksa volume dan izin situs. |
| Tidak ada internet / Wi-Fi | Tidak masalah; seluruh sistem offline. |
| Lupa urutan | Mode replay punya penanda alert di bilah posisi; arahkan kursor untuk melihat judulnya. |

---

## 9. Merekam sesi nyata untuk replay

```bash
./.venv/bin/python -m server --serial --config-dir config/lab-1node --fresh --record /tmp/lab.jsonl
```

> **Jangan simpan rekaman udara nyata di `data/samples/` lalu mem-push-nya.** Rekaman berisi nama Wi-Fi dan alamat
> perangkat milik orang di sekitar. Rekam ke luar repo dan sensor dulu (ganti SSID tetangga) bila ingin diterbitkan.

Buka rekaman dengan `?mode=replay&file=<nama>` dengan menaruhnya di `data/samples/` secara lokal, atau bangun situs statis dengan
`./.venv/bin/python tools/build_static.py` (hasilnya di `dist/`, tidak ikut repo).
