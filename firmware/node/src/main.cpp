// CONDA — firmware NODE
//
// Satu radio dipakai bergantian (time-slicing), siklus ±5,5 detik:
//   (a) promiscuous Wi-Fi, hop kanal 1..13 @150 ms: parsing beacon/probe-response
//       (SSID, BSSID, kanal, RSSI, keamanan dari RSN/WPA IE) + hitung frame deauth/disassoc per BSSID
//   (b) scan BLE pasif ±3 detik
//   (c) kembali ke kanal gateway, kirim laporan lewat ESP-NOW + heartbeat, lalu dengar perintah ±300 ms
//
// PASIF: node tidak pernah mengirim frame 802.11 mentah (tidak ada esp_wifi_80211_tx), tidak
// men-deauth, tidak memancarkan beacon, tidak men-jamming. Satu-satunya pemancaran adalah paket
// ESP-NOW ke gateway. Node TIDAK memutuskan apa pun: ia hanya mengumpulkan data mentah;
// seluruh logika deteksi ada di server (config/*.json) agar aturan bisa diubah tanpa flash ulang.
#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <NimBLEDevice.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "conda_proto.h"
#include "conda_json.h"

// ---- Mode USB-langsung (hanya untuk uji/demo satu papan; BUKAN arsitektur normal) ----
// Node yang dicolok ke laptop berperan juga sebagai gateway: paket yang sama persis dengan yang dikirim lewat
// ESP-NOW juga dicetak sebagai baris JSON berformat gateway (protokol.md §3), dan perintah alarm dari server
// diterima lewat serial. Server tidak perlu diubah. Aktifkan dengan env PlatformIO `node1usb`.
// Di mode ini serial hanya berisi JSON; log manusia dibungkam agar server tidak menerima baris non-JSON.
#ifndef CONDA_USB_DIRECT
#define CONDA_USB_DIRECT 0
#endif
#if CONDA_USB_DIRECT
struct NullLog {
  template <typename... A> size_t printf(const char *, A...) { return 0; }
  size_t print(const char *) { return 0; }
  size_t println(const char *) { return 0; }
};
static NullLog Log;
#else
#define Log Serial
#endif

#ifndef CONDA_NODE_ID
#error "Definisikan -DCONDA_NODE_ID=<1..250> (lihat platformio.ini, env node1/node2/node3)"
#endif

#define FW_VERSION 1

// ---- pin (sesuai rancangan perangkat keras) ----
#define PIN_LED_GREEN 25
#define PIN_LED_RED   26
#define PIN_BUZZER    27   // buzzer aktif: HIGH = bunyi

// ---- parameter siklus ----
#define DWELL_MS          150    // waktu per kanal
#define CH_FIRST          1
#define CH_LAST           13
#define BLE_SCAN_SECONDS  3
#define LISTEN_MS         300    // jendela terima perintah setelah melapor
#define MAX_APS           64
#define MAX_DEAUTH        16
#define BLE_MAX_REPORT    48     // maks perangkat BLE per siklus (RSSI terkuat dulu)
#define SELFTEST_BUZZER   1      // bunyi pendek saat boot

// ---- OLED SSD1306 (I2C), opsional ----
#define PIN_OLED_SDA 21
#define PIN_OLED_SCL 22
#ifndef OLED_WIDTH
#define OLED_WIDTH 128
#endif
#ifndef OLED_HEIGHT
#define OLED_HEIGHT 64           // 64 atau 32 (-DOLED_HEIGHT=32); layar 32 piksel hanya menampilkan 4 baris teratas
#endif

static const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// ======================================================================
// Tabel hasil scan (diisi callback sniffer di task Wi-Fi, dibaca task utama)
// ======================================================================
struct ApEntry {
  uint8_t bssid[6];
  uint8_t ch;
  int8_t  rssi;           // terkuat selama siklus
  uint8_t sec;
  uint8_t ssidLen;        // 0 = tersembunyi
  char    ssid[33];
};
struct DeauthEntry {
  uint8_t  bssid[6];
  uint8_t  ch;
  uint16_t deauth;
  uint16_t disassoc;
  int32_t  rssiSum;
  uint16_t nFrames;
  uint8_t  flags;
};
static ApEntry apTab[MAX_APS];
static int apN = 0;
static DeauthEntry dTab[MAX_DEAUTH];
static int dN = 0;
static portMUX_TYPE tabMux = portMUX_INITIALIZER_UNLOCKED;
static volatile bool sniffing = false;

// ---- status alarm (diatur perintah gateway, dijalankan alarmTask) ----
static volatile uint8_t  gLevel = 0;
static volatile uint32_t gUntilMs = 0;

static uint16_t cycleNo = 0;
static uint16_t lastCycleMs = 0;

// ---- status untuk layar (ditulis loop utama, dibaca displayTask; nilai tunggal, aman tanpa kunci) ----
enum Phase : uint8_t { PH_BOOT = 0, PH_WIFI, PH_BLE, PH_REPORT };
static volatile uint8_t  gPhase = PH_BOOT;
static volatile uint8_t  gCurCh = 0;
static volatile uint16_t gShownAp = 0, gShownBle = 0, gShownDeauth = 0;
static volatile uint32_t gLastCmdMs = 0;                  // kapan terakhir menerima perintah dari gateway (0 = belum pernah)
static volatile uint16_t gTxPkts = 0;                     // paket terkirim pada siklus terakhir

// ======================================================================
// Parsing frame 802.11
// ======================================================================
static uint8_t secFromIes(const uint8_t *ies, int len, bool privacy) {
  bool hasRsn = false, hasWpa = false, psk = false, sae = false, ent = false;
  int off = 0;
  while (off + 2 <= len) {
    uint8_t tag = ies[off], l = ies[off + 1];
    if (off + 2 + l > len) break;
    const uint8_t *d = ies + off + 2;
    if (tag == 48 && l >= 8) {                       // RSN IE
      hasRsn = true;
      // version(2) group(4) pairwiseCount(2) pairwise(4*n) akmCount(2) akm(4*m)
      int pos = 2 + 4;
      if (pos + 2 <= l) {
        int pc = d[pos] | (d[pos + 1] << 8);
        pos += 2 + 4 * pc;
        if (pos + 2 <= l) {
          int ac = d[pos] | (d[pos + 1] << 8);
          pos += 2;
          for (int i = 0; i < ac && pos + 4 <= l; i++, pos += 4) {
            if (d[pos] == 0x00 && d[pos + 1] == 0x0F && d[pos + 2] == 0xAC) {
              switch (d[pos + 3]) {
                case 1: case 3: case 5: ent = true; break;      // 802.1X (+FT, SHA256)
                case 2: case 4: case 6: psk = true; break;      // PSK (+FT, SHA256)
                case 8: case 9: sae = true; break;              // SAE (+FT)
                default: break;
              }
            }
          }
        }
      }
    } else if (tag == 221 && l >= 4 && d[0] == 0x00 && d[1] == 0x50 && d[2] == 0xF2 && d[3] == 0x01) {
      hasWpa = true;                                  // IE vendor WPA (WPA1)
    }
    off += 2 + l;
  }
  if (hasRsn) {
    if (sae && psk) return SEC_WPA3_TRANSITION;
    if (sae) return SEC_WPA3;
    if (psk) return SEC_WPA2;
    if (ent) return SEC_ENTERPRISE;
    return SEC_UNKNOWN;                               // mis. OWE
  }
  if (hasWpa) return SEC_WPA;
  return privacy ? SEC_WEP : SEC_OPEN;
}

static void updateAp(const uint8_t *bssid, uint8_t ch, int8_t rssi, uint8_t sec, const uint8_t *ssid, uint8_t ssidLen) {
  portENTER_CRITICAL(&tabMux);
  int idx = -1;
  for (int i = 0; i < apN; i++) if (memcmp(apTab[i].bssid, bssid, 6) == 0) { idx = i; break; }
  if (idx < 0) {
    if (apN < MAX_APS) idx = apN++;
    else {                                            // penuh: ganti entri terlemah bila yang baru lebih kuat
      int w = 0;
      for (int i = 1; i < apN; i++) if (apTab[i].rssi < apTab[w].rssi) w = i;
      if (apTab[w].rssi < rssi) idx = w;
    }
    if (idx >= 0) {
      memcpy(apTab[idx].bssid, bssid, 6);
      apTab[idx].ssidLen = 0;
      apTab[idx].ssid[0] = 0;
      apTab[idx].rssi = -127;
    }
  }
  if (idx >= 0) {
    ApEntry &e = apTab[idx];
    e.ch = ch;
    e.sec = sec;
    if (rssi > e.rssi) e.rssi = rssi;
    if (ssidLen > 0 && e.ssidLen == 0) {              // probe-response bisa membuka SSID yang tersembunyi di beacon
      e.ssidLen = ssidLen;
      memcpy(e.ssid, ssid, ssidLen);
      e.ssid[ssidLen] = 0;
    }
  }
  portEXIT_CRITICAL(&tabMux);
}

static void parseBeacon(const uint8_t *f, int len, int8_t rssi, uint8_t rxCh) {
  if (len < 36) return;
  const uint8_t *bssid = f + 16;                      // addr3
  uint16_t cap = f[34] | (f[35] << 8);
  bool privacy = cap & 0x0010;
  const uint8_t *ies = f + 36;
  int ielen = len - 36;
  uint8_t ch = rxCh, ssidLen = 0;
  const uint8_t *ssid = nullptr;
  int off = 0;
  while (off + 2 <= ielen) {
    uint8_t tag = ies[off], l = ies[off + 1];
    if (off + 2 + l > ielen) break;
    if (tag == 0 && l <= 32) { ssid = ies + off + 2; ssidLen = l; }
    else if (tag == 3 && l == 1) ch = ies[off + 2];   // DS Parameter Set = kanal sebenarnya
    off += 2 + l;
  }
  if (ssid) {                                         // SSID berisi nol semua = tersembunyi
    bool allZero = true;
    for (int i = 0; i < ssidLen; i++) if (ssid[i]) { allZero = false; break; }
    if (allZero) ssidLen = 0;
  }
  if (ch < 1 || ch > 14) ch = rxCh;
  updateAp(bssid, ch, rssi, secFromIes(ies, ielen, privacy), ssid, ssidLen);
}

static void countDeauth(const uint8_t *f, bool isDeauth, int8_t rssi, uint8_t rxCh) {
  const uint8_t *bssid = f + 16;                      // addr3
  bool bcast = true;
  for (int i = 0; i < 6; i++) if (f[4 + i] != 0xFF) { bcast = false; break; }
  portENTER_CRITICAL(&tabMux);
  int idx = -1;
  for (int i = 0; i < dN; i++) if (memcmp(dTab[i].bssid, bssid, 6) == 0) { idx = i; break; }
  if (idx < 0 && dN < MAX_DEAUTH) {
    idx = dN++;
    memset(&dTab[idx], 0, sizeof(DeauthEntry));
    memcpy(dTab[idx].bssid, bssid, 6);
    dTab[idx].ch = rxCh;
  }
  if (idx >= 0) {
    DeauthEntry &e = dTab[idx];
    if (isDeauth) { if (e.deauth < 65535) e.deauth++; } else { if (e.disassoc < 65535) e.disassoc++; }
    e.rssiSum += rssi;
    e.nFrames++;
    if (bcast) e.flags |= DEAUTH_FLAG_BCAST;
  }
  portEXIT_CRITICAL(&tabMux);
}

static void onFrame(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!sniffing || type != WIFI_PKT_MGMT) return;
  const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
  const uint8_t *f = pkt->payload;
  int len = (int)pkt->rx_ctrl.sig_len - 4;            // sig_len termasuk FCS
  if (len < 24) return;
  if ((f[0] & 0x0C) != 0x00) return;                  // hanya frame manajemen
  uint8_t subtype = f[0] >> 4;
  int8_t rssi = pkt->rx_ctrl.rssi;
  uint8_t rxCh = pkt->rx_ctrl.channel;
  switch (subtype) {
    case 8:  case 5:  parseBeacon(f, len, rssi, rxCh); break;   // beacon, probe response
    case 12: countDeauth(f, true, rssi, rxCh);  break;          // deauthentication
    case 10: countDeauth(f, false, rssi, rxCh); break;          // disassociation
    default: break;
  }
}

// ======================================================================
// (a) scan Wi-Fi  (b) scan BLE
// ======================================================================
static void scanWifi() {
  portENTER_CRITICAL(&tabMux);
  apN = 0;
  dN = 0;
  portEXIT_CRITICAL(&tabMux);

  wifi_promiscuous_filter_t flt = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
  esp_wifi_set_promiscuous_filter(&flt);
  esp_wifi_set_promiscuous_rx_cb(&onFrame);
  sniffing = true;
  esp_wifi_set_promiscuous(true);
  for (uint8_t ch = CH_FIRST; ch <= CH_LAST; ch++) {
    gCurCh = ch;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    delay(DWELL_MS);
  }
  sniffing = false;
  esp_wifi_set_promiscuous(false);
}

struct BleSeen { BleRec r; };
static BleRec bleTab[BLE_MAX_REPORT];
static int bleN = 0;

static void scanBle() {
  bleN = 0;
  NimBLEScan *scan = NimBLEDevice::getScan();
  NimBLEScanResults results = scan->start(BLE_SCAN_SECONDS, false);   // blocking, pasif
  int total = results.getCount();
  static BleRec all[96];                              // kandidat sebelum dipangkas ke BLE_MAX_REPORT
  int n = 0;
  for (int i = 0; i < total && n < 96; i++) {
    NimBLEAdvertisedDevice dev = results.getDevice(i);      // NimBLE 1.4: dikembalikan by value
    NimBLEAdvertisedDevice *d = &dev;
    BleRec r;
    memset(&r, 0, sizeof(r));
    const uint8_t *nat = d->getAddress().getNative();   // LSB dulu -> balik ke urutan tampil
    for (int k = 0; k < 6; k++) r.addr[k] = nat[5 - k];
    r.atype = d->getAddressType() & 3;
    r.rssi = (int8_t)constrain(d->getRSSI(), -127, 0);
    r.company = BLE_COMPANY_NONE;
    if (d->haveManufacturerData()) {
      std::string md = d->getManufacturerData();
      if (md.size() >= 2) {
        r.company = (uint8_t)md[0] | ((uint8_t)md[1] << 8);
        if (md.size() >= 3) r.mtype = (uint8_t)md[2];     // mdata[0]
        if (md.size() >= 5) r.info = (uint8_t)md[4];      // mdata[2]
      }
    }
    // UUID 16-bit pertama: daftar service UUID dulu, lalu service data (Samsung SmartTag memakai service data 0xFD5A)
    for (int u = 0; u < d->getServiceUUIDCount() && r.svc == 0; u++) {
      NimBLEUUID id = d->getServiceUUID(u);
      if (id.bitSize() == 16) r.svc = id.getNative()->u16.value;
    }
    for (int u = 0; u < d->getServiceDataCount() && r.svc == 0; u++) {
      NimBLEUUID id = d->getServiceDataUUID(u);
      if (id.bitSize() == 16) r.svc = id.getNative()->u16.value;
    }
    all[n++] = r;
  }
  scan->clearResults();
  // urutkan RSSI terkuat dulu lalu pangkas
  for (int i = 1; i < n; i++) {
    BleRec k = all[i];
    int j = i - 1;
    while (j >= 0 && all[j].rssi < k.rssi) { all[j + 1] = all[j]; j--; }
    all[j + 1] = k;
  }
  bleN = n < BLE_MAX_REPORT ? n : BLE_MAX_REPORT;
  memcpy(bleTab, all, bleN * sizeof(BleRec));
}

// ======================================================================
// (c) laporan ESP-NOW
// ======================================================================
static uint8_t selfMac[6];

static void sendPkt(const uint8_t *buf, size_t len) {
#if CONDA_USB_DIRECT
  condaPacketToJson(selfMac, buf, (int)len);          // jalur USB: JSON berformat gateway
  // Tunggu UART benar-benar selesai mengirim SEBELUM radio memancar: Serial.write kembali saat byte masih
  // di FIFO (128 B, ±11 ms). Pancaran ESP-NOW tepat pada ekor baris menjatuhkan byte (terukur ±12% baris).
  Serial.flush();
#endif
  esp_err_t e = esp_now_send(BROADCAST_MAC, buf, len);
  if (e == ESP_ERR_ESPNOW_NO_MEM) { delay(25); e = esp_now_send(BROADCAST_MAC, buf, len); }
  delay(8);                                           // beri waktu antrean radio
}

static void beginPkt(uint8_t *buf, uint8_t type) {
  PktHeader h = {CONDA_PROTO_VER, type, (uint8_t)CONDA_NODE_ID, 0, cycleNo};
  memcpy(buf, &h, sizeof(h));
}
static void finishPkt(uint8_t *buf, size_t len, uint8_t count) {
  buf[3] = count;
  sendPkt(buf, len);
}

static int reportAps() {
  int order[MAX_APS];
  for (int i = 0; i < apN; i++) order[i] = i;
  for (int i = 1; i < apN; i++) {                     // RSSI terkuat dulu
    int k = order[i], j = i - 1;
    while (j >= 0 && apTab[order[j]].rssi < apTab[k].rssi) { order[j + 1] = order[j]; j--; }
    order[j + 1] = k;
  }
  uint8_t buf[ESPNOW_MAX_PAYLOAD];
  size_t off = sizeof(PktHeader);
  uint8_t count = 0;
  int pkts = 0;
  beginPkt(buf, PKT_AP);
  for (int i = 0; i < apN; i++) {
    const ApEntry &e = apTab[order[i]];
    size_t rec = AP_REC_FIXED + e.ssidLen;
    if (off + rec > sizeof(buf)) { finishPkt(buf, off, count); pkts++; off = sizeof(PktHeader); count = 0; beginPkt(buf, PKT_AP); }
    memcpy(buf + off, e.bssid, 6);
    buf[off + 6] = e.ch;
    buf[off + 7] = (uint8_t)e.rssi;
    buf[off + 8] = e.sec;
    buf[off + 9] = e.ssidLen;
    memcpy(buf + off + AP_REC_FIXED, e.ssid, e.ssidLen);
    off += rec;
    count++;
  }
  if (count) { finishPkt(buf, off, count); pkts++; }
  return pkts;
}

static int reportDeauth() {
  if (dN == 0) return 0;
  uint8_t buf[ESPNOW_MAX_PAYLOAD];
  size_t off = sizeof(PktHeader);
  uint8_t count = 0;
  beginPkt(buf, PKT_DEAUTH);
  for (int i = 0; i < dN; i++) {
    DeauthRec r;
    memcpy(r.bssid, dTab[i].bssid, 6);
    r.ch = dTab[i].ch;
    r.deauth = dTab[i].deauth;
    r.disassoc = dTab[i].disassoc;
    r.rssi = dTab[i].nFrames ? (int8_t)(dTab[i].rssiSum / dTab[i].nFrames) : 0;
    r.flags = dTab[i].flags;
    memcpy(buf + off, &r, sizeof(r));
    off += sizeof(r);
    count++;
  }
  finishPkt(buf, off, count);
  return 1;
}

static int reportBle() {
  int pkts = 0;
  uint8_t buf[ESPNOW_MAX_PAYLOAD];
  const int perPkt = (ESPNOW_MAX_PAYLOAD - sizeof(PktHeader)) / sizeof(BleRec);   // 17
  for (int i = 0; i < bleN; i += perPkt) {
    int c = min(perPkt, bleN - i);
    beginPkt(buf, PKT_BLE);
    memcpy(buf + sizeof(PktHeader), &bleTab[i], c * sizeof(BleRec));
    finishPkt(buf, sizeof(PktHeader) + c * sizeof(BleRec), c);
    pkts++;
  }
  return pkts;
}

static void reportHeartbeat() {
  uint8_t buf[ESPNOW_MAX_PAYLOAD];
  beginPkt(buf, PKT_HB);
  HbRec r;
  r.uptime_s = millis() / 1000;
  r.heap_kb = ESP.getFreeHeap() / 1024;
  r.cycle_ms = lastCycleMs;
  r.fw = FW_VERSION;
  uint8_t lvl = gLevel;
  r.flags = (lvl > 0 ? HB_FLAG_LED_RED : 0) | (lvl >= 2 ? HB_FLAG_BUZZER : 0);
  memcpy(buf + sizeof(PktHeader), &r, sizeof(r));
  finishPkt(buf, sizeof(PktHeader) + sizeof(r), 1);
}

// ======================================================================
// Perintah dari gateway
// ======================================================================
// Menjalankan perintah alarm untuk node ini. true bila perintah ditujukan ke node ini (atau ke semua).
static bool applyCmd(const CmdPkt &c) {
  if (c.node != 0xFF && c.node != CONDA_NODE_ID) return false;
  gLastCmdMs = millis() | 1;                          // |1: jangan sampai bernilai 0 (= belum pernah)
  if (c.level == 0) { gLevel = 0; return true; }
  gUntilMs = millis() + (uint32_t)c.ttl_s * 1000UL;
  gLevel = c.level > 3 ? 3 : c.level;
  return true;
}

static void onRecv(const uint8_t *mac, const uint8_t *data, int len) {
  if (len != (int)sizeof(CmdPkt)) return;
  CmdPkt c;
  memcpy(&c, data, sizeof(c));
  if (c.ver != CONDA_PROTO_VER || c.type != PKT_CMD) return;
  applyCmd(c);
}

#if CONDA_USB_DIRECT
// Perintah dari server lewat serial (task sendiri, agar tidak menunggu scan yang memblokir).
static void serialCmdTask(void *) {
  static char buf[200];
  size_t n = 0;
  for (;;) {
    while (Serial.available()) {
      char ch = (char)Serial.read();
      if (ch == '\n') {
        buf[n] = 0;
        CmdPkt c;
        if (n && condaParseCmd(buf, c) && applyCmd(c)) condaCmdAck(c);
        n = 0;
      } else if (ch != '\r') {
        if (n < sizeof(buf) - 1) buf[n++] = ch;
        else n = 0;                                   // baris terlalu panjang: buang
      }
    }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
}
#endif

// LED & buzzer dijalankan task terpisah agar polanya tidak terganggu scan yang memblokir.
static void alarmTask(void *) {
  for (;;) {
    uint32_t now = millis();
    uint8_t lvl = gLevel;
    if (lvl && (int32_t)(now - gUntilMs) >= 0) { gLevel = 0; lvl = 0; }   // TTL habis: padam sendiri
    bool green = false, red = false, buz = false;
    switch (lvl) {
      case 0: green = true; break;
      case 1: red = true; break;
      case 2: red = true; buz = (now % 1000) < 200; break;
      default: red = ((now / 150) % 2) == 0; buz = true; break;
    }
    digitalWrite(PIN_LED_GREEN, green);
    digitalWrite(PIN_LED_RED, red);
    digitalWrite(PIN_BUZZER, buz);
    vTaskDelay(pdMS_TO_TICKS(20));
  }
}

// ======================================================================
// Layar OLED: task terpisah (core 1) memperbarui tampilan 2x per detik.
// Layar tidak terpasang / tidak terdeteksi -> task tidak dibuat, node berjalan normal.
// ======================================================================
static Adafruit_SSD1306 oled(OLED_WIDTH, OLED_HEIGHT, &Wire, -1);

static bool probeI2c(uint8_t addr) {
  Wire.beginTransmission(addr);
  return Wire.endTransmission() == 0;
}

static const char *phaseName(uint8_t p) {
  switch (p) {
    case PH_WIFI:   return "Scan Wi-Fi";
    case PH_BLE:    return "Scan BLE";
    case PH_REPORT: return "Lapor";
    default:        return "Mulai";
  }
}

static void displayTask(void *) {
  char line[24];
  for (;;) {
    uint32_t now = millis();
    uint8_t lvl = gLevel;
    oled.clearDisplay();
    oled.setTextSize(1);
    oled.setTextColor(SSD1306_WHITE);

    oled.setCursor(0, 0);                              // baris 0: judul + fase
    oled.printf("CONDA N%d", CONDA_NODE_ID);
    snprintf(line, sizeof(line), "#%u", (unsigned)cycleNo);
    oled.setCursor(OLED_WIDTH - 6 * strlen(line), 0);
    oled.print(line);

    oled.setCursor(0, 8);                              // baris 1: jumlah temuan siklus lalu
    oled.printf("AP:%-3u BLE:%-3u Dau:%u", (unsigned)gShownAp, (unsigned)gShownBle, (unsigned)gShownDeauth);

    oled.setCursor(0, 16);                             // baris 2: fase sekarang
    if (gPhase == PH_WIFI) oled.printf("%s ch%u", phaseName(gPhase), (unsigned)gCurCh);
    else oled.print(phaseName(gPhase));

    oled.setCursor(0, 24);                             // baris 3: tautan ke gateway (perintah terakhir diterima)
    uint32_t lc = gLastCmdMs;
    if (lc == 0) oled.print("GW: belum ada balasan");
    else oled.printf("GW: perintah %lus lalu", (unsigned long)((now - lc) / 1000));

#if OLED_HEIGHT >= 64
    oled.setCursor(0, 32);
    oled.printf("Siklus %.1fs  tx %u pkt", lastCycleMs / 1000.0f, (unsigned)gTxPkts);
    oled.setCursor(0, 40);
    uint32_t s = now / 1000;
    oled.printf("Hidup %02lu:%02lu:%02lu", (unsigned long)(s / 3600), (unsigned long)((s / 60) % 60), (unsigned long)(s % 60));
    oled.setCursor(0, 48);
    oled.printf("Heap %uK", (unsigned)(ESP.getFreeHeap() / 1024));
    // baris 7: status alarm (inversi saat alarm agar mencolok dari jauh)
    if (lvl) {
      oled.fillRect(0, 56, OLED_WIDTH, 8, SSD1306_WHITE);
      oled.setTextColor(SSD1306_BLACK);
      oled.setCursor(2, 56);
      oled.printf("!! ALARM LEVEL %u !!", (unsigned)lvl);
    } else {
      oled.setCursor(0, 56);
      oled.print("Status: AMAN");
    }
#endif
    oled.display();
    vTaskDelay(pdMS_TO_TICKS(500));
  }
}

// ----------------------------------------------------------------------
// LCD karakter HD44780 + backpack I2C PCF8574 (alamat 0x27 / 0x3F), mode 4-bit.
// Driver ditulis sendiri (tanpa library). Pemetaan umum backpack:
//   P0=RS P1=RW P2=E P3=lampu latar P4..P7=D4..D7
// Ukuran: -DLCD_COLS=16 -DLCD_ROWS=2 (bawaan) atau -DLCD_COLS=20 -DLCD_ROWS=4
// ----------------------------------------------------------------------
#ifndef LCD_COLS
#define LCD_COLS 16
#endif
#ifndef LCD_ROWS
#define LCD_ROWS 2
#endif
static uint8_t lcdAddr = 0;

static void lcdRaw(uint8_t v) {
  Wire.beginTransmission(lcdAddr);
  Wire.write(v);
  Wire.endTransmission();
}
static void lcdNibble(uint8_t nib, bool rs) {
  uint8_t d = (uint8_t)((nib << 4) | 0x08 | (rs ? 0x01 : 0x00));   // 0x08 = lampu latar menyala
  lcdRaw(d | 0x04);                                   // E tinggi
  delayMicroseconds(2);
  lcdRaw(d & ~0x04);                                  // E rendah: data diambil
  delayMicroseconds(60);
}
static void lcdByte(uint8_t b, bool rs) { lcdNibble(b >> 4, rs); lcdNibble(b & 0x0F, rs); }
static void lcdCmd(uint8_t c) { lcdByte(c, false); if (c <= 0x03) delay(2); }

static void lcdInit() {
  delay(50);
  lcdNibble(0x03, false); delay(5);                   // urutan reset resmi HD44780 -> mode 4-bit
  lcdNibble(0x03, false); delay(1);
  lcdNibble(0x03, false); delay(1);
  lcdNibble(0x02, false); delay(1);
  lcdCmd(0x28);                                       // 4-bit, 2 baris (juga dipakai 4 baris), font 5x8
  lcdCmd(0x0C);                                       // tampilan hidup, kursor mati
  lcdCmd(0x06);                                       // kursor bergerak ke kanan
  lcdCmd(0x01);                                       // bersihkan
}
static void lcdRow(int row, const char *s) {          // tulis satu baris penuh (dipadatkan dengan spasi)
  static const uint8_t base[4] = {0x00, 0x40, 0x14, 0x54};
  lcdCmd(0x80 | base[row & 3]);
  int i = 0;
  for (; i < LCD_COLS && s[i]; i++) lcdByte((uint8_t)s[i], true);
  for (; i < LCD_COLS; i++) lcdByte(' ', true);
}

static void lcdTask(void *) {
  char ln[8][24];
  uint32_t page = 0;
  for (;;) {
    uint32_t now = millis();
    uint8_t lvl = gLevel;
    uint32_t lc = gLastCmdMs;
    // Inisialisasi ulang berkala: bila layar sempat kehilangan daya (kabel goyang, brown-out) ia kembali
    // ke keadaan awal dan akan menampilkan sampah; init ulang memulihkannya tanpa me-reset node.
    if (page % 20 == 0) lcdInit();
    snprintf(ln[0], sizeof(ln[0]), "CONDA N%d #%u", CONDA_NODE_ID, (unsigned)cycleNo);
    snprintf(ln[1], sizeof(ln[1]), "AP:%u BLE:%u D:%u", (unsigned)gShownAp, (unsigned)gShownBle, (unsigned)gShownDeauth);
    if (gPhase == PH_WIFI) snprintf(ln[2], sizeof(ln[2]), "%s ch%u", phaseName(gPhase), (unsigned)gCurCh);
    else snprintf(ln[2], sizeof(ln[2]), "%s", phaseName(gPhase));
#if CONDA_USB_DIRECT
    if (lc == 0) snprintf(ln[3], sizeof(ln[3]), "Mode USB-server");
#else
    if (lc == 0) snprintf(ln[3], sizeof(ln[3]), "GW: belum ada");
#endif
    else snprintf(ln[3], sizeof(ln[3]), "GW cmd %lus lalu", (unsigned long)((now - lc) / 1000));
    snprintf(ln[4], sizeof(ln[4]), "Siklus %.1fs tx%u", lastCycleMs / 1000.0f, (unsigned)gTxPkts);
    uint32_t s = now / 1000;
    snprintf(ln[5], sizeof(ln[5]), "Up %02lu:%02lu:%02lu", (unsigned long)(s / 3600), (unsigned long)((s / 60) % 60), (unsigned long)(s % 60));
    snprintf(ln[6], sizeof(ln[6]), "Heap %uK", (unsigned)(ESP.getFreeHeap() / 1024));
    if (lvl) snprintf(ln[7], sizeof(ln[7]), "!!ALARM LVL %u!!", (unsigned)lvl);
    else snprintf(ln[7], sizeof(ln[7]), "Status: AMAN");

#if LCD_ROWS >= 4
    lcdRow(0, ln[0]); lcdRow(1, ln[1]); lcdRow(2, ln[2]);
    lcdRow(3, lvl ? ln[7] : (((page / 4) % 2) ? ln[7] : ln[3]));
#else
    // 2 baris: baris atas berganti halaman tiap ±2 detik; saat alarm, baris bawah selalu menampilkan alarm
    static const uint8_t pages[4][2] = {{0, 1}, {2, 3}, {4, 5}, {6, 7}};
    const uint8_t *p = pages[(page / 4) % 4];
    if (lvl) { lcdRow(0, ln[1]); lcdRow(1, ln[7]); }
    else { lcdRow(0, ln[p[0]]); lcdRow(1, ln[p[1]]); }
#endif
    page++;
    vTaskDelay(pdMS_TO_TICKS(500));
  }
}

static bool startLcd(uint8_t addr) {
  lcdAddr = addr;
  Wire.setClock(100000);                              // PCF8574 standar 100 kHz paling aman
  lcdInit();
  lcdRow(0, "CONDA sensor");
#if LCD_ROWS >= 2
  char b[24];
  snprintf(b, sizeof(b), "Node N%d LCD 0x%02X", CONDA_NODE_ID, addr);
  lcdRow(1, b);
#endif
  Log.printf("[CONDA] LCD aktif di 0x%02X (%dx%d)\n", addr, LCD_COLS, LCD_ROWS);
  xTaskCreatePinnedToCore(lcdTask, "lcd", 4096, nullptr, 1, nullptr, 1);
  return true;
}

static bool startOled() {
  Wire.begin(PIN_OLED_SDA, PIN_OLED_SCL);
  Wire.setClock(400000);
  Log.print("[CONDA] pindai I2C:");
  uint8_t found = 0, addr = 0, lcd = 0;
  for (uint8_t a = 1; a < 127; a++) {
    if (!probeI2c(a)) continue;
    Log.printf(" 0x%02X", a);
    found++;
    if (a == 0x3C || a == 0x3D) addr = a;                              // SSD1306
    else if (!lcd && ((a >= 0x20 && a <= 0x27) || a == 0x3F)) lcd = a; // backpack LCD PCF8574 (0x27 / 0x3F paling umum)
  }
  Log.println(found ? "" : " (tidak ada perangkat)");
  if (!addr && lcd) return startLcd(lcd);
  if (!addr) { Log.println("[CONDA] layar tidak ditemukan; lanjut tanpa layar"); return false; }
  if (!oled.begin(SSD1306_SWITCHCAPVCC, addr)) { Log.println("[CONDA] OLED begin() gagal; lanjut tanpa layar"); return false; }
  oled.clearDisplay();
  oled.setTextColor(SSD1306_WHITE);
  oled.setTextSize(2);
  oled.setCursor(0, 0);
  oled.printf("CONDA N%d", CONDA_NODE_ID);
  oled.setTextSize(1);
  oled.setCursor(0, 24);
  oled.print("Sensor pasif Wi-Fi/BLE");
  oled.setCursor(0, 36);
  oled.printf("OLED 0x%02X %dx%d", addr, OLED_WIDTH, OLED_HEIGHT);
  oled.display();
  Log.printf("[CONDA] OLED aktif di 0x%02X (%dx%d)\n", addr, OLED_WIDTH, OLED_HEIGHT);
  xTaskCreatePinnedToCore(displayTask, "oled", 4096, nullptr, 1, nullptr, 1);
  return true;
}

// ======================================================================
// setup / loop
// ======================================================================
void setup() {
  Serial.begin(115200);
  pinMode(PIN_LED_GREEN, OUTPUT);
  pinMode(PIN_LED_RED, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT);

  // uji perangkat keras singkat: hijau, merah, bip
  digitalWrite(PIN_LED_GREEN, HIGH); delay(200); digitalWrite(PIN_LED_GREEN, LOW);
  digitalWrite(PIN_LED_RED, HIGH);
#if SELFTEST_BUZZER
  digitalWrite(PIN_BUZZER, HIGH); delay(80); digitalWrite(PIN_BUZZER, LOW);
#endif
  delay(150); digitalWrite(PIN_LED_RED, LOW);

  startOled();                                        // opsional; tanpa layar -> dilewati

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(CONDA_CHANNEL, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(false);

  if (esp_now_init() != ESP_OK) {
    Log.println("[CONDA] esp_now_init GAGAL, restart");
    delay(1500);
    ESP.restart();
  }
  esp_now_register_recv_cb(onRecv);
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, BROADCAST_MAC, 6);
  peer.channel = 0;
  peer.ifidx = WIFI_IF_STA;
  peer.encrypt = false;
  esp_now_add_peer(&peer);

  NimBLEDevice::init("");
  NimBLEScan *scan = NimBLEDevice::getScan();
  scan->setActiveScan(false);                         // pasif: tidak mengirim scan request
  scan->setInterval(100);
  scan->setWindow(99);

  xTaskCreatePinnedToCore(alarmTask, "alarm", 2048, nullptr, 1, nullptr, 1);
  esp_read_mac(selfMac, ESP_MAC_WIFI_STA);
  Log.printf("[CONDA] node N%d siap (fw %d, kanal gateway %d)\n", CONDA_NODE_ID, FW_VERSION, CONDA_CHANNEL);
#if CONDA_USB_DIRECT
  {
    char extra[120], mac[18];
    condaMacStr(selfMac, mac);
    snprintf(extra, sizeof(extra), "\"fw\":%d,\"channel\":%d,\"mac\":\"%s\",\"mode\":\"usb_direct\",\"node\":\"N%d\"",
             FW_VERSION, CONDA_CHANNEL, mac, CONDA_NODE_ID);
    condaGwEvent("boot", extra);
    xTaskCreatePinnedToCore(serialCmdTask, "cmd", 3072, nullptr, 1, nullptr, 1);
  }
#endif
}

void loop() {
  uint32_t t0 = millis();
  cycleNo++;

  gPhase = PH_WIFI;
  scanWifi();                                         // (a)
  gPhase = PH_BLE;
  scanBle();                                          // (b)

  gPhase = PH_REPORT;
  esp_wifi_set_channel(CONDA_CHANNEL, WIFI_SECOND_CHAN_NONE);   // (c)
  delay(5);
  int pa = reportAps(), pd = reportDeauth(), pb = reportBle();
  reportHeartbeat();
  uint32_t reportDone = millis();
  {
    uint32_t dfr0 = 0;
    for (int i = 0; i < dN; i++) dfr0 += dTab[i].deauth + dTab[i].disassoc;
    gShownAp = apN; gShownBle = bleN; gShownDeauth = dfr0;
    gTxPkts = pa + pd + pb + 1;
  }
  delay(LISTEN_MS);                                   // jendela terima perintah alarm

  lastCycleMs = (uint16_t)min<uint32_t>(millis() - t0, 65535);
  uint32_t dfr = 0;
  for (int i = 0; i < dN; i++) dfr += dTab[i].deauth + dTab[i].disassoc;
  Log.printf("[N%d] siklus %u: AP=%d deauth=%u frame BLE=%d | paket ap=%d deauth=%d ble=%d | lapor %lu ms, total %u ms | heap %u KB | alarm L%u\n",
                CONDA_NODE_ID, cycleNo, apN, (unsigned)dfr, bleN, pa, pd, pb,
                (unsigned long)(reportDone - t0 - 0), lastCycleMs, (unsigned)(ESP.getFreeHeap() / 1024), gLevel);
}
