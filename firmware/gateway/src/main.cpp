// CONDA — firmware GATEWAY
//
// Menerima paket ESP-NOW dari node, mendekodenya, dan mencetak SATU BARIS JSON per paket
// ke Serial (115200) sesuai docs/protokol.md §3. Sebaliknya, membaca perintah alarm dari
// server (satu JSON per baris) dan menyiarkannya ke node lewat ESP-NOW.
//
// PASIF: gateway tidak terhubung ke Wi-Fi mana pun dan tidak mengirim frame selain
// ESP-NOW (perintah alarm). Tidak ada logika deteksi di sini — itu tugas server.
#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include "conda_proto.h"
#include "conda_json.h"

#define FW_VERSION 1
#ifndef LED_PIN
#define LED_PIN 2            // LED bawaan DevKit V1
#endif

static const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// ---------------------------------------------------------------- antrean penerimaan
// Callback ESP-NOW berjalan di task Wi-Fi: hanya salin ke antrean, jangan cetak di sini.
struct RxItem {
  uint8_t mac[6];
  uint8_t len;
  uint8_t data[ESPNOW_MAX_PAYLOAD];
};
static QueueHandle_t rxQueue;
static volatile uint32_t statRx = 0, statBad = 0, statDrop = 0;

static void onRecv(const uint8_t *mac, const uint8_t *data, int len) {
  if (len < (int)sizeof(PktHeader) || len > ESPNOW_MAX_PAYLOAD) { statBad++; return; }
  RxItem it;
  memcpy(it.mac, mac, 6);
  it.len = (uint8_t)len;
  memcpy(it.data, data, len);
  if (xQueueSend(rxQueue, &it, 0) != pdTRUE) statDrop++;
}

// ---------------------------------------------------------------- dekode paket -> JSON
// Dekode dan pembangun JSON ada di ../../common/conda_json.h (dipakai juga node mode USB-langsung).
static void badPacket(const RxItem &it, const char *why) {
  statBad++;
  char extra[96];
  snprintf(extra, sizeof(extra), "\"msg\":\"bad_packet\",\"why\":\"%s\",\"len\":%u", why, it.len);
  condaGwEvent("error", extra);
}

static void handlePacket(const RxItem &it) {
  const char *why = condaPacketToJson(it.mac, it.data, it.len);
  if (why) badPacket(it, why);
  else statRx++;
}

// ---------------------------------------------------------------- perintah dari server
// Format (dari server): {"cmd":"alert","node":"N2","level":3,"ttl_s":20}
static void handleCmdLine(const char *line) {
  CmdPkt c;
  if (!condaParseCmd(line, c)) return;
  // Siaran tidak ber-ACK: kirim 3x agar lebih andal.
  for (int i = 0; i < 3; i++) {
    esp_now_send(BROADCAST_MAC, (const uint8_t *)&c, sizeof(c));
    delay(15);
  }
  condaCmdAck(c);
}


static void pollSerial() {
  static char buf[200];
  static size_t n = 0;
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n') {
      buf[n] = 0;
      if (n) handleCmdLine(buf);
      n = 0;
    } else if (c != '\r') {
      if (n < sizeof(buf) - 1) buf[n++] = c;
      else n = 0;            // baris terlalu panjang: buang
    }
  }
}

// ---------------------------------------------------------------- setup / loop
void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  rxQueue = xQueueCreate(32, sizeof(RxItem));

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  // Trik standar: kanal hanya bisa diset saat promiscuous aktif bila tidak terhubung ke AP.
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(CONDA_CHANNEL, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(false);

  if (esp_now_init() != ESP_OK) {
    condaGwEvent("error", "\"msg\":\"esp_now_init_failed\"");
    delay(2000);
    ESP.restart();
  }
  esp_now_register_recv_cb(onRecv);

  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, BROADCAST_MAC, 6);
  peer.channel = 0;                  // 0 = kanal saat ini
  peer.ifidx = WIFI_IF_STA;
  peer.encrypt = false;
  esp_now_add_peer(&peer);

  char extra[96], mac[18];
  uint8_t m[6];
  esp_read_mac(m, ESP_MAC_WIFI_STA);
  condaMacStr(m, mac);
  snprintf(extra, sizeof(extra), "\"fw\":%d,\"channel\":%d,\"mac\":\"%s\"", FW_VERSION, CONDA_CHANNEL, mac);
  condaGwEvent("boot", extra);
}

void loop() {
  static uint32_t lastStats = 0;
  RxItem it;
  if (xQueueReceive(rxQueue, &it, pdMS_TO_TICKS(10)) == pdTRUE) {
    digitalWrite(LED_PIN, HIGH);
    handlePacket(it);
    digitalWrite(LED_PIN, LOW);
  }
  pollSerial();
  if (millis() - lastStats > 30000) {
    lastStats = millis();
    char extra[120];
    snprintf(extra, sizeof(extra), "\"rx\":%lu,\"bad\":%lu,\"drop\":%lu,\"heap_kb\":%u",
             (unsigned long)statRx, (unsigned long)statBad, (unsigned long)statDrop, (unsigned)(ESP.getFreeHeap() / 1024));
    condaGwEvent("stats", extra);
  }
}
