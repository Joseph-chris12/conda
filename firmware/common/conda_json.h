// CONDA — pembuat baris JSON (protokol.md §3) dan parser perintah (§3, "Server -> Gateway").
// Dipakai bersama oleh gateway (paket ESP-NOW -> serial) dan node mode USB-langsung
// (paket yang dibangun node sendiri -> serial), sehingga satu sumber kebenaran.
//
// Header-only, semua fungsi static: sertakan setelah <Arduino.h> dan "conda_proto.h".
#pragma once
#include <Arduino.h>
#include <stdarg.h>
#include "conda_proto.h"

// ---------------------------------------------------------------- pembangun baris JSON
struct JsonLine {
  char buf[2304];
  size_t n = 0;
  bool overflow = false;

  void raw(const char *s) {
    size_t l = strlen(s);
    if (n + l >= sizeof(buf)) { overflow = true; return; }
    memcpy(buf + n, s, l);
    n += l;
    buf[n] = 0;
  }
  __attribute__((format(printf, 2, 3))) void fmt(const char *f, ...) {
    va_list ap;
    va_start(ap, f);
    int w = vsnprintf(buf + n, sizeof(buf) - n, f, ap);
    va_end(ap);
    if (w < 0 || (size_t)w >= sizeof(buf) - n) { overflow = true; return; }
    n += w;
  }
  // SSID dari udara bisa berisi apa saja: escape agar JSON tetap valid.
  void ssid(const uint8_t *s, int len) {
    raw("\"");
    for (int i = 0; i < len; i++) {
      uint8_t c = s[i];
      if (c == '"' || c == '\\') { char t[3] = {'\\', (char)c, 0}; raw(t); }
      else if (c < 0x20 || c == 0x7F) fmt("\\u%04x", c);
      else { char t[2] = {(char)c, 0}; raw(t); }   // byte >= 0x80 diteruskan; server men-decode dengan 'replace'
    }
    raw("\"");
  }
  void flush() {
    if (overflow) {
      Serial.print("{\"v\":1,\"t\":\"gw\",\"event\":\"error\",\"msg\":\"line_overflow\"}\n");
      return;
    }
    Serial.write((const uint8_t *)buf, n);          // satu panggilan tulis: tidak terselip baris lain
  }
};

static inline void condaMacStr(const uint8_t *m, char *out) {
  snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

// Baris status "gw" (boot, cmd_ack, error). `extra` = fragmen JSON tanpa kurung, mis. "\"node\":\"N1\"".
static inline void condaGwEvent(const char *event, const char *extra = nullptr) {
  char b[220];
  snprintf(b, sizeof(b), "{\"v\":1,\"t\":\"gw\",\"gw_ms\":%lu,\"event\":\"%s\"%s%s}\n",
           (unsigned long)millis(), event, extra ? "," : "", extra ? extra : "");
  Serial.print(b);
}

// ---------------------------------------------------------------- paket biner -> baris JSON
static const char *CONDA_SEC_NAMES[] = {"OPEN", "WEP", "WPA", "WPA2", "WPA3_TRANSITION", "WPA3", "ENTERPRISE", "UNKNOWN"};
static const char *CONDA_ATYPE_NAMES[] = {"public", "random", "rpa_public", "rpa_random"};

// Mengubah satu paket (protokol.md §1) menjadi satu baris JSON di Serial.
// Mengembalikan nullptr bila berhasil; bila paket rusak mengembalikan alasan singkat dan TIDAK mencetak apa pun.
// `mac` = alamat pengirim (dicetak sebagai "src").
static inline const char *condaPacketToJson(const uint8_t *mac, const uint8_t *data, int len) {
  if (len < (int)sizeof(PktHeader)) return "short";
  PktHeader h;
  memcpy(&h, data, sizeof(h));
  if (h.ver != CONDA_PROTO_VER) return "version";
  const uint8_t *p = data + sizeof(h);
  int rem = len - (int)sizeof(h);

  const char *tname = h.type == PKT_AP ? "ap" : h.type == PKT_DEAUTH ? "deauth" : h.type == PKT_BLE ? "ble" : h.type == PKT_HB ? "hb" : nullptr;
  if (!tname) return "type";

  static JsonLine L;       // statis: hemat stack
  L.n = 0; L.overflow = false; L.buf[0] = 0;
  char src[18];
  condaMacStr(mac, src);
  L.fmt("{\"v\":1,\"t\":\"%s\",\"node\":\"N%u\",\"cycle\":%u,\"gw_ms\":%lu,\"src\":\"%s\"",
        tname, h.node, h.cycle, (unsigned long)millis(), src);

  if (h.type == PKT_AP) {
    L.raw(",\"aps\":[");
    for (int i = 0; i < h.count; i++) {
      if (rem < AP_REC_FIXED) return "ap_short";
      const uint8_t *bssid = p;
      uint8_t ch = p[6];
      int8_t rssi = (int8_t)p[7];
      uint8_t sec = p[8];
      uint8_t sl = p[9];
      if (sl > 32 || rem < AP_REC_FIXED + sl) return "ap_ssid";
      char b[18];
      condaMacStr(bssid, b);
      if (i) L.raw(",");
      L.raw("{\"ssid\":");
      L.ssid(p + AP_REC_FIXED, sl);
      L.fmt(",\"bssid\":\"%s\",\"ch\":%u,\"rssi\":%d,\"sec\":\"%s\"%s}", b, ch, rssi,
            CONDA_SEC_NAMES[sec > SEC_UNKNOWN ? SEC_UNKNOWN : sec], sl == 0 ? ",\"hidden\":true" : "");
      p += AP_REC_FIXED + sl;
      rem -= AP_REC_FIXED + sl;
    }
    L.raw("]");
  } else if (h.type == PKT_DEAUTH) {
    L.raw(",\"items\":[");
    for (int i = 0; i < h.count; i++) {
      if (rem < (int)sizeof(DeauthRec)) return "deauth_short";
      DeauthRec r;
      memcpy(&r, p, sizeof(r));
      char b[18];
      condaMacStr(r.bssid, b);
      L.fmt("%s{\"bssid\":\"%s\",\"ch\":%u,\"deauth\":%u,\"disassoc\":%u,\"rssi\":%d,\"bcast\":%s}",
            i ? "," : "", b, r.ch, r.deauth, r.disassoc, r.rssi, (r.flags & DEAUTH_FLAG_BCAST) ? "true" : "false");
      p += sizeof(r);
      rem -= sizeof(r);
    }
    L.raw("]");
  } else if (h.type == PKT_BLE) {
    L.raw(",\"items\":[");
    for (int i = 0; i < h.count; i++) {
      if (rem < (int)sizeof(BleRec)) return "ble_short";
      BleRec r;
      memcpy(&r, p, sizeof(r));
      char b[18], comp[8], mt[8], sv[8];
      condaMacStr(r.addr, b);
      if (r.company == BLE_COMPANY_NONE) strcpy(comp, "null"); else snprintf(comp, sizeof(comp), "\"%04x\"", r.company);
      if (r.mtype == 0) strcpy(mt, "null"); else snprintf(mt, sizeof(mt), "\"%02x\"", r.mtype);
      if (r.svc == 0) strcpy(sv, "null"); else snprintf(sv, sizeof(sv), "\"%04x\"", r.svc);
      L.fmt("%s{\"addr\":\"%s\",\"atype\":\"%s\",\"rssi\":%d,\"company\":%s,\"mtype\":%s,\"svc\":%s,\"info\":%u}",
            i ? "," : "", b, CONDA_ATYPE_NAMES[r.atype & 3], r.rssi, comp, mt, sv, r.info);
      p += sizeof(r);
      rem -= sizeof(r);
    }
    L.raw("]");
  } else {  // PKT_HB
    if (rem < (int)sizeof(HbRec)) return "hb_short";
    HbRec r;
    memcpy(&r, p, sizeof(r));
    L.fmt(",\"uptime_s\":%lu,\"heap_kb\":%u,\"cycle_ms\":%u,\"fw\":%u,\"led_red\":%s,\"buzzer\":%s",
          (unsigned long)r.uptime_s, r.heap_kb, r.cycle_ms, r.fw,
          (r.flags & HB_FLAG_LED_RED) ? "true" : "false", (r.flags & HB_FLAG_BUZZER) ? "true" : "false");
  }
  L.raw("}\n");
  L.flush();
  return nullptr;
}

// ---------------------------------------------------------------- perintah dari server
// Format: {"cmd":"alert","node":"N2","level":3,"ttl_s":20}   (node: "N<id>" atau "all")
static inline bool condaFindInt(const char *line, const char *key, int &out) {
  const char *k = strstr(line, key);
  if (!k) return false;
  out = atoi(k + strlen(key));
  return true;
}

// true bila `line` adalah perintah alert yang valid; hasilnya di `out` (node 0xFF = semua).
static inline bool condaParseCmd(const char *line, CmdPkt &out) {
  if (!strstr(line, "\"cmd\":\"alert\"")) return false;
  int level = 0, ttl = 20;
  condaFindInt(line, "\"level\":", level);
  condaFindInt(line, "\"ttl_s\":", ttl);
  uint8_t node = 0xFF;
  const char *nk = strstr(line, "\"node\":\"");
  if (nk) {
    nk += 8;
    if (*nk == 'N' || *nk == 'n') node = (uint8_t)atoi(nk + 1);
  }
  out = {CONDA_PROTO_VER, PKT_CMD, node, (uint8_t)constrain(level, 0, 3), (uint8_t)constrain(ttl, 0, 255)};
  return true;
}

// Balasan "cmd_ack" untuk perintah yang sudah dijalankan.
static inline void condaCmdAck(const CmdPkt &c) {
  char extra[80];
  if (c.node == 0xFF) snprintf(extra, sizeof(extra), "\"node\":\"all\",\"level\":%u", c.level);
  else snprintf(extra, sizeof(extra), "\"node\":\"N%u\",\"level\":%u", c.node, c.level);
  condaGwEvent("cmd_ack", extra);
}
