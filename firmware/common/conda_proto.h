// CONDA — format paket ESP-NOW node <-> gateway (v1).
// Sumber kebenaran: docs/protokol.md §1–§2. Dipakai bersama oleh firmware node dan gateway.
// Semua angka multi-byte little-endian (urutan asli ESP32), struct di-pack tanpa padding.
#pragma once
#include <stdint.h>

#define CONDA_PROTO_VER 1
#define ESPNOW_MAX_PAYLOAD 250

// Kanal Wi-Fi tetap untuk ESP-NOW. Node dan gateway HARUS sama.
// Node meng-hop 1..13 untuk scan lalu kembali ke kanal ini untuk melapor.
#ifndef CONDA_CHANNEL
#define CONDA_CHANNEL 1
#endif

enum PktType : uint8_t {
  PKT_AP     = 1,
  PKT_DEAUTH = 2,
  PKT_BLE    = 3,
  PKT_HB     = 4,
  PKT_CMD    = 0x80,   // gateway -> node
};

// Kode keamanan AP (tabel di protokol.md §1)
enum SecType : uint8_t {
  SEC_OPEN = 0, SEC_WEP = 1, SEC_WPA = 2, SEC_WPA2 = 3,
  SEC_WPA3_TRANSITION = 4, SEC_WPA3 = 5, SEC_ENTERPRISE = 6, SEC_UNKNOWN = 7,
};

#pragma pack(push, 1)
struct PktHeader {          // 6 byte
  uint8_t  ver;
  uint8_t  type;
  uint8_t  node;
  uint8_t  count;
  uint16_t cycle;
};

// Record AP bervariasi: bssid[6] ch rssi sec ssid_len ssid[ssid_len]
#define AP_REC_FIXED 10

struct DeauthRec {          // 13 byte
  uint8_t  bssid[6];
  uint8_t  ch;
  uint16_t deauth;
  uint16_t disassoc;
  int8_t   rssi;
  uint8_t  flags;           // bit0 = ada frame ke broadcast
};

struct BleRec {             // 14 byte
  uint8_t  addr[6];         // urutan tampil (MSB dulu)
  uint8_t  atype;           // 0 public, 1 random, 2 rpa-public, 3 rpa-random
  int8_t   rssi;
  uint16_t company;         // 0xFFFF = tidak ada manufacturer data
  uint8_t  mtype;           // mdata[0], 0 = tidak ada
  uint16_t svc;             // UUID 16-bit pertama, 0 = tidak ada
  uint8_t  info;            // mdata[2], 0 = tidak ada
};

struct HbRec {              // 10 byte
  uint32_t uptime_s;
  uint16_t heap_kb;
  uint16_t cycle_ms;
  uint8_t  fw;
  uint8_t  flags;           // bit0 LED merah, bit1 buzzer
};

struct CmdPkt {             // 5 byte, gateway -> node (broadcast)
  uint8_t ver;
  uint8_t type;             // PKT_CMD
  uint8_t node;             // 0xFF = semua
  uint8_t level;            // 0 padam, 1 LED, 2 LED + buzzer putus-putus, 3 LED + buzzer terus
  uint8_t ttl_s;            // padam sendiri bila tak ada perintah baru
};
#pragma pack(pop)

static_assert(sizeof(PktHeader) == 6, "PktHeader harus 6 byte");
static_assert(sizeof(DeauthRec) == 13, "DeauthRec harus 13 byte");
static_assert(sizeof(BleRec) == 14, "BleRec harus 14 byte");
static_assert(sizeof(HbRec) == 10, "HbRec harus 10 byte");
static_assert(sizeof(CmdPkt) == 5, "CmdPkt harus 5 byte");

#define HB_FLAG_LED_RED 0x01
#define HB_FLAG_BUZZER  0x02
#define DEAUTH_FLAG_BCAST 0x01
#define BLE_COMPANY_NONE 0xFFFF
