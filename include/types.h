#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>

// ─── 802.11 Deauth / Disassoc çerçeve yapısı ─────────────────────────────────
typedef struct {
  uint8_t  frame_control[2];
  uint8_t  duration[2];
  uint8_t  station[6];
  uint8_t  sender[6];
  uint8_t  access_point[6];
  uint8_t  fragment_sequence[2];
  uint16_t reason;
} deauth_frame_t;

// ─── Minimal 802.11 MAC başlığı ───────────────────────────────────────────────
typedef struct {
  uint16_t frame_ctrl;
  uint16_t duration;
  uint8_t  dest[6];
  uint8_t  src[6];
  uint8_t  bssid[6];
  uint16_t sequence_ctrl;
  uint8_t  addr4[6];
} mac_hdr_t;

// ─── Ham paket (MAC başlığı + veri yükü) ─────────────────────────────────────
typedef struct {
  mac_hdr_t hdr;
  uint8_t   payload[0];
} wifi_packet_t;

// ─── Statik başlatıcılar ───────────────────────────────────────────────────────
static inline deauth_frame_t make_deauth_frame() {
  deauth_frame_t f = {};
  f.frame_control[0] = 0xC0;
  f.frame_control[1] = 0x00;
  f.fragment_sequence[0] = 0xF0;
  f.fragment_sequence[1] = 0xFF;
  return f;
}

#endif
