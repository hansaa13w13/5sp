#include <Arduino.h>
#include <WiFi.h>
#include "board_hal.h"
#include "definitions.h"

// ─── Dahili değişken: kayıtlı callback ───────────────────────────────────────
static hal_promisc_cb_t g_promisc_cb = nullptr;

// ═════════════════════════════════════════════════════════════════════════════
// BW16 / RTL8720DN — Ameba Arduino SDK
// ═════════════════════════════════════════════════════════════════════════════

// RTL8720DN düşük seviyeli SDK fonksiyon bildirimleri
// Kaynak: Arduino_package/hardware/system/component/common/api/wifi/wifi_conf.h
//         Arduino_package/hardware/system/component/common/api/wifi/wifi_util.h
extern "C" {
  // Ham yönetim çerçevesi göndermek için gerçek SDK fonksiyonu
  // wext_send_mgnt("wlan0", buf, buf_len, flags)
  int wext_send_mgnt(const char *ifname, char *buf,
                     unsigned short buf_len, unsigned short flags);

  // Kanal değiştirme — sdk imzası: int channel (işaretli int)
  int wifi_set_channel(int channel);

  // Promiscuous mod — sdk imzası: rtw_rcr_level_t (enum, int eşdeğeri)
  int wifi_set_promisc(int enabled,
                       void (*callback)(unsigned char*, unsigned int, void*),
                       unsigned char len_used);

  int wifi_get_mac_address(char *mac);
  int wifi_set_mac_address(char *mac);
  int wifi_disable_powersave(void);

  // TX gücü — sdk imzası: unsigned long
  int wifi_set_tx_power_percentage(unsigned long power_percentage_idx);
}

// Ameba promiscuous callback sarmalayıcı
static void rtl_promisc_wrapper(unsigned char *buf, unsigned int len, void *userdata) {
  (void)userdata;
  if (g_promisc_cb && buf && len > 0) {
    g_promisc_cb(buf, (uint16_t)len);
  }
}

void hal_hw_init() {
  WiFi.disablePowerSave();
  wifi_disable_powersave();
  wifi_set_tx_power_percentage(100UL);
}

void hal_apply_max_performance() {
  WiFi.disablePowerSave();
  wifi_disable_powersave();
  wifi_set_tx_power_percentage(100UL);
}

void hal_reapply_wifi_power(bool wps_running) {
  (void)wps_running;
  wifi_disable_powersave();
  wifi_set_tx_power_percentage(100UL);
}

void hal_wifi_80211_tx(int ifx, const void *buf, int len) {
  (void)ifx;
  // RTL8720DN: wext_send_mgnt aracılığıyla raw 802.11 çerçevesi gönder
  wext_send_mgnt("wlan0", (char *)buf, (unsigned short)len, 0);
}

void hal_wifi_set_promiscuous(bool enable) {
  if (enable) {
    // RTW_PROMISC_ENABLE_2 = 3 → tüm 802.11 çerçeveleri (yönetim + veri)
    wifi_set_promisc(3, rtl_promisc_wrapper, 1);
  } else {
    wifi_set_promisc(0, nullptr, 0);
  }
}

void hal_wifi_set_promiscuous_filter() {
  // RTL8720DN'de filtre wifi_set_promisc() parametresiyle belirlenir
}

void hal_wifi_set_promiscuous_rx_cb(hal_promisc_cb_t cb) {
  g_promisc_cb = cb;
  if (cb) {
    wifi_set_promisc(3, rtl_promisc_wrapper, 1);
  } else {
    wifi_set_promisc(0, nullptr, 0);
  }
}

void hal_wifi_set_channel(int channel) {
  wifi_set_channel(channel);
}

bool hal_has_wps()            { return false; }
bool hal_has_https_redirect() { return false; }

void hal_wifi_save_mac(uint8_t *out_mac) {
  char mac_str[18] = {};
  wifi_get_mac_address(mac_str);
  sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
         &out_mac[0], &out_mac[1], &out_mac[2],
         &out_mac[3], &out_mac[4], &out_mac[5]);
}

void hal_wifi_rotate_mac(uint8_t *mac, int len) {
  (void)len;
  char mac_str[18];
  snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  wifi_set_mac_address(mac_str);
}
