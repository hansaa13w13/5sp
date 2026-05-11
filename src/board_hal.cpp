#include <Arduino.h>
#include <WiFi.h>
#include "board_hal.h"
#include "definitions.h"

// ─── Dahili değişken: kayıtlı callback ───────────────────────────────────────
static hal_promisc_cb_t g_promisc_cb = nullptr;

// ═════════════════════════════════════════════════════════════════════════════
// ESP32 platformu
// ═════════════════════════════════════════════════════════════════════════════
#ifdef HAL_PLATFORM_ESP32

#include <esp_wifi.h>
#include <esp_pm.h>

// ESP32 raw frame inject bildirimi
esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

// ── ESP32 promiscuous sarmalayıcı ─────────────────────────────────────────────
static void esp32_promisc_wrapper(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!g_promisc_cb) return;
  const wifi_promiscuous_pkt_t *raw = (const wifi_promiscuous_pkt_t *)buf;
  g_promisc_cb(raw->payload, (uint16_t)raw->rx_ctrl.sig_len);
}

void hal_hw_init() {
  // ── Bluetooth tamamen kapat — radyo kaynağını sadece WiFi'ye ver ────────────
  btStop();

  // ── Regulatory kısıtı kaldır: özel ülke kodu "00" + azami TX yetkisi ───────
  // max_tx_power=84 → 84×0.25=21 dBm (ESP32 donanım tavanı).
  // Bu ayar yapılmazsa esp_wifi_set_max_tx_power(84) çağrısı regulatory
  // sınır (ör. TR=20 dBm) tarafından kesilir.
  wifi_country_t country;
  memset(&country, 0, sizeof(country));
  country.cc[0]        = '0';
  country.cc[1]        = '0';
  country.schan        = 1;
  country.nchan        = 13;
  country.max_tx_power = 84;            // ← 84×0.25=21 dBm tavan
  country.policy       = WIFI_COUNTRY_POLICY_MANUAL;
  esp_wifi_set_country(&country);

  // ── WiFi uyku katmanlarını kapat ───────────────────────────────────────────
  WiFi.setSleep(false);
  esp_wifi_set_ps(WIFI_PS_NONE);

  // ── CPU güç yönetimi: 240 MHz sabit, light sleep kapalı ───────────────────
#if defined(CONFIG_IDF_TARGET_ESP32S3)
  esp_pm_config_esp32s3_t pm_cfg = {
    .max_freq_mhz       = 240,
    .min_freq_mhz       = 240,
    .light_sleep_enable = false
  };
  esp_pm_configure(&pm_cfg);
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
  esp_pm_config_esp32s2_t pm_cfg = {
    .max_freq_mhz       = 240,
    .min_freq_mhz       = 240,
    .light_sleep_enable = false
  };
  esp_pm_configure(&pm_cfg);
#else // ESP32 klasik
  esp_pm_config_esp32_t pm_cfg = {
    .max_freq_mhz       = 240,
    .min_freq_mhz       = 240,
    .light_sleep_enable = false
  };
  esp_pm_configure(&pm_cfg);
#endif
}

void hal_apply_max_performance() {
  // ── CPU: 240 MHz sabit (hal_hw_init PM kilidiyle tutarlı) ─────────────────
  setCpuFrequencyMhz(240);

  // ── WiFi uyku: tamamen kapat ───────────────────────────────────────────────
  esp_wifi_set_ps(WIFI_PS_NONE);

  // ── TX gücü: donanım tavanı 84 (84×0.25=21 dBm) ──────────────────────────
  // AP ve STA arayüzlerine ayrı ayrı uygula (IDF ≥4.4 destekler)
  esp_wifi_set_max_tx_power(84);

  // ── Bant genişliği: HT40 → daha hızlı raw frame inject ───────────────────
  // AP modunda 40 MHz kanal; inject paketleri daha az süre havayı meşgul eder
  esp_wifi_set_bandwidth(WIFI_IF_AP,  WIFI_BW_HT40);
  esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT40);

  // ── Protokol: 11b+g+n (LR modunu kapat) ───────────────────────────────────
  esp_wifi_set_protocol(WIFI_IF_AP,
    WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);
  esp_wifi_set_protocol(WIFI_IF_STA,
    WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);
}

void hal_reapply_wifi_power(bool wps_running) {
  // Her loop iterasyonunda TX gücü ve PS durumunu zorla — IDF bazen sıfırlar
  esp_wifi_set_max_tx_power(84);
  if (!wps_running) esp_wifi_set_ps(WIFI_PS_NONE);
}

void hal_wifi_80211_tx(int ifx, const void *buf, int len) {
  esp_wifi_80211_tx((wifi_interface_t)ifx, buf, len, false);
}

void hal_wifi_set_promiscuous(bool enable) {
  esp_wifi_set_promiscuous(enable);
}

void hal_wifi_set_promiscuous_filter() {
  static const wifi_promiscuous_filter_t flt = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
  };
  esp_wifi_set_promiscuous_filter(&flt);
}

void hal_wifi_set_promiscuous_rx_cb(hal_promisc_cb_t cb) {
  g_promisc_cb = cb;
  if (cb) {
    esp_wifi_set_promiscuous_rx_cb(esp32_promisc_wrapper);
  } else {
    esp_wifi_set_promiscuous_rx_cb(nullptr);
  }
}

void hal_wifi_set_channel(int channel) {
  esp_wifi_set_channel((uint8_t)channel, WIFI_SECOND_CHAN_NONE);
}

bool hal_has_wps()            { return true; }
bool hal_has_https_redirect() { return true; }

void hal_wifi_save_mac(uint8_t *out_mac) {
  esp_wifi_get_mac(WIFI_IF_STA, out_mac);
}

void hal_wifi_rotate_mac(uint8_t *mac, int len) {
  esp_wifi_set_mac(WIFI_IF_STA, mac);
}

// ═════════════════════════════════════════════════════════════════════════════
// BW16 / RTL8720DN platformu (Ameba Arduino SDK)
// ═════════════════════════════════════════════════════════════════════════════
#else // HAL_PLATFORM_RTL8720DN

// Ameba-D (RTL8720DN) düşük seviyeli SDK fonksiyon bildirimleri
extern "C" {
  int  wifi_send_raw_frame(unsigned char *buf, int buf_len);
  int  wifi_set_channel(unsigned int channel);
  // RTW_PROMISC_ENABLE_2 = 3: tüm 802.11 çerçeveleri (yönetim + veri)
  int  wifi_set_promisc(int enabled,
         void (*callback)(unsigned char*, unsigned int, void*),
         unsigned char len_used);
  int  wifi_get_mac_address(char *mac);
  int  wifi_set_mac_address(char *mac);

  // ── Güç tasarrufu ─────────────────────────────────────────────────────────
  // WiFi.disablePowerSave() yalnızca STA modunda etkilidir;
  // aşağıdaki C çağrısı hem AP hem STA arayüzünü etkiler.
  int  wifi_disable_powersave(void);

  // ── TX gücü ───────────────────────────────────────────────────────────────
  // RTL8720DN: 0–100 arasında yüzde değeri.
  // 100 = donanım tavanı ≈ 20 dBm (2.4 GHz) / 18 dBm (5 GHz)
  int  wifi_set_tx_power_percentage(unsigned char tx_pwr_percentage);

  // ── Ülke kodu ─────────────────────────────────────────────────────────────
  // "00" → en geniş izin verilen kanal + güç kümesi
  // Bazı Ameba SDK sürümlerinde bu fonksiyon bulunmayabilir;
  // derleme hatası alınırsa satırı yorum satırına alın.
  // int  wifi_set_country_code(char *country_code);
}

// Ameba promiscuous callback sarmalayıcı
static void rtl_promisc_wrapper(unsigned char *buf, unsigned int len, void *userdata) {
  if (g_promisc_cb && buf && len > 0) {
    g_promisc_cb(buf, (uint16_t)len);
  }
}

void hal_hw_init() {
  // ── Güç tasarrufunu kapat (hem STA hem AP arayüzü) ─────────────────────────
  WiFi.disablePowerSave();
  wifi_disable_powersave();

  // ── TX gücü: azami (%100) ─────────────────────────────────────────────────
  // RTL8720DN 2.4 GHz ≈ 20 dBm, 5 GHz ≈ 18 dBm donanım tavanı
  wifi_set_tx_power_percentage(100);
}

void hal_apply_max_performance() {
  // ── Güç tasarrufunu kapat + TX gücü azami ────────────────────────────────
  // Ameba SDK CPU frekansını (KM4@200MHz, KM0@20MHz) otomatik yönetir;
  // frekans düşürmeyi engellemek için PS'i kapatmak yeterlidir.
  WiFi.disablePowerSave();
  wifi_disable_powersave();
  wifi_set_tx_power_percentage(100);
}

void hal_reapply_wifi_power(bool wps_running) {
  (void)wps_running;
  // Her loop iterasyonunda TX gücünü ve PS'i zorla — SDK bazen sıfırlar
  wifi_disable_powersave();
  wifi_set_tx_power_percentage(100);
}

void hal_wifi_80211_tx(int ifx, const void *buf, int len) {
  (void)ifx;
  // RTL8720DN: tek birleşik arayüz üzerinden raw frame inject
  wifi_send_raw_frame((unsigned char *)buf, len);
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
  // RTL8720DN'de filtre wifi_set_promisc parametresiyle belirlenir
  // (mode=3 zaten tüm 802.11 çerçevelerini alır — ek filtre gerekmez)
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
  wifi_set_channel((unsigned int)channel);
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
  char mac_str[18];
  snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  wifi_set_mac_address(mac_str);
}

#endif // Platform seçimi
