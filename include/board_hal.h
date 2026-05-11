#ifndef BOARD_HAL_H
#define BOARD_HAL_H

// ─── Platform tespiti ─────────────────────────────────────────────────────────
#if defined(BOARD_BW16)
  #define HAL_PLATFORM_RTL8720DN
#else
  #define HAL_PLATFORM_ESP32
  #include <esp_wifi.h>
#endif

// ─── Arayüz sabitleri (raw frame TX için) ────────────────────────────────────
#ifdef HAL_PLATFORM_ESP32
  #define HAL_IF_AP  WIFI_IF_AP
  #define HAL_IF_STA WIFI_IF_STA
#else
  #define HAL_IF_AP  0
  #define HAL_IF_STA 1
#endif

// ─── Birleşik promiscuous callback imzası ────────────────────────────────────
// Hem ESP32 hem RTL8720DN için aynı imzayı kullanır.
// frame: ham 802.11 çerçevesi (MAC başlığı dahil)
// len  : çerçeve uzunluğu (byte)
typedef void (*hal_promisc_cb_t)(const uint8_t *frame, uint16_t len);

// ─── Fonksiyon bildirimleri ───────────────────────────────────────────────────

// Donanım başlatma — setup()'ta bir kez çağrılır
void hal_hw_init();

// Maks performans uygula
void hal_apply_max_performance();

// Her loop iterasyonunda çağrılır (TX gücü + PS sabitler)
void hal_reapply_wifi_power(bool wps_running);

// Ham 802.11 çerçevesi gönder
// ifx: HAL_IF_AP veya HAL_IF_STA
void hal_wifi_80211_tx(int ifx, const void *buf, int len);

// Promiscuous modunu aç/kapat
void hal_wifi_set_promiscuous(bool enable);

// Promiscuous filtre ayarla (yalnızca ESP32'de etkilidir)
void hal_wifi_set_promiscuous_filter();

// Promiscuous callback kaydet
void hal_wifi_set_promiscuous_rx_cb(hal_promisc_cb_t cb);

// Kanal değiştir (hem 2.4 hem 5 GHz kanalları desteklenir)
void hal_wifi_set_channel(int channel);

// WPS desteği var mı?
bool hal_has_wps();

// HTTPS yönlendirme desteği var mı?
bool hal_has_https_redirect();

// MAC adresi değiştir (STA arayüzü) — yalnızca ESP32'de desteklenir
void hal_wifi_rotate_mac(uint8_t *mac, int len);

// Orijinal STA MAC'i kaydet
void hal_wifi_save_mac(uint8_t *out_mac);

#endif
