#ifndef BOARD_HAL_H
#define BOARD_HAL_H

// BW16 / RTL8720DN — tek hedef platform
#define HAL_PLATFORM_RTL8720DN

// ─── Arayüz sabitleri (raw frame TX için) ────────────────────────────────────
#define HAL_IF_AP  0
#define HAL_IF_STA 1

// ─── Birleşik promiscuous callback imzası ────────────────────────────────────
typedef void (*hal_promisc_cb_t)(const uint8_t *frame, uint16_t len);

// ─── Fonksiyon bildirimleri ───────────────────────────────────────────────────

void hal_hw_init();
void hal_apply_max_performance();
void hal_reapply_wifi_power(bool wps_running);
void hal_wifi_80211_tx(int ifx, const void *buf, int len);
void hal_wifi_set_promiscuous(bool enable);
void hal_wifi_set_promiscuous_filter();
void hal_wifi_set_promiscuous_rx_cb(hal_promisc_cb_t cb);
void hal_wifi_set_channel(int channel);
bool hal_has_wps();
bool hal_has_https_redirect();
void hal_wifi_rotate_mac(uint8_t *mac, int len);
void hal_wifi_save_mac(uint8_t *out_mac);

#endif
