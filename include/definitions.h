#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#define AP_SSID "X"
#define AP_PASS "20192019"
#define SERIAL_DEBUG
#define CHANNEL_MAX 13          // 2.4 GHz kanal üst sınırı
#define NUM_FRAMES_PER_DEAUTH 30
#define DEAUTH_BLINK_TIMES 2
#define DEAUTH_BLINK_DURATION 20
#define DEAUTH_TYPE_SINGLE 0
#define DEAUTH_TYPE_ALL 1
#define DEAUTH_TYPE_EVIL_TWIN 2

// Hedef yeniden tarama aralığı (ms)
#define RETRACK_INTERVAL_MS 25000
// CSA beacon gönderim aralığı (ms) — iOS PMF bypass
#define CSA_INTERVAL_MS 500
// Evil Twin şifre testi sırasında sunucu cevap döngüsü (ms)
#define ET_TEST_TIMEOUT_MS 9000
// Proaktif deauth aralığı (ms) — hedef cihazı gerçek AP'den sürekli düşürür
#define ET_DEAUTH_INTERVAL_MS 250

// ─── 5 GHz Kanal Tanımları ────────────────────────────────────────────────────
// BW16 (RTL8720DN) çift bantlı: hem 2.4 hem 5 GHz destekler
#define IS_5GHZ_CHANNEL(ch) ((ch) >= 36)

// 5 GHz UNII bandları için CSA operating class
static inline uint8_t get_5ghz_op_class(uint8_t ch) {
  if (ch <= 48)  return 115;
  if (ch <= 64)  return 118;
  if (ch <= 144) return 121;
  return 125;
}

// Tüm geçerli 5 GHz kanalları (802.11a/n/ac)
static const uint8_t CHANNELS_5GHZ[] = {
  36, 40, 44, 48,
  52, 56, 60, 64,
  100, 104, 108, 112,
  116, 120, 124, 128,
  132, 136, 140, 144,
  149, 153, 157, 161, 165
};
static const int CHANNELS_5GHZ_COUNT = (int)(sizeof(CHANNELS_5GHZ) / sizeof(CHANNELS_5GHZ[0]));

// ─── LED pin tanımları ────────────────────────────────────────────────────────
// BW16-KIT: GPIO10 (mavi LED, aktif-düşük)
#define LED 10

// ─── Debug makroları ──────────────────────────────────────────────────────────
#ifdef SERIAL_DEBUG
#define DEBUG_PRINT(...)   Serial.print(__VA_ARGS__)
#define DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
#define DEBUG_PRINTF(...) do { char _dbg[256]; snprintf(_dbg, sizeof(_dbg), __VA_ARGS__); Serial.print(_dbg); } while(0)
#else
#define DEBUG_PRINT(...)
#define DEBUG_PRINTLN(...)
#define DEBUG_PRINTF(...)
#endif

#ifdef LED
#define BLINK_LED(n, d) blink_led(n, d)
#else
#define BLINK_LED(n, d)
#endif

void blink_led(int num_times, int blink_duration);
void led_on();
void led_off();
void apply_max_performance();
void reapply_wifi_power();

#endif
