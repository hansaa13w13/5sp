// wps.cpp
// BW16 / RTL8720DN için WPS saldırısı stub'ları
// ESP-IDF WPS API'si Ameba SDK'da bulunmadığından WPS saldırısı desteklenmiyor.

#include "wps_attack.h"
#include "wps_beacon_ie.h"

// ─── Dışa açılan WPS değişkenleri ────────────────────────────────────────────
wps_target_t wps_targets[WPS_MAX_TARGETS];
int          wps_target_count  = 0;
wps_state_t  wps_attack_state  = WPS_IDLE;
int          wps_attempt       = 0;
int          wps_total         = 0;
char         wps_current_pin[9]  = {0};
char         wps_found_pin[9]    = {0};
char         wps_found_ssid[33]  = {0};
char         wps_found_pass[65]  = {0};
char         wps_vendor_name[32] = {0};
uint8_t      wps_current_mac[6]  = {0};
int          wps_lockout_count   = 0;

// ─── WPS beacon IE global ─────────────────────────────────────────────────────
wps_device_info_t wps_device_info = {};

// ─── Stub fonksiyonlar ────────────────────────────────────────────────────────
void wps_scan()                     {}
void wps_start_attack(int)          {}
void wps_stop()                     {}
void wps_loop()                     {}

int wps_ssid_to_pins(const char *, const uint8_t *, char[][9], int) { return 0; }

bool wps_capture_device_info(const uint8_t *, int, uint32_t) { return false; }
int  wps_serial_to_pins(const char *, char[][9], int)          { return 0; }
void wps_assess_pixie_risk(wps_device_info_t &)                {}
uint8_t wps_pin_checksum(uint32_t)                             { return 0; }
