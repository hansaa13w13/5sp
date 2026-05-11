#ifndef EVIL_TWIN_H
#define EVIL_TWIN_H

#include <Arduino.h>

void start_evil_twin(int wifi_number);
void stop_evil_twin();
void evil_twin_loop();
bool evil_twin_test_password(const String &password);

// ── WPS PBC sosyal mühendislik saldırısı ────────────────────────────────────
void et_start_wps_pbc();
void et_stop_wps_pbc();

extern bool   evil_twin_active;
extern String evil_twin_ssid;
extern int    evil_twin_clients;
extern int    evil_twin_channel;
extern uint8_t evil_twin_bssid[6];

// ─── Çift bant eşlikçi ───────────────────────────────────────────────────────
extern bool    evil_twin_has_companion;
extern uint8_t evil_twin_bssid2[6];
extern int     evil_twin_channel2;

// WPS PBC durum değişkenleri (web_interface.cpp okur)
extern bool et_wps_pbc_running;
extern bool et_wps_pbc_found;
extern char et_wps_pbc_pass[65];

#endif
