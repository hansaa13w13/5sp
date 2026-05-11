#ifndef DEAUTH_H
#define DEAUTH_H

#include <Arduino.h>

void start_deauth(int wifi_number, int attack_type, uint16_t reason);
void stop_deauth();
void send_csa_beacon();
void retrack_deauth_target();
void send_companion_deauth_burst();  // Periyodik ikinci bant deauth — main loop çağırır

extern int     eliminated_stations;
extern int     deauth_type;
extern char    deauth_target_ssid[33];
extern uint8_t deauth_target_bssid[6];
extern int     deauth_target_channel;

// ─── Çift bant eşlikçi (aynı modem, farklı bant) ─────────────────────────────
extern bool    deauth_has_companion;
extern uint8_t deauth_target2_bssid[6];
extern int     deauth_target2_channel;
extern char    deauth_target2_ssid[33];

#endif
