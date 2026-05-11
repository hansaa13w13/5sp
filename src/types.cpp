// types.cpp — BW16 WiFi tarama önbelleği
#include "types.h"
#include "platform_compat.h"

BW16ScanEntry bw16_scan_cache[BW16_MAX_NETWORKS];
int           bw16_scan_cache_count = 0;

// ─── Yardımcı: hex string'den BSSID byte dizisine ────────────────────────────
static bool parse_bssid(const char *str, uint8_t *out) {
    unsigned int b[6] = {};
    if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
        for (int i = 0; i < 6; i++) out[i] = (uint8_t)b[i];
        return true;
    }
    return false;
}

void bw16_cache_scan(int n) {
    bw16_scan_cache_count = (n < BW16_MAX_NETWORKS) ? n : BW16_MAX_NETWORKS;
    for (int i = 0; i < bw16_scan_cache_count; i++) {
        // AmebaD WiFi scan API: SSID(i), RSSI(i), encryptionType(i) destekler.
        // channel() ve BSSIDstr() mevcut değil — BSSID/kanal 0 olarak bırakılır.
        memset(bw16_scan_cache[i].bssid, 0, 6);
        bw16_scan_cache[i].ch = 0;
    }
}
