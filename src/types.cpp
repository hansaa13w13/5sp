// types.cpp — platform bağımsız; tüm tipler types.h'ta tanımlı
#include "types.h"

// ─── BW16 WiFi tarama önbelleği (sadece BOARD_BW16) ──────────────────────────
#ifdef BOARD_BW16
#include "platform_compat.h"

BW16ScanEntry bw16_scan_cache[BW16_MAX_NETWORKS];
int           bw16_scan_cache_count = 0;

void bw16_cache_scan(int n) {
    bw16_scan_cache_count = (n < BW16_MAX_NETWORKS) ? n : BW16_MAX_NETWORKS;
    for (int i = 0; i < bw16_scan_cache_count; i++) {
        String s = WiFi.BSSIDstr((uint8_t)i);
        unsigned int b[6] = {};
        sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]);
        for (int j = 0; j < 6; j++)
            bw16_scan_cache[i].bssid[j] = (uint8_t)b[j];
        bw16_scan_cache[i].ch = 0;
    }
}
#endif
