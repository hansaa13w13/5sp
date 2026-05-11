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
        // AmebaD'de tarama sonucu başına BSSID alma API'si yok:
        // WiFi.BSSID(uint8_t* buf) yalnızca bağlı AP'yi döndürür (indeks almaz).
        // BSSID bilinmiyor olarak 0 bırakılır; kanal 0 = bilinmiyor.
        memset(bw16_scan_cache[i].bssid, 0, 6);
        bw16_scan_cache[i].ch = 0;
    }
}
#endif
