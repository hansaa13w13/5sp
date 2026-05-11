// types.cpp — BW16 WiFi tarama önbelleği
#include "types.h"
#include "platform_compat.h"
#include <WiFi.h>

BW16ScanEntry bw16_scan_cache[BW16_MAX_NETWORKS];
int           bw16_scan_cache_count = 0;

// ─── Tarama önbelleğini doldur ────────────────────────────────────────────────
// AmebaD Arduino SDK scan API: WiFi.SSID(i), WiFi.RSSI(i), WiFi.encryptionType(i)
// NOT: Bu SDK sürümü tarama sonuçlarından BSSID/kanal döndürmüyor.
// BSSID alanları sıfır, ch alanı 0 olarak bırakılır.
void bw16_cache_scan(int n) {
    bw16_scan_cache_count = (n < BW16_MAX_NETWORKS) ? n : BW16_MAX_NETWORKS;
    for (int i = 0; i < bw16_scan_cache_count; i++) {
        memset(bw16_scan_cache[i].bssid, 0, 6);
        bw16_scan_cache[i].ch = 0;
        // BSSID ve kanal bu SDK sürümünde tarama indexiyle alınamıyor
    }
}
