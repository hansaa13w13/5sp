#ifndef PLATFORM_COMPAT_H
#define PLATFORM_COMPAT_H

#if defined(BOARD_BW16)

#include <WiFi.h>
#include <WiFiUdp.h>
#include <IPAddress.h>

// ─── IRAM_ATTR ────────────────────────────────────────────────────────────────
#ifndef IRAM_ATTR
#define IRAM_ATTR
#endif

// ─── WiFi mod sabitleri ────────────────────────────────────────────────────────
typedef int wifi_mode_t;
#ifndef WIFI_MODE_NULL
#define WIFI_MODE_NULL   0
#endif
#ifndef WIFI_MODE_STA
#define WIFI_MODE_STA    1
#endif
#ifndef WIFI_MODE_AP
#define WIFI_MODE_AP     2
#endif
#ifndef WIFI_MODE_APSTA
#define WIFI_MODE_APSTA  3
#endif

// ─── Şifreleme türü uyumluluğu ────────────────────────────────────────────────
typedef int wifi_auth_mode_t;
#define WIFI_AUTH_OPEN          7
#define WIFI_AUTH_WEP           5
#define WIFI_AUTH_WPA_PSK       2
#define WIFI_AUTH_WPA2_PSK      4
#define WIFI_AUTH_WPA_WPA2_PSK  8

// ─── WebServer uyumluluğu ─────────────────────────────────────────────────────
#include <WiFiWebServer.h>
typedef WiFiWebServer WebServerCompat;

// ─── DNSServer (Captive Portal DNS — UDP tabanlı BW16 implementasyonu) ────────
class DNSServer {
    WiFiUDP  _udp;
    IPAddress _ip;
    bool      _running = false;
public:
    void start(uint16_t port, const String&, IPAddress ip) {
        _ip = ip;
        _udp.begin(port);
        _running = true;
    }
    void start(uint16_t port, const char* domain, IPAddress ip) {
        start(port, String(domain), ip);
    }
    void processNextRequest() {
        if (!_running) return;
        if (_udp.parsePacket() < 12) return;
        uint8_t buf[256];
        int size = _udp.read(buf, sizeof(buf));
        if (size < 12) return;
        uint8_t rsp[320];
        memcpy(rsp, buf, 12);
        rsp[2] = 0x81; rsp[3] = 0x80;
        rsp[4] = 0;    rsp[5] = 1;
        rsp[6] = 0;    rsp[7] = 1;
        rsp[8] = 0;    rsp[9] = 0;
        rsp[10] = 0;   rsp[11] = 0;
        int qEnd = 12;
        while (qEnd < size && buf[qEnd] != 0) qEnd += buf[qEnd] + 1;
        qEnd += 5;
        if (qEnd > size || qEnd > 280) return;
        memcpy(rsp + 12, buf + 12, qEnd - 12);
        int rlen = qEnd;
        rsp[rlen++] = 0xC0; rsp[rlen++] = 0x0C;
        rsp[rlen++] = 0;    rsp[rlen++] = 1;
        rsp[rlen++] = 0;    rsp[rlen++] = 1;
        rsp[rlen++] = 0; rsp[rlen++] = 0; rsp[rlen++] = 0; rsp[rlen++] = 60;
        rsp[rlen++] = 0; rsp[rlen++] = 4;
        rsp[rlen++] = _ip[0]; rsp[rlen++] = _ip[1];
        rsp[rlen++] = _ip[2]; rsp[rlen++] = _ip[3];
        _udp.beginPacket(_udp.remoteIP(), _udp.remotePort());
        _udp.write(rsp, rlen);
        _udp.endPacket();
    }
    void stop() { _udp.stop(); _running = false; }
};

// ─── BW16 WiFi tarama sonucu önbelleği ────────────────────────────────────────
// AmebaD 3.1.x WiFiClass; channel(networkItem) ve BSSID(networkItem) içermiyor.
// BSSIDstr(i) ayrıştırılarak BSSID saklanır; kanal bilinmiyor (0 döner).
#define BW16_MAX_NETWORKS 30
struct BW16ScanEntry { uint8_t bssid[6]; int ch; };
extern BW16ScanEntry bw16_scan_cache[];
extern int           bw16_scan_cache_count;
void bw16_cache_scan(int n);

inline uint8_t* WiFi_BSSID_scan(int i) {
    static uint8_t z[6] = {};
    if (i < 0 || i >= bw16_scan_cache_count) return z;
    return bw16_scan_cache[i].bssid;
}
inline int WiFi_channel_scan(int i) {
    if (i < 0 || i >= bw16_scan_cache_count) return 0;
    return bw16_scan_cache[i].ch;
}
inline const char* WiFi_SSID_cstr(int i)    { return WiFi.SSID((uint8_t)i); }
inline int         WiFi_scanNetworks_ex()    { return (int)WiFi.scanNetworks(); }
inline void        WiFi_scanDelete()         {}

#else
// ─── ESP32 ────────────────────────────────────────────────────────────────────
#include <esp_wifi.h>
#include <WebServer.h>
#include <DNSServer.h>
typedef WebServer WebServerCompat;

inline uint8_t*    WiFi_BSSID_scan(int i)   { return WiFi.BSSID(i); }
inline int         WiFi_channel_scan(int i)  { return WiFi.channel(i); }
inline const char* WiFi_SSID_cstr(int i)     { return WiFi.SSID(i).c_str(); }
inline int         WiFi_scanNetworks_ex()    { return (int)WiFi.scanNetworks(false, true, false, 120); }
inline void        WiFi_scanDelete()         { WiFi.scanDelete(); }

#endif // BOARD_BW16

#endif // PLATFORM_COMPAT_H
