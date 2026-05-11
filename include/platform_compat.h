#ifndef PLATFORM_COMPAT_H
#define PLATFORM_COMPAT_H

// ─── Şifreleme türü uyumluluğu ────────────────────────────────────────────────
// ESP32: wifi_auth_mode_t (esp_wifi.h)
// BW16/RTL8720DN Ameba: wl_enc_type (Arduino WiFi)
//
// Ameba wl_enc_type değerleri ESP32'dekiyle birebir aynı değil,
// ancak aşağıdaki makrolar her iki platformda doğru etiket döndürür.
#if defined(BOARD_BW16)
  #include <WiFi.h>
  // wl_enc_type yerine WiFi kütüphanesi int döndürdüğünde da çalışır
  typedef int wifi_auth_mode_t;
  // Ameba ENC_TYPE_* → ESP32 WIFI_AUTH_* eşlemeleri
  #define WIFI_AUTH_OPEN          7   // ENC_TYPE_NONE
  #define WIFI_AUTH_WEP           5   // ENC_TYPE_WEP
  #define WIFI_AUTH_WPA_PSK       2   // ENC_TYPE_TKIP
  #define WIFI_AUTH_WPA2_PSK      4   // ENC_TYPE_CCMP
  #define WIFI_AUTH_WPA_WPA2_PSK  8   // ENC_TYPE_AUTO

  // BW16 WebServer: Ameba'da WiFiWebServer olarak isimlendirilmiş
  #include <WiFiWebServer.h>
  typedef WiFiWebServer WebServerCompat;
#else
  #include <esp_wifi.h>
  #include <WebServer.h>
  typedef WebServer WebServerCompat;
#endif

#endif // PLATFORM_COMPAT_H
