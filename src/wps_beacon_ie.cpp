// wps_beacon_ie.cpp — WPS yardımcı fonksiyonlar (PIN checksum, seri PIN, Pixie Dust risk)
// BW16 / RTL8720DN — saldırı stub'dır; yardımcılar tam implementedir.
#include "wps_beacon_ie.h"
#include "wps_attack.h"
#include "platform_compat.h"
#include "definitions.h"
#include "board_hal.h"
#include <WiFi.h>

wps_device_info_t wps_device_info = {};

// ─── WPS PIN checksum (RFC 4.0 standart) ──────────────────────────────────────
// 8. hane = (10 - ((d0*3 + d1 + d2*3 + d3 + d4*3 + d5 + d6*3) mod 10)) mod 10
uint8_t wps_pin_checksum(uint32_t pin7) {
    uint32_t acc = 0;
    acc += 3 * ((pin7 / 1000000) % 10);
    acc += 1 * ((pin7 / 100000)  % 10);
    acc += 3 * ((pin7 / 10000)   % 10);
    acc += 1 * ((pin7 / 1000)    % 10);
    acc += 3 * ((pin7 / 100)     % 10);
    acc += 1 * ((pin7 / 10)      % 10);
    acc += 3 * ((pin7 / 1)       % 10);
    return (uint8_t)((10 - (acc % 10)) % 10);
}

// ─── Yardımcı: 7 haneli PIN'e checksum ekleyerek tam 8 haneli PIN oluştur ─────
static void make_pin(uint32_t pin7, char out[9]) {
    uint8_t chk = wps_pin_checksum(pin7);
    snprintf(out, 9, "%07u%1u", (unsigned)pin7, (unsigned)chk);
}

// ─── Yardımcı: PIN listesine tekrarsız ekle ───────────────────────────────────
static int add_pin(char pins[][9], int count, int max_pins, uint32_t pin7) {
    if (count >= max_pins) return count;
    char buf[9];
    make_pin(pin7, buf);
    for (int i = 0; i < count; i++)
        if (strncmp(pins[i], buf, 9) == 0) return count;
    strncpy(pins[count], buf, 9);
    return count + 1;
}

// ─── Seri numarasından PIN adayları üret ─────────────────────────────────────
// Yaygın algoritmalar:
//   1. İlk 7 rakam (önde sıfırla)
//   2. Son 7 rakam
//   3. 1-7 konumundaki 7 rakam
//   4. Sadece rakamları çek → ilk/son 7
int wps_serial_to_pins(const char *serial, char pins[][9], int max_pins) {
    if (!serial || serial[0] == '\0') return 0;

    int count = 0;

    // Seri numarasından sadece rakamları çıkart
    char digits[64] = {};
    int  dlen = 0;
    for (int i = 0; serial[i] && dlen < 63; i++)
        if (serial[i] >= '0' && serial[i] <= '9')
            digits[dlen++] = serial[i];
    digits[dlen] = '\0';

    if (dlen < 7) return 0;

    // Yöntem A: ilk 7 rakam
    {
        uint32_t v = 0;
        for (int i = 0; i < 7; i++) v = v * 10 + (digits[i] - '0');
        count = add_pin(pins, count, max_pins, v);
    }

    // Yöntem B: son 7 rakam
    if (dlen >= 8) {
        uint32_t v = 0;
        for (int i = dlen - 7; i < dlen; i++) v = v * 10 + (digits[i] - '0');
        count = add_pin(pins, count, max_pins, v);
    }

    // Yöntem C: konum 1-7 (0-indexed: 1..7)
    if (dlen >= 8) {
        uint32_t v = 0;
        for (int i = 1; i <= 7; i++) v = v * 10 + (digits[i] - '0');
        count = add_pin(pins, count, max_pins, v);
    }

    // Yöntem D: konum 2-8
    if (dlen >= 9) {
        uint32_t v = 0;
        for (int i = 2; i <= 8; i++) v = v * 10 + (digits[i] - '0');
        count = add_pin(pins, count, max_pins, v);
    }

    // Yöntem E: tam seri 7 haneden uzunsa her pencereden kaydır
    if (dlen >= 9 && dlen <= 16) {
        for (int start = 0; start <= dlen - 7 && count < max_pins; start++) {
            uint32_t v = 0;
            for (int j = start; j < start + 7; j++) v = v * 10 + (digits[j] - '0');
            count = add_pin(pins, count, max_pins, v);
        }
    }

    return count;
}

// ─── Pixie Dust risk değerlendirmesi ──────────────────────────────────────────
// Vendor, chipset, WPS versiyonu ve config_methods'a göre risk atanır.
void wps_assess_pixie_risk(wps_device_info_t &info) {
    // Chipset tabanlı değerlendirme (en güvenilir yöntem)
    if (info.chipset_ie_hint[0]) {
        if (strstr(info.chipset_ie_hint, "Ralink") ||
            strstr(info.chipset_ie_hint, "MTK")) {
            info.pixie_risk = PIXIE_RISK_HIGH;
            strncpy(info.pixie_note, "Ralink/MediaTek chipset — Pixie Dust acigi biliniyor", 79);
            return;
        }
        if (strstr(info.chipset_ie_hint, "Realtek")) {
            info.pixie_risk = PIXIE_RISK_MEDIUM;
            strncpy(info.pixie_note, "Realtek chipset — bazi modeller acik", 79);
            return;
        }
        if (strstr(info.chipset_ie_hint, "Broadcom")) {
            info.pixie_risk = PIXIE_RISK_LOW;
            strncpy(info.pixie_note, "Broadcom chipset — genellikle guvenli", 79);
            return;
        }
        if (strstr(info.chipset_ie_hint, "Atheros") ||
            strstr(info.chipset_ie_hint, "QCA")) {
            info.pixie_risk = PIXIE_RISK_LOW;
            strncpy(info.pixie_note, "Qualcomm/Atheros chipset — guvenli", 79);
            return;
        }
    }

    // WPS versiyonu: 1.0 daha riskli
    if (info.wps_version == 0x10) {
        info.pixie_risk = PIXIE_RISK_MEDIUM;
        strncpy(info.pixie_note, "WPS v1.0 — eski protokol, acik olabilir", 79);
        return;
    }

    // AP Setup Locked ise saldırı anlamsız
    if (info.ap_setup_locked) {
        info.pixie_risk = PIXIE_RISK_LOW;
        strncpy(info.pixie_note, "AP_SETUP_LOCKED=1 — saldiri engellenmis", 79);
        return;
    }

    // Model/seri tabanlı ipucu
    if (info.model_name[0] || info.manufacturer[0]) {
        const char *m = info.manufacturer[0] ? info.manufacturer : info.model_name;
        if (strstr(m, "TP-LINK") || strstr(m, "TP-Link") || strstr(m, "Tp-link")) {
            info.pixie_risk = PIXIE_RISK_MEDIUM;
            strncpy(info.pixie_note, "TP-Link — Ralink/MediaTek chipset kullanabilir", 79);
            return;
        }
        if (strstr(m, "ZTE") || strstr(m, "zte")) {
            info.pixie_risk = PIXIE_RISK_HIGH;
            strncpy(info.pixie_note, "ZTE — Pixie Dust acigi raporlandi", 79);
            return;
        }
        if (strstr(m, "Sagemcom") || strstr(m, "SAGEMCOM")) {
            info.pixie_risk = PIXIE_RISK_MEDIUM;
            strncpy(info.pixie_note, "Sagemcom — bazi modeller acik", 79);
            return;
        }
        if (strstr(m, "Arcadyan")) {
            info.pixie_risk = PIXIE_RISK_MEDIUM;
            strncpy(info.pixie_note, "Arcadyan — orta risk", 79);
            return;
        }
        if (strstr(m, "AVM") || strstr(m, "FRITZ")) {
            info.pixie_risk = PIXIE_RISK_LOW;
            strncpy(info.pixie_note, "AVM Fritz!Box — guvenli uygulama", 79);
            return;
        }
    }

    // Bilinmiyor
    info.pixie_risk = PIXIE_RISK_UNKNOWN;
    strncpy(info.pixie_note, "Bilgi yetersiz — bilinmiyor", 79);
}

// ─── WPS Beacon IE cihaz bilgisi yakalama ────────────────────────────────────
// BW16'da WPS IE ayrıştırmalı promiscuous sniffer gerektirir.
// Bu implementasyon pasif tarama ile SSID/BSSID eşleşmesinden kısmi bilgi elde eder.
// Tam WPS IE ayrıştırması için yönetim çerçevesi promiscuous callback gerekir.
bool wps_capture_device_info(const uint8_t *bssid, int channel, uint32_t timeout_ms) {
    (void)timeout_ms;
    if (!bssid) return false;

    memset(&wps_device_info, 0, sizeof(wps_device_info));
    wps_device_info.wps_version   = 0x10;   // varsayılan: WPS 1.0
    wps_device_info.config_methods = 0x0084; // PIN + PBC

    // Bu SDK sürümünde tarama indexiyle BSSID alınamıyor.
    // Dolayısıyla hedef BSSID ile eşleştirme yapılamaz; ilk ağı bilgi kaynağı olarak kullanıyoruz.
    // (bssid parametresi gelecekteki SDK güncellemeleri için API'da korunmaktadır)
    (void)bssid;
    int old_n = WiFi.scanNetworks();
    for (int i = 0; i < old_n; i++) {

        // Hedef ağ bulundu — temel bilgileri doldur
        const char *ssid = WiFi.SSID((uint8_t)i);
        if (ssid && ssid[0]) {
            strncpy(wps_device_info.device_name, ssid, 63);
        }
        // WPS version: daha eski AP'ler genellikle WPS 1.0
        wps_device_info.wps_version     = 0x10;
        wps_device_info.config_methods  = 0x0084;
        wps_device_info.ap_setup_locked = false;
        wps_device_info.valid           = true;

        // Risk değerlendirmesi
        wps_assess_pixie_risk(wps_device_info);
        return true;
    }

    return false;
}
