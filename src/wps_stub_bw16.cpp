// wps_stub_bw16.cpp — BW16 / RTL8720DN WPS implementasyonu
// ESP-IDF WPS API mevcut olmadığından saldırı stub'dır.
// Ancak: tarama, vendor tespiti ve PIN üretme algoritmaları tam implementedir.
// NOT: wps_pin_checksum / wps_serial_to_pins / wps_assess_pixie_risk / wps_capture_device_info
//      wps_beacon_ie.cpp içinde tanımlanmıştır — bu dosyada tekrar tanımlanmaz.

#include "wps_attack.h"
#include "wps_beacon_ie.h"
#include "platform_compat.h"
#include "board_hal.h"
#include "definitions.h"
#include "passwords.h"
#include <WiFi.h>
#include <cctype>

static bool prefix_icase(const char *str, const char *pfx, size_t len) {
    for (size_t k = 0; k < len; k++) {
        if (tolower((unsigned char)str[k]) != tolower((unsigned char)pfx[k])) return false;
    }
    return true;
}

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

// ═══════════════════════════════════════════════════════════════════════════════
// OUI (İlk 3 bayt) → Vendor tablosu
// ═══════════════════════════════════════════════════════════════════════════════

struct OUI_Entry {
    uint8_t      oui[3];
    wps_vendor_t vendor;
};

static const OUI_Entry OUI_TABLE[] = {
    // ── ZTE ──────────────────────────────────────────────────────────────────
    {{0x00, 0x19, 0xE0}, VENDOR_ZTE},
    {{0x00, 0x26, 0xE9}, VENDOR_ZTE},
    {{0x6C, 0x8B, 0x2F}, VENDOR_ZTE},
    {{0x80, 0x89, 0x17}, VENDOR_ZTE},
    {{0xA4, 0xC3, 0xF0}, VENDOR_ZTE},
    {{0xBC, 0x0F, 0xF3}, VENDOR_ZTE},
    {{0xC8, 0x9A, 0x24}, VENDOR_ZTE},
    {{0xDC, 0x71, 0x44}, VENDOR_ZTE},
    {{0xE0, 0x63, 0xDA}, VENDOR_ZTE},
    {{0xF4, 0x60, 0xE2}, VENDOR_ZTE},
    {{0x28, 0x2C, 0x02}, VENDOR_ZTE},
    {{0x58, 0x49, 0x3B}, VENDOR_ZTE},
    {{0x64, 0x13, 0xE9}, VENDOR_ZTE},
    {{0xCC, 0x9E, 0x00}, VENDOR_ZTE},
    {{0xD4, 0x5D, 0x64}, VENDOR_ZTE},
    {{0x14, 0xB9, 0x68}, VENDOR_ZTE},
    {{0x18, 0x31, 0xBF}, VENDOR_ZTE},
    {{0x20, 0x76, 0x93}, VENDOR_ZTE},
    {{0x34, 0x96, 0xCF}, VENDOR_ZTE},
    {{0x40, 0xE2, 0x30}, VENDOR_ZTE},
    {{0x48, 0x7A, 0xDA}, VENDOR_ZTE},
    {{0x50, 0xCF, 0x12}, VENDOR_ZTE},
    {{0x60, 0xDE, 0x44}, VENDOR_ZTE},
    {{0x70, 0x72, 0x3C}, VENDOR_ZTE},
    {{0x84, 0x74, 0x2A}, VENDOR_ZTE},
    {{0x90, 0x0A, 0x27}, VENDOR_ZTE},
    {{0x9C, 0xD6, 0x43}, VENDOR_ZTE},
    {{0xAC, 0x30, 0x5A}, VENDOR_ZTE},
    {{0xBC, 0xE1, 0x2C}, VENDOR_ZTE},
    {{0xC0, 0x14, 0x3D}, VENDOR_ZTE},

    // ── Huawei ───────────────────────────────────────────────────────────────
    {{0x00, 0x18, 0x82}, VENDOR_HUAWEI},
    {{0x00, 0x1E, 0x10}, VENDOR_HUAWEI},
    {{0x00, 0x25, 0x9E}, VENDOR_HUAWEI},
    {{0x04, 0xF9, 0x38}, VENDOR_HUAWEI},
    {{0x10, 0x47, 0x80}, VENDOR_HUAWEI},
    {{0x20, 0x0B, 0xC7}, VENDOR_HUAWEI},
    {{0x20, 0xF3, 0xA3}, VENDOR_HUAWEI},
    {{0x28, 0x31, 0x52}, VENDOR_HUAWEI},
    {{0x34, 0x6B, 0xD3}, VENDOR_HUAWEI},
    {{0x40, 0x4D, 0x8E}, VENDOR_HUAWEI},
    {{0x44, 0xC3, 0x46}, VENDOR_HUAWEI},
    {{0x48, 0x62, 0x76}, VENDOR_HUAWEI},
    {{0x4C, 0x1F, 0xCC}, VENDOR_HUAWEI},
    {{0x54, 0xA5, 0x1B}, VENDOR_HUAWEI},
    {{0x60, 0xA4, 0xB7}, VENDOR_HUAWEI},
    {{0x64, 0x16, 0xF0}, VENDOR_HUAWEI},
    {{0x70, 0x7B, 0xE8}, VENDOR_HUAWEI},
    {{0x78, 0x1D, 0xBA}, VENDOR_HUAWEI},
    {{0x80, 0x65, 0x99}, VENDOR_HUAWEI},
    {{0x88, 0xA2, 0x5E}, VENDOR_HUAWEI},
    {{0x90, 0x17, 0xAC}, VENDOR_HUAWEI},
    {{0x98, 0xE7, 0xF5}, VENDOR_HUAWEI},
    {{0xA0, 0x08, 0x6F}, VENDOR_HUAWEI},
    {{0xBC, 0x9C, 0x31}, VENDOR_HUAWEI},
    {{0xC4, 0x0B, 0xCB}, VENDOR_HUAWEI},
    {{0xCC, 0x53, 0xB5}, VENDOR_HUAWEI},
    {{0xD0, 0x7A, 0xB5}, VENDOR_HUAWEI},
    {{0xD4, 0x94, 0xE8}, VENDOR_HUAWEI},
    {{0xDC, 0xD2, 0xFC}, VENDOR_HUAWEI},
    {{0xE8, 0xCD, 0x2D}, VENDOR_HUAWEI},
    {{0xF0, 0x01, 0xD8}, VENDOR_HUAWEI},
    {{0xF4, 0x4C, 0x7F}, VENDOR_HUAWEI},
    {{0xFC, 0x48, 0xEF}, VENDOR_HUAWEI},

    // ── Zyxel ────────────────────────────────────────────────────────────────
    {{0x00, 0x13, 0x49}, VENDOR_ZYXEL},
    {{0x00, 0xA0, 0xC5}, VENDOR_ZYXEL},
    {{0x28, 0x84, 0xFA}, VENDOR_ZYXEL},
    {{0x3C, 0x31, 0x04}, VENDOR_ZYXEL},
    {{0x40, 0x4A, 0x03}, VENDOR_ZYXEL},
    {{0x58, 0x8B, 0xF3}, VENDOR_ZYXEL},
    {{0x70, 0x59, 0xEA}, VENDOR_ZYXEL},
    {{0x84, 0x1B, 0x5E}, VENDOR_ZYXEL},
    {{0x88, 0x25, 0xF3}, VENDOR_ZYXEL},
    {{0xA0, 0x18, 0x28}, VENDOR_ZYXEL},
    {{0xBC, 0x99, 0x11}, VENDOR_ZYXEL},
    {{0xC4, 0xE9, 0x84}, VENDOR_ZYXEL},
    {{0xC8, 0x6C, 0x87}, VENDOR_ZYXEL},
    {{0xE8, 0x9F, 0x80}, VENDOR_ZYXEL},

    // ── TP-Link ───────────────────────────────────────────────────────────────
    {{0x00, 0x14, 0x78}, VENDOR_TPLINK},
    {{0x00, 0x1D, 0x0F}, VENDOR_TPLINK},
    {{0x00, 0x23, 0xCD}, VENDOR_TPLINK},
    {{0x00, 0x27, 0x19}, VENDOR_TPLINK},
    {{0x08, 0x57, 0x00}, VENDOR_TPLINK},
    {{0x0C, 0x80, 0x63}, VENDOR_TPLINK},
    {{0x10, 0xFE, 0xED}, VENDOR_TPLINK},
    {{0x14, 0xCC, 0x20}, VENDOR_TPLINK},
    {{0x18, 0xA6, 0xF7}, VENDOR_TPLINK},
    {{0x1C, 0xFA, 0x68}, VENDOR_TPLINK},
    {{0x20, 0xDC, 0xE6}, VENDOR_TPLINK},
    {{0x24, 0x69, 0xA5}, VENDOR_TPLINK},
    {{0x2C, 0x3D, 0x28}, VENDOR_TPLINK},
    {{0x2C, 0xD0, 0x5A}, VENDOR_TPLINK},
    {{0x30, 0xDE, 0x4B}, VENDOR_TPLINK},
    {{0x34, 0x96, 0x72}, VENDOR_TPLINK},
    {{0x38, 0x83, 0x45}, VENDOR_TPLINK},
    {{0x3C, 0x46, 0xD8}, VENDOR_TPLINK},
    {{0x40, 0x16, 0x7E}, VENDOR_TPLINK},
    {{0x44, 0x33, 0x4C}, VENDOR_TPLINK},
    {{0x50, 0x3E, 0xAA}, VENDOR_TPLINK},
    {{0x54, 0xC6, 0xFF}, VENDOR_TPLINK},
    {{0x58, 0xD5, 0x6E}, VENDOR_TPLINK},
    {{0x5C, 0x89, 0x9A}, VENDOR_TPLINK},
    {{0x60, 0xE3, 0x27}, VENDOR_TPLINK},
    {{0x60, 0xE6, 0xCB}, VENDOR_TPLINK},
    {{0x64, 0x09, 0x80}, VENDOR_TPLINK},
    {{0x68, 0xFF, 0x7B}, VENDOR_TPLINK},
    {{0x6C, 0x19, 0x8F}, VENDOR_TPLINK},
    {{0x6C, 0x5A, 0xB5}, VENDOR_TPLINK},
    {{0x70, 0x4F, 0x57}, VENDOR_TPLINK},
    {{0x74, 0xDA, 0x38}, VENDOR_TPLINK},
    {{0x78, 0x44, 0x76}, VENDOR_TPLINK},
    {{0x78, 0xA1, 0x06}, VENDOR_TPLINK},
    {{0x7C, 0x8B, 0xCA}, VENDOR_TPLINK},
    {{0x80, 0xCC, 0x9C}, VENDOR_TPLINK},
    {{0x84, 0x16, 0xF9}, VENDOR_TPLINK},
    {{0x8C, 0x21, 0x0A}, VENDOR_TPLINK},
    {{0x90, 0xF6, 0x52}, VENDOR_TPLINK},
    {{0x98, 0xDA, 0xC4}, VENDOR_TPLINK},
    {{0x9C, 0x21, 0x6A}, VENDOR_TPLINK},
    {{0xA0, 0xF3, 0xC1}, VENDOR_TPLINK},
    {{0xA4, 0x56, 0x02}, VENDOR_TPLINK},
    {{0xAC, 0x84, 0xC6}, VENDOR_TPLINK},
    {{0xB0, 0x48, 0x7A}, VENDOR_TPLINK},
    {{0xB0, 0x95, 0x8E}, VENDOR_TPLINK},
    {{0xB4, 0xB0, 0x24}, VENDOR_TPLINK},
    {{0xB8, 0x7E, 0x05}, VENDOR_TPLINK},
    {{0xBC, 0x46, 0x99}, VENDOR_TPLINK},
    {{0xC0, 0x4A, 0x00}, VENDOR_TPLINK},
    {{0xC0, 0xC9, 0xE3}, VENDOR_TPLINK},
    {{0xC4, 0x6E, 0x1F}, VENDOR_TPLINK},
    {{0xC8, 0xD3, 0xA3}, VENDOR_TPLINK},
    {{0xCC, 0xB0, 0xDA}, VENDOR_TPLINK},
    {{0xD0, 0x37, 0x45}, VENDOR_TPLINK},
    {{0xD4, 0x6E, 0x0E}, VENDOR_TPLINK},
    {{0xD8, 0x0D, 0x17}, VENDOR_TPLINK},
    {{0xDC, 0xFE, 0x07}, VENDOR_TPLINK},
    {{0xE0, 0x10, 0x7F}, VENDOR_TPLINK},
    {{0xE0, 0x28, 0x6D}, VENDOR_TPLINK},
    {{0xE4, 0x02, 0x9B}, VENDOR_TPLINK},
    {{0xE8, 0x4D, 0xD0}, VENDOR_TPLINK},
    {{0xEC, 0x08, 0x6B}, VENDOR_TPLINK},
    {{0xF0, 0xB4, 0x29}, VENDOR_TPLINK},
    {{0xF4, 0xEC, 0x38}, VENDOR_TPLINK},
    {{0xF8, 0x1A, 0x67}, VENDOR_TPLINK},
    {{0xFC, 0xD7, 0x33}, VENDOR_TPLINK},

    // ── Sagemcom ─────────────────────────────────────────────────────────────
    {{0x00, 0x0F, 0xE0}, VENDOR_SAGEMCOM},
    {{0x00, 0x0F, 0xF3}, VENDOR_SAGEMCOM},
    {{0x00, 0x21, 0xBE}, VENDOR_SAGEMCOM},
    {{0x00, 0x22, 0x01}, VENDOR_SAGEMCOM},
    {{0x04, 0xBF, 0x6D}, VENDOR_SAGEMCOM},
    {{0x08, 0x3E, 0x8E}, VENDOR_SAGEMCOM},
    {{0x14, 0x4F, 0x8A}, VENDOR_SAGEMCOM},
    {{0x18, 0x41, 0xF1}, VENDOR_SAGEMCOM},
    {{0x1C, 0x75, 0x08}, VENDOR_SAGEMCOM},
    {{0x20, 0xCF, 0x30}, VENDOR_SAGEMCOM},
    {{0x28, 0xEE, 0x52}, VENDOR_SAGEMCOM},
    {{0x2C, 0x39, 0xC1}, VENDOR_SAGEMCOM},
    {{0x34, 0x08, 0x04}, VENDOR_SAGEMCOM},
    {{0x38, 0x72, 0xC0}, VENDOR_SAGEMCOM},
    {{0x44, 0x14, 0x5B}, VENDOR_SAGEMCOM},
    {{0x48, 0x8F, 0x5A}, VENDOR_SAGEMCOM},
    {{0x50, 0x7E, 0x5D}, VENDOR_SAGEMCOM},
    {{0x54, 0xA0, 0x50}, VENDOR_SAGEMCOM},
    {{0x58, 0xAC, 0x78}, VENDOR_SAGEMCOM},
    {{0x5C, 0xF4, 0xAB}, VENDOR_SAGEMCOM},
    {{0x60, 0x45, 0xCB}, VENDOR_SAGEMCOM},
    {{0x6C, 0x6C, 0xD3}, VENDOR_SAGEMCOM},
    {{0x78, 0x67, 0x0E}, VENDOR_SAGEMCOM},
    {{0x88, 0xD7, 0xF6}, VENDOR_SAGEMCOM},
    {{0x90, 0x6C, 0xAC}, VENDOR_SAGEMCOM},
    {{0x9C, 0xDF, 0x03}, VENDOR_SAGEMCOM},
    {{0xA0, 0xAB, 0x1B}, VENDOR_SAGEMCOM},
    {{0xAC, 0xE0, 0x10}, VENDOR_SAGEMCOM},
    {{0xB0, 0x75, 0xD5}, VENDOR_SAGEMCOM},
    {{0xBC, 0xA9, 0x20}, VENDOR_SAGEMCOM},
    {{0xC0, 0x25, 0xE9}, VENDOR_SAGEMCOM},
    {{0xC8, 0x00, 0x84}, VENDOR_SAGEMCOM},
    {{0xCC, 0x50, 0xE3}, VENDOR_SAGEMCOM},
    {{0xD0, 0x2D, 0xB3}, VENDOR_SAGEMCOM},
    {{0xD4, 0x3D, 0x7E}, VENDOR_SAGEMCOM},

    // ── Arcadyan ─────────────────────────────────────────────────────────────
    {{0x00, 0x90, 0xD0}, VENDOR_ARCADYAN},
    {{0xD4, 0x35, 0x1D}, VENDOR_ARCADYAN},
    {{0xD8, 0xEB, 0x97}, VENDOR_ARCADYAN},
    {{0xEC, 0x43, 0xF6}, VENDOR_ARCADYAN},
    {{0x84, 0x78, 0xAC}, VENDOR_ARCADYAN},
    {{0xCC, 0xA3, 0xE4}, VENDOR_ARCADYAN},
    {{0xE4, 0xF3, 0x2B}, VENDOR_ARCADYAN},
    {{0xA0, 0x63, 0x91}, VENDOR_ARCADYAN},
    {{0x00, 0x1A, 0x2A}, VENDOR_ARCADYAN},
    {{0x00, 0x1F, 0xCE}, VENDOR_ARCADYAN},

    // ── D-Link ───────────────────────────────────────────────────────────────
    {{0x00, 0x05, 0x5D}, VENDOR_DLINK},
    {{0x00, 0x0D, 0x88}, VENDOR_DLINK},
    {{0x00, 0x11, 0x95}, VENDOR_DLINK},
    {{0x00, 0x13, 0x46}, VENDOR_DLINK},
    {{0x00, 0x15, 0xE9}, VENDOR_DLINK},
    {{0x00, 0x17, 0x9A}, VENDOR_DLINK},
    {{0x00, 0x19, 0x5B}, VENDOR_DLINK},
    {{0x00, 0x1B, 0x11}, VENDOR_DLINK},
    {{0x00, 0x1C, 0xF0}, VENDOR_DLINK},
    {{0x00, 0x1E, 0x58}, VENDOR_DLINK},
    {{0x00, 0x21, 0x91}, VENDOR_DLINK},
    {{0x00, 0x22, 0xB0}, VENDOR_DLINK},
    {{0x00, 0x24, 0x01}, VENDOR_DLINK},
    {{0x00, 0x26, 0x5A}, VENDOR_DLINK},
    {{0x1C, 0x7E, 0xE5}, VENDOR_DLINK},
    {{0x28, 0x10, 0x7B}, VENDOR_DLINK},
    {{0x5C, 0xD9, 0x98}, VENDOR_DLINK},
    {{0x78, 0x32, 0x1B}, VENDOR_DLINK},
    {{0x84, 0xC9, 0xB2}, VENDOR_DLINK},
    {{0x90, 0x94, 0xE4}, VENDOR_DLINK},
    {{0xBC, 0xF6, 0x85}, VENDOR_DLINK},
    {{0xC8, 0xBE, 0x19}, VENDOR_DLINK},
    {{0xCC, 0xB2, 0x55}, VENDOR_DLINK},
    {{0xF0, 0x7D, 0x68}, VENDOR_DLINK},

    // ── Netgear ───────────────────────────────────────────────────────────────
    {{0x00, 0x09, 0x5B}, VENDOR_NETGEAR},
    {{0x00, 0x0F, 0xB5}, VENDOR_NETGEAR},
    {{0x00, 0x14, 0x6C}, VENDOR_NETGEAR},
    {{0x00, 0x18, 0x4D}, VENDOR_NETGEAR},
    {{0x00, 0x1B, 0x2F}, VENDOR_NETGEAR},
    {{0x00, 0x1E, 0x2A}, VENDOR_NETGEAR},
    {{0x00, 0x22, 0x3F}, VENDOR_NETGEAR},
    {{0x00, 0x24, 0xB2}, VENDOR_NETGEAR},
    {{0x00, 0x26, 0xF2}, VENDOR_NETGEAR},
    {{0x04, 0xA1, 0x51}, VENDOR_NETGEAR},
    {{0x20, 0x0C, 0xC8}, VENDOR_NETGEAR},
    {{0x28, 0xC6, 0x8E}, VENDOR_NETGEAR},
    {{0x2C, 0xB0, 0x5D}, VENDOR_NETGEAR},
    {{0x44, 0x94, 0xFC}, VENDOR_NETGEAR},
    {{0x4C, 0x60, 0xDE}, VENDOR_NETGEAR},
    {{0x6C, 0xB0, 0xCE}, VENDOR_NETGEAR},
    {{0xA0, 0x21, 0xB7}, VENDOR_NETGEAR},
    {{0xA0, 0x40, 0xA0}, VENDOR_NETGEAR},
    {{0xB0, 0x39, 0x56}, VENDOR_NETGEAR},
    {{0xC0, 0x3F, 0x0E}, VENDOR_NETGEAR},
    {{0xC0, 0xFF, 0xD4}, VENDOR_NETGEAR},
    {{0xE4, 0xF4, 0xC6}, VENDOR_NETGEAR},

    // ── ASUS ─────────────────────────────────────────────────────────────────
    {{0x00, 0x0C, 0x6E}, VENDOR_ASUS},
    {{0x00, 0x0E, 0xA6}, VENDOR_ASUS},
    {{0x00, 0x11, 0xD8}, VENDOR_ASUS},
    {{0x00, 0x13, 0xD4}, VENDOR_ASUS},
    {{0x00, 0x15, 0xF2}, VENDOR_ASUS},
    {{0x00, 0x17, 0x31}, VENDOR_ASUS},
    {{0x00, 0x1A, 0x92}, VENDOR_ASUS},
    {{0x00, 0x1D, 0x60}, VENDOR_ASUS},
    {{0x00, 0x1E, 0x8C}, VENDOR_ASUS},
    {{0x00, 0x1F, 0xC6}, VENDOR_ASUS},
    {{0x00, 0x22, 0x15}, VENDOR_ASUS},
    {{0x00, 0x23, 0x54}, VENDOR_ASUS},
    {{0x00, 0x24, 0x8C}, VENDOR_ASUS},
    {{0x00, 0x26, 0x18}, VENDOR_ASUS},
    {{0x04, 0x92, 0x26}, VENDOR_ASUS},
    {{0x08, 0x62, 0x66}, VENDOR_ASUS},
    {{0x10, 0x7B, 0x44}, VENDOR_ASUS},
    {{0x10, 0xBF, 0x48}, VENDOR_ASUS},
    {{0x10, 0xC3, 0x7B}, VENDOR_ASUS},
    {{0x14, 0xDA, 0xE9}, VENDOR_ASUS},
    {{0x1C, 0x87, 0x2C}, VENDOR_ASUS},
    {{0x24, 0x4B, 0xFE}, VENDOR_ASUS},
    {{0x2C, 0xFD, 0xA1}, VENDOR_ASUS},
    {{0x30, 0x5A, 0x3A}, VENDOR_ASUS},
    {{0x38, 0xD5, 0x47}, VENDOR_ASUS},
    {{0x3C, 0x97, 0x0E}, VENDOR_ASUS},
    {{0x50, 0x46, 0x5D}, VENDOR_ASUS},
    {{0x6C, 0x72, 0x20}, VENDOR_ASUS},
    {{0x70, 0x4D, 0x7B}, VENDOR_ASUS},
    {{0x74, 0xD0, 0x2B}, VENDOR_ASUS},
    {{0x7C, 0x10, 0xC9}, VENDOR_ASUS},
    {{0x84, 0xA9, 0xC4}, VENDOR_ASUS},
    {{0x8C, 0xAE, 0x4C}, VENDOR_ASUS},
    {{0x90, 0xE6, 0xBA}, VENDOR_ASUS},
    {{0x9C, 0x5C, 0x8E}, VENDOR_ASUS},
    {{0xA8, 0xF7, 0xE0}, VENDOR_ASUS},
    {{0xAC, 0x22, 0x0B}, VENDOR_ASUS},
    {{0xB0, 0x6E, 0xBF}, VENDOR_ASUS},
    {{0xBC, 0xEE, 0x7B}, VENDOR_ASUS},
    {{0xC8, 0x60, 0x00}, VENDOR_ASUS},
    {{0xD0, 0x17, 0xC2}, VENDOR_ASUS},
    {{0xE0, 0x3F, 0x49}, VENDOR_ASUS},
    {{0xF0, 0x79, 0x59}, VENDOR_ASUS},
    {{0xFC, 0x34, 0x97}, VENDOR_ASUS},

    // ── Tenda ────────────────────────────────────────────────────────────────
    {{0xC8, 0x3A, 0x35}, VENDOR_TENDA},
    {{0xD0, 0x15, 0xA6}, VENDOR_TENDA},
    {{0x1C, 0xB7, 0x2C}, VENDOR_TENDA},
    {{0x00, 0x0A, 0xEB}, VENDOR_TENDA},

    // ── Mercusys ─────────────────────────────────────────────────────────────
    {{0x28, 0x87, 0xBA}, VENDOR_MERCUSYS},
    {{0xB0, 0x8C, 0x75}, VENDOR_MERCUSYS},
    {{0x48, 0x22, 0x54}, VENDOR_MERCUSYS},

    // ── Buffalo ──────────────────────────────────────────────────────────────
    {{0x00, 0x07, 0x40}, VENDOR_BUFFALO},
    {{0x00, 0x0D, 0x0B}, VENDOR_BUFFALO},
    {{0x00, 0x16, 0x01}, VENDOR_BUFFALO},
    {{0x00, 0x1D, 0x73}, VENDOR_BUFFALO},
    {{0x00, 0x24, 0xA5}, VENDOR_BUFFALO},

    // ── Belkin ───────────────────────────────────────────────────────────────
    {{0x00, 0x11, 0x50}, VENDOR_BELKIN},
    {{0x00, 0x17, 0x3F}, VENDOR_BELKIN},
    {{0x00, 0x1C, 0xDF}, VENDOR_BELKIN},
    {{0x00, 0x22, 0x75}, VENDOR_BELKIN},
    {{0x08, 0x86, 0x3B}, VENDOR_BELKIN},
    {{0x44, 0xE3, 0x37}, VENDOR_BELKIN},
    {{0x94, 0x44, 0x52}, VENDOR_BELKIN},
    {{0xEC, 0x1A, 0x59}, VENDOR_BELKIN},

    // ── Xiaomi ───────────────────────────────────────────────────────────────
    {{0x28, 0x6C, 0x07}, VENDOR_XIAOMI},
    {{0x34, 0xCE, 0x94}, VENDOR_XIAOMI},
    {{0x50, 0x64, 0x2B}, VENDOR_XIAOMI},
    {{0x58, 0x44, 0x98}, VENDOR_XIAOMI},
    {{0x74, 0x23, 0x44}, VENDOR_XIAOMI},
    {{0x78, 0x11, 0xDC}, VENDOR_XIAOMI},
    {{0x8C, 0xBE, 0xBE}, VENDOR_XIAOMI},
    {{0xF4, 0x8B, 0x32}, VENDOR_XIAOMI},
    {{0xFC, 0x64, 0xBA}, VENDOR_XIAOMI},

    // ── Totolink ─────────────────────────────────────────────────────────────
    {{0xEC, 0x60, 0x73}, VENDOR_TOTOLINK},
    {{0xF4, 0x4D, 0x30}, VENDOR_TOTOLINK},

    // ── Linksys ──────────────────────────────────────────────────────────────
    {{0x00, 0x06, 0x25}, VENDOR_LINKSYS},
    {{0x00, 0x0C, 0x41}, VENDOR_LINKSYS},
    {{0x00, 0x0E, 0x08}, VENDOR_LINKSYS},
    {{0x00, 0x12, 0x17}, VENDOR_LINKSYS},
    {{0x00, 0x13, 0x10}, VENDOR_LINKSYS},
    {{0x00, 0x14, 0xBF}, VENDOR_LINKSYS},
    {{0x00, 0x16, 0xB6}, VENDOR_LINKSYS},
    {{0x00, 0x18, 0xF8}, VENDOR_LINKSYS},
    {{0x00, 0x1A, 0x70}, VENDOR_LINKSYS},
    {{0x00, 0x1C, 0x10}, VENDOR_LINKSYS},
    {{0x00, 0x1D, 0x7E}, VENDOR_LINKSYS},
    {{0x00, 0x1E, 0xE5}, VENDOR_LINKSYS},
    {{0x00, 0x21, 0x29}, VENDOR_LINKSYS},
    {{0x00, 0x22, 0x6B}, VENDOR_LINKSYS},
    {{0x00, 0x23, 0x69}, VENDOR_LINKSYS},
    {{0x00, 0x25, 0x9C}, VENDOR_LINKSYS},
    {{0xC0, 0xC1, 0xC0}, VENDOR_LINKSYS},

    // ── Technicolor / Thomson ─────────────────────────────────────────────────
    {{0x00, 0x0E, 0x50}, VENDOR_TECHNICOLOR},
    {{0x00, 0x14, 0xD1}, VENDOR_TECHNICOLOR},
    {{0x00, 0x18, 0xA8}, VENDOR_TECHNICOLOR},
    {{0x00, 0x1A, 0x79}, VENDOR_TECHNICOLOR},
    {{0x00, 0x23, 0x8B}, VENDOR_TECHNICOLOR},
    {{0x10, 0x62, 0xEB}, VENDOR_TECHNICOLOR},
    {{0x30, 0xD3, 0x2D}, VENDOR_TECHNICOLOR},
    {{0x44, 0x40, 0x4D}, VENDOR_TECHNICOLOR},
    {{0x4C, 0xE1, 0x73}, VENDOR_TECHNICOLOR},
    {{0x64, 0x14, 0x13}, VENDOR_TECHNICOLOR},
    {{0x7C, 0x4C, 0xA5}, VENDOR_TECHNICOLOR},
    {{0x80, 0x28, 0xF8}, VENDOR_TECHNICOLOR},

    // ── AVM Fritz!Box ────────────────────────────────────────────────────────
    {{0x00, 0x04, 0x0E}, VENDOR_FRITZ},
    {{0x3C, 0xA6, 0x2F}, VENDOR_FRITZ},
    {{0x98, 0x9B, 0xCB}, VENDOR_FRITZ},
    {{0xBC, 0x05, 0x43}, VENDOR_FRITZ},
    {{0xC4, 0x86, 0xE9}, VENDOR_FRITZ},

    // ── Arris ────────────────────────────────────────────────────────────────
    {{0x00, 0x1A, 0x31}, VENDOR_ARRIS},
    {{0x00, 0x20, 0x40}, VENDOR_ARRIS},
    {{0x34, 0x37, 0x59}, VENDOR_ARRIS},
    {{0x48, 0xF8, 0xB3}, VENDOR_ARRIS},
    {{0x58, 0x9E, 0xC6}, VENDOR_ARRIS},
    {{0x78, 0xD3, 0x8F}, VENDOR_ARRIS},
    {{0xAC, 0x83, 0x29}, VENDOR_ARRIS},
    {{0xB0, 0x82, 0xFE}, VENDOR_ARRIS},

    // ── Sercomm ──────────────────────────────────────────────────────────────
    {{0x00, 0x0B, 0x0E}, VENDOR_SERCOMM},
    {{0x00, 0x13, 0xC1}, VENDOR_SERCOMM},
    {{0x00, 0x19, 0x15}, VENDOR_SERCOMM},
    {{0x00, 0x23, 0xA2}, VENDOR_SERCOMM},
    {{0x28, 0xCA, 0x57}, VENDOR_SERCOMM},
    {{0x54, 0xBE, 0xF7}, VENDOR_SERCOMM},
    {{0x60, 0x02, 0xB4}, VENDOR_SERCOMM},
    {{0x64, 0xD9, 0x54}, VENDOR_SERCOMM},
    {{0x74, 0x9D, 0xDC}, VENDOR_SERCOMM},
    {{0x80, 0x9F, 0xF5}, VENDOR_SERCOMM},

    // ── Netis ────────────────────────────────────────────────────────────────
    {{0xEC, 0x60, 0x73}, VENDOR_NETIS},

    // ── Compal ───────────────────────────────────────────────────────────────
    {{0x00, 0xE0, 0x12}, VENDOR_COMPAL},
    {{0xA4, 0x0C, 0xC3}, VENDOR_COMPAL},

    // ── Comtrend ─────────────────────────────────────────────────────────────
    {{0x00, 0x1A, 0xDD}, VENDOR_COMTREND},
    {{0x44, 0xE4, 0xD9}, VENDOR_COMTREND},

    // ── Actiontec ────────────────────────────────────────────────────────────
    {{0x00, 0x1F, 0x90}, VENDOR_ACTIONTEC},
    {{0x18, 0x1B, 0xEB}, VENDOR_ACTIONTEC},
    {{0x40, 0x16, 0x9F}, VENDOR_ACTIONTEC},
    {{0x50, 0x67, 0xF0}, VENDOR_ACTIONTEC},

    // ── Gemtek ───────────────────────────────────────────────────────────────
    {{0x00, 0x0F, 0x97}, VENDOR_GEMTEK},
    {{0x00, 0x1B, 0x8E}, VENDOR_GEMTEK},
    {{0x00, 0x1E, 0xBD}, VENDOR_GEMTEK},
    {{0x60, 0xD9, 0x05}, VENDOR_GEMTEK},
    {{0xB0, 0x70, 0x2D}, VENDOR_GEMTEK},
    {{0xE0, 0x43, 0xDB}, VENDOR_GEMTEK},

    // ── Iskratel ─────────────────────────────────────────────────────────────
    {{0x00, 0x1D, 0x96}, VENDOR_ISKRATEL},
    {{0x00, 0x26, 0x97}, VENDOR_ISKRATEL},
    {{0x38, 0xBB, 0x3C}, VENDOR_ISKRATEL},
    {{0xE8, 0xC7, 0xFD}, VENDOR_ISKRATEL},

    // ── DrayTek ──────────────────────────────────────────────────────────────
    {{0x00, 0x1D, 0xAA}, VENDOR_DRAYTEK},
    {{0x00, 0x50, 0x7F}, VENDOR_DRAYTEK},
    {{0x00, 0xE0, 0xA6}, VENDOR_DRAYTEK},
    {{0x10, 0x7E, 0xE8}, VENDOR_DRAYTEK},

    // ── MikroTik ─────────────────────────────────────────────────────────────
    {{0x00, 0x0C, 0x42}, VENDOR_MIKROTIK},
    {{0x18, 0xFD, 0x74}, VENDOR_MIKROTIK},
    {{0x2C, 0xC8, 0x1B}, VENDOR_MIKROTIK},
    {{0x4C, 0x5E, 0x0C}, VENDOR_MIKROTIK},
    {{0x6C, 0x3B, 0x6B}, VENDOR_MIKROTIK},
    {{0x74, 0x4D, 0x28}, VENDOR_MIKROTIK},
    {{0xB8, 0x69, 0xF4}, VENDOR_MIKROTIK},
    {{0xCC, 0x2D, 0xE0}, VENDOR_MIKROTIK},
    {{0xD4, 0xCA, 0x6D}, VENDOR_MIKROTIK},
    {{0xDC, 0x2C, 0x6E}, VENDOR_MIKROTIK},
    {{0xE4, 0x8D, 0x8C}, VENDOR_MIKROTIK},

    // ── Cisco (ISP) ──────────────────────────────────────────────────────────
    {{0x00, 0x02, 0x4A}, VENDOR_CISCO},
    {{0x00, 0x0B, 0xBE}, VENDOR_CISCO},
    {{0x00, 0x0C, 0xCE}, VENDOR_CISCO},
    {{0x00, 0x11, 0x92}, VENDOR_CISCO},
    {{0x00, 0x13, 0x7F}, VENDOR_CISCO},
    {{0x00, 0x14, 0xF1}, VENDOR_CISCO},
    {{0x00, 0x17, 0xE0}, VENDOR_CISCO},
    {{0x00, 0x19, 0x06}, VENDOR_CISCO},
    {{0x00, 0x1A, 0xA2}, VENDOR_CISCO},
    {{0x00, 0x1C, 0xB0}, VENDOR_CISCO},
    {{0x00, 0x21, 0x55}, VENDOR_CISCO},
    {{0x00, 0x22, 0x0C}, VENDOR_CISCO},
    {{0x00, 0x23, 0xBE}, VENDOR_CISCO},
    {{0x00, 0x25, 0x2E}, VENDOR_CISCO},
    {{0x00, 0x25, 0xB3}, VENDOR_CISCO},
    {{0x00, 0x26, 0x0A}, VENDOR_CISCO},
    {{0x00, 0x26, 0xCB}, VENDOR_CISCO},

    // ── NetComm ──────────────────────────────────────────────────────────────
    {{0x00, 0x1C, 0x8B}, VENDOR_NETCOMM},
    {{0x00, 0x26, 0x75}, VENDOR_NETCOMM},

    // ── Ubiquiti ─────────────────────────────────────────────────────────────
    {{0x00, 0x15, 0x6D}, VENDOR_UBIQUITI},
    {{0x00, 0x27, 0x22}, VENDOR_UBIQUITI},
    {{0x04, 0x18, 0xD6}, VENDOR_UBIQUITI},
    {{0x24, 0xA4, 0x3C}, VENDOR_UBIQUITI},
    {{0x44, 0xD9, 0xE7}, VENDOR_UBIQUITI},
    {{0x68, 0x72, 0x51}, VENDOR_UBIQUITI},
    {{0x78, 0x8A, 0x20}, VENDOR_UBIQUITI},
    {{0xDC, 0x9F, 0xDB}, VENDOR_UBIQUITI},
    {{0xF4, 0x92, 0xBF}, VENDOR_UBIQUITI},
    {{0xFC, 0xEC, 0xDA}, VENDOR_UBIQUITI},
};

// ─── OUI'dan vendor tespiti ────────────────────────────────────────────────────
static wps_vendor_t detect_vendor_oui(const uint8_t *bssid) {
    int n = (int)(sizeof(OUI_TABLE) / sizeof(OUI_TABLE[0]));
    for (int i = 0; i < n; i++) {
        if (bssid[0] == OUI_TABLE[i].oui[0] &&
            bssid[1] == OUI_TABLE[i].oui[1] &&
            bssid[2] == OUI_TABLE[i].oui[2]) {
            return OUI_TABLE[i].vendor;
        }
    }
    return VENDOR_UNKNOWN;
}

// ─── SSID deseniyle vendor doğrulama ─────────────────────────────────────────
static wps_vendor_t refine_vendor_by_ssid(wps_vendor_t oui_vendor,
                                          const char *ssid,
                                          const uint8_t * /*bssid*/) {
    if (!ssid || ssid[0] == '\0') return oui_vendor;

    if (strncmp(ssid, "TTNET_", 6) == 0 || strncmp(ssid, "TT_", 3) == 0)
        return (oui_vendor == VENDOR_UNKNOWN) ? VENDOR_ZTE : oui_vendor;
    if (strncmp(ssid, "TP-Link_", 8) == 0 || strncmp(ssid, "TP-LINK_", 8) == 0)
        return VENDOR_TPLINK;
    if (prefix_icase(ssid, "dlink", 5)) return VENDOR_DLINK;
    if (prefix_icase(ssid, "NETGEAR", 7)) return VENDOR_NETGEAR;
    if (strncmp(ssid, "ASUS_", 5) == 0 || strncmp(ssid, "Asus_", 5) == 0)
        return VENDOR_ASUS;
    if (strncmp(ssid, "Vodafone_", 9) == 0 || strncmp(ssid, "VODAFONE", 8) == 0)
        return VENDOR_ARCADYAN;
    if (strncmp(ssid, "Tenda_", 6) == 0) return VENDOR_TENDA;
    if (strncmp(ssid, "Xiaomi_", 7) == 0 || strncmp(ssid, "MiWifi_", 7) == 0)
        return VENDOR_XIAOMI;
    if (strncmp(ssid, "FRITZ!Box", 9) == 0 || strncmp(ssid, "FritzBox", 8) == 0)
        return VENDOR_FRITZ;
    if (strncmp(ssid, "MikroTik", 8) == 0) return VENDOR_MIKROTIK;
    if (strncmp(ssid, "TOTOLINK", 8) == 0) return VENDOR_TOTOLINK;

    return oui_vendor;
}

// ─── Vendor'a göre açık seviyesi ──────────────────────────────────────────────
static wps_vuln_t vendor_to_vuln(wps_vendor_t v) {
    switch (v) {
        case VENDOR_ZTE:         return VULN_HIGH;
        case VENDOR_SAGEMCOM:    return VULN_HIGH;
        case VENDOR_TOTOLINK:    return VULN_HIGH;
        case VENDOR_COMTREND:    return VULN_HIGH;
        case VENDOR_GEMTEK:      return VULN_HIGH;
        case VENDOR_BILLION:     return VULN_HIGH;
        case VENDOR_DLINK:       return VULN_HIGH;
        case VENDOR_NETCOMM:     return VULN_HIGH;

        case VENDOR_HUAWEI:      return VULN_MEDIUM;
        case VENDOR_ZYXEL:       return VULN_MEDIUM;
        case VENDOR_TPLINK:      return VULN_MEDIUM;
        case VENDOR_ARCADYAN:    return VULN_MEDIUM;
        case VENDOR_TECHNICOLOR: return VULN_MEDIUM;
        case VENDOR_ARRIS:       return VULN_MEDIUM;
        case VENDOR_COMPAL:      return VULN_MEDIUM;
        case VENDOR_SERCOMM:     return VULN_MEDIUM;
        case VENDOR_SAGEM:       return VULN_MEDIUM;
        case VENDOR_ACTIONTEC:   return VULN_MEDIUM;
        case VENDOR_ISKRATEL:    return VULN_MEDIUM;

        case VENDOR_ASUS:        return VULN_LOW;
        case VENDOR_LINKSYS:     return VULN_LOW;
        case VENDOR_BELKIN:      return VULN_LOW;
        case VENDOR_TENDA:       return VULN_LOW;
        case VENDOR_MERCUSYS:    return VULN_LOW;
        case VENDOR_BUFFALO:     return VULN_LOW;
        case VENDOR_MIKROTIK:    return VULN_LOW;
        case VENDOR_NETGEAR:     return VULN_LOW;
        case VENDOR_NETIS:       return VULN_LOW;
        case VENDOR_CISCO:       return VULN_LOW;
        case VENDOR_DRAYTEK:     return VULN_LOW;
        case VENDOR_UBIQUITI:    return VULN_LOW;
        case VENDOR_FRITZ:       return VULN_LOW;
        case VENDOR_XIAOMI:      return VULN_LOW;

        default:                 return VULN_NONE;
    }
}

// ─── Vendor adı string ────────────────────────────────────────────────────────
static const char *vendor_name_str(wps_vendor_t v) {
    switch (v) {
        case VENDOR_ZTE:         return "ZTE";
        case VENDOR_HUAWEI:      return "Huawei";
        case VENDOR_ZYXEL:       return "Zyxel";
        case VENDOR_TPLINK:      return "TP-Link";
        case VENDOR_SAGEMCOM:    return "Sagemcom";
        case VENDOR_ARCADYAN:    return "Arcadyan";
        case VENDOR_DLINK:       return "D-Link";
        case VENDOR_NETGEAR:     return "Netgear";
        case VENDOR_ASUS:        return "ASUS";
        case VENDOR_LINKSYS:     return "Linksys";
        case VENDOR_BELKIN:      return "Belkin";
        case VENDOR_TENDA:       return "Tenda";
        case VENDOR_MERCUSYS:    return "Mercusys";
        case VENDOR_TOTOLINK:    return "Totolink";
        case VENDOR_TECHNICOLOR: return "Technicolor";
        case VENDOR_FRITZ:       return "Fritz!Box";
        case VENDOR_ARRIS:       return "Arris";
        case VENDOR_XIAOMI:      return "Xiaomi";
        case VENDOR_BUFFALO:     return "Buffalo";
        case VENDOR_MIKROTIK:    return "MikroTik";
        case VENDOR_COMPAL:      return "Compal";
        case VENDOR_SERCOMM:     return "Sercomm";
        case VENDOR_NETIS:       return "Netis";
        case VENDOR_CISCO:       return "Cisco";
        case VENDOR_SAGEM:       return "Sagem";
        case VENDOR_COMTREND:    return "Comtrend";
        case VENDOR_ACTIONTEC:   return "Actiontec";
        case VENDOR_GEMTEK:      return "Gemtek";
        case VENDOR_ISKRATEL:    return "Iskratel";
        case VENDOR_DRAYTEK:     return "DrayTek";
        case VENDOR_BILLION:     return "Billion";
        case VENDOR_NETCOMM:     return "NetComm";
        case VENDOR_UBIQUITI:    return "Ubiquiti";
        default:                 return "Bilinmiyor";
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// WPS PIN Üretme
// ═══════════════════════════════════════════════════════════════════════════════

static int add_pin(char pins[][9], int count, int max_pins, uint32_t pin7) {
    if (count >= max_pins) return count;
    uint32_t acc = 0;
    acc += 3 * ((pin7 / 1000000) % 10);
    acc += 1 * ((pin7 / 100000)  % 10);
    acc += 3 * ((pin7 / 10000)   % 10);
    acc += 1 * ((pin7 / 1000)    % 10);
    acc += 3 * ((pin7 / 100)     % 10);
    acc += 1 * ((pin7 / 10)      % 10);
    acc += 3 * ((pin7 / 1)       % 10);
    uint8_t chk = (uint8_t)((10 - (acc % 10)) % 10);
    char buf[9];
    snprintf(buf, 9, "%07u%1u", (unsigned)pin7, (unsigned)chk);
    for (int i = 0; i < count; i++)
        if (strncmp(pins[i], buf, 9) == 0) return count;
    strncpy(pins[count], buf, 9);
    return count + 1;
}

static int ssid_suffix_pins(const char *ssid, char pins[][9], int count, int max_pins) {
    if (!ssid) return count;
    int slen = (int)strlen(ssid);
    char digits[32] = {};
    int  dlen = 0;
    for (int i = 0; i < slen && dlen < 31; i++)
        if (ssid[i] >= '0' && ssid[i] <= '9')
            digits[dlen++] = ssid[i];
    digits[dlen] = '\0';
    if (dlen < 4) return count;

    if (dlen >= 7) {
        uint32_t v = 0;
        for (int i = dlen - 7; i < dlen; i++) v = v * 10 + (digits[i] - '0');
        count = add_pin(pins, count, max_pins, v);
    }
    if (dlen >= 7) {
        uint32_t v = 0;
        for (int i = 0; i < 7; i++) v = v * 10 + (digits[i] - '0');
        count = add_pin(pins, count, max_pins, v);
    }
    if (dlen >= 6) {
        uint32_t v = 0;
        for (int i = dlen - 6; i < dlen; i++) v = v * 10 + (digits[i] - '0');
        count = add_pin(pins, count, max_pins, v);
    }
    return count;
}

static int bssid_based_pins(const uint8_t *bssid, char pins[][9], int count, int max_pins) {
    if (!bssid) return count;
    uint32_t v1 = ((uint32_t)bssid[3] << 16 |
                   (uint32_t)bssid[4] <<  8 |
                   (uint32_t)bssid[5])  % 10000000;
    count = add_pin(pins, count, max_pins, v1);
    uint32_t v2 = ((uint32_t)bssid[5] << 16 |
                   (uint32_t)bssid[4] <<  8 |
                   (uint32_t)bssid[3])  % 10000000;
    count = add_pin(pins, count, max_pins, v2);
    char tmp[16];
    snprintf(tmp, sizeof(tmp), "%02u%02u%02u",
             (unsigned)bssid[3], (unsigned)bssid[4], (unsigned)bssid[5]);
    tmp[7] = '\0';
    uint32_t v3 = (uint32_t)atoi(tmp);
    count = add_pin(pins, count, max_pins, v3);
    return count;
}

static const uint32_t COMMON_PINS[] = {
    1234567, 0000000, 1111111, 2222222, 3333333,
    4444444, 5555555, 6666666, 7777777, 8888888,
    9999999, 1234560, 0000001, 9999990, 1111110,
    7654321, 9876543, 2468135, 1357924, 0123456,
};
static const int COMMON_PINS_COUNT = (int)(sizeof(COMMON_PINS) / sizeof(COMMON_PINS[0]));

int wps_ssid_to_pins(const char *ssid, const uint8_t *bssid,
                     char pins[][9], int max_pins) {
    if (max_pins <= 0) return 0;
    int count = 0;

    wps_vendor_t vendor = detect_vendor_oui(bssid);
    vendor = refine_vendor_by_ssid(vendor, ssid, bssid);

    count = ssid_suffix_pins(ssid, pins, count, max_pins);
    count = bssid_based_pins(bssid, pins, count, max_pins);

    // Vendor'a özel ek PIN'ler
    if (vendor == VENDOR_ZTE || vendor == VENDOR_SAGEMCOM || vendor == VENDOR_GEMTEK) {
        static const uint32_t isp_fixed[] = {1234567, 0000000, 8888880, 7654321};
        for (int i = 0; i < 4 && count < max_pins; i++)
            count = add_pin(pins, count, max_pins, isp_fixed[i]);
    }

    // Her vendor için genel yaygın PIN'ler (sonda)
    for (int i = 0; i < COMMON_PINS_COUNT && count < max_pins; i++)
        count = add_pin(pins, count, max_pins, COMMON_PINS[i]);

    return count;
}

// ═══════════════════════════════════════════════════════════════════════════════
// WPS Tarama
// ═══════════════════════════════════════════════════════════════════════════════

void wps_scan() {
    wps_target_count = 0;
    memset(wps_targets, 0, sizeof(wps_targets));

    int n = (int)WiFi.scanNetworks();
    if (n <= 0) return;

    for (int i = 0; i < n && wps_target_count < WPS_MAX_TARGETS; i++) {
        int enc = (int)WiFi.encryptionType((uint8_t)i);
        if (enc == WIFI_AUTH_OPEN) continue;

        wps_target_t &t = wps_targets[wps_target_count];

        const char *s = WiFi.SSID((uint8_t)i);
        if (s) strncpy(t.ssid, s, 32);
        t.ssid[32] = '\0';

        // NOT: Bu SDK sürümü tarama indexiyle BSSID/kanal döndürmüyor.
        memset(t.bssid, 0, 6);
        t.channel = 0;
        t.rssi    = (int32_t)WiFi.RSSI((uint8_t)i);

        t.vendor = detect_vendor_oui(t.bssid);
        t.vendor = refine_vendor_by_ssid(t.vendor, t.ssid, t.bssid);
        t.vuln   = vendor_to_vuln(t.vendor);

        wps_target_count++;
        DEBUG_PRINTF("WPS [%d]: %s | %s | Kanal %d | %d dBm\n",
            wps_target_count - 1,
            t.ssid[0] ? t.ssid : "(Gizli)",
            vendor_name_str(t.vendor),
            t.channel, (int)t.rssi);
    }

    DEBUG_PRINTF("WPS Tarama: %d hedef\n", wps_target_count);
}

// ─── WPS saldırı stub'ları — BW16'da WPS protokolü desteklenmiyor ─────────────

void wps_start_attack(int target_index) {
    if (target_index < 0 || target_index >= wps_target_count) return;
    wps_attack_state = WPS_IDLE;
    strncpy(wps_vendor_name,
            vendor_name_str(wps_targets[target_index].vendor), 31);
    wps_vendor_name[31] = '\0';
    memcpy(wps_current_mac, wps_targets[target_index].bssid, 6);
    DEBUG_PRINTLN("WPS saldirisi BW16'da desteklenmiyor.");
    DEBUG_PRINTLN("Vendor ve PIN listesi hazir — ESP32 gibi baska platformda kullanin.");
}

void wps_stop() {
    wps_attack_state  = WPS_IDLE;
    wps_attempt       = 0;
    wps_total         = 0;
    wps_lockout_count = 0;
    memset(wps_current_pin, 0, sizeof(wps_current_pin));
    memset(wps_found_pin,   0, sizeof(wps_found_pin));
    memset(wps_found_ssid,  0, sizeof(wps_found_ssid));
    memset(wps_found_pass,  0, sizeof(wps_found_pass));
    memset(wps_vendor_name, 0, sizeof(wps_vendor_name));
    memset(wps_current_mac, 0, sizeof(wps_current_mac));
}

void wps_loop() {}
