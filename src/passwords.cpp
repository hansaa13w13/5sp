#include "passwords.h"
#include "definitions.h"

// ═════════════════════════════════════════════════════════════════════════════
// ESP32 — Preferences (NVS flash) ile kalıcı depolama
// ═════════════════════════════════════════════════════════════════════════════
#ifndef BOARD_BW16

#include <Preferences.h>

static Preferences prefs;

void passwords_init() {
  prefs.begin("deauther", false);
}

bool passwords_save(const String &ssid, const String &password) {
  int count = prefs.getInt("count", 0);
  if (count >= MAX_PASSWORDS) return false;

  char ssid_key[8], pass_key[8];
  snprintf(ssid_key, sizeof(ssid_key), "ss%d", count);
  snprintf(pass_key, sizeof(pass_key), "pw%d", count);

  prefs.putString(ssid_key, ssid);
  prefs.putString(pass_key, password);
  prefs.putInt("count", count + 1);

  DEBUG_PRINT("Sifre kaydedildi: ");
  DEBUG_PRINTLN(password);
  return true;
}

int passwords_count() {
  return prefs.getInt("count", 0);
}

SavedPassword passwords_get(int index) {
  SavedPassword sp;
  if (index < 0 || index >= passwords_count()) return sp;

  char ssid_key[8], pass_key[8];
  snprintf(ssid_key, sizeof(ssid_key), "ss%d", index);
  snprintf(pass_key, sizeof(pass_key), "pw%d", index);

  sp.ssid     = prefs.getString(ssid_key, "");
  sp.password = prefs.getString(pass_key, "");
  return sp;
}

void passwords_delete(int index) {
  int count = passwords_count();
  if (index < 0 || index >= count) return;

  for (int i = index; i < count - 1; i++) {
    char ssid_src[8], pass_src[8], ssid_dst[8], pass_dst[8];
    snprintf(ssid_src, sizeof(ssid_src), "ss%d", i + 1);
    snprintf(pass_src, sizeof(pass_src), "pw%d", i + 1);
    snprintf(ssid_dst, sizeof(ssid_dst), "ss%d", i);
    snprintf(pass_dst, sizeof(pass_dst), "pw%d", i);

    prefs.putString(ssid_dst, prefs.getString(ssid_src, ""));
    prefs.putString(pass_dst, prefs.getString(pass_src, ""));
  }

  char ssid_last[8], pass_last[8];
  snprintf(ssid_last, sizeof(ssid_last), "ss%d", count - 1);
  snprintf(pass_last, sizeof(pass_last), "pw%d", count - 1);
  prefs.remove(ssid_last);
  prefs.remove(pass_last);
  prefs.putInt("count", count - 1);
}

void passwords_clear_all() {
  prefs.clear();
}

// ═════════════════════════════════════════════════════════════════════════════
// BW16 / RTL8720DN — EEPROM ile kalıcı depolama
// Her giriş: 33 byte SSID + 65 byte şifre = 98 byte
// Başlık: 4 byte (count)  →  toplam: 4 + 30×98 = 2944 byte
// ═════════════════════════════════════════════════════════════════════════════
#else // BOARD_BW16

#include <EEPROM.h>

#define EEPROM_SIZE    2944
#define EEPROM_HDR_OFF 0           // 4 byte: count (int32)
#define EEPROM_DAT_OFF 4           // giriş başlangıcı
#define ENTRY_SIZE     98          // 33 + 65
#define SSID_OFF       0
#define PASS_OFF       33

static bool eeprom_ready = false;

void passwords_init() {
  EEPROM.begin(EEPROM_SIZE);
  eeprom_ready = true;
}

static int _count() {
  int32_t c = 0;
  EEPROM.get(EEPROM_HDR_OFF, c);
  if (c < 0 || c > MAX_PASSWORDS) c = 0;
  return (int)c;
}

static void _set_count(int c) {
  int32_t v = (int32_t)c;
  EEPROM.put(EEPROM_HDR_OFF, v);
  EEPROM.commit();
}

static int _entry_offset(int idx) {
  return EEPROM_DAT_OFF + idx * ENTRY_SIZE;
}

bool passwords_save(const String &ssid, const String &password) {
  if (!eeprom_ready) return false;
  int count = _count();
  if (count >= MAX_PASSWORDS) return false;

  int off = _entry_offset(count);
  char buf[98] = {};

  strncpy(buf + SSID_OFF, ssid.c_str(),     32);
  strncpy(buf + PASS_OFF, password.c_str(), 64);

  for (int i = 0; i < ENTRY_SIZE; i++)
    EEPROM.write(off + i, (uint8_t)buf[i]);

  _set_count(count + 1);

  DEBUG_PRINT("Sifre kaydedildi: ");
  DEBUG_PRINTLN(password);
  return true;
}

int passwords_count() {
  if (!eeprom_ready) return 0;
  return _count();
}

SavedPassword passwords_get(int index) {
  SavedPassword sp;
  if (!eeprom_ready || index < 0 || index >= _count()) return sp;

  int off = _entry_offset(index);
  char ssid_buf[33] = {};
  char pass_buf[65] = {};

  for (int i = 0; i < 33; i++) ssid_buf[i] = (char)EEPROM.read(off + SSID_OFF + i);
  for (int i = 0; i < 65; i++) pass_buf[i] = (char)EEPROM.read(off + PASS_OFF + i);

  ssid_buf[32] = '\0';
  pass_buf[64] = '\0';

  sp.ssid     = String(ssid_buf);
  sp.password = String(pass_buf);
  return sp;
}

void passwords_delete(int index) {
  if (!eeprom_ready) return;
  int count = _count();
  if (index < 0 || index >= count) return;

  for (int i = index; i < count - 1; i++) {
    int src = _entry_offset(i + 1);
    int dst = _entry_offset(i);
    for (int b = 0; b < ENTRY_SIZE; b++)
      EEPROM.write(dst + b, EEPROM.read(src + b));
  }
  // Son girişi sıfırla
  int last_off = _entry_offset(count - 1);
  for (int b = 0; b < ENTRY_SIZE; b++)
    EEPROM.write(last_off + b, 0);

  _set_count(count - 1);
}

void passwords_clear_all() {
  if (!eeprom_ready) return;
  for (int i = 0; i < EEPROM_SIZE; i++)
    EEPROM.write(i, 0);
  EEPROM.commit();
}

#endif // BOARD_BW16
