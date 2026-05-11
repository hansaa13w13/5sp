#include <Arduino.h>
#include "definitions.h"

#ifdef LED
void blink_led(int num_times, int blink_duration) {
  for (int i = 0; i < num_times; i++) {
#if defined(BOARD_BW16)
    // BW16-KIT: LED ters mantık (aktif-düşük) — LOW = yanar
    digitalWrite(LED, LOW);
    delay(blink_duration / 2);
    digitalWrite(LED, HIGH);
    delay(blink_duration / 2);
#else
    digitalWrite(LED, HIGH);
    delay(blink_duration / 2);
    digitalWrite(LED, LOW);
    delay(blink_duration / 2);
#endif
  }
}

void led_on() {
#if defined(BOARD_BW16)
  digitalWrite(LED, LOW);   // BW16: aktif-düşük
#else
  digitalWrite(LED, HIGH);
#endif
}

void led_off() {
#if defined(BOARD_BW16)
  digitalWrite(LED, HIGH);  // BW16: aktif-düşük
#else
  digitalWrite(LED, LOW);
#endif
}
#else
void led_on()  {}
void led_off() {}
#endif
