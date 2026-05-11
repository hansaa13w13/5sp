#include <Arduino.h>
#include "definitions.h"

// BW16-KIT: LED aktif-düşük (LOW = yanar, HIGH = söner)

#ifdef LED
void blink_led(int num_times, int blink_duration) {
  for (int i = 0; i < num_times; i++) {
    digitalWrite(LED, LOW);
    delay(blink_duration / 2);
    digitalWrite(LED, HIGH);
    delay(blink_duration / 2);
  }
}

void led_on() {
  digitalWrite(LED, LOW);
}

void led_off() {
  digitalWrite(LED, HIGH);
}
#else
void led_on()  {}
void led_off() {}
void blink_led(int, int) {}
#endif
