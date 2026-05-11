#include "EEPROM.h"

#ifdef BOARD_BW16

#include <FlashMemory.h>

/*
 * RTL8720DN Flash layout: 2MB total.
 * We reserve one 4 KB sector at 0x100000 for EEPROM emulation.
 * FlashMemoryClass API (AmebaD Arduino SDK):
 *   begin(unsigned int base_address, unsigned int length)
 *   read()               – reads flash → FlashMemory.buf[]
 *   update()             – writes FlashMemory.buf[] → flash
 *   clear()              – fills FlashMemory.buf[] with 0xFF
 *   uint8_t buf[4096]    – public staging buffer
 */

#define EEPROM_FLASH_BASE   0x100000U
#define FLASH_SECTOR_SIZE   4096U

void EEPROMClass::_load() {
    FlashMemory.begin(EEPROM_FLASH_BASE, FLASH_SECTOR_SIZE);
    FlashMemory.read();
    int copy_len = (_size < (int)FLASH_SECTOR_SIZE) ? _size : (int)FLASH_SECTOR_SIZE;
    memcpy(_data, FlashMemory.buf, copy_len);
}

void EEPROMClass::_store() {
    FlashMemory.begin(EEPROM_FLASH_BASE, FLASH_SECTOR_SIZE);
    FlashMemory.read();
    int copy_len = (_size < (int)FLASH_SECTOR_SIZE) ? _size : (int)FLASH_SECTOR_SIZE;
    memcpy(FlashMemory.buf, _data, copy_len);
    FlashMemory.update();
}

#else

void EEPROMClass::_load()  {}
void EEPROMClass::_store() {}

#endif

EEPROMClass EEPROM;
