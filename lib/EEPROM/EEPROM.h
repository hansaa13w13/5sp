#ifndef EEPROM_H
#define EEPROM_H

// BW16 / RTL8720DN — Flash-backed EEPROM emülatörü
// FlashMemoryClass (AmebaD Arduino SDK) üzerinde çalışır.

#include <stdint.h>
#include <string.h>

class EEPROMClass {
public:
    EEPROMClass() : _data(nullptr), _size(0), _dirty(false) {}

    void begin(int size) {
        if (size <= 0 || size > 4096) size = 4096;
        if (_data) { delete[] _data; _data = nullptr; }
        _size  = size;
        _data  = new uint8_t[_size];
        memset(_data, 0xFF, _size);
        _dirty = false;
        _load();
    }

    uint8_t read(int addr) const {
        if (!_data || addr < 0 || addr >= _size) return 0xFF;
        return _data[addr];
    }

    void write(int addr, uint8_t val) {
        if (!_data || addr < 0 || addr >= _size) return;
        if (_data[addr] != val) { _data[addr] = val; _dirty = true; }
    }

    bool commit() {
        if (!_data || !_dirty) return true;
        _store();
        _dirty = false;
        return true;
    }

    // Şablon get/put — herhangi bir POD türü için
    template<typename T>
    T& get(int addr, T& val) {
        uint8_t* p = reinterpret_cast<uint8_t*>(&val);
        for (int i = 0; i < (int)sizeof(T); i++)
            p[i] = read(addr + i);
        return val;
    }

    template<typename T>
    const T& put(int addr, const T& val) {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&val);
        for (int i = 0; i < (int)sizeof(T); i++)
            write(addr + i, p[i]);
        return val;
    }

    int length() const { return _size; }

    // Köşeli parantez operatörü — doğrudan byte erişimi
    uint8_t operator[](int addr) const { return read(addr); }

private:
    uint8_t* _data;
    int      _size;
    bool     _dirty;

    void _load();
    void _store();
};

extern EEPROMClass EEPROM;

#endif // EEPROM_H
