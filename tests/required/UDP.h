#ifndef UDP_h
#define UDP_h

#ifdef COMPILING_TESTS

#include "tests/required/IPAddress.h"
#include <stddef.h>

class UDP {
  public:
    void begin(int) {};

    int parsePacket() { return 0; }

    void beginPacket(IPAddress, uint16_t) {};

    int endPacket() { return 1; };

    void write(uint8_t *, size_t) {};

    void stop() {};

    int read(uint8_t *, int) { return 0; }

    IPAddress remoteIP() { return IPAddress(); }

    int remotePort() { return 0; }

};

#endif
#endif