#ifndef WiFi_h
#define WiFi_h

#include "IPAddress.h"
#include "Serial.h"
#include "misc.h"

#ifdef COMPILING_TESTS

enum STATUS {
    WL_CONNECTED
};

class WiFiClass {
  public:
    int begin(const char *ssid, const char *password) {
        (void) password;
        (void) ssid;
        return 0;
    };

    STATUS status() { return (STATUS) 0; }

    IPAddress localIP() { return IPAddress(0, 0, 0, 0); }
};

WiFiClass WiFi;
#endif
#endif