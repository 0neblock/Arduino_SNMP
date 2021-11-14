#ifndef Serial_h
#define Serial_h

#include <stdarg.h>

#ifdef COMPILING_TESTS
class HardwareSerial {
  public:
    int begin(int){return 0;};
    int printf(...){return 0;};
    int println(...){return 0;};
    int print(...){return 0;};
};

HardwareSerial Serial;
#endif
#endif