# Arduino_SNMP v2
SNMP Agent v2c built with Arduino

This is a fully-compliant SNMPv2c Agent built for Arduinos, but will work on any OS, providing API code is written for packet serialization (See tests/mock.cpp for an example)

It was designed and tested around an ESP32, but will work with any Arduino-based devied that has a UDP object available.

The example goes into detail around how to use, or look at `src/Arduino_SNMP.h` for the API.

If you're coming from v1, most, but not all APIs are drop-in replaceable.
Some of the API's, especially around strings have changed. Look in `Arduino_SNMP.h` for details.

It you need a STRING OID that can be written to/updated, be very sure that you need to update it, because you will be dealingwith raw pointers. It's safer to use `addReadOnlyStaticStringHandler()` instead.

It does not support the Arduino `String()` type, only the C++ standard `std::string` type

Pull requests/comments are welcome