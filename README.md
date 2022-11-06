# SNMP_Agent
### (Previously Arduino_SNMP)

SNMP Agent built with Arduino

This is a fully-compliant SNMPv2c Agent built for Arduino's, but will work on any OS, providing API code is written for packet serialization (See tests/mock.cpp for an example)

## Features
* Full SNMPv2c Data Type support:
  * INTEGER `int`
  * STRING  `std::string` or `const char*`
  * NULLTYPE
  * OIDTYPE
* Complex data type support:
  * NETWORK ADDRESS
  * COUNTER32 `uint32_t`
  * GAUGE32 `uint32_t`
  * TIMESTAMP `uint32_t`
  * OPAQUE `uint8_t*`
  * CONTER64 `uint64_t`
* SNMP PDU Support
  * GetRequest
  * GetNextRequest
  * GetResponse (For SNMPv2c INFORM Responses only for now)
  * SetRequest
  * SNMPv2 Trap
  * GetBulkRequest
  * InformRequest
  * SNMPv2 Trap

It was designed and tested around an ESP32, but will work with any Arduino-based devied that has a UDP object available.

The example goes into detail around how to use, or look at `src/SNMP_Agent.h` for the API.

If you're coming from v1, most, but not all APIs are drop-in replaceable.
Some of the API's, especially around strings have changed. Look in `SNMP_Agent.h` for details.

It you need a STRING OID that can be written to/updated, be very sure that you need to update it, because you will be dealing with raw pointers. It's safer to use `addReadOnlyStaticStringHandler()` instead.

It does not support the Arduino `String` type, only the C++ standard `std::string` type.

## Getting Started

To setup a simple SNMP Agent, include the required libraries and declare an instance of the SNMPAgent class;

```
#include <SNMP_Agent.h>

/* Can declare read-write, or both read-only and read-write community strings */
SNMPAgent snmp("public", "private");
```

Depending on what arduino you are using, you will have to setup the wifi/internet conection for the device.
For ESP32, you can use `WiFi.begin()`, you will then need to supply a `UDP` object to the snmp library.

```
#include <WiFi.h>
#include <WiFiUdp.h>
WiFiUDP udp;

... later in setup()

WiFi.begin(ssid, password);

// Give snmp a pointer to the UDP object
snmp.setUDP(&udp);

// Add OID Handlers (see below)
...

snmp.begin();

... later in loop()
snmp.loop();
```

### Setting OID callbacks

If you want the Arduino to response to an SNMP server at some specified OIDs, you need to implement a `ValueCallback` for each OID, attached to a variable to respond with.
Whenever an OID is requested by sn SNMP manager, the ValueCallback for that OID is found, and the latest value of that variable is used to respond.

For example, to respones to the OID ".1.3.6.1.4.1.5.0" with the number: 5.
```
int testNumber = 5;
snmp.addIntegerHandler(".1.3.6.1.4.1.5.0", &testNumber);
```

Yopu can enable SNMPSet requests, by setting `isSettable = true` as a parameter when adding the handler, for example:
```
int settableNumber = 0;
snmp.addIntegerHandler(".1.3.6.1.4.1.5.1", &settableNumber, true);
// snmpset -v 2c -c private <IP> 1.3.6.1.4.1.5.1 i 24
```

You can store the return value of the handler calls in a variable `ValueCallback*`, and use them later for things like SNMP Traps, or for removing the handler later.

Be sure to call `snmp.sortHandlers()` after adding any OID handlers, to ensure functions like SNMP Walk work correctly.


The full list of ValueCallback handlers you can specify can be found in `SNMP_Agent.h`

### SNMP Traps

You can send SNMP v1 traps, as well as SNMPv2 Trap and INFORMS with this library.

Therre are a few requirements in setting up a trap in order to comply with the SNMP RFC.

```
// Setup a trap object for later use, specify the SNMP version to use 
// SNMP_VERSION_1 or SNMP_VERSION_2C

SNMPTrap* testTrap = new SNMPTrap("public", SNMP_VERSION_2C);

// SNMP Traps MUST send a timestamp value when sent. This timestamp doesn't have to be valid, but we have to create one anyway. The timestamp value is stored as "tens of milliseconds"
TimestampCallback* timestampCallback;
int tensOfMillisCounter = 0;
```
In `setup()`:
```
// The SNMP Trap spec requires an uptime counter to be sent along with the trap.
timestampCallback = (TimestampCallback*)snmp.addTimestampHandler(".1.3.6.1.2.1.1.3.0", &tensOfMillisCounter);

// Set UDP Object for trap to be sent on
testTrap->setUDP(&udp);

// OID of the trap
testTrap->setTrapOID(new OIDType(".1.3.6.1.2.1.33.2")); 

// Specific Number of the trap
testTrap->setSpecificTrap(1); 

// Set the uptime counter to use in the trap (required)
testTrap->setUptimeCallback(timestampCallback);

// Set some previously set OID Callbacks to send these values with the trap (optional)
testTrap->addOIDPointer(previouslySetValueCallback);

// Set our Source IP so the receiver knows where this is coming from
testTrap->setIP(WiFi.localIP()); 

// Set INFORM to be true or false (only works for SNMPV2 traps)
testTrap->setInform(true);
```

in `loop()`

```
// must be called as often as possible
snmp.loop(); 

// Update our timestamp value
tensOfMillisCounter = millis()/10;

// Send the trap to the specified IP address

IPAddress destinationIP = IPAddress(192, 168, 1, 243);

if(snmp.sendTrapTo(testTrap, destinationIP, true, 2, 5000) != INVALID_SNMP_REQUEST_ID){ 
    Serial.println("Sent SNMP Trap");
} else {
    Serial.println("Couldn't send SNMP Trap");
}
```

The `snmp.sendTrapTo()` values of `true, 2, 5000` indicate that if this is an INFORM request, it will try to send the INFORM up to 2 times, with a Timeout of 5000 milliseconds before it gives up, if it receives no response from the other end. The snmp.loop() will keep trying to resend the trap until the timeout or retry limit is reached.

There is currencly no mechanism to know (with code) if an SNMP INFORM request has been responded to. I hope to work on this in the future.

### SNMP Manager

I am working on adding the functionality to act as an SNMP Server or Manager. In the meantime, if you need to do this, look at the library here: https://github.com/shortbloke/Arduino_SNMP_Manager

Pull requests/comments are welcome