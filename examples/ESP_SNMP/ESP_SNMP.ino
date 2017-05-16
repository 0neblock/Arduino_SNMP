#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <Arduino_SNMP.h>

const char* ssid = "SSID";
const char* password = "PASSWORD";

WiFiUDP udp;
SNMPAgent snmp = SNMPAgent("public");

int changingNumber = 1;

void setup(){
    Serial.begin(115200);
    WiFi.begin(ssid, password);
    Serial.println("");

    // Wait for connection
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("");
    Serial.print("Connected to ");
    Serial.println(ssid);
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());
    
    // give snmp a pointer to the UDP object
    snmp.setUDP(&udp);
    snmp.begin();
    
    // add 'callback' for an OID - pointer to an integer
    snmp.addIntegerHandler(".1.3.6.1.4.1.5.0", &changingNumber);
    
    // Using your favourite snmp tool:
    // snmpget -v 1 -c public <IP> 1.3.6.1.4.1.5.0
}

void loop(){
    snmp.loop(); // must be called as often as possible
    changingNumber++;
}