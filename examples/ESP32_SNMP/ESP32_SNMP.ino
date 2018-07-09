#include <WiFi.h>
#include <WiFiUdp.h>
#include <Arduino_SNMP.h>

const char* ssid = "Fusion";
const char* password = "1357902468";

WiFiUDP udp;
SNMPAgent snmp = SNMPAgent("public");  // Starts an SMMPAgent instance with the community string 'public'

int changingNumber = 1;
int settableNumber = 0;

ValueCallback* changingNumberOID;
ValueCallback* settableNumberOID;


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
    changingNumberOID = snmp.addIntegerHandler(".1.3.6.1.4.1.5.0", &changingNumber);
    
    // Using your favourite snmp tool:
    // snmpget -v 1 -c public <IP> 1.3.6.1.4.1.5.0
    
    // you can accept SET commands with a pointer to an integer (or string)
    settableNumberOID = snmp.addIntegerHandler(".1.3.6.1.4.1.5.1", &settableNumber, true);
    
    // snmpset -v 1 -c public <IP> 1.3.6.1.4.1.5.0 i 99
    // sort_oid(".1.3.6.1.4.1.5.0");

    snmp.addIntegerHandler(".1.3.6.1.4.1.4.0", &changingNumber);

    
}

void loop(){
    snmp.loop(); // must be called as often as possible
    if(snmp.setOccurred){
        Serial.printf("Number has been set to value: %i\n", settableNumber);
        Serial.println("Lets remove the changingNumber reference");
        snmp.sortHandlers();
        // if(snmp.removeHandler(settableNumberOID)){
        //     Serial.println("Remove succesful");
        // }
        snmp.resetSetOccurred();
    }
    changingNumber++;
}