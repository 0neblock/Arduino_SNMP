#include <WiFi.h>
#include <WiFiUdp.h>
#include <SNMP_Agent.h>
#include <SNMPTrap.h>

const char* ssid = "SSID";
const char* password = "password";

WiFiUDP udp;
SNMPAgent snmp = SNMPAgent("public");  // Starts an SMMPAgent instance with the community string 'public'

int changingNumber = 1;
int settableNumber = 0;
int tensOfMillisCounter = 0;

uint8_t* stuff = 0;

ValueCallback* changingNumberOID;
ValueCallback* settableNumberOID;
TimestampCallback* timestampCallbackOID;

SNMPTrap* settableNumberTrap = new SNMPTrap("public", SNMP_VERSION_2C);

void setup(){
    Serial.begin(115200);
    WiFi.begin(ssid, password);
    // WiFi.begin(ssid);
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

    stuff = (uint8_t*)malloc(4);
    stuff[0] = 1;
    stuff[1] = 2;
    stuff[2] = 24;
    stuff[3] = 67;
    
    // add 'callback' for an OID - pointer to an integer
    changingNumberOID = snmp.addIntegerHandler(".1.3.6.1.4.1.5.0", &changingNumber);
    
    // Using your favourite snmp tool:
    // snmpget -v 1 -c public <IP> 1.3.6.1.4.1.5.0
    
    // you can accept SET commands with a pointer to an integer (or string)
    settableNumberOID = snmp.addIntegerHandler(".1.3.6.1.4.1.5.1", &settableNumber, true);
    
    // snmpset -v 1 -c public <IP> 1.3.6.1.4.1.5.0 i 99

    snmp.addIntegerHandler(".1.3.6.1.4.1.4.0", &changingNumber);

    snmp.addOpaqueHandler(".1.3.6.1.4.1.5.9", stuff, 4, true);


    // Setup SNMP TRAP
    // The SNMP Trap spec requires an uptime counter to be sent along with the trap.
    timestampCallbackOID = (TimestampCallback*)snmp.addTimestampHandler(".1.3.6.1.2.1.1.3.0", &tensOfMillisCounter);

    settableNumberTrap->setUDP(&udp); // give a pointer to our UDP object
    settableNumberTrap->setTrapOID(new OIDType(".1.3.6.1.2.1.33.2")); // OID of the trap
    settableNumberTrap->setSpecificTrap(1); 

    // Set the uptime counter to use in the trap
    settableNumberTrap->setUptimeCallback(timestampCallbackOID);

    // Set some previously set OID Callbacks to send these values with the trap
    settableNumberTrap->addOIDPointer(changingNumberOID);
    settableNumberTrap->addOIDPointer(settableNumberOID);

    settableNumberTrap->setIP(WiFi.localIP()); // Set our Source IP

    snmp.sortHandlers();
} 

void loop(){
    snmp.loop(); // must be called as often as possible
    if(snmp.setOccurred){
        Serial.printf("Number has been set to value: %i\n", settableNumber);
        if(settableNumber%2 == 0){
            settableNumberTrap->setVersion(SNMP_VERSION_2C);
            settableNumberTrap->setInform(true);
        } else {
            settableNumberTrap->setVersion(SNMP_VERSION_1);
            settableNumberTrap->setInform(false);
        }
        // Serial.println("Lets remove the changingNumber reference");
        // snmp.sortHandlers();
        // if(snmp.removeHandler(settableNumberOID)){
        //     Serial.println("Remove succesful");
        // }
        snmp.resetSetOccurred();

        Serial.println("Lets send out a trap to indicate a changed value");
        
        IPAddress destinationIP = IPAddress(192, 168, 1, 75);
        if(snmp.sendTrapTo(settableNumberTrap, destinationIP, true, 2, 5000) != INVALID_SNMP_REQUEST_ID){ // Send the trap to the specified IP address
            Serial.println("Sent SNMP Trap");
        } else {
            Serial.println("Couldn't send SNMP Trap");
        }
        // Serial.println(ESP.getFreeHeap());
    }
    changingNumber++;
    tensOfMillisCounter = millis()/10;
}
