#if defined(ESP8266)
    #include <ESP8266WiFi.h> // ESP8266 Core WiFi Library
#else
    #include <WiFi.h> // ESP32 Core WiFi Library
#endif

#include <WiFiUdp.h>
#include <SNMP_Agent.h>

#include <LITTLEFS.h>    // For storing and retreiving previous values or states (note: SPIFFS is deprecated and replaced by LittleFS)
#include <ArduinoJson.h> // Saved data will be stored in JSON

#define FORMAT_LITTLEFS_IF_FAILED true // Be careful, this will wipe all the data stored. So you may want to set this to false once used once.

//************************************
//* Your WiFi info                   *
//************************************
const char* ssid = "SSID";
const char* password = "PASSWORD";
//************************************

//************************************
//* SNMP Configuration               *
//************************************
const char* rocommunity = "public";  // Read only community string
const char* rwcommunity = "private"; // Read Write community string for set commands

// RFC1213-MIB (System)
char* oidSysDescr = ".1.3.6.1.2.1.1.1.0";    // OctetString SysDescr
char* oidSysObjectID = ".1.3.6.1.2.1.1.2.0"; // OctetString SysObjectID
char* oidSysUptime = ".1.3.6.1.2.1.1.3.0";   // TimeTicks sysUptime (hundredths of seconds)
char* oidSysContact = ".1.3.6.1.2.1.1.4.0";  // OctetString SysContact
char* oidSysName = ".1.3.6.1.2.1.1.5.0";     // OctetString SysName
char* oidSysLocation = ".1.3.6.1.2.1.1.6.0"; // OctetString SysLocation
char* oidSysServices = ".1.3.6.1.2.1.1.7.0"; // Integer sysServices

std::string sysDescr = "SNMP Agent";
std::string sysObjectID = "";
int sysUptime = 0;
char sysContactValue[255];
char *sysContact = sysContactValue;
char sysNameValue[255];
char *sysName = sysNameValue;
char sysLocationValue[255];
char *sysLocation = sysLocationValue;
int sysServices = 65; // Physical and Application

// ENTITY-MIB .1.3.6.1.2.1.47 - Needs to be implemented to support ENTITY-SENSOR-MIB
// An entry would be required per sensor. This is index 1.

// entityPhysicalTable
char* oidentPhysicalIndex_1 = ".1.3.6.1.2.1.47.1.1.1.1.1.1";
char* oidentPhysicalDescr_1 = ".1.3.6.1.2.1.47.1.1.1.1.2.1";
char* oidentPhysicalVendorType_1 = ".1.3.6.1.2.1.47.1.1.1.1.3.1";
char* oidentPhysicalContainedIn_1 = ".1.3.6.1.2.1.47.1.1.1.1.4.1";
char* oidentPhysicalClass_1 = ".1.3.6.1.2.1.47.1.1.1.1.5.1";
char* oidentPhysicalParentRelPos_1 = ".1.3.6.1.2.1.47.1.1.1.1.6.1";
char* oidentPhysicalName_1 = ".1.3.6.1.2.1.47.1.1.1.1.7.1";
char* oidentPhysicalHardwareRev_1 = ".1.3.6.1.2.1.47.1.1.1.1.8.1";
char* oidentPhysicalFirmwareRev_1 = ".1.3.6.1.2.1.47.1.1.1.1.9.1";
char* oidentPhysicalSoftwareRev_1 = ".1.3.6.1.2.1.47.1.1.1.1.10.1";
char* oidentPhysicalSerialNum_1 = ".1.3.6.1.2.1.47.1.1.1.1.11.1";
char* oidentPhysicalMfgName_1 = ".1.3.6.1.2.1.47.1.1.1.1.12.1";
char* oidentPhysicalModelName_1 = ".1.3.6.1.2.1.47.1.1.1.1.13.1";
char* oidentPhysicalAlias_1 = ".1.3.6.1.2.1.47.1.1.1.1.14.1";
char* oidentPhysicalAssetID_1 = ".1.3.6.1.2.1.47.1.1.1.1.15.1";
char* oidentPhysicalIsFRU_1 = ".1.3.6.1.2.1.47.1.1.1.1.16.1";
char* oidentPhysicalMfgDate_1 = ".1.3.6.1.2.1.47.1.1.1.1.17.1";
char* oidentPhysicalUris_1 = ".1.3.6.1.2.1.47.1.1.1.1.18.1";

int entPhysicalIndex_1 = 1;
std::string entPhysicalDescr_1 = "Fake Temperature Sensor";
std::string entPhysicalVendorType_1 = "";
int entPhysicalContainedIn_1 = 0;
int entPhysicalClass_1 = 8; // Sensor
int entPhysicalParentRelPos_1 = -1;
std::string entPhysicalName_1 = "";
std::string entPhysicalHardwareRev_1 = "";
std::string entPhysicalFirmwareRev_1 = "";
std::string entPhysicalSoftwareRev_1 = "";
std::string entPhysicalSerialNum_1 = "";
std::string entPhysicalMfgName_1 = "";
std::string entPhysicalModelName_11 = "";
std::string entPhysicalAlias_1 = "";
std::string entPhysicalAssetID_1 = "";
int entPhysicalIsFRU_1 = 0;
std::string entPhysicalMfgDate_1 = "'0000000000000000'H"; // Special value, not sure it's correct. Or meant to be a Hex string?
std::string entPhysicalUris_1 = "";

// EntityPhysicalGroup

// ENTITY-SENSOR-MIB .1.3.6.1.2.1.99
// An entry would be required per sensor. This is index 1.
// Must match index in ENTITY-MIB
char* oidentPhySensorType_1 = ".1.3.6.1.2.1.99.1.1.1.1.1";
char* oidentPhySensorScale_1 = ".1.3.6.1.2.1.99.1.1.1.2.1";
char* oidentPhySensorPrecision_1 = ".1.3.6.1.2.1.99.1.1.1.3.1";
char* oidentPhySensorValue_1 = ".1.3.6.1.2.1.99.1.1.1.4.1";
char* oidentPhySensorOperStatus_1 = ".1.3.6.1.2.1.99.1.1.1.5.1";
char* oidentPhySensorUnitsDisplay_1 = ".1.3.6.1.2.1.99.1.1.1.6.1";
char* oidentPhySensorValueTimeStamp_1 = ".1.3.6.1.2.1.99.1.1.1.7.1";
char* oidentPhySensorValueUpdateRate_1 = ".1.3.6.1.2.1.99.1.1.1.8.1";

int entPhySensorType_1 = 8;       // Celsius
int entPhySensorScale_1 = 9;      // Units
int entPhySensorPrecision_1 = 0;
int entPhySensorValue_1 = 0;      // Value to be updated
int entPhySensorOperStatus_1 = 1; // OK
std::string entPhySensorUnitsDisplay_1 = "Celsius";
int entPhySensorValueTimeStamp_1 = 0;
int entPhySensorValueUpdateRate_1 = 0; // Unknown at declaration, set later.
//************************************

//************************************
//* Initialise                       *
//************************************
// Global Variables
static const unsigned long UPTIME_UPDATE_INTERVAL = 1000; // ms = 1 second
static unsigned long lastUptimeUpdateTime = 0;
static const unsigned long SENSOR_UPDATE_INTERVAL = 5000; // ms = 5 Seconds
static unsigned long lastSensorUpdateTime = 0;
const char* savedValuesFile = "/SNMP.json";
// SNMP Objects
WiFiUDP udp;
// SNMPAgent snmp = SNMPAgent(rocommunity, rwcommunity); // Creates an SMMPAgent instance with the community strings defined
SNMPAgent snmp = SNMPAgent(rocommunity, rwcommunity); // Creates an SMMPAgent instance
//************************************

//************************************
//* Function declarations            *
//************************************
void addRFC1213MIBHandler();
void addENTITYMIBHandler();
void addENTITYSENSORMIBHandler();
int getUptime();
bool loadSNMPValues();
bool saveSNMPValues();
int readFakeSensor();
uint64_t uptimeMillis();
void printFile(const char* filename);
//************************************

void setup()
{
    Serial.begin(115200);
    if (!LITTLEFS.begin(FORMAT_LITTLEFS_IF_FAILED))
    {
        Serial.println("LITTLEFS Mount Failed");
        return;
    }
    WiFi.begin(ssid, password);
    Serial.println("");
    // Wait for connection
    while (WiFi.status() != WL_CONNECTED)
    {
        delay(500);
        Serial.print(".");
    }
    Serial.println("");
    Serial.print("Connected to SSID: ");
    Serial.println(ssid);
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());

    // give snmp a pointer to the UDP object
    snmp.setUDP(&udp);
    snmp.begin();

    addRFC1213MIBHandler();      // RFC1213-MIB (System)
    addENTITYMIBHandler();       // ENTITY-MIB
    addENTITYSENSORMIBHandler(); // ENTITY-SENSOR-MIB

    // Read previously stored values, if any.
    if (loadSNMPValues())
    {
        Serial.println(F("Loaded stored values"));
        printFile(savedValuesFile);
    }

    // Ensure to sortHandlers after adding/removing and OID callbacks - this makes snmpwalk work
    snmp.sortHandlers();
}

void loop()
{
    // put your main code here, to run repeatedly:
    snmp.loop(); // This must be called as often as possible to process incoming requests
    if (snmp.setOccurred)
    {
        Serial.println("A Set event has occured.");
        saveSNMPValues(); // Store the values
        snmp.resetSetOccurred();
    }
    // Periodically update Uptime. Don't need to update it on every loop as it can interfere with responding to SNMP requests
    if (millis() - lastUptimeUpdateTime >= UPTIME_UPDATE_INTERVAL)
    {
        lastUptimeUpdateTime += UPTIME_UPDATE_INTERVAL;
        sysUptime = getUptime();
    }
    // Read Sensor Values
    if (millis() - lastSensorUpdateTime >= SENSOR_UPDATE_INTERVAL)
    {
        lastSensorUpdateTime += SENSOR_UPDATE_INTERVAL;
        entPhySensorValue_1 = readFakeSensor();
        entPhySensorValueTimeStamp_1 = sysUptime;
    }
}

int readFakeSensor()
{
    int min = -50;
    int max = 100;
    return min + esp_random() % ((max + 1) - min);
}

#if defined(ESP32)
uint64_t uptimeMillis()
{
    return (esp_timer_get_time() / 1000);
}
#else
uint64_t uptimeMillis()
{
    // https://arduino.stackexchange.com/questions/12587/how-can-i-handle-the-millis-rollover
    static uint32_t low32, high32;
    uint32_t new_low32 = millis();
    if (new_low32 < low32)
        high32++;
    low32 = new_low32;
    return (uint64_t)high32 << 32 | low32;
}
#endif

int getUptime()
{
    return (int)(uptimeMillis() / 10); // Convert milliseconds to timeticks (hundredths of a second)
}

// Prints the content of a file to the Serial
void printFile(const char* filename)
{
    // Open file for reading
    File file = LITTLEFS.open(filename, "r");
    if (!file)
    {
        Serial.println(F("Failed to read file"));
        return;
    }
    Serial.println("SNMP saved values file: ");
    // Extract each characters by one by one
    while (file.available())
    {
        Serial.print((char)file.read());
    }
    Serial.println();
    file.close();
}

bool loadSNMPValues()
{
    File file = LITTLEFS.open(savedValuesFile, "r");
    if (!file)
    {
        Serial.println(F("Failed to read saved values file"));
        return false;
    }
    size_t size = file.size();
    if (size > 1024)
    {
        Serial.print(F("Stored SNMP values file too large"));
        file.close();
        return false;
    }
    StaticJsonDocument<1024> doc;
    // Deserialize the JSON document
    DeserializationError error = deserializeJson(doc, file);
    if (error)
    {
        Serial.print(F("deserializeJson() failed: "));
        Serial.println(error.f_str());
        file.close();
        return false;
    }
    // Fetch values
    strlcpy(sysContact, doc["sysContact"], sizeof(sysContactValue));
    strlcpy(sysName, doc["sysName"], sizeof(sysNameValue));
    strlcpy(sysLocation, doc["sysLocation"], sizeof(sysLocationValue));
    file.close();
    return true;
}

bool saveSNMPValues()
{

    File file = LITTLEFS.open(savedValuesFile, "w");
    if (!file)
    {
        Serial.println(F("Failed to open saved values file for writing"));
        return false;
    }
    StaticJsonDocument<1024> doc;
    // Store the values in the JSON document
    doc["sysContact"] = sysContact;
    doc["sysName"] = sysName;
    doc["sysLocation"] = sysLocation;

    // Serialize JSON to file
    if (serializeJson(doc, file) == 0)
    {
        Serial.println(F("Failed to save values to file"));
        file.close();
        return false;
    }
    file.close();
    printFile(savedValuesFile);
    return true;
}

void addRFC1213MIBHandler()
{
    // Add SNMP Handlers of correct type to each OID
    snmp.addReadOnlyStaticStringHandler(oidSysDescr, sysDescr);
    snmp.addReadOnlyStaticStringHandler(oidSysObjectID, sysObjectID);
    snmp.addIntegerHandler(oidSysServices, &sysServices);
    snmp.addTimestampHandler(oidSysUptime, &sysUptime);
    // Add Settable Handlers
    snmp.addReadWriteStringHandler(oidSysContact, &sysContact, 25, true);
    snmp.addReadWriteStringHandler(oidSysName, &sysName, 25, true);
    snmp.addReadWriteStringHandler(oidSysLocation, &sysLocation, 25, true);
}

void addENTITYMIBHandler()
{
    snmp.addIntegerHandler(oidentPhysicalIndex_1, &entPhysicalIndex_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalDescr_1, entPhysicalDescr_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalVendorType_1, entPhysicalVendorType_1);
    snmp.addIntegerHandler(oidentPhysicalContainedIn_1, &entPhysicalContainedIn_1);
    snmp.addIntegerHandler(oidentPhysicalClass_1, &entPhysicalClass_1);
    snmp.addIntegerHandler(oidentPhysicalParentRelPos_1, &entPhysicalParentRelPos_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalName_1, entPhysicalName_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalHardwareRev_1, entPhysicalHardwareRev_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalFirmwareRev_1, entPhysicalFirmwareRev_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalSoftwareRev_1, entPhysicalSoftwareRev_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalSerialNum_1, entPhysicalSerialNum_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalMfgName_1, entPhysicalMfgName_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalModelName_1, entPhysicalModelName_11);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalAlias_1, entPhysicalAlias_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalAssetID_1, entPhysicalAssetID_1);
    snmp.addIntegerHandler(oidentPhysicalIsFRU_1, &entPhysicalIsFRU_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalMfgDate_1, entPhysicalMfgDate_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhysicalUris_1, entPhysicalUris_1);
}

void addENTITYSENSORMIBHandler()
{
    entPhySensorValueUpdateRate_1 = SENSOR_UPDATE_INTERVAL;

    snmp.addIntegerHandler(oidentPhySensorType_1, &entPhySensorType_1);
    snmp.addIntegerHandler(oidentPhySensorScale_1, &entPhySensorScale_1);
    snmp.addIntegerHandler(oidentPhySensorPrecision_1, &entPhySensorPrecision_1);
    snmp.addIntegerHandler(oidentPhySensorValue_1, &entPhySensorValue_1);
    snmp.addIntegerHandler(oidentPhySensorOperStatus_1, &entPhySensorOperStatus_1);
    snmp.addReadOnlyStaticStringHandler(oidentPhySensorUnitsDisplay_1, entPhySensorUnitsDisplay_1);
    snmp.addTimestampHandler(oidentPhySensorValueTimeStamp_1, &entPhySensorValueTimeStamp_1);
    snmp.addIntegerHandler(oidentPhySensorValueUpdateRate_1, &entPhySensorValueUpdateRate_1);
}