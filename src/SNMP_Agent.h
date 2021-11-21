#ifndef SNMPAgent_h
#define SNMPAgent_h

#ifdef COMPILING_TESTS

#include "tests/required/IPAddress.h"
#include "tests/required/UDP.h"
#include "tests/required/millis.h"

#else
#include <WiFiUdp.h>
#endif

#include "SNMPTrap.h"
#include "include/BER.h"
#include "include/SNMPInform.h"
#include "include/SNMPPacket.h"
#include "include/SNMPParser.h"
#include "include/SNMPResponse.h"
#include "include/ValueCallbacks.h"
#include "include/VarBinds.h"
#include "include/defs.h"

#include <deque>
#include <list>
#include <string>
#include <unordered_map>

class SNMPAgent {
  public:
    SNMPAgent() {
        SNMPAgent::agents.push_back(this);
    };

    SNMPAgent(const char *community) : _community(community) {
        SNMPAgent::agents.push_back(this);
    };

    SNMPAgent(const char *readOnlyCommunity, const char *readWriteCommunity) : _community(readWriteCommunity),
                                                                               _readOnlyCommunity(readOnlyCommunity) {
        SNMPAgent::agents.push_back(this);
    }

    void setReadOnlyCommunity(std::string community) {
        this->_readOnlyCommunity = community;
    }

    void setReadWriteCommunity(std::string community) {
        this->_community = community;
    }

    std::string _community = "public";
    std::string _readOnlyCommunity = "";

    ValueCallback *addIntegerHandler(char *oid, int *value, bool isSettable = false, bool overwritePrefix = false);

    ValueCallback *addReadWriteStringHandler(char *oid, char **value, size_t max_len = 0, bool isSettable = false,
                                             bool overwritePrefix = false);

    ValueCallback *addReadOnlyStaticStringHandler(char *oid, std::string value, bool overwritePrefix = false);

    ValueCallback *
    addOpaqueHandler(char *oid, uint8_t *value, size_t data_len, bool isSettable = false, bool overwritePrefix = false);

    ValueCallback *addTimestampHandler(char *oid, int *value, bool isSettable = false, bool overwritePrefix = false);

    ValueCallback *addOIDHandler(char *oid, std::string value, bool overwritePrefix = false);

    ValueCallback *addCounter64Handler(char *oid, uint64_t *value, bool overwritePrefix = false);

    ValueCallback *addCounter32Handler(char *oid, uint32_t *value, bool overwritePrefix = false);

    ValueCallback *addGuageHandler(char *oid, uint32_t *value, bool overwritePrefix);

    bool setUDP(UDP *udp);

    bool restartUDP();

    bool begin();

    bool begin(const char *oidPrefix);

    enum SNMP_ERROR_RESPONSE loop();

    void setUDPport(short port) {
        agentPort = port;
    }

    bool setOccurred = false;

    void resetSetOccurred() {
        setOccurred = false;
    }

    bool removeHandler(ValueCallback *callback);

    bool sortHandlers();

    snmp_request_id_t
    sendTrapTo(SNMPTrap *trap, const IPAddress &ip, bool replaceQueuedRequests = true, int retries = 0,
               int delay_ms = 30000);

    static void markTrapDeleted(SNMPTrap *trap);

    // Our snmpDevice is ip-agnostic because we can have multiple udp clients, which might have different IPs, but will have same port
    // Using default address makes sense here because we can use it if we're running a manager at the same time
    //    SNMPDevice deviceIdentifier = SNMPDevice(INADDR_NONE, 161, SNMP_VERSION_2C, "public");

  private:
    std::deque<ValueCallbackContainer> callbacks;

    ValueCallback *addHandler(ValueCallback *callback, bool isSettable);

    static bool informCallback(void *, snmp_request_id_t, bool);

    void handleInformQueue();

    std::list<UDP *> _udp;

    std::string oidPrefix;
    uint8_t _packetBuffer[MAX_SNMP_PACKET_LENGTH] = {0};

    SortableOIDType *buildOIDWithPrefix(char *oid, bool overwritePrefix);

    static std::list<SNMPAgent *> agents;
    std::list<struct InformItem *> informList;
    std::unordered_map<snmp_request_id_t, ASN_TYPE> liveRequests;

    short agentPort = 161;
};

#endif
