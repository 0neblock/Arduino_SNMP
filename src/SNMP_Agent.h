#ifndef SNMPAgent_h
#define SNMPAgent_h

#ifdef COMPILING_TESTS
	#include "tests/required/millis.h"
	#include "tests/required/IPAddress.h"
	#include "tests/required/UDP.h"
#else
	#include <Arduino.h>
	#include "IPAddress.h"
	
	#if defined(ESP8266) || defined(ESP32)
		#include <WiFiUdp.h>
	#else
		#include "Udp.h"
	#endif
#endif

#include "include/BER.h"
#include "include/VarBinds.h"
#include "include/SNMPPacket.h"
#include "SNMPTrap.h"
#include "include/SNMPResponse.h"
#include "include/ValueCallbacks.h"
#include "include/SNMPParser.h"
#include "include/defs.h"
#include "include/SNMPInform.h"

#include <list>
#include <deque>
#include <string>

class SNMPAgent {
    public:
        SNMPAgent(){
            SNMPAgent::agents.push_back(this);
        };

        SNMPAgent(const char* community): _community(community){
            SNMPAgent::agents.push_back(this);
        };

        SNMPAgent(const char* readOnlyCommunity, const char* readWriteCommunity): _community(readWriteCommunity), _readOnlyCommunity(readOnlyCommunity){
            SNMPAgent::agents.push_back(this);
        }

        void setReadOnlyCommunity(const std::string& community){
            this->_readOnlyCommunity = community;
        }

        void setReadWriteCommunity(const std::string& community){
            this->_community = community;
        }

        std::string _community = "public";
        std::string _readOnlyCommunity;
        
        ValueCallback* addIntegerHandler(const char *oid, int* value, bool isSettable = false, bool overwritePrefix = false);
        ValueCallback* addReadOnlyIntegerHandler(const char *oid, int value, bool overwritePrefix = false);
        ValueCallback* addDynamicIntegerHandler(const char *oid, GETINT_FUNC callback_func, bool overwritePrefix = false);
        ValueCallback* addReadWriteStringHandler(const char *oid, char** value, size_t max_len = 0, bool isSettable = false, bool overwritePrefix = false);
        ValueCallback* addReadOnlyStaticStringHandler(const char *oid, const std::string& value, bool overwritePrefix = false);
        ValueCallback* addDynamicReadOnlyStringHandler(const char *oid, GETSTRING_FUNC callback_func, bool overwritePrefix = false);
        ValueCallback* addOpaqueHandler(const char *oid, uint8_t* value, size_t data_len, bool isSettable = false, bool overwritePrefix = false);
        ValueCallback* addTimestampHandler(const char *oid, uint32_t* value, bool isSettable = false, bool overwritePrefix = false);
        ValueCallback* addDynamicReadOnlyTimestampHandler(const char *oid, GETUINT_FUNC callback_func, bool overwritePrefix = false);
        ValueCallback* addOIDHandler(const char *oid, const std::string& value, bool overwritePrefix = false);
        ValueCallback* addCounter64Handler(const char *oid, uint64_t* value, bool overwritePrefix = false);
        ValueCallback* addCounter32Handler(const char *oid, uint32_t* value, bool overwritePrefix = false);
        ValueCallback* addGaugeHandler(const char *oid, uint32_t* value, bool overwritePrefix = false);
        // Depreciated, use addGaugeHandler()
        __attribute__((deprecated)) ValueCallback* addGuageHandler(const char *oid, uint32_t* value, bool overwritePrefix = false) {
            return addGaugeHandler(oid, value, overwritePrefix);
        }

        void
        setUDP(UDP* udp);
        bool restartUDP();

        void
        begin();
        void
        begin(const char* oidPrefix);
        void stop();
	    enum SNMP_ERROR_RESPONSE loop();
        
        short AgentUDPport = 161;
        void setUDPport(short port){
	        AgentUDPport = port;
        }
        
        bool setOccurred = false;
        void resetSetOccurred(){
            setOccurred = false;
        }

        bool removeHandler(ValueCallback* callback);
        bool sortHandlers();

        snmp_request_id_t sendTrapTo(SNMPTrap* trap, const IPAddress& ip, bool replaceQueuedRequests = true, int retries = 0, int delay_ms = 30000);
        static void markTrapDeleted(SNMPTrap* trap);
        
    private:
        std::deque<ValueCallback*> callbacks;
        ValueCallback* addHandler(ValueCallback *callback, bool isSettable);
        
        static void informCallback(void*, snmp_request_id_t, bool);
        void handleInformQueue();

        std::list<UDP*> _udp;

        std::string oidPrefix;
        uint8_t _packetBuffer[MAX_SNMP_PACKET_LENGTH] = {0};

        SortableOIDType* buildOIDWithPrefix(const char *oid, bool overwritePrefix);

        static std::list<SNMPAgent*> agents;
        std::list<struct InformItem*> informList;
};

#endif
