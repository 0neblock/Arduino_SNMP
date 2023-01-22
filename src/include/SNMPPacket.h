#ifndef SNMPPacket_h
#define SNMPPacket_h

#include "VarBinds.h"
#include "defs.h"
#include <vector>
#include <math.h>
#include <string>

enum SNMPParsingState {
    SNMPVERSION,
    COMMUNITY,
    PDU,
    REQUESTID,
    ERRORSTATUS,
    ERRORID,
    VARBINDS,
    VARBIND,
    DONE
};

typedef int SNMP_PACKET_PARSE_ERROR;

#define SNMP_PARSE_ERROR_MAGIC_BYTE -2 + SNMP_PACKET_PARSE_ERROR_OFFSET
#define SNMP_PARSE_ERROR_GENERIC -1 + SNMP_PACKET_PARSE_ERROR_OFFSET


union ErrorStatus {
  SNMP_ERROR_STATUS errorStatus;
  int nonRepeaters;
};

union ErrorIndex {
  int errorIndex;
  int maxRepititions;
};

class SNMPPacket {
  public:
    SNMPPacket(){};
    explicit SNMPPacket(const SNMPPacket& packet){
        this->setRequestID(packet.requestID);
        this->setVersion(packet.snmpVersion);
        this->setCommunityString(packet.communityString);

        // Provide reusable ASN containers if required
        if(packet.requestIDPtr){
            this->requestIDPtr = packet.requestIDPtr;
        }

        if(packet.snmpVersionPtr){
            this->snmpVersionPtr = packet.snmpVersionPtr;
        }

        if(packet.communityStringPtr){
            this->communityStringPtr = packet.communityStringPtr;
        }
    };

    virtual ~SNMPPacket();

    static snmp_request_id_t generate_request_id();
    
    SNMP_PACKET_PARSE_ERROR parseFrom(uint8_t* buf, size_t max_len);
    int serialiseInto(uint8_t* buf, size_t max_len);

    //TODO: put checks in all these setters
    void setCommunityString(const std::string &CommunityString);
    void setRequestID(snmp_request_id_t);
    bool setPDUType(ASN_TYPE);
    void setVersion(SNMP_VERSION);

    bool reuse = false;

    std::shared_ptr<IntegerType> requestIDPtr = nullptr;
    std::shared_ptr<IntegerType> snmpVersionPtr = nullptr;
    std::shared_ptr<OctetType> communityStringPtr = nullptr;

    snmp_request_id_t requestID = 0;
    SNMP_VERSION snmpVersion = (SNMP_VERSION)0;
    std::string communityString;

    ASN_TYPE packetPDUType;

    std::deque<VarBind> varbindList;

    union ErrorStatus errorStatus = { NO_ERROR };
    union ErrorIndex errorIndex = {0};

    ComplexType* packet = nullptr;
    
  protected:
    virtual bool build();

    virtual std::shared_ptr<ComplexType> generateVarBindList();

  private:
    SNMP_PACKET_PARSE_ERROR parsePacket(ComplexType* structure, enum SNMPParsingState state);
};


#endif