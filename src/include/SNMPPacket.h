#ifndef SNMPPacket_h
#define SNMPPacket_h

#include "SNMPParser.h"
#include "VarBinds.h"
#include "defs.h"
#include <math.h>
#include <string>
#include <vector>

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

class SNMPPacket {
  public:
    SNMPPacket(){};

    SNMPPacket(ASN_TYPE type) : packetPDUType(type){};

    SNMPPacket(const SNMPPacket &packet) {
        this->setRequestID(packet.requestID);
        this->setVersion(packet.snmpVersion);
        this->setCommunityString(packet.communityString);

        // Provide reusable ASN containers if required
        if (packet.requestIDPtr) {
            this->requestIDPtr = packet.requestIDPtr;
        }

        if (packet.snmpVersionPtr) {
            this->snmpVersionPtr = packet.snmpVersionPtr;
        }

        if (packet.communityStringPtr) {
            this->communityStringPtr = packet.communityStringPtr;
        }
    };

    virtual ~SNMPPacket();

    static snmp_request_id_t generate_request_id();

    SNMP_PACKET_PARSE_ERROR parseFrom(uint8_t *buf, size_t max_len);

    int serialiseInto(uint8_t *buf, size_t max_len);

    //TODO: put checks in all these setters
    void setCommunityString(std::string);

    void setRequestID(snmp_request_id_t);

    void setVersion(SNMP_VERSION);

    bool reuse = false;

    std::shared_ptr<IntegerType> requestIDPtr = nullptr;
    std::shared_ptr<IntegerType> snmpVersionPtr = nullptr;
    std::shared_ptr<OctetType> communityStringPtr = nullptr;

    snmp_request_id_t requestID = INVALID_SNMP_REQUEST_ID;
    SNMP_VERSION snmpVersion = (SNMP_VERSION) 0;
    std::string communityString;

    ASN_TYPE packetPDUType;

    VarBindList varbindList;

    union ErrorStatus errorStatus = {NO_ERROR};
    union ErrorIndex errorIndex = {0};

    ComplexType *packet = nullptr;

  protected:
    virtual bool build();

    bool setPDUType(ASN_TYPE);

    virtual std::shared_ptr<ComplexType> generateVarBindList();

  private:
    SNMP_PACKET_PARSE_ERROR parsePacket(ComplexType *structure, enum SNMPParsingState state);
};


#endif