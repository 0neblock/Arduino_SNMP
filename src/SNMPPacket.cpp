#include "include/SNMPPacket.h"

#define SNMP_PARSE_ERROR_AT_STATE(STATE) ((int)STATE * -1) - 10 + SNMP_PACKET_PARSE_ERROR_OFFSET

#define ASN_TYPE_FOR_STATE_SNMPVERSION  INTEGER
#define ASN_TYPE_FOR_STATE_COMMUNITY    STRING
#define ASN_TYPE_FOR_STATE_REQUESTID    INTEGER
#define ASN_TYPE_FOR_STATE_ERRORSTATUS  INTEGER
#define ASN_TYPE_FOR_STATE_ERRORID      INTEGER
#define ASN_TYPE_FOR_STATE_VARBINDS     STRUCTURE
#define ASN_TYPE_FOR_STATE_VARBIND      STRUCTURE

#define STR_IMPL_(x) #x      //stringify argument
#define STR(x) STR_IMPL_(x)  //indirection to expand argument macros

#define ASSERT_ASN_TYPE_AT_STATE(value, TYPE, STATE) \
    if(!value || value->_type != TYPE) { \
        SNMP_LOGW("Expecting value to be " STR(TYPE) " for " #STATE); \
        return SNMP_PARSE_ERROR_GENERIC; \
    }

#define ASSERT_ASN_STATE_TYPE(value, STATE) \
    if(!value || value->_type != ASN_TYPE_FOR_STATE_##STATE) { \
        SNMP_LOGW("Expecting " STR(ASN_TYPE_FOR_STATE_##STATE) " for " #STATE " failed: %d\n", value->_type); \
        return SNMP_PARSE_ERROR_AT_STATE(STATE); \
    }

#define ASSERT_ASN_PARSING_TYPE_RANGE(value, LOW_TYPE, HIGH_TYPE) \
    if(!value || !(value->_type >= LOW_TYPE && value->_type <= HIGH_TYPE)){ \
        SNMP_LOGW("Expecting vartype for PDU failed: %d\n", value->_type); \
        return SNMP_PARSE_ERROR_GENERIC; \
    }

SNMPPacket::~SNMPPacket(){
    delete this->packet;
}

SNMP_PACKET_PARSE_ERROR SNMPPacket::parsePacket(ComplexType *structure, enum SNMPParsingState state) {
    for(const auto& value : structure->values){
        if(state == DONE) break;

        switch(state) {

            case SNMPVERSION:
                ASSERT_ASN_STATE_TYPE(value, SNMPVERSION);
                this->snmpVersionPtr = std::static_pointer_cast<IntegerType>(value);
                this->snmpVersion = (SNMP_VERSION) this->snmpVersionPtr.get()->_value;
                if (this->snmpVersion >= SNMP_VERSION_MAX) {
                    SNMP_LOGW("Invalid SNMP Version: %d\n", this->snmpVersion);
                    return SNMP_PARSE_ERROR_AT_STATE(SNMPVERSION);
                };
                state = COMMUNITY;
            break;

            case COMMUNITY:
                ASSERT_ASN_STATE_TYPE(value, COMMUNITY);
                this->communityStringPtr = std::static_pointer_cast<OctetType>(value);
                this->communityString = this->communityStringPtr.get()->_value;
                state = PDU;
            break;

            case PDU:
                ASSERT_ASN_PARSING_TYPE_RANGE(value, ASN_PDU_TYPE_MIN_VALUE, ASN_PDU_TYPE_MAX_VALUE)
                this->packetPDUType = value->_type;
                return this->parsePacket(static_cast<ComplexType*>(value.get()), REQUESTID);

            case REQUESTID:
                ASSERT_ASN_STATE_TYPE(value, REQUESTID);
                this->requestIDPtr = std::static_pointer_cast<IntegerType>(value);
                this->requestID = this->requestIDPtr.get()->_value;
                state = ERRORSTATUS;
            break;

            case ERRORSTATUS:
                ASSERT_ASN_STATE_TYPE(value, ERRORSTATUS);
                this->errorStatus.errorStatus = (SNMP_ERROR_STATUS) static_cast<IntegerType *>(value.get())->_value;
                state = ERRORID;
            break;

            case ERRORID:
                ASSERT_ASN_STATE_TYPE(value, ERRORID);
                this->errorIndex.errorIndex = static_cast<IntegerType*>(value.get())->_value;
                state = VARBINDS;
            break;

            case VARBINDS:
                ASSERT_ASN_STATE_TYPE(value, VARBINDS);
                // we have a varbind structure, lets dive into it.
                return this->parsePacket(static_cast<ComplexType*>(value.get()), VARBIND);

            case VARBIND:
            {
                ASSERT_ASN_STATE_TYPE(value, VARBIND);
                // we are in a single varbind

                auto varbindValues = std::static_pointer_cast<ComplexType>(value);

                if (varbindValues->values.size() != 2) {
                    SNMP_LOGW("Expecting VARBIND TO CONTAIN 2 OBEJCTS; %lu\n",
                              varbindValues ? varbindValues->values.size() : 0);
                    return SNMP_PARSE_ERROR_AT_STATE(VARBIND);
                };

                auto vbOid = varbindValues->values[0];
                ASSERT_ASN_TYPE_AT_STATE(vbOid, OID, VARBIND);

                auto vbValue = varbindValues->values[1];
                this->varbindList.emplace_back(
                    std::static_pointer_cast<OIDType>(vbOid),
                    vbValue
                );
            }
            break;

            case DONE:
                return true;
        }
    }
    return SNMP_ERROR_OK;
}

SNMP_PACKET_PARSE_ERROR SNMPPacket::parseFrom(unsigned char* buf, size_t max_len){
    SNMP_LOGD("Parsing %ld bytes\n", max_len);
    if(buf[0] != 0x30) {
        SNMP_LOGD("First byte error\n");
        return SNMP_PARSE_ERROR_MAGIC_BYTE;
    }

    packet = new ComplexType(STRUCTURE);

    SNMP_BUFFER_PARSE_ERROR decodePacket = packet->fromBuffer(buf, max_len);
    if(decodePacket <= 0){
        SNMP_LOGD("failed to fromBuffer\n");
        return decodePacket;
    }

    // we now have a full ASN.1 packet in SNMPPacket
    return parsePacket(packet, SNMPVERSION);
}

int SNMPPacket::serialiseInto(uint8_t* buf, size_t max_len){
    if(this->build()){
        return this->packet->serialise(buf, max_len);
    }
    return 0;
}

bool SNMPPacket::build(){
    // Delete the existing packet if we've built it before (generally only traps)
    delete this->packet;

    this->packet = new ComplexType(STRUCTURE);
    // Try to reuse existing containers if we got em
    if(this->snmpVersionPtr)
        this->packet->addValueToList(this->snmpVersionPtr);
    else
        this->packet->addValueToList(std::make_shared<IntegerType>(this->snmpVersion));

    if(this->communityStringPtr)
        this->packet->addValueToList(this->communityStringPtr);
    else
        this->packet->addValueToList(std::make_shared<OctetType>(this->communityString.c_str()));

    auto snmpPDU = std::make_shared<ComplexType>(this->packetPDUType);

    if(this->requestIDPtr)
        snmpPDU->addValueToList(this->requestIDPtr);
    else
        snmpPDU->addValueToList(std::make_shared<IntegerType>(this->requestID));


    snmpPDU->addValueToList(std::make_shared<IntegerType>(this->errorStatus.errorStatus));
    snmpPDU->addValueToList(std::make_shared<IntegerType>(this->errorIndex.errorIndex));

    // We need to do this dynamically incase we're building a trap, generateVarBindList is virtual
    auto varBindList = this->generateVarBindList();
    if(!varBindList) return false;
    
    snmpPDU->addValueToList(varBindList);

    this->packet->addValueToList(snmpPDU);

    return true;
}

void SNMPPacket::setCommunityString(const std::string &CommunityString){
    // poison any cached containers we have
    this->communityStringPtr = nullptr;
    this->communityString = CommunityString;
}

void SNMPPacket::setRequestID(snmp_request_id_t RequestId){
    this->requestIDPtr = nullptr;
    this->requestID = RequestId;
}

bool SNMPPacket::setPDUType(ASN_TYPE responseType){
    if(responseType >= ASN_PDU_TYPE_MIN_VALUE && responseType <= ASN_PDU_TYPE_MAX_VALUE){
        //TODO: check that we're a valid response type
        this->packetPDUType = responseType;
        return true;
    }
    return false;
}

void SNMPPacket::setVersion(SNMP_VERSION SnmpVersion){
    this->snmpVersionPtr = nullptr;
    this->snmpVersion = SnmpVersion;
}

std::shared_ptr<ComplexType> SNMPPacket::generateVarBindList(){
    SNMP_LOGD("generateVarBindList from SNMPPacket");
    // This is for normal packets where our response values have already been built, not traps
    auto varBindList = std::make_shared<ComplexType>(STRUCTURE);

    for(const auto& varBindItem : varbindList){
        auto varBind = std::make_shared<ComplexType>(STRUCTURE);

        varBind->addValueToList(varBindItem.oid);
        varBind->addValueToList(varBindItem.value);

        varBindList->addValueToList(varBind);
    }

    return varBindList;
}

snmp_request_id_t SNMPPacket::generate_request_id(){
    //NOTE: do not generate 0
    snmp_request_id_t request_id = 0;
    while(request_id == 0){
        request_id |= rand();
        request_id <<= 8;
        request_id |= rand();
    }
    return request_id;
}
