#include "SNMPTrap.h"
#include "include/SNMPParser.h"

SNMPTrap::~SNMPTrap() {
    delete timestampOID;
    delete snmpTrapOID;
    delete packet;
}

bool SNMPTrap::build() {
    // Building V1 Traps
    delete packet;

    if (!this->trapOID) return false;

    packet = new ComplexType(STRUCTURE);

    packet->addValueToList(std::make_shared<IntegerType>((int) this->snmpVersion));
    packet->addValueToList(std::make_shared<OctetType>(this->communityString.c_str()));
    auto trapPDU = std::make_shared<ComplexType>(TrapPDU);

    trapPDU->addValueToList(trapOID->cloneOID());
    trapPDU->addValueToList(std::make_shared<NetworkAddress>(agentIP));
    trapPDU->addValueToList(std::make_shared<IntegerType>(genericTrap));
    trapPDU->addValueToList(std::make_shared<IntegerType>(specificTrap));

    if (uptimeCallback) {
        trapPDU->addValueToList(std::static_pointer_cast<TimestampType>(uptimeCallback->buildTypeWithValue()));
    } else {
        trapPDU->addValueToList(std::make_shared<TimestampType>(0));
    }

    auto ourVBList = this->generateVarBindList();
    if (!ourVBList) return false;

    trapPDU->addValueToList(ourVBList);
    packet->addValueToList(trapPDU);
    return true;
}

std::shared_ptr<ComplexType> SNMPTrap::generateVarBindList() {
    //    SNMP_LOGD("generateVarBindList from SNMPTrap");
    auto ourVBList = std::make_shared<ComplexType>(STRUCTURE);
    // If we're an SNMPv2 Trap, our first two are timestamp and OIDType, v1 already has them included
    if (this->snmpVersion == SNMP_VERSION_2C) {
        if (!this->trapOID) {
            return nullptr;
        }
        // Timestamp
        auto timestampVarBind = std::make_shared<ComplexType>(STRUCTURE);
        timestampVarBind->addValueToList(timestampOID->cloneOID());

        if (uptimeCallback) {
            timestampVarBind->addValueToList(
                    std::static_pointer_cast<TimestampType>(uptimeCallback->buildTypeWithValue()));
        } else {
            timestampVarBind->addValueToList(std::make_shared<TimestampType>(0));
        }
        ourVBList->addValueToList(timestampVarBind);

        // OID
        auto oidVarBind = std::make_shared<ComplexType>(STRUCTURE);
        oidVarBind->addValueToList(snmpTrapOID->cloneOID());
        oidVarBind->addValueToList(trapOID->cloneOID());
        ourVBList->addValueToList(oidVarBind);
    }

    for (auto value : this->callbacks) {
        if (!value) continue;
        auto varBind = std::make_shared<ComplexType>(STRUCTURE);

        varBind->addValueToList(value->OID->cloneOID());
        varBind->addValueToList(value->buildTypeWithValue());

        ourVBList->addValueToList(varBind);
    }

    return ourVBList;
}

void SNMPTrap::addOIDPointer(ValueCallback *callback) {
    this->callbacks.push_back(callback);
}

bool SNMPTrap::setInform(bool inf) {
    this->inform = inf;
    ASN_TYPE pduType = this->packetPDUType;
    switch (this->snmpVersion) {
        case SNMP_VERSION_1:
            pduType = TrapPDU;
            break;
        case SNMP_VERSION_2C:
            pduType = this->inform ? InformRequestPDU : Trapv2PDU;
            break;
        default:
            break;
    }
    this->setPDUType(pduType);
    return true;
}

bool SNMPTrap::buildForSending() {
    // This is the start of a fresh send, we're going to reset our requestID, and build the packet
    this->setRequestID(SNMPPacket::generate_request_id());

    // Flow for v2Trap/v2Inform is SNMPPacket::build()  -> SNMPTrap::generateVarBindList() -> v2 logic
    // flow for v1Trap is          SNMPTrap::build()    -> SNMPTrap::generateVarBindList() -> v1 logic

    if (this->snmpVersion == SNMP_VERSION_1) {
        // Version 1 needs a special structure, so we overwrite the building part
        return this->build();
    } else {
        // Version 2 will use regular packet building but call back our generateVarBindList, so we can still use callbacks
        return SNMPPacket::build();
    }
}

bool SNMPTrap::sendTo(const IPAddress &ip, bool skipBuild) {
    bool buildStatus = true;
    if (!skipBuild) {
        buildStatus = this->buildForSending();
    }

    if (!_udp) {
        return false;
    }

    if (!this->packet) {
        return false;
    }

    if (!buildStatus) {
        SNMP_LOGW("Failed Building packet..");
        return false;
    }

    uint8_t _packetBuffer[MAX_SNMP_PACKET_LENGTH] = {0};
    int length = packet->serialise(_packetBuffer, MAX_SNMP_PACKET_LENGTH);

    if (length <= 0) return false;

    _udp->beginPacket(ip, trapUdpPort);
    _udp->write(_packetBuffer, length);
    return _udp->endPacket();
}
