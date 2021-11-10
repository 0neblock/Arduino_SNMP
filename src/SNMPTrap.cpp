#include "SNMPTrap.h"
#include "include/SNMPParser.h"

SNMPTrap::~SNMPTrap(){
    delete timestampOID;
    delete snmpTrapOID;
    delete packet;
}

bool SNMPTrap::build(){
    // Building V1 Traps
    delete packet;

    if(!this->trapOID) return false;

    packet = new ComplexType(STRUCTURE);

    packet->addValueToList(std::make_shared<IntegerType>((int)this->snmpVersion));
    packet->addValueToList(std::make_shared<OctetType>(this->communityString.c_str()));
    auto trapPDU = std::make_shared<ComplexType>(TrapPDU);
    
    trapPDU->addValueToList(trapOID->cloneOID());
    trapPDU->addValueToList(std::make_shared<NetworkAddress>(agentIP));
    trapPDU->addValueToList(std::make_shared<IntegerType>(genericTrap));
    trapPDU->addValueToList(std::make_shared<IntegerType>(specificTrap));
    
    if(uptimeCallback){
        trapPDU->addValueToList(std::static_pointer_cast<TimestampType>(ValueCallback::getValueForCallback(uptimeCallback)));
    } else {
        trapPDU->addValueToList(std::make_shared<TimestampType>(0));
    }

    auto ourVBList = this->generateVarBindList();
    if(!ourVBList) return false;
    
    trapPDU->addValueToList(ourVBList);
    packet->addValueToList(trapPDU);
    return true;
}

std::shared_ptr<ComplexType> SNMPTrap::generateVarBindList(){
    SNMP_LOGD("generateVarBindList from SNMPTrap");
    auto ourVBList = std::make_shared<ComplexType>(STRUCTURE);
    // If we're an SNMPv2 Trap, our first two are timestamp and OIDType, v1 already has them included
    if(this->snmpVersion == SNMP_VERSION_2C){
        if(!this->trapOID){
            return nullptr;
        }
        // Timestamp
        auto timestampVarBind = std::make_shared<ComplexType>(STRUCTURE);
        timestampVarBind->addValueToList(timestampOID->cloneOID());

        if(uptimeCallback){
            timestampVarBind->addValueToList(std::static_pointer_cast<TimestampType>(ValueCallback::getValueForCallback(uptimeCallback)));
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

    for(auto value : this->callbacks){
        if(!value) continue;
        auto varBind = std::make_shared<ComplexType>(STRUCTURE);

        varBind->addValueToList(value->OID->cloneOID());
        varBind->addValueToList(ValueCallback::getValueForCallback(value));

        ourVBList->addValueToList(varBind);
    }

    return ourVBList;
}

void SNMPTrap::addOIDPointer(ValueCallback* callback){
    this->callbacks.push_back(callback);
}
