// we're going to have a trap object, which is created in setup. it includes the main trapOID, other trap-ish options, and an attached list of the OIDCallback objects (the ones you get back from addIntegerHandler etc) to contain the values that need to be ent with this Trap.
// it ca then be called from code, trap->send of fuckin whatever. trap receivers should also be attached to a list that can be changed

#ifndef SNMPTrap_h
#define SNMPTrap_h

class SNMPTrap {
  public:
    SNMPTrap(const char* community, short version): _community(community), _version(version){
        if(version == 0){
            version1 = true;
        }
        if(version == 1){
            version2 = true;
        }
    };
    short _version;
    const char* _community;
    IPAddress agentIP;
    OIDType* trapOID;
    TimestampCallback* uptimeCallback;
    short genericTrap = 6;
    short specificTrap;
    
    // the setters that need to be configured for each trap.
    
    void setTrapOID(OIDType* oid){
        trapOID = oid;
    }
    
    void setSpecificTrap(short num){
        specificTrap = num;
    }
    void setIP(IPAddress ip){ // sets our IP
        agentIP = ip;
    }
    
    void setUDP(UDP* udp){
        _udp = udp;
    }
    
    void setUptimeCallback(TimestampCallback* uptime){
        uptimeCallback = uptime;
    }
    
    void addOIDPointer(ValueCallback* callback);
    
    
    ValueCallbacks* callbacks = new ValueCallbacks();
    ValueCallbacks* callbacksCursor = callbacks;
    
    
    UDP* _udp = 0;
    bool sendTo(IPAddress ip){
        if(!_udp){
            return false;
        }
        if(!build()){
            Serial.println("Failed Building packet..");
            delete packet;
            packet = 0;
            return false;
        }
        unsigned char _packetBuffer[SNMP_PACKET_LENGTH*3];
        memset(_packetBuffer, 0, SNMP_PACKET_LENGTH*3);
        int length = packet->serialise(_packetBuffer);
        delete packet;
        packet = 0;
        _udp->beginPacket(ip, 162);
        _udp->write(_packetBuffer, length);
        return _udp->endPacket();
    }
    
    ComplexType* packet = 0;
    bool build();
    
    bool version1 = false;
    bool version2 = false;
    
    void clearOIDList(){ // this just removes the list, does not kill the values in the list
        callbacksCursor = callbacks;
        delete callbacksCursor;
        callbacks = new ValueCallbacks();
        callbacksCursor = callbacks;
    }
};

bool SNMPTrap::build(){
    if(packet) delete packet;
    packet = new ComplexType(STRUCTURE);
    packet->addValueToList(new IntegerType((int)_version));
    packet->addValueToList(new OctetType((char*)_community));
    ComplexType* trapPDU;
    if(version1){
        trapPDU = new ComplexType(TrapPDU);
    } else if(version2){
        trapPDU = new ComplexType(Trapv2PDU);
    } else {
        return false;
    }
    
    trapPDU->addValueToList(new OIDType(trapOID->_value));
    trapPDU->addValueToList(new NetworkAddress(agentIP));
    trapPDU->addValueToList(new IntegerType(genericTrap));
    trapPDU->addValueToList(new IntegerType(specificTrap));
    trapPDU->addValueToList(new TimestampType(*(uptimeCallback->value)));
    ComplexType* varBindList = new ComplexType(STRUCTURE);
    
    callbacksCursor = callbacks;
    if(callbacksCursor->value){
        while(true){
            ComplexType* varBind = new ComplexType(STRUCTURE);
            varBind->addValueToList(new OIDType(callbacksCursor->value->OID));
            BER_CONTAINER* value;
            switch(callbacksCursor->value->type){
                case INTEGER:
                    {
                        value = new IntegerType(*((IntegerCallback*)callbacksCursor->value)->value);
                    }
                break;
                case TIMESTAMP:
                    {
                        value = new TimestampType(*((TimestampCallback*)callbacksCursor->value)->value);
                    }
                break;
                case STRING:
                    {
                        value = new OctetType(*((StringCallback*)callbacksCursor->value)->value);
                    }
                break;
            }
            varBind->addValueToList(value);
            varBindList->addValueToList(varBind);
            
            if(callbacksCursor->next){
                callbacksCursor = callbacksCursor->next;
            } else {
                break;
            }
        }
    }
    
    trapPDU->addValueToList(varBindList);
    packet->addValueToList(trapPDU);
    return true;
}

void SNMPTrap::addOIDPointer(ValueCallback* callback){
    callbacksCursor = callbacks;
    if(callbacksCursor->value){
        while(callbacksCursor->next != 0){
            callbacksCursor = callbacksCursor->next;
        }
        callbacksCursor->next = new ValueCallbacks();
        callbacksCursor = callbacksCursor->next;
        callbacksCursor->value = callback;
        callbacksCursor->next = 0;
    } else 
        callbacks->value = callback;
}



#endif