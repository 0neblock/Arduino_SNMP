#ifndef SNMPRequest_h
#define SNMPRequest_h

enum SNMPExpect {
    HEADER,
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


class SNMPRequest {
  public:
    SNMPRequest(){};
    ~SNMPRequest(){
        delete varBinds;
        delete SNMPPacket;
    };
    char* communityString;
    int version;
    ASN_TYPE requestType;
    int requestID;
    int errorStatus;
    int errorIndex;
    VarBindList* varBinds = 0;
    VarBindList* varBindsCursor = 0;
    
    ComplexType* SNMPPacket;
    bool parseFrom(char* buf);
    bool serialise(char* buf);
    enum SNMPExpect EXPECTING = SNMPVERSION;
    bool isCorrupt = false;
};

bool SNMPRequest::parseFrom(char* buf){
    SNMPPacket = new ComplexType(STRUCTURE);
    if(buf[0] != 0x30) {
        isCorrupt = true;
        return false;
    }
    SNMPPacket->fromBuffer(buf);
    // we now have a full ASN.1 packet in SNMPPacket
    ValuesList* cursor = SNMPPacket->_values;
    ValuesList* tempCursor;
    
    while(EXPECTING != DONE){
        switch(EXPECTING){
            case SNMPVERSION:
                if(cursor->value->_type == INTEGER){
                    version = ((IntegerType*)cursor->value)->_value + 1;
                    if(!cursor->next){
                        isCorrupt = true;
                        return false;
                    }
                    cursor = cursor->next;
                    EXPECTING = COMMUNITY;
                } else {
                    isCorrupt = true;
                    return false;
                }
            break;
            case COMMUNITY:
                if(cursor->value->_type == STRING){
                    communityString = ((OctetType*)cursor->value)->_value;
                    if(!cursor->next){
                        isCorrupt = true;
                        return false;
                    }
                    cursor = cursor->next;
                    EXPECTING = PDU; // temp
                } else {
                    isCorrupt = true;
                    return false;
                }
            break;
            case PDU:
                switch(cursor->value->_type){
                    case GetRequestPDU:
                    case GetNextRequestPDU:
                    case GetResponsePDU:
                    case SetRequestPDU:
                        requestType = cursor->value->_type;
                    break;
                    default:
                        isCorrupt = true;
                        return false;
                    break;
                }
                cursor = ((ComplexType*)cursor->value)->_values;
                EXPECTING = REQUESTID;
            break;
            case REQUESTID:
                if(cursor->value->_type == INTEGER){
                    requestID = ((IntegerType*)cursor->value)->_value;
                    if(!cursor->next){
                        isCorrupt = true;
                        return false;
                    }
                    cursor = cursor->next;
                    EXPECTING = ERRORSTATUS;
                } else {
                    isCorrupt = true;
                    return false;
                }
            break;
            case ERRORSTATUS:
                if(cursor->value->_type == INTEGER){
                    errorStatus = ((IntegerType*)cursor->value)->_value;
                    if(!cursor->next){
                        isCorrupt = true;
                        return false;
                    }
                    cursor = cursor->next;
                    EXPECTING = ERRORID;
                } else {
                    isCorrupt = true;
                    return false;
                }
            break;
            case ERRORID:
                if(cursor->value->_type == INTEGER){
                    errorIndex = ((IntegerType*)cursor->value)->_value;
                    if(!cursor->next){
                        isCorrupt = true;
                        return false;
                    }
                    cursor = cursor->next;
                    EXPECTING = VARBINDS;
                } else {
                    isCorrupt = true;
                    return false;
                }
            break;
            case VARBINDS: // we have a varbind structure, lets dive into it.
                if(cursor->value->_type == STRUCTURE){
                    varBinds = new VarBindList();
                    varBindsCursor = varBinds;
                    tempCursor = ((ComplexType*)cursor->value)->_values;
                    EXPECTING = VARBIND;
                } else {
                    isCorrupt = true;
                    return false;
                }
            break;
            case VARBIND:
                 // we need to keep the cursor outside the varbindlist itself so we always have access to the list
                if(tempCursor->value->_type == STRUCTURE && ((ComplexType*)tempCursor->value)->_values->value->_type == OID){
                    VarBind* varbind = new VarBind();
                    varbind->oid = ((OIDType*)((ComplexType*)tempCursor->value)->_values->value);
//                    //Serial.print("OID: ");//Serial.println(varbind->oid->_value);
                    varbind->type = ((ComplexType*)tempCursor->value)->_values->next->value->_type;
                    varbind->value = ((ComplexType*)tempCursor->value)->_values->next->value;
                    varBindsCursor->value = varbind;
                    varBindsCursor->next = new VarBindList();
                    
                    if(!tempCursor->next){
                        EXPECTING = DONE;
                    } else {
//                        tempCursor = ((ComplexType*)cursor->next->value)->_values;
                        tempCursor = tempCursor->next;
                        varBindsCursor = varBindsCursor->next;
                    }
                } else {
                    isCorrupt = true;
                    return false;
                }
            break;
        }
    }
    return true;
}

#endif