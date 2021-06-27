#ifndef SNMPAgent_h
#define SNMPAgent_h

#ifndef UDP_TX_PACKET_MAX_SIZE
    #define UDP_TX_PACKET_MAX_SIZE 484
#endif

#ifndef SNMP_PACKET_LENGTH
    #define SNMP_PACKET_LENGTH 484
#endif

#define MIN(X, Y) ((X < Y) ? X : Y)

#include <Udp.h>

#include "BER.h"
#include "VarBinds.h"
#include "SNMPRequest.h"
#include "SNMPResponse.h"

class ValueCallback {
  public:
    ValueCallback(ASN_TYPE atype): type(atype){};
    char* OID;
    ASN_TYPE type;
    bool isSettable = false;
    bool overwritePrefix = false;
};

class IntegerCallback: public ValueCallback {
  public:
    IntegerCallback(): ValueCallback(INTEGER){};
    int* value;
    bool isFloat = false;
};

class TimestampCallback: public ValueCallback {
  public:
    TimestampCallback(): ValueCallback(TIMESTAMP){};
    int* value;
};

class StringCallback: public ValueCallback {
  public:
    StringCallback(): ValueCallback(STRING){};
    char** value;
};

class OIDCallback: public ValueCallback {
  public:
    OIDCallback(): ValueCallback(ASN_TYPE::OID){};
    char* value;
};

class Counter32Callback: public ValueCallback {
  public:
    Counter32Callback(): ValueCallback(ASN_TYPE::COUNTER32){};
    uint32_t* value;
};

class Guage32Callback: public ValueCallback {
  public:
    Guage32Callback(): ValueCallback(ASN_TYPE::GUAGE32){};
    uint32_t* value;
};

class Counter64Callback: public ValueCallback {
  public:
    Counter64Callback(): ValueCallback(ASN_TYPE::COUNTER64){};
    uint64_t* value;
};

typedef struct ValueCallbackList {
    ~ValueCallbackList(){
        delete next;
    }
    ValueCallback* value;
    struct ValueCallbackList* next = 0;
} ValueCallbacks;

typedef struct RFC1213SystemStruct { // TODO: complete this
    char* sysDescr;
    char* sysObjectID;
    char* sysContact;
} RFC1213_list;

typedef enum {
     SNMP_PERM_NONE,
     SNMP_PERM_READ_ONLY,
     SNMP_PERM_READ_WRITE
} SNMP_PERMISSION;

#include "SNMPTrap.h"

class SNMPAgent {
    public:
        SNMPAgent(){};
        SNMPAgent(const char* community): _community(community){};

        void setRWCommunity(const char* readWrite){       // read/write
            this->_community = readWrite;
        }

        void setROCommunity(const char* readOnly){       // read/write
            this->_readOnlyCommunity = readOnly;
        }

        void setCommunity(const char* readOnly, const char* readWrite){    // readOPnly, read/write
            this->_community = readWrite;
            this->_readOnlyCommunity = readOnly;
        }
        const char* _community;
        const char* _readOnlyCommunity = 0;


        ValueCallbacks* callbacks = new ValueCallbacks();
        ValueCallbacks* callbacksCursor = callbacks;
//        bool addHandler(char* OID, SNMPOIDResponse (*callback)(SNMPOIDResponse* response, char* oid));
        ValueCallback* findCallback(char* oid, bool next);
        ValueCallback* addFloatHandler(char* oid, float* value, bool isSettable = false, bool overwritePrefix = false); // this obv just adds integer but with the *0.1 set
        ValueCallback* addStringHandler(char*, char**, bool isSettable = false, bool overwritePrefix = false); // passing in a pointer to a char* 
        ValueCallback* addIntegerHandler(char* oid, int* value, bool isSettable = false, bool overwritePrefix = false);
        ValueCallback* addTimestampHandler(char* oid, int* value, bool isSettable = false, bool overwritePrefix = false);
        ValueCallback* addOIDHandler(char* oid, char* value, bool overwritePrefix = false);
        ValueCallback* addCounter64Handler(char* oid, uint64_t* value, bool overwritePrefix = false);
        ValueCallback* addCounter32Handler(char* oid, uint32_t* value, bool overwritePrefix = false);
        ValueCallback* addGuageHandler(char* oid, uint32_t* value, bool overwritePrefix);

        bool setUDP(UDP* udp);
        bool begin();
        bool begin(char*);
        bool loop();
        char oidPrefix[40];
        char OIDBuf[50];
        bool setOccurred = false;
        void resetSetOccurred(){
            setOccurred = false;
        }
        UDP* _udp;
        bool removeHandler(ValueCallback* callback);
        void addHandler(ValueCallback* callback);
        bool sortHandlers();
        
        void swap(ValueCallbacks*, ValueCallbacks*);

        void enableRFC1213(){ // automatically enables and adds RFC1213 "System" variables. provide a 

        }
    private:
        bool sort_oid(char*, char*);
        unsigned char _packetBuffer[SNMP_PACKET_LENGTH*3];
        bool inline receivePacket(int length);
        SNMPOIDResponse* generateErrorResponse(ERROR_STATUS error, char* oid){
            SNMPOIDResponse* errorResponse = new SNMPOIDResponse();
            errorResponse->oid = new OIDType(oid);
            errorResponse->errorStatus = error;
            errorResponse->value = new NullType();
            errorResponse->type = NULLTYPE;
            return errorResponse;
        }
};

bool SNMPAgent::setUDP(UDP* udp){
    if(_udp){
        _udp->stop();
    }
    _udp = udp;
    this->begin();
}

bool SNMPAgent::begin(){
    if(!_udp) return false;
    _udp->begin(161);
}

bool SNMPAgent::begin(char* prefix){
    strncpy(oidPrefix, prefix, 40);
    return this->begin();
}

bool SNMPAgent::loop(){
    if(!_udp){
        return false;
    }
    receivePacket(_udp->parsePacket());
}

bool inline SNMPAgent::receivePacket(int packetLength){
    if(!packetLength) return false;
//    Serial.print("Received from: ");Serial.print(packetLength);Serial.print(" ");Serial.println(_udp->remoteIP());
   if(packetLength < 0 || packetLength > SNMP_PACKET_LENGTH){
       Serial.println("dropping packet");
       return false;
   }
    memset(_packetBuffer, 0, SNMP_PACKET_LENGTH*3);
    int len = packetLength;
//    int len = _udp->read(_packetBuffer, SNMP_PACKET_LENGTH);
    _udp->read(_packetBuffer, MIN(len, SNMP_PACKET_LENGTH));
//     for(int i = 0; i < len; i++){
//         _packetBuffer[i] = _udp->read();
// //        Serial.print(_packetBuffer[i], HEX);
// //        Serial.print(" ");
//     }
    // Serial.println(len);
    _udp->flush();
    _packetBuffer[len] = 0;
//    Serial.println(_packetBuffer);
    SNMPRequest* snmprequest = new SNMPRequest();
    if(snmprequest->parseFrom(_packetBuffer)){
        
        // check version and community

        SNMP_PERMISSION requestPermission = SNMP_PERM_NONE;


        if(_readOnlyCommunity != 0 && strcmp(_readOnlyCommunity, snmprequest->communityString) == 0) { // snmprequest->version != 1
            requestPermission = SNMP_PERM_READ_ONLY;
        }

        if(strcmp(_community, snmprequest->communityString) == 0) { // snmprequest->version != 1
            requestPermission = SNMP_PERM_READ_WRITE;
        }

        if(requestPermission == SNMP_PERM_NONE){
            Serial.println(F("Invalid permissions"));
            delete snmprequest;
            return false;
        }
        
        SNMPResponse* response = new SNMPResponse();
        response->requestID = snmprequest->requestID;
        response->version = snmprequest->version - 1;
        strncpy(response->communityString, snmprequest->communityString, 15);
        int varBindIndex = 1;
        snmprequest->varBindsCursor = snmprequest->varBinds;
        while(true){
            //Serial.print("OID: ");//Serial.println(snmprequest->varBindsCursor->value->oid->_value);
            
            // Deal with OID request here:
            bool walk = false;
            if(snmprequest->requestType == GetNextRequestPDU){
                walk = true;
            }
            ValueCallback* callback = findCallback(snmprequest->varBindsCursor->value->oid->_value, walk);
            if(callback){ // this is where we deal with the response varbind
                SNMPOIDResponse* OIDResponse = new SNMPOIDResponse();
                OIDResponse->errorStatus = (ERROR_STATUS)0;
                
                memset(OIDBuf, 0, 50);
                if(!callback->overwritePrefix){
                    strcat(OIDBuf, oidPrefix);
                }
                
                strcat(OIDBuf, callback->OID);
                
                OIDResponse->oid = new OIDType(OIDBuf);
                OIDResponse->type = callback->type;
                
                // TODO: this whole thing needs better flow: proper checking for errors etc.
                
                if(snmprequest->requestType == SetRequestPDU){
                    // settable data..
                    if(callback->isSettable){
                        if(requestPermission == SNMP_PERM_READ_ONLY){ // community is readOnly
                            Serial.println(F("READONLY COMMUNITY USED")); 
                            SNMPOIDResponse* errorResponse = generateErrorResponse(NO_ACCESS, snmprequest->varBindsCursor->value->oid->_value);
                            response->addErrorResponse(errorResponse, varBindIndex);
                        } else {
                            if(callback->type != snmprequest->varBindsCursor->value->type){
                                // wrong data type to set..
                                // BAD_VALUE
                                Serial.println(F("VALUE-TYPE DOES NOT MATCH")); 
                                SNMPOIDResponse* errorResponse = generateErrorResponse(BAD_VALUE, snmprequest->varBindsCursor->value->oid->_value);
                                response->addErrorResponse(errorResponse, varBindIndex);
                            } else {
                                // actually set it
                                switch(callback->type){
                                    case STRING:
                                        {
                                            memcpy(*((StringCallback*)callback)->value, String(((OctetType*)snmprequest->varBindsCursor->value->value)->_value).c_str(), 32);// FIXME: this is VERY dangerous, i'm assuming the length of the source char*, this needs to change. for some reason strncpy didnd't work, need to look into this. the '25' also needs to be defined somewhere so this won't break;
                                            *(*((StringCallback*)callback)->value + 31) = 0x0; // close off the dest string, temporary
                                            OctetType* value = new OctetType(*((StringCallback*)callback)->value);
                                            OIDResponse->value = value;
                                            setOccurred = true;
                                        }
                                    break;
                                    case INTEGER:
                                        {
                                            IntegerType* value = new IntegerType();
                                            if(!((IntegerCallback*)callback)->isFloat){
                                                *(((IntegerCallback*)callback)->value) = ((IntegerType*)snmprequest->varBindsCursor->value->value)->_value;
                                                value->_value = *(((IntegerCallback*)callback)->value);
                                            } else {
                                                *(((IntegerCallback*)callback)->value) = (float)(((IntegerType*)snmprequest->varBindsCursor->value->value)->_value / 10);
                                                value->_value = *(float*)(((IntegerCallback*)callback)->value) * 10;
                                            }
                                            OIDResponse->value = value;
                                            setOccurred = true;
                                        }
                                    break;
                                }
                                response->addResponse(OIDResponse);
                            }
                        }
                    } else {
                        // not settable, send error
                        Serial.println(F("OID NOT SETTABLE")); 
                        SNMPOIDResponse* errorResponse = generateErrorResponse(READ_ONLY, snmprequest->varBindsCursor->value->oid->_value);
                        response->addErrorResponse(errorResponse, varBindIndex);
                    }
                } else if(snmprequest->requestType == GetRequestPDU || snmprequest->requestType == GetNextRequestPDU){
                
                    if(callback->type == INTEGER){
                        IntegerType* value = new IntegerType();
                        if(!((IntegerCallback*)callback)->isFloat){
                            value->_value = *(((IntegerCallback*)callback)->value);
                        } else {
                            value->_value = *(float*)(((IntegerCallback*)callback)->value) * 10;
                        }
                        OIDResponse->value = value;
                    } else if(callback->type == STRING){
                        OctetType* value = new OctetType(*((StringCallback*)callback)->value);
                        OIDResponse->value = value;
                    } else if(callback->type == TIMESTAMP){
                        TimestampType* value = new TimestampType(*(((TimestampCallback*)callback)->value));
                        OIDResponse->value = value;
                    } else if(callback->type == OID){
                        OIDType* value = new OIDType((((OIDCallback*)callback)->value));
                        OIDResponse->value = value;
                    } else if(callback->type == COUNTER64){
                        Counter64* value = new Counter64(*((Counter64Callback*)callback)->value);
                        OIDResponse->value = value;
                    } else if(callback->type == COUNTER32){
                        Counter32* value = new Counter32(*((Counter32Callback*)callback)->value);
                        OIDResponse->value = value;
                    } else if(callback->type == GUAGE32){
                        Guage* value = new Guage(*((Guage32Callback*)callback)->value);
                        OIDResponse->value = value;
                    }
                    response->addResponse(OIDResponse);
                }
            } else {
                // inject a NoSuchObject error
                Serial.println(F("OID NOT FOUND")); 
                SNMPOIDResponse* errorResponse = generateErrorResponse(NO_SUCH_NAME, snmprequest->varBindsCursor->value->oid->_value);
                response->addErrorResponse(errorResponse, varBindIndex);
               
            }
            // -------------------------
            
            snmprequest->varBindsCursor = snmprequest->varBindsCursor->next;
            if(!snmprequest->varBindsCursor->value){
                break;
            }
            varBindIndex++;
        }
//        Serial.println("Sending UDP");
        memset(_packetBuffer, 0, SNMP_PACKET_LENGTH*3);
        int length = response->serialise(_packetBuffer);
        if(length <= SNMP_PACKET_LENGTH*2){
            _udp->beginPacket(_udp->remoteIP(), _udp->remotePort());
            _udp->write(_packetBuffer, length);
            if(!_udp->endPacket()){
                Serial.println(F("COULDN'T SEND PACKET"));
                for(int i = 0;  i < length; i++){
                    Serial.print(_packetBuffer[i], HEX);
                }
                Serial.print(F("Length: "));Serial.println(length);
                Serial.print(F("Length of incoming: "));Serial.println(len);
            }
        } else {
            Serial.println("dropping packet");
        }
        
        delete response;
    } else {
        Serial.println(F("CORRUPT PACKET"));
        VarBindList* tempList = snmprequest->varBinds;
        if(tempList){
            while(tempList->next){
                delete tempList->value->oid;
                delete tempList->value->value;
                tempList = tempList->next;
            }
            delete tempList->value->oid;
            delete tempList->value->value;
        }
    }
    delete snmprequest;

//    //Serial.printf("Current heap size: %u\n", ESP.getFreeHeap());
}

ValueCallback* SNMPAgent::findCallback(char* oid, bool next){
    bool useNext = false;
    callbacksCursor = callbacks;
    
    if(callbacksCursor->value){
        while(true){
            if(!useNext){
                memset(OIDBuf, 0, 50);
                if(!callbacksCursor->value->overwritePrefix){
                    strcat(OIDBuf, oidPrefix);
                }
                strcat(OIDBuf, callbacksCursor->value->OID);
                if(strcmp(OIDBuf, oid) == 0){
                    //  found
                    if(next){
                        useNext = true;
                    } else {
                        return callbacksCursor->value;
                    }
                } else if(next){
                    // doesn't match, lets do a strstr to find out if it's possible for a walk
                    if(strstr(OIDBuf, oid)){ // this is the first occurance of the ENTIRE requested OID, which means it's the start of a walk, lets start here
                        return callbacksCursor->value;
                    }
                }
            } else {
                return callbacksCursor->value;
            }
            
            if(callbacksCursor->next){
                callbacksCursor = callbacksCursor->next;
            } else {
                break;
            }
        }
    }
    
    return 0;
}

ValueCallback* SNMPAgent::addStringHandler(char* oid, char** value, bool isSettable, bool overwritePrefix){
    ValueCallback* callback = new StringCallback();
    callback->overwritePrefix = overwritePrefix;
    if(isSettable) callback->isSettable = true;
    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
    strcpy(callback->OID, oid);
    ((StringCallback*)callback)->value = value;
    addHandler(callback);
    return callback;
}

ValueCallback* SNMPAgent::addIntegerHandler(char* oid, int* value, bool isSettable, bool overwritePrefix){
    ValueCallback* callback = new IntegerCallback();
    callback->overwritePrefix = overwritePrefix;
    if(isSettable) callback->isSettable = true;
    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
    strcpy(callback->OID, oid);
    ((IntegerCallback*)callback)->value = value;
    ((IntegerCallback*)callback)->isFloat = false;
    addHandler(callback);
    return callback;
}

ValueCallback* SNMPAgent::addFloatHandler(char* oid, float* value, bool isSettable, bool overwritePrefix){
    ValueCallback* callback = new IntegerCallback();
    callback->overwritePrefix = overwritePrefix;
    if(isSettable) callback->isSettable = true;
    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
    strcpy(callback->OID, oid);
    ((IntegerCallback*)callback)->value = (int*)value;
    ((IntegerCallback*)callback)->isFloat = true;
    addHandler(callback);
    return callback;
}

ValueCallback* SNMPAgent::addTimestampHandler(char* oid, int* value, bool isSettable, bool overwritePrefix){
    ValueCallback* callback = new TimestampCallback();
    callback->overwritePrefix = overwritePrefix;
    if(isSettable) callback->isSettable = true;
    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
    strcpy(callback->OID, oid);
    ((TimestampCallback*)callback)->value = value;
    addHandler(callback);
    return callback;
}

ValueCallback* SNMPAgent::addOIDHandler(char* oid, char* value, bool overwritePrefix){
    ValueCallback* callback = new OIDCallback();
    callback->overwritePrefix = overwritePrefix;
    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
    strcpy(callback->OID, oid);
    ((OIDCallback*)callback)->value = value;
    addHandler(callback);
    return callback;
}

ValueCallback* SNMPAgent::addCounter64Handler(char* oid, uint64_t* value, bool overwritePrefix){
    ValueCallback* callback = new Counter64Callback();
    callback->overwritePrefix = overwritePrefix;
    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
    strcpy(callback->OID, oid);
    ((Counter64Callback*)callback)->value = value;
    addHandler(callback);
    return callback;
}

ValueCallback* SNMPAgent::addCounter32Handler(char* oid, uint32_t* value, bool overwritePrefix){
    ValueCallback* callback = new Counter32Callback();
    callback->overwritePrefix = overwritePrefix;
    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
    strcpy(callback->OID, oid);
    ((Counter32Callback*)callback)->value = value;
    addHandler(callback);
    return callback;
}

ValueCallback* SNMPAgent::addGuageHandler(char* oid, uint32_t* value, bool overwritePrefix){
    ValueCallback* callback = new Guage32Callback();
    callback->overwritePrefix = overwritePrefix;
    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
    strcpy(callback->OID, oid);
    ((Guage32Callback*)callback)->value = value;
    addHandler(callback);
    return callback;
}

void SNMPAgent::addHandler(ValueCallback* callback){
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

// Let's implement this properly, we also want to inntroduce a sort() so after we add or remove stuff around we can make sure snmpwalk will still erturn in an expected way.

bool SNMPAgent::removeHandler(ValueCallback* callback){ // this will remove the callback from the list and shift everything in the list back so there are no gaps, this will not delete the actual callback
    callbacksCursor = callbacks;
    // Serial.println("Entering hell...");
    if(!callbacksCursor->value){
            return false;
    }
    bool shifting = false;
    if(callbacksCursor->value == callback){ // first callback is it
        shifting = true;
        callbacks = callbacksCursor->next; // save next element to the current global cursor
    } else {
        while(callbacksCursor->next != 0){
            if(callbacksCursor->next->value == callback){ // if the thing pouinted to by NEXT is the thing we want to remove
                if(callbacksCursor->next->next != 0){ // if next has a next that we replace the first next by
                    callbacksCursor->next = callbacksCursor->next->next;
                } else {
                    callbacksCursor->next = 0;
                }
                shifting = true;
                break;
            }
            callbacksCursor = callbacksCursor->next;
        }
    }
    return shifting;
}

bool SNMPAgent::sortHandlers(){ // we want to sort our callbacks in order of OID's so we can walk correctly
    callbacksCursor = callbacks;
    
    int swapped, i;
    ValueCallbacks* ptr1;
    ValueCallbacks* lptr = 0;
 
    /* Checking for empty list */
    if (callbacksCursor == 0)
        return false;
 
    do
    {
        swapped = 0;
        ptr1 = callbacksCursor;
 
        while (ptr1->next != lptr)
        {
            char OID1[100] = {0};
            char OID2[100] = {0};

            if(!ptr1->value->overwritePrefix){
                strcat(OID1, oidPrefix);
            }
            strcat(OID1, ptr1->value->OID);


            if(!ptr1->next->value->overwritePrefix){
                strcat(OID2, oidPrefix);
            }
            strcat(OID2, ptr1->next->value->OID);


            if (!sort_oid(OID1, OID2))
            { 
                swap(ptr1, ptr1->next);
                swapped = 1;
            }
            ptr1 = ptr1->next;
        }
        lptr = ptr1;
    }
    while (swapped);
    return true;
}

void SNMPAgent::swap(ValueCallbacks* one, ValueCallbacks* two){
    ValueCallback* temp = one->value;
    one->value = two->value;
    two->value = temp; 
}

bool SNMPAgent::sort_oid(char* oid1, char* oid2){ // returns true if oid1 EARLIER than oid2
    uint16_t oid_nums_1[40] = {0}; // max 40 deep
    uint16_t oid_nums_2[40] = {0}; // max 40 deep

    int i = 0; // current num_array index
    bool toBreak = false;
    
    while(*oid1){
        if(*oid1 == '.') oid1++;
        int num = 0;
        if(sscanf(oid1, "%d", &num)){
            // worked?
            oid_nums_1[i++] = num;
            while(*oid1 != '.') {
                if(*oid1 == 0){
                    toBreak = true;
                    break;
                }
                oid1++;
            }
            if(toBreak) break;
        } else {
            // break
            break;
        }
    }

    i = 0; // current num_array index
    toBreak = false;
    
    while(*oid2){
        if(*oid2 == '.') oid2++;
        int num = 0;
        if(sscanf(oid2, "%d", &num)){
            // worked?
            oid_nums_2[i++] = num;
            while(*oid2 != '.') {
                if(*oid2 == 0){
                    toBreak = true;
                    break;
                }
                oid2++;
            }
            if(toBreak) break;
        } else {
            // break
            break;
        }
    }

    
    for(int j = 0; j < i; j++){
        if(oid_nums_1[j] != oid_nums_2[j]){ // if they're the same then we're on same levvel
            if(oid_nums_1[j] < oid_nums_2[j]){ // if this level is smaller, then we are earlier. this will also work if this oid is a parent of the other oid because by default we'll be 0
                return true;
            } else {
                return false;
            }
        }
    }
    return true;
}

#endif
