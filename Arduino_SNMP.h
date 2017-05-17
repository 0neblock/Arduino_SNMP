#ifndef SNMPAgent_h
#define SNMPAgent_h

#ifndef UDP_TX_PACKET_MAX_SIZE
    #define UDP_TX_PACKET_MAX_SIZE 128
#endif

#define SNMP_PACKET_LENGTH 128

#include <UDP.h>

#include "BER.h"
#include "VarBinds.h"
#include "SNMPRequest.h"
#include "SNMPResponse.h"

class ValueCallback {
  public:
    ValueCallback(ASN_TYPE atype): type(atype){};
    char* OID;
    ASN_TYPE type;
};

class IntegerCallback: public ValueCallback {
  public:
    IntegerCallback(): ValueCallback(INTEGER){};
    int* value;
    bool isFloat = false;
};

class StringCallback: public ValueCallback {
  public:
    StringCallback(): ValueCallback(STRING){};
    char** value;
};

typedef struct ValueCallbackList {
    ValueCallback* value;
    struct ValueCallbackList* next = 0;
} ValueCallbacks;

class SNMPAgent {
    public:
        SNMPAgent(const char* community): _community(community){};
        const char* _community;
        ValueCallbacks* callbacks = new ValueCallbacks();
        ValueCallbacks* callbacksCursor = callbacks;
//        bool addHandler(char* OID, SNMPOIDResponse (*callback)(SNMPOIDResponse* response, char* oid));
        ValueCallback* findCallback(char* oid, bool next);
        float* addFloatHandler(char* oid, float* value); // this obv just adds integer but with the *0.1 set
        char** addStringHandler(char*, char**); // passing in a pointer to a char* 
        int* addIntegerHandler(char* oid, int* value);
        void addHandler(ValueCallback* callback);
        bool setUDP(UDP* udp);
        bool begin();
        bool begin(char*);
        bool loop();
        char oidPrefix[30];
        char OIDBuf[50];
    private:
        UDP* _udp;
        unsigned char _packetBuffer[SNMP_PACKET_LENGTH];
        bool inline receivePacket(int length);
};

bool SNMPAgent::setUDP(UDP* udp){
    _udp = udp;
}

bool SNMPAgent::begin(){
    if(!_udp) return false;
    _udp->begin(161);
}

bool SNMPAgent::begin(char* prefix){
    if(!_udp) return false;
    _udp->begin(161);
    strncpy(oidPrefix, prefix, 30);
}

bool SNMPAgent::loop(){
    receivePacket(_udp->parsePacket());
}

bool inline SNMPAgent::receivePacket(int packetLength){
    if(!packetLength) return false;
//    Serial.print("Received from: ");Serial.print(packetLength);Serial.print(" ");Serial.println(_udp->remoteIP());
    memset(_packetBuffer, 0, SNMP_PACKET_LENGTH);
    int len = packetLength;
//    int len = _udp->read(_packetBuffer, SNMP_PACKET_LENGTH);
    for(int i = 0; i < len; i++){
        _packetBuffer[i] = _udp->read();
//        Serial.print(_packetBuffer[i], HEX);
//        Serial.print(" ");
    }
    Serial.println();
    _udp->flush();
    _packetBuffer[len] = 0;
//    Serial.println(_packetBuffer);
    SNMPRequest* snmprequest = new SNMPRequest();
    if(snmprequest->parseFrom(_packetBuffer)){
        
        // check version and community
        if(snmprequest->version != 1 || strcmp("public", snmprequest->communityString) != 0) {
            Serial.println("Invalid community or version");
            delete snmprequest;
            return false;
        }
        
        SNMPResponse* response = new SNMPResponse();
        response->requestID = snmprequest->requestID;
        strncpy(response->communityString, snmprequest->communityString, 15);
        int varBindIndex = 1;
        snmprequest->varBindsCursor = snmprequest->varBinds;
        while(true){
            delay(1);
            //Serial.print("OID: ");//Serial.println(snmprequest->varBindsCursor->value->oid->_value);
            
            // Deal with OID request here:
            bool walk = false;
            if(snmprequest->requestType == GetNextRequestPDU){
                walk = true;
            }
            ValueCallback* callback = findCallback(snmprequest->varBindsCursor->value->oid->_value, walk);
            if(callback){
                SNMPOIDResponse* OIDResponse = new SNMPOIDResponse();
                OIDResponse->errorStatus = (ERROR_STATUS)0;
                
                memset(OIDBuf, 0, 50);
                strcat(OIDBuf, oidPrefix);
                strcat(OIDBuf, callback->OID);
                
                OIDResponse->oid = new OIDType(OIDBuf);
                OIDResponse->type = callback->type;
                if(callback->type == INTEGER){
                    IntegerType* value = new IntegerType();
                    if(!((IntegerCallback*)callback)->isFloat){
                        value->_value = *(((IntegerCallback*)callback)->value);
//                        //Serial.println(value->_value);
                    } else {
                        value->_value = *(float*)(((IntegerCallback*)callback)->value) * 10;
                    }
                    OIDResponse->value = value;
                } else if(callback->type == STRING){
                    OctetType* value = new OctetType(*((StringCallback*)callback)->value);
                    OIDResponse->value = value;
                }
                response->addResponse(OIDResponse);
            } else {
                // inject a NoSuchObject error
                Serial.println("OID NOT FOUND"); 
                SNMPOIDResponse* errorResponse = new SNMPOIDResponse();
                errorResponse->oid = new OIDType(snmprequest->varBindsCursor->value->oid->_value);
                errorResponse->errorStatus = NO_SUCH_NAME;
                errorResponse->value = new NullType();
                errorResponse->type = NULLTYPE;
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
         memset(_packetBuffer, 0, SNMP_PACKET_LENGTH);
        delay(1);
        int length = response->serialise(_packetBuffer);
        //Serial.print("Serialised into length: ");//Serial.println(length);
        delay(1);
        _udp->beginPacket(_udp->remoteIP(), _udp->remotePort());
        _udp->write(_packetBuffer, length);
        if(!_udp->endPacket()){
            Serial.println("COULDN'T SEND PACKET");
            for(int i = 0;  i < length; i++){
                Serial.print(_packetBuffer[i], HEX);
            }
            Serial.print("Length: ");Serial.println(length);
            Serial.print("Length of incoming: ");Serial.println(len);
        }
        delay(1);
        //Serial.println("Packet Sent");
//        
//        //Serial.print("Length of response: ");//Serial.println(length);
//        //Serial.print("Response: ");
//        char* buff = buf;
//        while(length != 0){
//            //Serial.print(*buff, HEX);
//            //Serial.print(" ");
//            buff++;
//            length--;
//        }
//        //Serial.println();
        
        delete response;
    } else {
        Serial.println("CORRUPT PACKET");
        VarBindList* tempList = snmprequest->varBinds;
        while(tempList->next){
            delete tempList->value->oid;
            delete tempList->value->value;
            tempList = tempList->next;
        }
        delete tempList->value->oid;
        delete tempList->value->value;
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
                strcat(OIDBuf, oidPrefix);
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
        // if we get here and next is true, we give back the reference to the first value (this is the start of an snmpwalk)
        // TODO: act more like a real SNMPWalk - if 1.3.6.1.4.1.9 is called, and we have 9.1, find the 9.1. (at the moment it just spits back the first OID we have)
//        if(next){
//            return callbacks->value;
//        }
    }
    
    return 0;
}

char** SNMPAgent::addStringHandler(char* oid, char** value){
    ValueCallback* callback = new StringCallback();
    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
    strcpy(callback->OID, oid);
    ((StringCallback*)callback)->value = value;
    addHandler(callback);
    return value;
}

int* SNMPAgent::addIntegerHandler(char* oid, int* value){
    ValueCallback* callback = new IntegerCallback();
    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
    strcpy(callback->OID, oid);
    ((IntegerCallback*)callback)->value = value;
    ((IntegerCallback*)callback)->isFloat = false;
    addHandler(callback);
    return value;
}

float* SNMPAgent::addFloatHandler(char* oid, float* value){
    ValueCallback* callback = new IntegerCallback();
    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
    strcpy(callback->OID, oid);
    ((IntegerCallback*)callback)->value = (int*)value;
    ((IntegerCallback*)callback)->isFloat = true;
    addHandler(callback);
    return value;
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



#endif