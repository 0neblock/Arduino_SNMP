#ifndef SNMPAgent_h
#define SNMPAgent_h

#ifndef UDP_TX_PACKET_MAX_SIZE
    #define UDP_TX_PACKET_MAX_SIZE 256
#endif

#include <UDP.h>

#include "BER.h"
#include "VarBinds.h"
#include "SNMPRequest.h"
#include "SNMPResponse.h"

class ValueCallback {
  public:
    ValueCallback(ASN_TYPE atype): type(atype){};
    char OID[50];
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
    char* value;
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
        char* addStringHandler(char*, char*);
        int* addIntegerHandler(char* oid, int* value);
        void addHandler(ValueCallback* callback);
        bool setUDP(UDP* udp);
        bool begin();
        bool loop();
    private:
        UDP* _udp;
        char _packetBuffer[UDP_TX_PACKET_MAX_SIZE];
        bool inline receivePacket(int length);
};

bool SNMPAgent::setUDP(UDP* udp){
    _udp = udp;
}

bool SNMPAgent::begin(){
    if(!_udp) return false;
    _udp->begin(161);
}

bool SNMPAgent::loop(){
    receivePacket(_udp->parsePacket());
}

bool inline SNMPAgent::receivePacket(int packetLength){
    if(!packetLength) return false;
//    Serial.printf("Received %i from: ", packetLength);Serial.println(_udp->remoteIP());
    memset(_packetBuffer, 0, UDP_TX_PACKET_MAX_SIZE);
    int len = _udp->read(_packetBuffer, UDP_TX_PACKET_MAX_SIZE);
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
        strncpy(response->communityString, snmprequest->communityString, 20);
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
                
                OIDResponse->oid = new OIDType(callback->OID);
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
                    OctetType* value = new OctetType(((StringCallback*)callback)->value);
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
        //Serial.println("Sending UDP");
        char buf[400];
        memset(buf, 0, 400);
        delay(1);
        int length = response->serialise(buf);
        //Serial.print("Serialised into length: ");//Serial.println(length);
        delay(1);
        _udp->beginPacket(_udp->remoteIP(), _udp->remotePort());
        _udp->write((unsigned char*)buf, length);
        if(!_udp->endPacket()){
            Serial.println("COULDN'T SEND PACKET");
            for(int i = 0;  i < length; i++){
                Serial.print(buf[i], HEX);
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
                if(strcmp(callbacksCursor->value->OID, oid) == 0){
                    // found
                    if(next){
                        useNext = true;
                    } else {
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
        // if we get here and next is true, we give back the reference to the first value (this is the sart of an snmpwalk)
        if(next){
            return callbacks->value;
        }
    }
    
    return 0;
}

char* SNMPAgent::addStringHandler(char* oid, char* value){
    ValueCallback* callback = new StringCallback();
    strcpy(callback->OID, oid);
    ((StringCallback*)callback)->value = value;
    addHandler(callback);
    return value;
}

int* SNMPAgent::addIntegerHandler(char* oid, int* value){
    ValueCallback* callback = new IntegerCallback();
    strcpy(callback->OID, oid);
    ((IntegerCallback*)callback)->value = value;
    ((IntegerCallback*)callback)->isFloat = false;
    addHandler(callback);
    return value;
}

float* SNMPAgent::addFloatHandler(char* oid, float* value){
    ValueCallback* callback = new IntegerCallback();
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