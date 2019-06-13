#ifndef SNMPAgent_h
#define SNMPAgent_h

#ifndef UDP_TX_PACKET_MAX_SIZE
    #define UDP_TX_PACKET_MAX_SIZE 256
#endif

#ifndef SNMP_PACKET_LENGTH
    #define SNMP_PACKET_LENGTH 256
#endif

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
    bool isSettable = false;
};

class IntegerCallback: public ValueCallback {
  public:
    IntegerCallback(): ValueCallback(INTEGER){};
	unsigned int* value;
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


typedef struct ValueCallbackList {
    ~ValueCallbackList(){
        delete next;
    }
    ValueCallback* value;
    struct ValueCallbackList* next = 0;
} ValueCallbacks;


#include "SNMPTrap.h"
#include "SNMPGet.h"
#include "SNMPGetResponse.h"

class SNMPAgent {
    public:
        SNMPAgent(const char* community): _community(community){};
        const char* _community;
        ValueCallbacks* callbacks = new ValueCallbacks();
        ValueCallbacks* callbacksCursor = callbacks;
//        bool addHandler(char* OID, SNMPOIDResponse (*callback)(SNMPOIDResponse* response, char* oid));
        ValueCallback* findCallback(char* oid, bool next);
        ValueCallback* addFloatHandler(char* oid, float* value, bool isSettable = false); // this obv just adds integer but with the *0.1 set
        ValueCallback* addStringHandler(char*, char**, bool isSettable = false); // passing in a pointer to a char* 
        ValueCallback* addIntegerHandler(char* oid, unsigned int* value, bool isSettable = false);
        ValueCallback* addTimestampHandler(char* oid, int* value, bool isSettable = false);
        
        bool setUDP(UDP* udp);
        bool begin();
		bool beginMaster();
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
		
    private:
        
        void addHandler(ValueCallback* callback);
        unsigned char _packetBuffer[SNMP_PACKET_LENGTH]; // create and array of unsigned char that is 256 long
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

bool SNMPAgent::beginMaster() {
	if (!_udp) return false;
	_udp->begin(162);
}

bool SNMPAgent::begin(char* prefix){
    strncpy(oidPrefix, prefix, 40);
    return this->begin();
}

bool SNMPAgent::loop(){
    if(!_udp){
        return false;
    }
	receivePacket(_udp->parsePacket()); // get the lenght of the packet is bytes and then run the recivePacket function
	
}

bool inline SNMPAgent::receivePacket(int packetLength) {
	if (!packetLength) return false;
	   // Serial.print("Received from: ");Serial.print(packetLength);Serial.print(" ");Serial.println(_udp->remoteIP());
	memset(_packetBuffer, 0, SNMP_PACKET_LENGTH);
	int len = packetLength;
	//    int len = _udp->read(_packetBuffer, SNMP_PACKET_LENGTH);
	for (int i = 0; i < len; i++) {
		_packetBuffer[i] = _udp->read();
	//	        Serial.print(_packetBuffer[i]);
	//	        Serial.print(" ");
				

	}

	_udp->flush();
	_packetBuffer[len] = 0;
	
	//Serial.println();
	if (_packetBuffer[13] == GetResponsePDU) {
		
		
		SNMPGetRespose* snmpgetresponse = new SNMPGetRespose();
		
		if (snmpgetresponse->parseFrom(_packetBuffer)) {
			
			// check version and community
			if (snmpgetresponse->version != 1 || strcmp(_community, snmpgetresponse->communityString) != 0) {
				Serial.println(F("Invalid community or version"));

			}
			int varBindIndex = 1;
			snmpgetresponse->varBindsCursor = snmpgetresponse->varBinds;
			while (true) {
				//Serial.print("OID: ");Serial.println(snmpgetresponse->varBindsCursor->value->oid->_value);
			
				ValueCallback* callback = findCallback(snmpgetresponse->varBindsCursor->value->oid->_value, false);
				//Serial.println(callback->OID);
				if (callback->isSettable) {
					//Serial.println("isSettable");
					if (callback->type != snmpgetresponse->varBindsCursor->value->type) {
						// wrong data type to set..
						// BAD_VALUE
						Serial.println(F("VALUE-TYPE DOES NOT MATCH"));

					}
					
					switch (callback->type) {
					case STRING:
					{
						memcpy(*((StringCallback*)callback)->value, String(((OctetType*)snmpgetresponse->varBindsCursor->value->value)->_value).c_str(), 25);// FIXME: this is VERY dangerous, i'm assuming the length of the source char*, this needs to change. for some reason strncpy didnd't work, need to look into this. the '25' also needs to be defined somewhere so this won't break;
						*(*((StringCallback*)callback)->value + 24) = 0x0; // close off the dest string, temporary
						OctetType* value = new OctetType(*((StringCallback*)callback)->value);
						//Serial.print("STR value: ");
						//	Serial.println(value);
						delete value;
						setOccurred = true;
					}
					break;
					case INTEGER:
					{
						IntegerType* value = new IntegerType();
						if (!((IntegerCallback*)callback)->isFloat) {
							//Serial.println(*(((IntegerCallback*)callback)->value));
							*(((IntegerCallback*)callback)->value) = ((IntegerType*)snmpgetresponse->varBindsCursor->value->value)->_value;
							value->_value = *(((IntegerCallback*)callback)->value);
						}
						else {
							
							*(((IntegerCallback*)callback)->value) = (float)(((IntegerType*)snmpgetresponse->varBindsCursor->value->value)->_value / 10);
							value->_value = *(float*)(((IntegerCallback*)callback)->value) * 10;
						}
						delete value;
						setOccurred = true;
					}
					break;
					}
					
				}
				else {
					// not settable, send error
					Serial.println(F("OID NOT SETTABLE"));
				}
				snmpgetresponse->varBindsCursor = snmpgetresponse->varBindsCursor->next;
				if (!snmpgetresponse->varBindsCursor->value) {
					break;
				}
				varBindIndex++;
			}
		}
		else {
			
			Serial.println(F("CORRUPT PACKET"));
			VarBindList* tempList = snmpgetresponse->varBinds;
			while (tempList->next) {
				delete tempList->value->oid;
				delete tempList->value->value;
				tempList = tempList->next;
			}
			delete tempList->value->oid;
			delete tempList->value->value;
			
		}
		


		delete snmpgetresponse;
		
		return true;
		
	}
	
	else if ((_packetBuffer[13] == GetRequestPDU) || (_packetBuffer[13] == SetRequestPDU)) {
		
		
		//    Serial.println(_packetBuffer);
		SNMPRequest* snmprequest = new SNMPRequest();
		if (snmprequest->parseFrom(_packetBuffer)) {

			// check version and community
			if (snmprequest->version != 1 || strcmp(_community, snmprequest->communityString) != 0)	 {
				Serial.println(F("Invalid community or version"));
				delete snmprequest;
				return false;
			}

			SNMPResponse* response = new SNMPResponse();
			response->requestID = snmprequest->requestID;
			strncpy(response->communityString, snmprequest->communityString, 15);
			int varBindIndex = 1;
			snmprequest->varBindsCursor = snmprequest->varBinds;
			while (true) {
				delay(1);
				//Serial.print("OID: ");//Serial.println(snmprequest->varBindsCursor->value->oid->_value);

				// Deal with OID request here:
				bool walk = false;
				if (snmprequest->requestType == GetNextRequestPDU) {
					walk = true;
				}
				ValueCallback* callback = findCallback(snmprequest->varBindsCursor->value->oid->_value, walk);
				if (callback) { // this is where we deal with the response varbind
					SNMPOIDResponse* OIDResponse = new SNMPOIDResponse();
					OIDResponse->errorStatus = (ERROR_STATUS)0;

					memset(OIDBuf, 0, 50);
					strcat(OIDBuf, oidPrefix);
					strcat(OIDBuf, callback->OID);

					OIDResponse->oid = new OIDType(OIDBuf);
					OIDResponse->type = callback->type;

					// TODO: this whole thing needs better flow: proper checking for errors etc.

					if (snmprequest->requestType == SetRequestPDU) {
						// settable data..
						if (callback->isSettable) {
							if (callback->type != snmprequest->varBindsCursor->value->type) {
								// wrong data type to set..
								// BAD_VALUE
								Serial.println(F("VALUE-TYPE DOES NOT MATCH"));
								SNMPOIDResponse* errorResponse = generateErrorResponse(BAD_VALUE, snmprequest->varBindsCursor->value->oid->_value);
								response->addErrorResponse(errorResponse, varBindIndex);
							}
							else {
								// actually set it
								switch (callback->type) {
									case STRING:
									{
										memcpy(*((StringCallback*)callback)->value, String(((OctetType*)snmprequest->varBindsCursor->value->value)->_value).c_str(), 25);// FIXME: this is VERY dangerous, i'm assuming the length of the source char*, this needs to change. for some reason strncpy didnd't work, need to look into this. the '25' also needs to be defined somewhere so this won't break;
										*(*((StringCallback*)callback)->value + 24) = 0x0; // close off the dest string, temporary
										OctetType* value = new OctetType(*((StringCallback*)callback)->value);
										OIDResponse->value = value;
										setOccurred = true;
									}
									break;
									case INTEGER:
									{
										IntegerType* value = new IntegerType();
										if (!((IntegerCallback*)callback)->isFloat) {
											*(((IntegerCallback*)callback)->value) = ((IntegerType*)snmprequest->varBindsCursor->value->value)->_value;
											value->_value = *(((IntegerCallback*)callback)->value);
										}
										else {
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
						else {
							// not settable, send error
							Serial.println(F("OID NOT SETTABLE"));
							SNMPOIDResponse* errorResponse = generateErrorResponse(READ_ONLY, snmprequest->varBindsCursor->value->oid->_value);
							response->addErrorResponse(errorResponse, varBindIndex);
						}
					}
					else if (snmprequest->requestType == GetRequestPDU || snmprequest->requestType == GetNextRequestPDU) {

						if (callback->type == INTEGER) {
							IntegerType* value = new IntegerType();
							if (!((IntegerCallback*)callback)->isFloat) {
								value->_value = *(((IntegerCallback*)callback)->value);
							}
							else {
								value->_value = *(float*)(((IntegerCallback*)callback)->value) * 10;
							}
							OIDResponse->value = value;
						}
						else if (callback->type == STRING) {
							OctetType* value = new OctetType(*((StringCallback*)callback)->value);
							OIDResponse->value = value;
						}
						else if (callback->type == TIMESTAMP) {
							TimestampType* value = new TimestampType(*(((TimestampCallback*)callback)->value));
							OIDResponse->value = value;
						}
						response->addResponse(OIDResponse);
					}
				}
				else {
					// inject a NoSuchObject error
					Serial.println(F("OID NOT FOUND"));
					SNMPOIDResponse* errorResponse = generateErrorResponse(NO_SUCH_NAME, snmprequest->varBindsCursor->value->oid->_value);
					response->addErrorResponse(errorResponse, varBindIndex);

				}
				// -------------------------

				snmprequest->varBindsCursor = snmprequest->varBindsCursor->next;
				if (!snmprequest->varBindsCursor->value) {
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
			if (!_udp->endPacket()) {
			Serial.println(F("COULDN'T SEND PACKET"));
			for (int i = 0; i < length; i++) {
			Serial.print(_packetBuffer[i], HEX);
			}
			Serial.print(F("Length: ")); Serial.println(length);
			Serial.print(F("Length of incoming: ")); Serial.println(len);
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
			//        Serial.print(F("freeMemory before delete="));
			//        Serial.println(freeMemory());
			delete response;
		}
		else {
			Serial.println(F("CORRUPT PACKET"));
			VarBindList* tempList = snmprequest->varBinds;
			while (tempList->next) {
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
	
	else {
		Serial.println("Could not determine PDU type");
	}


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
		

    }

    return 0;
}

ValueCallback* SNMPAgent::addStringHandler(char* oid, char** value, bool isSettable){
    ValueCallback* callback = new StringCallback();
    if(isSettable) callback->isSettable = true;
    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
    strcpy(callback->OID, oid);
    ((StringCallback*)callback)->value = value;
    addHandler(callback);
    return callback;
}

ValueCallback* SNMPAgent::addIntegerHandler(char* oid, unsigned int* value, bool isSettable){
    ValueCallback* callback = new IntegerCallback();
    if(isSettable) callback->isSettable = true;
    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
    strcpy(callback->OID, oid);
    ((IntegerCallback*)callback)->value = value;
    ((IntegerCallback*)callback)->isFloat = false;
    addHandler(callback);
    return callback;
}

ValueCallback* SNMPAgent::addFloatHandler(char* oid, float* value, bool isSettable){
    ValueCallback* callback = new IntegerCallback();
    if(isSettable) callback->isSettable = true;
    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
    strcpy(callback->OID, oid);
    ((IntegerCallback*)callback)->value = (unsigned int*)value;
    ((IntegerCallback*)callback)->isFloat = true;
    addHandler(callback);
    return callback;
}

ValueCallback* SNMPAgent::addTimestampHandler(char* oid, int* value, bool isSettable){
    ValueCallback* callback = new TimestampCallback();
    if(isSettable) callback->isSettable = true;
    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
    strcpy(callback->OID, oid);
    ((TimestampCallback*)callback)->value = value;
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

bool SNMPAgent::removeHandler(ValueCallback* callback){ // this will remove the callback and shift everything in the list back so there are no gaps, this will not delete the actual callback
	callbacksCursor = callbacks;
    Serial.println("Entering hell...");
    if(!callbacksCursor->value){
        return false;
    }
    bool shifting = false;
    do {
        if(callbacksCursor->value == callback){
            // found
            while(callbacksCursor->next != 0){
                callbacksCursor->value = callbacksCursor->next->value;
                callbacksCursor = callbacksCursor->next;
                if(callbacksCursor->next == 0){
                    // this was last in line, move it to here then break;
                    break;
                }
                
            }
            delete callbacksCursor;
            shifting = true;
            break;
        }
        callbacksCursor = callbacksCursor->next;
    } while(callbacksCursor->next != 0);
    
    return shifting;
    return false;
}

#endif