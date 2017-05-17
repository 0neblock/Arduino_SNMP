#ifndef SNMPResponse_h
#define SNMPResponse_h

typedef enum ERROR_STATUS_WITH_VALUE {
    NO_ERROR = 0,
    TOO_BIG = 1,
    NO_SUCH_NAME = 2,
    BAD_VALUE = 3,
    READ_ONLY = 4,
    GEN_ERR = 5
} ERROR_STATUS;

struct SNMPOIDResponse {
    ~SNMPOIDResponse(){
        
    }
    ERROR_STATUS errorStatus;
    ASN_TYPE type;
    OIDType* oid = 0;
    BER_CONTAINER* value = 0;
};

typedef struct OIDResponseList {
    ~OIDResponseList(){
        delete next; next = 0;
        delete value; value = 0;
    }
    SNMPOIDResponse* value = 0;
    struct OIDResponseList* next = 0;
} ResponseList; 

class SNMPResponse {
  public:
    ~SNMPResponse(){
        delete responseList; responseList = 0;
        delete response; response = 0;
    }
    int version = 0;
    char communityString[15];
    unsigned long requestID = 0;
    
    ERROR_STATUS errorStatus = (ERROR_STATUS)0;
    int errorIndex = 0;
    ASN_TYPE responseType = GetResponsePDU;
    
    ResponseList* responseList = new ResponseList();
    ResponseList* responseConductor = responseList;
    
    bool addResponse(SNMPOIDResponse* response);
    bool addErrorResponse(SNMPOIDResponse* response, int index);
    int serialise(unsigned char* buf);
    
  private:
    ComplexType* response = 0;
    bool build();
};

bool SNMPResponse::addResponse(SNMPOIDResponse* response){
    responseConductor->value = response;
    responseConductor->next = new ResponseList();
    responseConductor = responseConductor->next;
}

bool SNMPResponse::addErrorResponse(SNMPOIDResponse* response, int index){
    responseConductor->value = response;
    
    // check for error passed in
    if(response->errorStatus != NO_ERROR){
        errorStatus = response->errorStatus;
        errorIndex = index;
    }
    responseConductor->next = new ResponseList();
    responseConductor = responseConductor->next;
}



int SNMPResponse::serialise(unsigned char* buf){
    if(build()){
        return response->serialise(buf);
    }
    return 0;
}

bool SNMPResponse::build(){
    response = new ComplexType(STRUCTURE);
    response->addValueToList(new IntegerType(version));
    response->addValueToList(new OctetType(communityString));
    ComplexType* PDUObj = new ComplexType(responseType);
    PDUObj->addValueToList(new IntegerType(requestID));
    PDUObj->addValueToList(new IntegerType(errorStatus));
    PDUObj->addValueToList(new IntegerType(errorIndex));
    ComplexType* varBindList = new ComplexType(STRUCTURE);
    
    responseConductor = responseList;
    // chuck all varBinds in
    while(true){
        ComplexType* varBind = new ComplexType(STRUCTURE);
        varBind->addValueToList(responseConductor->value->oid);
        varBind->addValueToList(responseConductor->value->value);
        varBindList->addValueToList(varBind);
        if(!responseConductor->next->value){
            break;
        }
        responseConductor = responseConductor->next;
        delay(1);
    }
    
    PDUObj->addValueToList(varBindList);
    response->addValueToList(PDUObj);
}

#endif