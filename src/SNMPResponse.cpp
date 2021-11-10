#include "include/SNMPResponse.h"

bool SNMPResponse::addResponse(const VarBind& response){
    this->varbindList.emplace_back(response);
    return true;
}

bool SNMPResponse::addErrorResponse(const VarBind& response){
    int index = this->varbindList.size() + 1;
    this->varbindList.emplace_back(response);
    
    if(response.errorStatus != NO_ERROR){
        this->errorStatus.errorStatus = response.errorStatus;
        this->errorIndex.errorIndex = index;
    }
    return true;
}

bool SNMPResponse::setGlobalError(SNMP_ERROR_STATUS error, int index, int override){
    if(this->errorStatus.errorStatus == NO_ERROR || (this->errorStatus.errorStatus != NO_ERROR && override)){
        this->errorStatus.errorStatus = error;
        this->errorIndex.errorIndex = index;
    }
    return true;
}