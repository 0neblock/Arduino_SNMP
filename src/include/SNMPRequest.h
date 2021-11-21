//
// Created by Aidan on 20/11/2021.
//

#ifndef SNMPREQUEST_H
#define SNMPREQUEST_H

#include <list>
#include "SNMPPacket.h"
#include "include/ValueCallbacks.h"

class SNMPRequest : public SNMPPacket {
  public:
    SNMPRequest(ASN_TYPE type): SNMPPacket(){
        this->setPDUType(type);
    }

    void addValueCallback(ValueCallback* callback){
        if(this->packetPDUType == GetRequestPDU){
            // fill in OIDs with nullptr values
            this->varbindList.emplace_back(callback->OID->cloneOID());
        } else if(this->packetPDUType == SetRequestPDU){
            // fill in OIDs with actual values
            this->varbindList.emplace_back(callback->OID->cloneOID(), callback->buildTypeWithValue());
        }
    }

  private:
    bool build() override {
        this->requestID = SNMPPacket::generate_request_id();
        return SNMPPacket::build();
    }

};

#endif //SNMPREQUEST_H
