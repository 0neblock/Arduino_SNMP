//
// Created by Aidan on 20/11/2021.
//

#ifndef SNMPREQUEST_H
#define SNMPREQUEST_H

#include "SNMPPacket.h"
#include "include/ValueCallbacks.h"
#include <list>

class SNMPRequest : public SNMPPacket {
  public:
    explicit SNMPRequest(ASN_TYPE type) : SNMPPacket(type) {}

    void addValueCallback(ValueCallback *callback) {
        if (this->packetPDUType == GetRequestPDU || this->packetPDUType == GetNextRequestPDU) {
            // fill in OIDs with nullptr values
            this->varbindList.emplace_back(callback->OID->cloneOID());
        } else if (this->packetPDUType == SetRequestPDU) {
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

#endif//SNMPREQUEST_H
