//
// Created by Aidan on 20/11/2021.
//

#ifndef POLLINGINFO_H
#define POLLINGINFO_H

#ifdef COMPILING_TESTS

#include "tests/required/millis.h"

#endif

class ValueCallbackContainer;

typedef bool (*responseCB)(std::shared_ptr<OIDType> responseOID, bool success, int errorStatus,
                           const ValueCallbackContainer &container);

class PollingInfo {
  public:
    PollingInfo(unsigned long pollingInterval) : pollingInterval(pollingInterval){};

    bool has_timed_out(unsigned long timeout = 5000) {
        return this->on_wire && (millis() - this->last_sent > timeout);
    }

    void reset_poller(bool success = false) {
        this->on_wire = false;
        if (success)
            this->last_successful_poll = millis();
    }

    bool should_poll() {
        return !this->on_wire && millis() - this->last_successful_poll > this->pollingInterval;
    }

    bool on_wire;

    snmp_request_id_t last_request_id = 0;

    void send(snmp_request_id_t i) {
        this->last_request_id = i;
        this->last_sent = millis();
        this->on_wire = true;
    }

  private:
    const unsigned long pollingInterval;

    unsigned long last_sent;
    unsigned long last_successful_poll;
};

#endif//POLLINGINFO_H
