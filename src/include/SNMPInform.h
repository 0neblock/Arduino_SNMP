#ifndef SNMPINFORM_h
#define SNMPINFORM_h

#include "SNMPTrap.h"
#include "include/BER.h"
#include "include/defs.h"

#ifdef COMPILING_TESTS

#include "tests/required/IPAddress.h"

#endif

struct InformItem {
    snmp_request_id_t requestID;
    SNMPTrap *trap;

    int retries;
    unsigned long delay_ms;
    bool received;
    IPAddress ip;
    unsigned long lastSent;
    bool missed;

    InformItem(snmp_request_id_t id, SNMPTrap *trap) : requestID(id), trap(trap){};

    bool operator==(snmp_request_id_t id) {
        return this->requestID == id;
    }

    bool operator==(SNMPTrap *t) {
        return this->trap == t;
    }
};

typedef sbo::small_vector<InformItem, 4> InformList;

snmp_request_id_t queue_and_send_trap(InformList &informList, SNMPTrap *trap, const IPAddress &ip, bool replaceQueuedRequests, int retries, int delay_ms, LiveRequestList &liveRequests);

bool inform_callback(InformList &informList, snmp_request_id_t requestID, bool responseReceiveSuccess, LiveRequestList &liveRequests);

void handle_inform_queue(InformList &informList, LiveRequestList &liveRequests);

void mark_trap_deleted(InformList &informList, SNMPTrap *trap, LiveRequestList &liveRequests);

#endif