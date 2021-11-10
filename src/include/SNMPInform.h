#ifndef SNMPINFORM_h
#define SNMPINFORM_h

#include "include/defs.h"
#include "include/BER.h"
#include "SNMPTrap.h"

#ifdef COMPILING_TESTS
    #include "tests/required/IPAddress.h"
#endif

#include <list>
#include <functional>

struct InformItem {
    snmp_request_id_t requestID;
    int retries;
    unsigned long delay_ms;
    bool received;
    IPAddress ip;
    unsigned long lastSent;
    SNMPTrap* trap;
    bool missed;
};

snmp_request_id_t queue_and_send_trap(std::list<struct InformItem *> &informList, SNMPTrap* trap, const IPAddress& ip, bool replaceQueuedRequests, int retries, int delay_ms);
void inform_callback(std::list<struct InformItem *> &informList, snmp_request_id_t requestID, bool responseReceiveSuccess);
void handle_inform_queue(std::list<struct InformItem*> &informList);
void mark_trap_deleted(std::list<struct InformItem*> &informList, SNMPTrap* trap);
#endif