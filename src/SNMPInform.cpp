#include "include/SNMPInform.h"
#include "SNMPTrap.h"

#include <list>

#ifdef COMPILING_TESTS

#include <functional>
#include <tests/required/millis.h>

#endif

static void remove_request(LiveRequestList &liveRequests, snmp_request_id_t requestID) {
    //TODO: Write tests
    liveRequests.erase(std::remove_if(liveRequests.begin(), liveRequests.end(), [=](const LiveRequest &item) {
        return item == requestID;
    }));
}

static void remove_inform_from_list(InformList &list, LiveRequestList &liveRequests,
                                    snmp_request_id_t requestID) {
    //TODO: Write tests
    auto pos = std::remove(list.begin(), list.end(), requestID);
    if (pos != list.end()) {
        remove_request(liveRequests, pos->requestID);
        list.erase(pos);
    }
}

static void remove_inform_from_list(InformList &list, LiveRequestList &liveRequests,
                                    SNMPTrap *trap) {
    //TODO: Write tests
    auto pos = std::remove(list.begin(), list.end(), trap);
    if (pos != list.end()) {
        remove_request(liveRequests, pos->requestID);
        list.erase(pos);
    }
}

static void remove_finished_informs(InformList &list, LiveRequestList &liveRequests) {
    //TODO: Write tests
    auto pos = std::remove_if(list.begin(), list.end(), [](InformItem &item) -> bool {
        return item.received || (item.retries == 0 && item.missed);
    });
    if (pos != list.end()) {
        remove_request(liveRequests, pos->requestID);
        list.erase(pos);
    }
}

snmp_request_id_t
queue_and_send_trap(InformList &informList, SNMPTrap *trap, const IPAddress &ip, bool replaceQueuedRequests, int retries, int delay_ms, LiveRequestList &liveRequests) {
    if (!trap) return INVALID_SNMP_REQUEST_ID;

    bool buildStatus = trap->buildForSending();
    if (!buildStatus) {
        SNMP_LOGW("Couldn't build trap\n");
        return INVALID_SNMP_REQUEST_ID;
    };
    SNMP_LOGD("%lu informs in informList", informList.size());
    //TODO: could be race condition here, buildStatus to return packet?
    if (replaceQueuedRequests) {
        SNMP_LOGD("Removing any outstanding informs for this trap\n");
        remove_inform_from_list(informList, liveRequests, trap);
    }

    if (trap->inform) {
        InformItem item(trap->requestID, trap);

        item.delay_ms = delay_ms;
        item.received = false;
        item.retries = retries;
        item.ip = ip;
        item.lastSent = millis();
        item.missed = false;


        SNMP_LOGD("Adding Inform request to queue: %u\n", trap->requestID);
        informList.emplace_back(item);

        trap->sendTo(ip, true);
    } else {
        // normal send
        SNMP_LOGD("Sending normal trap\n");
        trap->sendTo(ip);
    }

    return trap->requestID;
}

bool inform_callback(InformList &informList, snmp_request_id_t requestID, bool responseReceiveSuccess, LiveRequestList &liveRequests) {
    (void) responseReceiveSuccess;
    SNMP_LOGD("Receiving InformCallback for requestID: %u, success: %d\n", requestID, responseReceiveSuccess);
    //TODO: if we ever want to keep received informs, change this logic

    remove_inform_from_list(informList, liveRequests, requestID);
    SNMP_LOGD("Informs waiting for responses: %lu\n", informList.size());
    return true;
}

void handle_inform_queue(InformList &informList, LiveRequestList &liveRequests) {
    auto thisLoop = millis();
    for (auto &informItem : informList) {
        SNMP_LOGI("informItem\n");
        if (!informItem.received && thisLoop - informItem.lastSent > informItem.delay_ms) {
            SNMP_LOGD("Missed Inform receive\n");
            // check if sending again
            informItem.missed = true;
            if (!informItem.retries) {
                SNMP_LOGD("No more retries for inform: %u, removing\n", informItem.requestID);
                continue;
            }
            SNMP_LOGD("No response received in %lums, Resending Inform: %u\n", thisLoop - informItem.lastSent,
                      informItem.requestID);
            informItem.trap->sendTo(informItem.ip, true);
            informItem.lastSent = thisLoop;
            informItem.missed = false;
            informItem.retries--;
        }
    }

    // Remove complete or expired informs
    if (informList.size() > 0) remove_finished_informs(informList, liveRequests);
}

void mark_trap_deleted(InformList &informList, SNMPTrap *trap, LiveRequestList &liveRequests) {
    SNMP_LOGD("Removing waiting Informs tied to Trap.\n");
    remove_inform_from_list(informList, liveRequests, trap);
}
