#include "include/SNMPInform.h"
#include "SNMPTrap.h"

#include <list>
#ifdef COMPILING_TESTS
    #include <tests/required/millis.h>
#endif

inline void delete_inform(struct InformItem* inform){
    free(inform);
}

static void remove_inform_from_list(std::list<struct InformItem *> &list,
                             std::function<bool(struct InformItem *)> predicate) {
    list.remove_if([&predicate](struct InformItem* item){
        if(predicate(item)){
            delete_inform(item);
            return true;
        }
        return false;
    });
}

snmp_request_id_t
queue_and_send_trap(std::list<struct InformItem *> &informList, SNMPTrap *trap, const IPAddress& ip, bool replaceQueuedRequests,
                    int retries, int delay_ms) {
    bool buildStatus = trap->buildForSending();
    if(!buildStatus) {
        SNMP_LOGW("Couldn't build trap\n");
        return INVALID_SNMP_REQUEST_ID;
    };
    SNMP_LOGD("%lu informs in informList", informList.size());
    //TODO: could be race condition here, buildStatus to return packet?
    if(replaceQueuedRequests){
        SNMP_LOGD("Removing any outstanding informs for this trap\n");
        remove_inform_from_list(informList, [trap](struct InformItem* informItem) -> bool {
            return informItem->trap == trap;
        });
    }

    if(trap->inform){
        struct InformItem* item = (struct InformItem*)calloc(1, sizeof(struct InformItem));
        item->delay_ms = delay_ms;
        item->received = false;
        item->requestID = trap->requestID;
        item->retries = retries;
        item->ip = ip;
        item->lastSent = millis();
        item->trap = trap;
        item->missed = false;

        SNMP_LOGD("Adding Inform request to queue: %lu\n", item->requestID);

        informList.push_back(item);

        trap->sendTo(ip, true);
    } else {
        // normal send
        SNMP_LOGD("Sending normal trap\n");
        trap->sendTo(ip);
    }

    return trap->requestID;
}

void inform_callback(std::list<struct InformItem *> &informList, snmp_request_id_t requestID, bool responseReceiveSuccess) {
    (void)responseReceiveSuccess;
    SNMP_LOGD("Receiving InformCallback for requestID: %lu, success: %d\n", requestID, responseReceiveSuccess);
    //TODO: if we ever want to keep received informs, change this logic

    remove_inform_from_list(informList, [requestID](struct InformItem* informItem) -> bool {
        return informItem->requestID == requestID;
    });

    SNMP_LOGD("Informs waiting for responses: %lu\n", informList.size());
}

void handle_inform_queue(std::list<struct InformItem *> &informList) {
    auto thisLoop = millis();
    for(auto informItem : informList){
        if(!informItem->received && thisLoop - informItem->lastSent > informItem->delay_ms){
            SNMP_LOGD("Missed Inform receive\n");
            // check if sending again
            informItem->missed = true;
            if(!informItem->retries){
                SNMP_LOGD("No more retries for inform: %lu, removing\n", informItem->requestID);
                continue;
            }
            if(informItem->trap){
                SNMP_LOGD("No response received in %lums, Resending Inform: %lu\n", thisLoop - informItem->lastSent, informItem->requestID);
                informItem->trap->sendTo(informItem->ip, true);
                informItem->lastSent = thisLoop;
                informItem->missed = false;
                informItem->retries--;
            }
        }
    }
    remove_inform_from_list(informList, [](struct InformItem* informItem) -> bool {
        return informItem->received || (informItem->retries == 0 && informItem->missed);
    });
}

void mark_trap_deleted(std::list<struct InformItem *> &informList, SNMPTrap *trap) {
    SNMP_LOGD("Removing waiting Informs tied to Trap.\n");
    remove_inform_from_list(informList, [trap](struct InformItem* informItem) -> bool {
        return informItem->trap == trap;
    });
}
