//
// Created by Aidan on 20/11/2021.
//

#ifndef SNMP_MANAGER_H
#define SNMP_MANAGER_H

#include "include/ValueCallbacks.h"
#include "include/PollingInfo.h"
#include <string>
#include <list>
#include <unordered_map>
#include "include/SNMPPacket.h"

#define SNMPREQUEST_VARBIND_COUNT 6

class SNMPManager {
  public:
    SNMPManager(){};
    SNMPManager(const char* community): _defaultCommunity(community){};

    ValueCallback* addIntegerPoller(SNMPDevice* device, char* oid, int* value, unsigned long pollingInterval = 30000);

    void removePoller(ValueCallback* callbackPoller, SNMPDevice* device);

    void begin();
    void loop();
    void setUDP(UDP* u);

  private:
    std::string _defaultCommunity = "public";

    ValueCallback* addCallbackPoller(SNMPDevice* device, ValueCallback* callback, unsigned long pollingInterval){
        auto pollingInfo = std::make_shared<PollingInfo>(pollingInterval);
        this->pollingCallbacks.emplace_back(device, callback, pollingInfo);
        return callback;
    }

    std::deque<ValueCallbackContainer> pollingCallbacks;
    std::unordered_map<snmp_request_id_t, ASN_TYPE> liveRequests;

    uint8_t _packetBuffer[MAX_SNMP_PACKET_LENGTH] = {0};

    void teardown_old_requests();

    UDP* udp;

    snmp_request_id_t send_polling_request(const SNMPDevice* device, const std::vector<ValueCallbackContainer *>& callbacks);

    snmp_request_id_t prepare_next_polling_request();

    SNMP_ERROR_RESPONSE process_incoming_packets();

    static bool responseCallback(std::shared_ptr<OIDType> responseOID, bool success, int errorStatus,
                          const ValueCallbackContainer &container);
};

#endif //SNMP_MANAGER_H
