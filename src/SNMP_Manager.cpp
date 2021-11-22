//
// Created by Aidan on 20/11/2021.
//

#ifdef COMPILING_TESTS

#include <tests/required/millis.h>

#endif

#include "SNMP_Manager.h"
#include "include/PollingInfo.h"
#include "include/SNMPParser.h"
#include "include/SNMPRequest.h"

#define REQUEST_TIMEOUT 5000


void SNMPManager::loop() {
    // Put on a timer
    if (millis() - this->last_processed > 1000) {
        teardown_old_requests();
        prepare_next_polling_request();
        this->last_processed = millis();
    }

    process_incoming_packets();
}

snmp_request_id_t SNMPManager::prepare_next_polling_request() {
    // Loop through our pollers, find the first one that needs to be polled again,
    // Use its device to et the next n callbacks, then send request
    const SNMPDevice *device = nullptr;
    std::array<ValueCallbackContainer *, SNMPREQUEST_VARBIND_COUNT> callbacks = {nullptr};

    int callbackCount = 0;
    for (auto &container : pollingCallbacks) {
        if (device == nullptr || container.agentDevice == device) {
            if (container.pollingInfo->should_poll()) {
                device = container.agentDevice;
                callbacks[callbackCount++] = &container;
                // max SNMPREQUEST_VARBIND_COUNT varbinds per packet
                // TODO: calculate as we go the assumed size of the packet, up to a limit
                if (callbackCount == SNMPREQUEST_VARBIND_COUNT) continue;
            }
        }
    }

    if (callbackCount > 0) {
        return send_polling_request(device, callbacks);
    }

    return 0;
}

snmp_request_id_t SNMPManager::send_polling_request(const SNMPDevice *const device,
                                                    std::array<ValueCallbackContainer *, SNMPREQUEST_VARBIND_COUNT> &callbacks) {
    // Should only call if we know we're going to send a request
    SNMP_LOGD("send_polling_request: %lu", callbacks.size());
    SNMPRequest request(GetRequestPDU);

    request.setVersion(device->_version);
    request.setCommunityString(device->_community);

    for (const auto callback : callbacks) {
        if (callback == nullptr) break;
        request.addValueCallback(callback->operator->());
    }

    memset(_packetBuffer, 0, MAX_SNMP_PACKET_LENGTH);
    int packetLength = request.serialiseInto(_packetBuffer, MAX_SNMP_PACKET_LENGTH);
    snmp_request_id_t request_id = request.requestID;
    if (packetLength > 0) {
        // send
        SNMP_LOGD("Built request, sending to: %s, %d\n", device->_ip.toString().c_str(), device->_port);
        udp->beginPacket(device->_ip, device->_port);
        udp->write(_packetBuffer, packetLength);

        if (!udp->endPacket()) {
            SNMP_LOGW("Failed to send response packet\n");
            return 0;
        }

        // Record tracking
        for (const auto &callback : callbacks) {
            if (callback == nullptr) break;
            callback->pollingInfo->send(request_id);
        }
        this->liveRequests.emplace_back(request_id, GetRequestPDU);
    }
    return request_id;
}

void SNMPManager::teardown_old_requests() {
    for (const auto &container : pollingCallbacks) {
        if (container.pollingInfo->has_timed_out(REQUEST_TIMEOUT)) {
            auto matchingRequest = std::find_if(liveRequests.begin(), liveRequests.end(), [=](const LiveRequest &item) {
                return item == container.pollingInfo->last_request_id;
            });
            if (matchingRequest != liveRequests.end()) liveRequests.erase(matchingRequest);
            container.pollingInfo->reset_poller(false);
        }
    }
}

void SNMPManager::begin() {
    udp->begin(162);
}

void SNMPManager::setUDP(UDP *u) {
    this->udp = u;
}

void SNMPManager::removePoller(ValueCallback *callbackPoller, SNMPDevice *device) {
    // remove poller
    auto it = std::remove_if(this->pollingCallbacks.begin(), this->pollingCallbacks.end(),
                             [=](const ValueCallbackContainer &container) {
                                 return callbackPoller == container.operator->() && device == container.agentDevice;
                             });
    this->pollingCallbacks.erase(it, this->pollingCallbacks.end());
}

bool SNMPManager::responseCallback(const VarBind &responseVarBind, bool success, int errorStatus,
                                   const ValueCallbackContainer &container) {
    if (container) {
        container.pollingInfo->reset_poller(success);
    } else {
        SNMP_LOGW("Unsolicited OID response: %s\n", responseVarBind.oid->string().c_str());
        SNMP_LOGD("Error Status: %d\n", errorStatus);
    }
    return true;
}

SNMP_ERROR_RESPONSE SNMPManager::process_incoming_packets() {
    int packetLength = udp->parsePacket();
    if (packetLength > 0) {
        SNMP_LOGD("Manager Received packet from: %s, of size: %d", udp->remoteIP().toString().c_str(), packetLength);

        if (packetLength > MAX_SNMP_PACKET_LENGTH) {
            SNMP_LOGW("Incoming packet too large: %d\n", packetLength);
            return SNMP_REQUEST_TOO_LARGE;
        }

        memset(_packetBuffer, 0, MAX_SNMP_PACKET_LENGTH);

        int readBytes = udp->read(_packetBuffer, packetLength);
        if (readBytes != packetLength) {
            SNMP_LOGW("Packet length mismatch: expected: %d, actual: %d\n", packetLength, readBytes);
            return SNMP_REQUEST_INVALID;
        }

        SNMPDevice incomingDevice = SNMPDevice(udp->remoteIP(), udp->remotePort());

        int reponseLength = 0;

        auto start = millis();

        auto ret = handlePacket(_packetBuffer, packetLength, &reponseLength,
                                MAX_SNMP_PACKET_LENGTH, pollingCallbacks, "",
                                "", liveRequests, nullptr, &responseCallback, nullptr, incomingDevice);
        auto end = millis() - start;
        SNMP_LOGI("Handled Manager Response packet in: %lu millis\n", end);
        return ret;
    }
    return SNMP_NO_PACKET;
}

ValueCallback *SNMPManager::addCallbackPoller(SNMPDevice *device, ValueCallback *callback, unsigned long pollingInterval) {
    auto pollingInfo = std::make_shared<PollingInfo>(pollingInterval);
    this->pollingCallbacks.emplace_back(device, callback, pollingInfo);
    return callback;
}

ValueCallback *SNMPManager::addIntegerPoller(SNMPDevice *device, const char *oid, int *value, unsigned long pollingInterval) {
    if (!value) return nullptr;

    auto *oidType = new SortableOIDType(std::string(oid));
    ValueCallback *callback = new IntegerCallback(oidType, value);

    return this->addCallbackPoller(device, callback, pollingInterval);
}

ValueCallback *SNMPManager::addStringPoller(SNMPDevice *device, const char *oid, char *const *value, unsigned long pollingInterval, size_t max_len) {
    if (!value) return nullptr;

    auto *oidType = new SortableOIDType(std::string(oid));
    ValueCallback *callback = new StringCallback(oidType, value, max_len);

    return this->addCallbackPoller(device, callback, pollingInterval);
}
