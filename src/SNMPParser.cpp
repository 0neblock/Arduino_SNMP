#include "include/SNMPParser.h"
#include <string>


static SNMP_PERMISSION getPermissionOfRequest(const SNMPPacket &request, const std::string &_community,
                                              const std::string &_readOnlyCommunity) {
    SNMP_PERMISSION requestPermission = SNMP_PERM_NONE;
    SNMP_LOGD("communitystring in packet: %s\n", request.communityString.c_str());

    if (_readOnlyCommunity != "" && _readOnlyCommunity == request.communityString) {// snmprequest->version != 1
        requestPermission = SNMP_PERM_READ_ONLY;
    }

    if (_community == request.communityString) {// snmprequest->version != 1
        requestPermission = SNMP_PERM_READ_WRITE;
    }
    return requestPermission;
}

SNMP_ERROR_RESPONSE handlePacket(uint8_t *buffer, int packetLength, int *responseLength, int max_packet_size,
                                 std::deque<ValueCallbackContainer> &callbacks, const std::string &_community,
                                 const std::string &_readOnlyCommunity,
                                 std::unordered_map<snmp_request_id_t, ASN_TYPE> &liveRequests, informCB informCallback,
                                 responseCB responseCallback, void *ctx, const SNMPDevice &device) {
    // we can't type the incoming packet, so we only type the packets we send out
    SNMPPacket incomingPacket;

    SNMP_PACKET_PARSE_ERROR parseResult = incomingPacket.parseFrom(buffer, packetLength);
    if (parseResult <= 0) {
        SNMP_LOGW("Received Error code: %d when attempting to parse\n", parseResult);
        return SNMP_REQUEST_INVALID;
    }

    SNMP_LOGD("Valid SNMP Packet!\n");

    if (incomingPacket.packetPDUType == GetResponsePDU) {
        SNMP_LOGD("Received GetResponse! requestID: %u\n", incomingPacket.requestID);
        auto matchingRequest = liveRequests.find(incomingPacket.requestID);
        if (matchingRequest != liveRequests.end()) {
            // Update SNMPDevice with community and version
            SNMPDevice updatedDevice = SNMPDevice(device, incomingPacket.snmpVersion, incomingPacket.communityString);
            SNMP_ERROR_RESPONSE ret = SNMP_GENERIC_ERROR;
            switch (matchingRequest->second) {
                case GetRequestPDU:
                case SetRequestPDU: {
                    // Match response to request
                    handleGetResponsePDU(callbacks, incomingPacket.varbindList, incomingPacket.errorStatus,
                                         incomingPacket.errorIndex, updatedDevice, responseCallback);
                    ret = SNMP_RESPONSE_RECEIVED;
                    break;
                }
                case InformRequestPDU:
                    if (informCallback)
                        informCallback(ctx, incomingPacket.requestID, !incomingPacket.errorStatus.errorStatus);
                    ret = SNMP_INFORM_RESPONSE_OCCURRED;
                    break;
                default:
                    SNMP_LOGW(
                            "Can't handle the response packet from request type (this should be static assert): %u, %u, %u\n",
                            matchingRequest->first, matchingRequest->second, incomingPacket.requestID);
                    ret = SNMP_GENERIC_ERROR;
                    break;
            }
            liveRequests.erase(incomingPacket.requestID);
            return ret;
        } else {
            SNMP_LOGW("Not sure what to do with ResponsePacket: %u\n", incomingPacket.requestID);
            return SNMP_UNSOLICITED_RESPONSE_PDU_RECEIVED;
        }
    }

    SNMP_PERMISSION requestPermission = getPermissionOfRequest(incomingPacket, _community, _readOnlyCommunity);
    if (requestPermission == SNMP_PERM_NONE) {
        SNMP_LOGW("Invalid communitystring provided: %s, no response to give\n",
                  incomingPacket.communityString.c_str());
        return SNMP_REQUEST_INVALID_COMMUNITY;
    }

    // this will take the required stuff from incomingPacket - like requestID and community string etc
    SNMPResponse response = SNMPResponse(incomingPacket);

    std::deque<VarBind> outResponseList;

    bool pass = false;
    SNMP_ERROR_RESPONSE handleStatus = SNMP_NO_ERROR;
    SNMP_ERROR_STATUS globalError = GEN_ERR;

    switch (incomingPacket.packetPDUType) {
        case GetRequestPDU:
        case GetNextRequestPDU:
            pass = handleGetRequestPDU(callbacks, incomingPacket.varbindList, outResponseList,
                                       incomingPacket.snmpVersion, incomingPacket.packetPDUType == GetNextRequestPDU);
            handleStatus = incomingPacket.packetPDUType == GetRequestPDU ? SNMP_GET_OCCURRED : SNMP_GETNEXT_OCCURRED;
            break;
        case GetBulkRequestPDU:
            if (incomingPacket.snmpVersion != SNMP_VERSION_2C) {
                SNMP_LOGD("Received GetBulkRequest in SNMP_VERSION_1");
                pass = false;
                globalError = GEN_ERR;
            } else {
                pass = handleGetBulkRequestPDU(callbacks, incomingPacket.varbindList, outResponseList,
                                               incomingPacket.errorStatus.nonRepeaters,
                                               incomingPacket.errorIndex.maxRepititions);
                handleStatus = SNMP_GETBULK_OCCURRED;
            }
            break;
        case SetRequestPDU:
            if (requestPermission != SNMP_PERM_READ_WRITE) {
                SNMP_LOGD("Attempting to perform a SET without required permissions");
                pass = false;
                globalError = NO_ACCESS;
            } else {
                pass = handleSetRequestPDU(callbacks, incomingPacket.varbindList, outResponseList,
                                           incomingPacket.snmpVersion);
                handleStatus = SNMP_SET_OCCURRED;
            }
            break;
        default:
            SNMP_LOGD("Not sure what to do with SNMP PDU of type: %d\n", incomingPacket.packetPDUType);
            handleStatus = SNMP_UNKNOWN_PDU_OCCURRED;
            pass = false;
            break;
    }

    if (pass) {
        for (const auto &item : outResponseList) {
            if (item.errorStatus != NO_ERROR) {
                response.addErrorResponse(item);
            } else {
                response.addResponse(item);
            }
        }
    } else {
        // Something went wrong, generic error response
        SNMP_LOGD("Handled error when building incomingPacket, error: %d, sending error PDU", globalError);
        response.setGlobalError(globalError, 0, true);
        handleStatus = SNMP_ERROR_PACKET_SENT;
    }

    memset(buffer, 0, max_packet_size);

    *responseLength = response.serialiseInto(buffer, max_packet_size);
    if (*responseLength <= 0) {
        SNMP_LOGD("Failed to build response packet");
        return SNMP_FAILED_SERIALISATION;
    }

    return handleStatus;
}