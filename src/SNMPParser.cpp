#include "include/SNMPParser.h"
#include <string>

static SNMP_PERMISSION getPermissionOfRequest(const SNMPPacket& request, const std::string& _community, const std::string& _readOnlyCommunity){
    SNMP_PERMISSION requestPermission = SNMP_PERM_NONE;
    SNMP_LOGD("community string in packet: %s\n", request.communityString.c_str());

    if(!_readOnlyCommunity.empty() && _readOnlyCommunity == request.communityString) { // snmprequest->version != 1
        requestPermission = SNMP_PERM_READ_ONLY;
    }

    if(_community == request.communityString) { // snmprequest->version != 1
        requestPermission = SNMP_PERM_READ_WRITE;
    }
    return requestPermission;
}

SNMP_ERROR_RESPONSE handlePacket(uint8_t* buffer, int packetLength, int* responseLength, int max_packet_size, std::deque<ValueCallback*> &callbacks, const std::string& _community, const std::string& _readOnlyCommunity, informCB informCallback, void* ctx){
    SNMPPacket request;

    SNMP_PACKET_PARSE_ERROR parseResult = request.parseFrom(buffer, packetLength);
    if(parseResult <= 0){
        SNMP_LOGW("Received Error code: %d when attempting to parse\n", parseResult);
        return SNMP_REQUEST_INVALID;
    }

    SNMP_LOGD("Valid SNMP Packet!");

    if(request.packetPDUType == GetResponsePDU){
        SNMP_LOGD("Received GetResponse! probably as a result of a recent InformTrap: %lu", request.requestID);
        if(informCallback){
            informCallback(ctx, request.requestID, !request.errorStatus.errorStatus);
        } else {
            SNMP_LOGW("Not sure what to do with Inform\n");
        }
        return SNMP_INFORM_RESPONSE_OCCURRED;
    }

    SNMP_PERMISSION requestPermission = getPermissionOfRequest(request, _community, _readOnlyCommunity);
    if(requestPermission == SNMP_PERM_NONE){
        SNMP_LOGW("Invalid communitystring provided: %s, no response to give\n", request.communityString.c_str());
        return SNMP_REQUEST_INVALID_COMMUNITY;
    }
    
    // this will take the required stuff from request - like requestID and community string etc
    SNMPResponse response = SNMPResponse(request);

    std::deque<VarBind> outResponseList;

    bool pass = false;
    SNMP_ERROR_RESPONSE handleStatus = SNMP_NO_ERROR;
    SNMP_ERROR_STATUS globalError = GEN_ERR;

    switch(request.packetPDUType){
        case GetRequestPDU:
        case GetNextRequestPDU:
            pass = handleGetRequestPDU(callbacks, request.varbindList, outResponseList, request.snmpVersion, request.packetPDUType == GetNextRequestPDU);
            handleStatus = request.packetPDUType == GetRequestPDU ? SNMP_GET_OCCURRED : SNMP_GETNEXT_OCCURRED;
        break;
        case GetBulkRequestPDU:
            if(request.snmpVersion != SNMP_VERSION_2C){
                SNMP_LOGD("Received GetBulkRequest in SNMP_VERSION_1");
                pass = false;
                globalError = GEN_ERR;
            } else {
                pass = handleGetBulkRequestPDU(callbacks, request.varbindList, outResponseList, request.errorStatus.nonRepeaters, request.errorIndex.maxRepititions);
                handleStatus = SNMP_GETBULK_OCCURRED;
            }
        break;
        case SetRequestPDU:
            if(requestPermission != SNMP_PERM_READ_WRITE){
                SNMP_LOGD("Attempting to perform a SET without required permissions");
                pass = false;
                globalError = NO_ACCESS;
            } else {
                pass = handleSetRequestPDU(callbacks, request.varbindList, outResponseList, request.snmpVersion);
                handleStatus = SNMP_SET_OCCURRED;
            }
        break;
        default:
            SNMP_LOGD("Not sure what to do with SNMP PDU of type: %d\n", request.packetPDUType);
            handleStatus = SNMP_UNKNOWN_PDU_OCCURRED;
            pass = false;
        break;
    }

    if(pass){
        for(const auto& item : outResponseList){
            if(item.errorStatus != NO_ERROR){
                response.addErrorResponse(item);
            } else {
                response.addResponse(item);
            }
        }
    } else {
        // Something went wrong, generic error response
        SNMP_LOGD("Handled error when building request, error: %d, sending error PDU", globalError);
        response.setGlobalError(globalError, 0, true);
        handleStatus = SNMP_ERROR_PACKET_SENT;
    }

    memset(buffer, 0, max_packet_size);

    *responseLength = response.serialiseInto(buffer, max_packet_size);
    if(*responseLength <= 0){
        SNMP_LOGD("Failed to build response packet");
        return SNMP_FAILED_SERIALISATION;
    }

    return handleStatus;
}