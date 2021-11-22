#ifndef SNMP_PARSER_h
#define SNMP_PARSER_h

#include "include/BER.h"
#include "include/ValueCallbacks.h"
#include "include/VarBinds.h"
#include "include/defs.h"
#include "small_vector.h"

#include <deque>
#include <list>
#include <unordered_map>

typedef bool (*informCB)(void *ctx, snmp_request_id_t, bool);

class LiveRequest {
  public:
    LiveRequest(snmp_request_id_t id, ASN_TYPE type) : requestId(id), type(type){};

    bool operator==(snmp_request_id_t requestId) const {
        return this->requestId == requestId;
    }

    snmp_request_id_t requestId;
    ASN_TYPE type;
};

typedef std::deque<ValueCallbackContainer> CallbackList;
typedef sbo::small_vector<VarBind, 8> VarBindList;
typedef sbo::small_vector<LiveRequest, 8> LiveRequestList;

bool handleGetRequestPDU(const CallbackList &callbacks, const VarBindList &varbindList,
                         VarBindList &outResponseList, SNMP_VERSION snmpVersion, bool isGetNextRequest);

bool handleSetRequestPDU(const CallbackList &callbacks, const VarBindList &varbindList,
                         VarBindList &outResponseList, SNMP_VERSION snmpVersion);

bool handleGetBulkRequestPDU(const CallbackList &callbacks, const VarBindList &varbindList,
                             VarBindList &outResponseList, unsigned int nonRepeaters,
                             unsigned int maxRepititions);

bool handleGetResponsePDU(const CallbackList &callbacks, const VarBindList &varbindList,
                          ErrorStatus errorStatus, ErrorIndex errorIndex, const SNMPDevice &device = NO_DEVICE,
                          responseCB responseCallback = nullptr);

SNMP_ERROR_RESPONSE handlePacket(uint8_t *buffer, int packetLength, int *responseLength, int max_packet_size,
                                 CallbackList &callbacks, const std::string &_community,
                                 const std::string &_readOnlyCommunity,
                                 LiveRequestList &liveRequests,
                                 informCB informCallback = nullptr,
                                 responseCB responseCallback = nullptr, void *ctx = nullptr,
                                 const SNMPDevice &device = NO_DEVICE);

#endif