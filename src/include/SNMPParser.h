#ifndef SNMP_PARSER_h
#define SNMP_PARSER_h

#include "include/defs.h"

//#includ# "include/SNMPPacket.h"
#include "include/PollingInfo.h"
#include "include/SNMPResponse.h"
#include "include/ValueCallbacks.h"

#include <deque>
#include <list>
#include <unordered_map>

typedef bool (*informCB)(void *ctx, snmp_request_id_t, bool);

bool handleGetRequestPDU(std::deque<ValueCallbackContainer> &callbacks, std::deque<VarBind> &varbindList,
                         std::deque<VarBind> &outResponseList, SNMP_VERSION version, bool isGetNextRequest);

bool handleSetRequestPDU(std::deque<ValueCallbackContainer> &callbacks, std::deque<VarBind> &varbindList,
                         std::deque<VarBind> &outResponseList, SNMP_VERSION version);

bool handleGetBulkRequestPDU(std::deque<ValueCallbackContainer> &callbacks, std::deque<VarBind> &varbindList,
                             std::deque<VarBind> &outResponseList, unsigned int nonRepeaters,
                             unsigned int maxRepititions);

bool handleGetResponsePDU(std::deque<ValueCallbackContainer> &callbacks, std::deque<VarBind> &varbindList,
                          ErrorStatus errorStatus, ErrorIndex errorIndex, const SNMPDevice &device = NO_DEVICE,
                          responseCB responseCallback = nullptr);

SNMP_ERROR_RESPONSE handlePacket(uint8_t *buffer, int packetLength, int *responseLength, int max_packet_size,
                                 std::deque<ValueCallbackContainer> &callbacks, const std::string &_community,
                                 const std::string &_readOnlyCommunity,
                                 std::unordered_map<snmp_request_id_t, ASN_TYPE> &liveRequests,
                                 informCB informCallback = nullptr,
                                 responseCB responseCallback = nullptr, void *ctx = nullptr,
                                 const SNMPDevice &device = NO_DEVICE);

#endif