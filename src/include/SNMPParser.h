#ifndef SNMP_PARSER_h
#define SNMP_PARSER_h

#include "include/defs.h"

#include "include/SNMPPacket.h"
#include "include/SNMPResponse.h"
#include "include/ValueCallbacks.h"

#include <deque>

typedef void (*informCB)(void* ctx, snmp_request_id_t, bool);

bool handleGetRequestPDU(std::deque<ValueCallback*> &callbacks, std::deque<VarBind>& varbindList, std::deque<VarBind>& outResponseList, SNMP_VERSION version, bool isGetNextRequest);
bool handleSetRequestPDU(std::deque<ValueCallback*> &callbacks, std::deque<VarBind>& varbindList, std::deque<VarBind>& outResponseList, SNMP_VERSION version);
bool handleGetBulkRequestPDU(std::deque<ValueCallback*> &callbacks, std::deque<VarBind>& varbindList, std::deque<VarBind>& outResponseList, unsigned int nonRepeaters, unsigned int maxRepititions);

SNMP_ERROR_RESPONSE handlePacket(uint8_t* buffer, int packetLength, int* responseLength, int max_packet_size, std::deque<ValueCallback*> &callbacks, const std::string &_community, const std::string &_readOnlyCommunity, informCB = nullptr, void* ctx = nullptr);

#endif