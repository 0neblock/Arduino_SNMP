#include "include/BER.h"
#include "include/SNMPParser.h"
#include "include/ValueCallbacks.h"
#include "include/defs.h"

bool handleGetRequestPDU(const CallbackList &callbacks, const VarBindList &varbindList,
                         VarBindList &outResponseList, SNMP_VERSION snmpVersion, bool isGetNextRequest) {
    SNMP_LOGD("handleGetRequestPDU\n");
    for (const VarBind &requestVarBind : varbindList) {
        SNMP_LOGD("finding callback for OID: %s\n", requestVarBind.oid->string().c_str());
        auto &callback = ValueCallback::findCallback(callbacks, requestVarBind.oid.get(), isGetNextRequest);
        if (!callback) {
            SNMP_LOGD("Couldn't find callback\n");
#if 1
            // According to RFC3416 we should be setting the value to 'noSuchObject' or 'noSuchInstance,
            // but this doesn't seem to render nicely in tools, so possibly revert to old NO_SUCH_NAME error
            if (isGetNextRequest) {
                // if it's a walk it's an endOfMibView
                outResponseList.emplace_back(requestVarBind, std::make_shared<ImplicitNullType>(ENDOFMIBVIEW));
            } else {
                outResponseList.emplace_back(requestVarBind, std::make_shared<ImplicitNullType>(NOSUCHOBJECT));
            }

#else
            outResponseList.emplace_back(generateErrorResponse(SNMP_ERROR_VERSION_CTRL_DEF(NOT_WRITABLE, snmpVersion, NO_SUCH_NAME), requestVarBind.oid));
#endif
            continue;
        }

        SNMP_LOGD("Callback found with OID: %s\n", callback->OID->string().c_str());
        //NOTE: we could just use the same pointer as the reqwuest, but delete the value and add a new one. Will have to figure out what to do if it errors, do that later
        auto value = ValueCallback::getValueForCallback(callback);

        if (!value) {
            SNMP_LOGD("Couldn't get value for callback\n");
            outResponseList.emplace_back(callback->OID, SNMP_ERROR_VERSION_CTRL(GEN_ERR, snmpVersion));
            continue;
        }

        outResponseList.emplace_back(callback->OID, value);
    }
    return true;// we didn't fail in our job, even if we filled in nothing
}

bool handleSetRequestPDU(const CallbackList &callbacks, const VarBindList &varbindList,
                         VarBindList &outResponseList, SNMP_VERSION snmpVersion) {
    SNMP_LOGD("handleSetRequestPDU\n");
    for (const VarBind &requestVarBind : varbindList) {
        SNMP_LOGD("finding callback for OID: %s\n", requestVarBind.oid->string().c_str());
        auto &callback = ValueCallback::findCallback(callbacks, requestVarBind.oid.get(), false);
        if (!callback) {
            SNMP_LOGD("Couldn't find callback\n");
            outResponseList.emplace_back(requestVarBind.oid,
                                         SNMP_ERROR_VERSION_CTRL_DEF(NOT_WRITABLE, snmpVersion, NO_SUCH_NAME));
            continue;
        }

        SNMP_LOGD("Callback found with OID: %s\n", callback->OID->string().c_str());

        if (callback->type != requestVarBind.type) {
            SNMP_LOGD("Callback Type mismatch: %d\n", callback->type);
            outResponseList.emplace_back(requestVarBind.oid,
                                         SNMP_ERROR_VERSION_CTRL_DEF(WRONG_TYPE, snmpVersion, BAD_VALUE));
            continue;
        }

        if (!callback->isSettable) {
            SNMP_LOGD("Cannot set this object\n");
            outResponseList.emplace_back(requestVarBind.oid, SNMP_ERROR_VERSION_CTRL(READ_ONLY, snmpVersion));
            continue;
        }
        //NOTE: we could just use the same pointer as the reqwuest, but delete the value and add a new one. Will have to figure out what to do if it errors, do that later
        SNMP_ERROR_STATUS setError = ValueCallback::setValueForCallback(callback, requestVarBind.value, true);
        if (setError != NO_ERROR) {
            SNMP_LOGD("Attempting to set Variable failed: %d\n", setError);
            outResponseList.emplace_back(callback->OID, SNMP_ERROR_VERSION_CTRL(setError, snmpVersion));
            continue;
        }

        auto value = ValueCallback::getValueForCallback(callback);

        if (!value) {
            SNMP_LOGD("Couldn't get value for callback\n");
            outResponseList.emplace_back(callback->OID, SNMP_ERROR_VERSION_CTRL(GEN_ERR, snmpVersion));
            continue;
        }

        outResponseList.emplace_back(callback->OID, value);
    }
    return true;// we didn't fail in our job
}

bool handleGetBulkRequestPDU(const CallbackList &callbacks, const VarBindList &varbindList,
                             VarBindList &outResponseList, unsigned int nonRepeaters,
                             unsigned int maxRepititions) {
    // from https://tools.ietf.org/html/rfc1448#page-18
    SNMP_LOGD("handleGetBulkRequestPDU, nonRepeaters:%d, maxRepititions:%d, varbindSize:%ld\n", nonRepeaters,
              maxRepititions, varbindList.size());
    // nonRepeaters is MIN(nonRepeaters, varbindList.size()
    // repeaters is the extra of varbindList.size() - nonRepeaters) which get 'walked' maxRepititions times

    SNMP_LOGD("handling nonRepeaters\n");
    if (nonRepeaters > 0) {
        // handle GET normally, but mark endOfMibView if not found
        for (unsigned int i = 0; i < nonRepeaters && i < varbindList.size(); i++) {
            const VarBind &requestVarBind = varbindList[i];
            auto &callback = ValueCallback::findCallback(callbacks, requestVarBind.oid.get(), true);
            if (!callback) {
                outResponseList.emplace_back(requestVarBind, std::make_shared<ImplicitNullType>(ENDOFMIBVIEW));
                continue;
            }

            auto value = ValueCallback::getValueForCallback(callback);
            if (!value) {
                SNMP_LOGD("Couldn't get value for callback\n");
                outResponseList.emplace_back(callback->OID, GEN_ERR);
                continue;
            }
            outResponseList.emplace_back(requestVarBind, value);
        }
    }

    if (varbindList.size() > nonRepeaters) {
        // For each extra varbind, WALK that tree until maxRepititions or endOfMibView
        SNMP_LOGD("handling repeaters\n");
        unsigned int repeatingVarBinds = varbindList.size() - nonRepeaters;

        for (unsigned int i = 0; i < repeatingVarBinds; i++) {
            // Store first varbind to get for each line
            auto oid = varbindList[i + nonRepeaters].oid;
            size_t foundAt = 0;

            for (unsigned int j = 0; j < maxRepititions; j++) {
                SNMP_LOGD("finding next callback for OID: %s\n", oid->string().c_str());
                auto &callback = ValueCallback::findCallback(callbacks, oid.get(), true, foundAt, &foundAt);
                if (!callback) {
                    // We're done, mark endOfMibView
                    outResponseList.emplace_back(oid, std::make_shared<ImplicitNullType>(ENDOFMIBVIEW));
                    break;
                }

                auto value = ValueCallback::getValueForCallback(callback);

                if (!value) {
                    SNMP_LOGD("Couldn't get value for callback\n");
                    outResponseList.emplace_back(callback->OID, GEN_ERR);
                    break;
                }

                outResponseList.emplace_back(callback->OID, value);

                // set next oid to callback OID
                oid = callback->OID->cloneOID();
            }

            //SNMP_LOGD("Walked tree of %s, %d times", (*varbindList)[i+nonRepeaters]->oid->_value, j);
        }
    }

    return true;
}

bool handleGetResponsePDU(const CallbackList &callbacks, const VarBindList &varbindList,
                          ErrorStatus errorStatus, ErrorIndex errorIndex, const SNMPDevice &device,
                          responseCB responseCallback) {
    SNMP_LOGD("handleGetResponsePDU\n");
    int i = 1;
    for (const VarBind &responseVarBind : varbindList) {
        SNMP_LOGD("finding callback for OID: %s\n", responseVarBind.oid->string().c_str());
        auto &callback = ValueCallback::findCallback(callbacks, responseVarBind.oid.get(), false, 0, nullptr, device);
        bool isError = responseVarBind.is_error_type() || i == errorIndex.errorIndex;
        if (callback) {
            if (isError) {
                //TODO: If we get one invalid response, do we stop processing the remaining VBs?
                SNMP_LOGI("Invalid response found for OID: %s\n", callback->OID->string().c_str());
                SNMP_LOGI("Response type: %s %d\n", ASN_TYPE_STR(responseVarBind.type), responseVarBind.type);
                if (i == errorIndex.errorIndex) {
                    SNMP_LOGI("Error recorded for OID: %s, %0xd\n", callback->OID->string().c_str(), errorStatus.errorStatus);
                }
            } else {
                auto setAttempt = ValueCallback::setValueForCallback(callback, responseVarBind.value, false);
                SNMP_LOGI("Recorded GetResponse for OID: %s, setAttempt: %d\n", callback->OID->string().c_str(),
                          setAttempt);
            }
        } else {
            // If we'd done a GetNextRequest, we might not have the ValueCallback in our callbacks, so how to tell application?
            SNMP_LOGD("Couldn't find callback\n");
        }

        if (responseCallback)
            responseCallback(responseVarBind, !isError, i == errorIndex.errorIndex ? errorStatus.errorStatus : 0,
                             callback);

        i++;
    }
    return true;// we didn't fail in our job, even if we filled in nothing
}