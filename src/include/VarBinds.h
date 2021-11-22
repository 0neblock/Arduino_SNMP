#ifndef VarBinds_h
#define VarBinds_h

#include "BER.h"

#include <memory>

class VarBind {
  public:
    VarBind(const std::shared_ptr<OIDType> &oid, const std::shared_ptr<BER_CONTAINER> &value) : oid(oid),
                                                                                                type(value->_type),
                                                                                                value(value){};

    VarBind(const std::shared_ptr<OIDType> &oid, const SNMP_ERROR_STATUS error) : oid(oid), type(NULLTYPE),
                                                                                  value(new NullType()),
                                                                                  errorStatus(error){};

    VarBind(const std::shared_ptr<OIDType> &oid) : oid(oid), type(NULLTYPE), value(new NullType()){};

    VarBind(const OIDType *oid, const std::shared_ptr<BER_CONTAINER> &value) : oid(oid->cloneOID()),
                                                                               type(value->_type),
                                                                               value(value){};

    VarBind(const OIDType *oid, const SNMP_ERROR_STATUS error) : oid(oid->cloneOID()), type(NULLTYPE),
                                                                 value(new NullType()), errorStatus(error){};

    VarBind(const VarBind &vb, const std::shared_ptr<BER_CONTAINER> &value) : oid(vb.oid), type(value->_type),
                                                                              value(value){};

    VarBind(const VarBind &vb) : oid(vb.oid), type(vb.type), value(vb.value), errorStatus(vb.errorStatus){};

    const std::shared_ptr<OIDType> oid;
    const ASN_TYPE type;
    const std::shared_ptr<BER_CONTAINER> value;
    const SNMP_ERROR_STATUS errorStatus = NO_ERROR;

    bool is_error_type() const {
        return value->_type == NULLTYPE ||
               value->_type == NOSUCHOBJECT ||
               value->_type == NOSUCHINSTANCE ||
               value->_type == ENDOFMIBVIEW;
    }
};

#endif