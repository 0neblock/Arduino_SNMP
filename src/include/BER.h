#ifndef BER_h
#define BER_h

#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <utility>
#include <vector>

#ifdef COMPILING_TESTS

#include "tests/required/IPAddress.h"
#include "tests/required/UDP.h"

#endif

#include "include/defs.h"
#include "small_vector.h"
#include <deque>
#include <memory>

typedef enum ASN_TYPE_WITH_VALUE {
    // Primatives
    INTEGER = 0x02,
    STRING = 0x04,
    NULLTYPE = 0x05,
    OID = 0x06,

    // Complex
    STRUCTURE = 0x30,
    NETWORK_ADDRESS = 0x40,
    COUNTER32 = 0x41,
    GUAGE32 = 0x42,
    USIGNED32 = 0x42,// Same as Guage32
    TIMESTAMP = 0x43,
    OPAQUE = 0x44,
    COUNTER64 = 0x46,

    /*
        FROM: RFC3416
    */
    NOSUCHOBJECT = 0x80,
    NOSUCHINSTANCE = 0x81,
    ENDOFMIBVIEW = 0x82,

    // Structure Types
    GetRequestPDU = 0xA0,
    GetNextRequestPDU = 0xA1,
    GetResponsePDU = 0xA2,
    SetRequestPDU = 0xA3,
    TrapPDU = 0xA4,
    GetBulkRequestPDU = 0xA5,
    InformRequestPDU = 0xA6,
    Trapv2PDU = 0xA7

} ASN_TYPE;

const char *ASN_TYPE_STR(ASN_TYPE);

#define ASN_PDU_TYPE_MIN_VALUE GetRequestPDU
#define ASN_PDU_TYPE_MAX_VALUE Trapv2PDU

#define MAX_DYNAMIC_ASN_TYPE COUNTER64

typedef int SNMP_BUFFER_PARSE_ERROR;
typedef int SNMP_BUFFER_ENCODE_ERROR;

#define SNMP_BUFFER_ERROR_MAX_LEN_EXCEEDED -1 + SNMP_BUFFER_PARSE_ERROR_OFFSET
#define SNMP_BUFFER_ERROR_TLV_TOO_SMALL -2 + SNMP_BUFFER_PARSE_ERROR_OFFSET
#define SNMP_BUFFER_ERROR_PROBLEM_DESERIALISING -3 + SNMP_BUFFER_PARSE_ERROR_OFFSET
#define SNMP_BUFFER_ERROR_UNKNOWN_TYPE -4 + SNMP_BUFFER_PARSE_ERROR_OFFSET
#define SNMP_BUFFER_ERROR_TYPE_MISMATCH -5 + SNMP_BUFFER_PARSE_ERROR_OFFSET
#define SNMP_BUFFER_ERROR_OCTET_TOO_BIG -6 + SNMP_BUFFER_PARSE_ERROR_OFFSET
#define SNMP_BUFFER_ERROR_INVALID_OID -7 + SNMP_BUFFER_PARSE_ERROR_OFFSET

#define SNMP_BUFFER_ENCODE_ERR_LEN_EXCEEDED -1 + SNMP_BUFFER_ENCODE_ERROR_OFFSET
#define SNMP_BUFFER_ENCODE_ERROR_INVALID_ITEM -2 + SNMP_BUFFER_ENCODE_ERROR_OFFSET
#define SNMP_BUFFER_ENCODE_ERROR_INVALID_OID -7 + SNMP_BUFFER_ENCODE_ERROR_OFFSET

#define CHECK_DECODE_ERR(i) \
    if (i < 0) return i
#define CHECK_ENCODE_ERR(i) \
    if (i < 0) return i

// primitive types inherits straight off the container, complex come off complexType
// all primitives have to serialiseInto themselves (type, length, data), to be put straight into the packet.
// for deserialising, from the parent container we check the type, then create anobject of that type and calls deSerialise,
// passing in the data, which pulls it out and saves, and if complex, first split up it schildren into seperate BERs,
// then creates and passes them creates a child with it's data using the same process.


class BER_CONTAINER {
  public:
    BER_CONTAINER(ASN_TYPE type) : _type(type){};

    virtual ~BER_CONTAINER(){};

    const ASN_TYPE _type;
    int _length = 0;

  protected:
    // Serialise object in BER notation into buf, with a maximum size of max_len; returns number of bytes used
    virtual int serialise(uint8_t *buf, const size_t max_len) const;

    virtual int serialise(uint8_t *buf, const size_t max_len, const size_t known_length) const;

    // returns number of bytes used from buf, limited by max_len, return -1 if failed to parse
    virtual int fromBuffer(const uint8_t *buf, const size_t max_len);

    friend class ComplexType;
};

typedef sbo::small_vector<std::shared_ptr<BER_CONTAINER>, 8> BerContainerList;
typedef sbo::small_vector<uint8_t, 16> OIDTypeData;
typedef sbo::small_vector<uint8_t, 16> OpaqueTypeData;


class NetworkAddress : public BER_CONTAINER {
  public:
    NetworkAddress() : BER_CONTAINER(NETWORK_ADDRESS){};

    explicit NetworkAddress(const IPAddress &ip) : NetworkAddress() {
        _value = ip;
    };

    IPAddress _value = INADDR_NONE;

  protected:
    int serialise(uint8_t *buf, const size_t max_len) const override;

    int fromBuffer(const uint8_t *buf, const size_t max_len) override;
};


class IntegerType : public BER_CONTAINER {
  public:
    IntegerType() : BER_CONTAINER(INTEGER){};
    IntegerType(ASN_TYPE type) : BER_CONTAINER(type){};

    explicit IntegerType(ASN_TYPE type, int value) : IntegerType(type) {
        _value = value;
    };

    explicit IntegerType(int value) : IntegerType() {
        _value = value;
    };

    int _value = 0;

  protected:
    int serialise(uint8_t *buf, const size_t max_len) const override;

    int fromBuffer(const uint8_t *buf, const size_t max_len) override;
};

class TimestampType : public IntegerType {
  public:
    TimestampType() : IntegerType(TIMESTAMP){};

    explicit TimestampType(unsigned long value) : IntegerType(TIMESTAMP, value){};
};

class OctetType : public BER_CONTAINER {
  public:
    explicit OctetType(const std::string &value) : BER_CONTAINER(STRING), _value(value){};

    std::string _value;

  protected:
    int serialise(uint8_t *buf, const size_t max_len) const override;

    int fromBuffer(const uint8_t *buf, const size_t max_len) override;

    OctetType() : BER_CONTAINER(STRING){};

    friend class ComplexType;// So ComplexType can use the empty constructor
};

class OpaqueType : public BER_CONTAINER {
  public:
    OpaqueType(uint8_t *value, int length) : OpaqueType() {
        this->_value.reserve(length);
        for (int j = 0; j < length; j++) {
            this->_value.push_back(*(value + j));
        }
    }

    OpaqueTypeData _value;

  protected:
    int serialise(uint8_t *buf, const size_t max_len) const override;

    int fromBuffer(const uint8_t *buf, const size_t max_len) override;

    OpaqueType() : BER_CONTAINER(OPAQUE){};

    friend class ComplexType;// So ComplexType can use the empty constructor
};

class OIDTestHelper {
};

class OIDType : public BER_CONTAINER {
  public:
    explicit OIDType(std::string value) : BER_CONTAINER(OID), _value(std::move(value)) {
        // When creating a user OID, we generate our data vector immediately
        this->valid = this->generateInternalData();
    };

    std::shared_ptr<OIDType> cloneOID() const {
        // Copy all available data points
        return std::shared_ptr<OIDType>(new OIDType(this->_value, this->data, this->valid));
    };

    // This is for display and finding purposes, only builds the string from data on request
    const std::string &string();

    bool valid = false;

    bool equals(const std::shared_ptr<OIDType> &oid) const {
        return this->data == oid->data;
    }

    bool equals(const OIDType *oid) const {
        return this->data == oid->data;
    }

    bool isSubTreeOf(const OIDType *const oid) const {
        // If the oid being searched for is smaller than us and is wholly contained in us, true
        // compare from the back so it's quicker
        return oid->data.size() < this->data.size() &&
               std::equal(oid->data.rbegin(), oid->data.rend(),
                          this->data.rbegin() + (this->data.size() - oid->data.size()));
    }

  protected:
    int serialise(uint8_t *buf, const size_t max_len) const override;

    int fromBuffer(const uint8_t *buf, const size_t max_len) override;

    friend class ComplexType;// So ComplexType gets the empty constructor
    OIDType() : BER_CONTAINER(OID){};

    // Value is only filled if we make it ourselves or a decoded one gets string() called on it
    std::string _value;
    OIDTypeData data;

  private:
    explicit OIDType(std::string value, const OIDTypeData &data, bool valid) : BER_CONTAINER(OID),
                                                                               valid(valid),
                                                                               _value(std::move(value)),
                                                                               data(data){};

    bool generateInternalData();
};

class SortableOIDType : public OIDType {
  public:
    explicit SortableOIDType(const std::string &value) : OIDType(value), sortingMap(generateSortingMap()) {}

    static bool sort_oids(const SortableOIDType *oid1, const SortableOIDType *oid2);

    bool operator<(SortableOIDType &other) const {
        return SortableOIDType::sort_oids(this, &other);
    }

    const std::vector<unsigned long> sortingMap;

  private:
    const std::vector<unsigned long> generateSortingMap() const;
};

class NullType : public BER_CONTAINER {
  public:
    NullType() : BER_CONTAINER(NULLTYPE){};
    NullType(ASN_TYPE type) : BER_CONTAINER(type){};

  protected:
    int serialise(uint8_t *buf, const size_t max_len) const override;

    int fromBuffer(const uint8_t *buf, const size_t max_len) override;
};

class ImplicitNullType : public NullType {
  public:
    explicit ImplicitNullType(ASN_TYPE type) : NullType(type){};
};

class Counter64 : public BER_CONTAINER {
  public:
    Counter64() : BER_CONTAINER(COUNTER64){};

    explicit Counter64(uint64_t value) : Counter64() {
        _value = value;
    };

    uint64_t _value = 0;

  protected:
    int serialise(uint8_t *buf, const size_t max_len) const override;

    int fromBuffer(const uint8_t *buf, const size_t max_len) override;
};

class Counter32 : public IntegerType {
  public:
    Counter32() : IntegerType(COUNTER32){};

    explicit Counter32(unsigned int value) : IntegerType(COUNTER32, value){};
};

class Guage : public IntegerType {// Unsigned int
  public:
    Guage() : IntegerType(GUAGE32){};

    explicit Guage(unsigned int value) : IntegerType(GUAGE32, value){};
};


class ComplexType : public BER_CONTAINER {
  public:
    explicit ComplexType(ASN_TYPE type) : BER_CONTAINER(type){};

    BerContainerList values;

    int fromBuffer(const uint8_t *buf, const size_t max_len) override;

    int serialise(uint8_t *buf, const size_t max_len) const override;

    std::shared_ptr<BER_CONTAINER> addValueToList(const std::shared_ptr<BER_CONTAINER> &newObj) {
        this->values.push_back(newObj);
        return newObj;
    }

  private:
    static std::shared_ptr<BER_CONTAINER> createObjectForType(ASN_TYPE valueType);
};


#endif