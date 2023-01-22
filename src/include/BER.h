#ifndef BER_h
#define BER_h

#include <math.h>
#include <utility>
#include <vector>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <stdint.h>
#include <string>

#ifdef COMPILING_TESTS
    #include "tests/required/IPAddress.h"
    #include "tests/required/UDP.h"
#else
    #include <Arduino.h>
    #include "IPAddress.h"
#endif

#include <memory>
#include "include/defs.h"

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
    GAUGE32 = 0x42,
    USIGNED32 = 0x42, // Same as Gauge32
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

#define ASN_PDU_TYPE_MIN_VALUE GetRequestPDU
#define ASN_PDU_TYPE_MAX_VALUE Trapv2PDU

#define MAX_DYNAMIC_ASN_TYPE COUNTER64

typedef int SNMP_BUFFER_PARSE_ERROR;
typedef int SNMP_BUFFER_ENCODE_ERROR;

#define SNMP_BUFFER_ERROR_MAX_LEN_EXCEEDED (-1 + SNMP_BUFFER_PARSE_ERROR_OFFSET)
#define SNMP_BUFFER_ERROR_TLV_TOO_SMALL (-2 + SNMP_BUFFER_PARSE_ERROR_OFFSET)
#define SNMP_BUFFER_ERROR_PROBLEM_DESERIALISING (-3 + SNMP_BUFFER_PARSE_ERROR_OFFSET)
#define SNMP_BUFFER_ERROR_UNKNOWN_TYPE (-4 + SNMP_BUFFER_PARSE_ERROR_OFFSET)
#define SNMP_BUFFER_ERROR_TYPE_MISMATCH (-5 + SNMP_BUFFER_PARSE_ERROR_OFFSET)
#define SNMP_BUFFER_ERROR_OCTET_TOO_BIG (-6 + SNMP_BUFFER_PARSE_ERROR_OFFSET)
#define SNMP_BUFFER_ERROR_INVALID_OID (-7 + SNMP_BUFFER_PARSE_ERROR_OFFSET)

#define SNMP_BUFFER_ENCODE_ERR_LEN_EXCEEDED (-1 + SNMP_BUFFER_ENCODE_ERROR_OFFSET)
#define SNMP_BUFFER_ENCODE_ERROR_INVALID_ITEM (-2 + SNMP_BUFFER_ENCODE_ERROR_OFFSET)
#define SNMP_BUFFER_ENCODE_ERROR_INVALID_OID (-7 + SNMP_BUFFER_ENCODE_ERROR_OFFSET)

#define CHECK_DECODE_ERR(i) if((i) < 0) return i
#define CHECK_ENCODE_ERR(i) if((i) < 0) return i

// primitive types inherits straight off the container, complex come off complexType
// all primitives have to serialiseInto themselves (type, length, data), to be put straight into the packet.
// for deserialising, from the parent container we check the type, then create anobject of that type and calls deSerialise, passing in the data, which pulls it out and saves, and if complex, first split up it schildren into seperate BERs, then creates and passes them creates a child with it's data using the same process.


class BER_CONTAINER {
  public:
    BER_CONTAINER(ASN_TYPE type) : _type(type){};
    virtual ~BER_CONTAINER()= default;

    ASN_TYPE _type;
    int _length = 0;

  protected:
    // Serialise object in BER notation into buf, with a maximum size of max_len; returns number of bytes used
    virtual int serialise(uint8_t* buf, size_t max_len);
    virtual int serialise(uint8_t* buf, size_t max_len, size_t known_length);

    // returns number of bytes used from buf, limited by max_len, return -1 if failed to parse
    virtual int fromBuffer(const uint8_t *buf, size_t max_len);

    friend class ComplexType;
};

class NetworkAddress: public BER_CONTAINER {
  public:
    NetworkAddress(): BER_CONTAINER(NETWORK_ADDRESS) {};
    explicit NetworkAddress(const IPAddress& ip): NetworkAddress(){
        _value = ip;
    };

    IPAddress _value = INADDR_NONE;

protected:
    int serialise(uint8_t* buf, size_t max_len) override;
    int fromBuffer(const uint8_t *buf, size_t max_len) override;
};


class IntegerType: public BER_CONTAINER {
  public:
    IntegerType(): BER_CONTAINER(INTEGER) {};
    explicit IntegerType(int value): IntegerType(){
        _value = value;
    };

    int _value = 0;

protected:
    int serialise(uint8_t* buf, size_t max_len) override;
    int fromBuffer(const uint8_t *buf, size_t max_len) override;
};

class TimestampType: public IntegerType {
  public:
    TimestampType(): IntegerType(){
        _type = TIMESTAMP;
    };
    explicit TimestampType(unsigned long value): IntegerType(value){
        _type = TIMESTAMP;
    };
};

class OctetType: public BER_CONTAINER {
  public:
    explicit OctetType(const std::string& value): BER_CONTAINER(STRING), _value(value){};

    std::string _value;

protected:
    int serialise(uint8_t* buf, size_t max_len) override;
    int fromBuffer(const uint8_t *buf, size_t max_len) override;

    OctetType(): BER_CONTAINER(STRING) {};
    friend class ComplexType; // So ComplexType can use the empty constructor
};

class OpaqueType: public BER_CONTAINER {
  public:
    OpaqueType(uint8_t* value, int length): OpaqueType(){
        this->_value = (uint8_t*)calloc(length, sizeof(uint8_t));
        memcpy(this->_value, value, length);
        this->_dataLength = length;
    }
    ~OpaqueType() override{
        if(this->_value) free(this->_value);
    }

    uint8_t* _value = nullptr;
    int _dataLength = 0;

protected:
    int serialise(uint8_t* buf, size_t max_len) override;
    int fromBuffer(const uint8_t *buf, size_t max_len) override;

    OpaqueType(): BER_CONTAINER(OPAQUE) {};
    friend class ComplexType; // So ComplexType can use the empty constructor
};


class OIDType: public BER_CONTAINER {
  public:
    explicit OIDType(const std::string& value): BER_CONTAINER(OID), _value(value) {
        // When creating a user OID, we generate our data vector immediately
        this->valid = this->generateInternalData();
    };

    std::shared_ptr<OIDType> cloneOID() const {
        // Copy all available data points
        return std::shared_ptr<OIDType>(new OIDType(this->_value, this->data, this->valid));
    };

    // This is for display and finding purposes, only builds the string from data on request
    const std::string& string();
    bool valid = false;

    bool equals(const std::shared_ptr<OIDType> oid) const {
        return this->data == oid->data;
    }

    bool equals(const OIDType* oid) const {
        return this->data == oid->data;
    }

    bool isSubTreeOf(const OIDType* const oid){
        // If the oid being searched for is smaller than us and is wholly contained in us, true
        // compare from the back so it's quicker
        return oid->data.size() < this->data.size() &&
            std::equal(oid->data.rbegin(), oid->data.rend(), this->data.rbegin() + (this->data.size() - oid->data.size()));
    }

  protected:
    int serialise(uint8_t* buf, size_t max_len) override;
    int fromBuffer(const uint8_t *buf, size_t max_len) override;

    friend class ComplexType; // So ComplexType gets the empty constructor
    OIDType(): BER_CONTAINER(OID) {};

    // Value is only filled if we make it ourselves or a decoded one gets string() called on it
    std::string _value;
    std::vector<uint8_t> data;

  private:
    explicit OIDType(const std::string& value, const std::vector<uint8_t>& data, bool valid): BER_CONTAINER(OID), valid(valid), _value(value), data(data) {};

    bool generateInternalData();
};

class SortableOIDType: public OIDType {
  public:
    explicit SortableOIDType(const std::string& value): OIDType(value), sortingMap(generateSortingMap()){}

    static bool sort_oids(SortableOIDType* oid1, SortableOIDType* oid2);

    bool operator < (SortableOIDType& other){
        return SortableOIDType::sort_oids(this, &other);
    }

    const std::vector<unsigned long> sortingMap;

  private:
    const std::vector<unsigned long> generateSortingMap() const;
};

class NullType: public BER_CONTAINER {
  public:
    NullType(): BER_CONTAINER(NULLTYPE) {};

protected:
    int serialise(uint8_t* buf, size_t max_len) override;
    int fromBuffer(const uint8_t *buf, size_t max_len) override;
};

class ImplicitNullType: public NullType {
  public:
    explicit ImplicitNullType(ASN_TYPE type): NullType(){
        //TODO: check that we're one of the implicit null types
        _type = type;
    };
};

class Counter64: public BER_CONTAINER {
  public:
    Counter64(): BER_CONTAINER(COUNTER64) {};
    explicit Counter64(uint64_t value): Counter64(){
        _value = value;
    };

    uint64_t _value = 0;

protected:
    int serialise(uint8_t* buf, size_t max_len) override;
    int fromBuffer(const uint8_t *buf, size_t max_len) override;
};

class Counter32: public IntegerType {
  public:
    Counter32(): IntegerType(){
        _type = COUNTER32;
    };
    explicit Counter32(unsigned int value): IntegerType(value){
        _type = COUNTER32;
    };

};

class Gauge: public IntegerType { // Unsigned int
  public:
    Gauge(): IntegerType(){
        _type = GAUGE32;
    };
    explicit Gauge(unsigned int value): IntegerType(value){
        _type = GAUGE32;
    };

};

class ComplexType: public BER_CONTAINER {
  public:
    explicit ComplexType(ASN_TYPE type): BER_CONTAINER(type) {};

    std::vector<std::shared_ptr<BER_CONTAINER>> values;

    int fromBuffer(const uint8_t *buf, size_t max_len) override;
    int serialise(uint8_t* buf, size_t max_len) override;
    
    std::shared_ptr<BER_CONTAINER> addValueToList(const std::shared_ptr<BER_CONTAINER>& newObj){
        this->values.push_back(newObj);
        return newObj;
    }

  private:
    static std::shared_ptr<BER_CONTAINER> createObjectForType(ASN_TYPE valueType);
};

#endif
