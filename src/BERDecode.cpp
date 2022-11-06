#include "include/BER.h"

// Two ways to decode an int, one way where the first byte indicates how many butes follow, and ne where you have to power things by 128
static size_t decode_ber_longform_integer(const uint8_t* buf, long* decoded_integer, int max_len){
    int i = 1;
    long running_length = 0;
    while(*buf >= 128 && i < max_len && running_length < INT_MAX){
        running_length += *buf & 0x7F;
        running_length *= 128;
        buf++;
        i++;
    }
    running_length += *buf; // the lone byte
    *decoded_integer = running_length;
    return i;
}

static size_t decode_ber_length_integer(const uint8_t* buf, int* decoded_integer, int){
    if(*buf <= 127) {
        *decoded_integer = *buf;
        return 1;
    } else {
        int numBytes = *buf & 0x7F;
        int special_length = 0;
        for(int k = 0; k < numBytes; k++){
            buf++;
            special_length <<= 8;
            special_length |= *buf;
        }
        *decoded_integer = special_length;
        return numBytes + 1;
    }
}

int BER_CONTAINER::fromBuffer(const uint8_t *buf, size_t max_len) {
    // In the base class we are going to double check our type, and decode the length of this structure, then return bytes read
    if(max_len < 2) return SNMP_BUFFER_ERROR_TLV_TOO_SMALL; // Too small for any type

    const uint8_t* ptr = buf;
    if(*ptr != _type){
        SNMP_LOGE("Mismatched type when decoding %d, %d\n", _type, *ptr);
        return SNMP_BUFFER_ERROR_TYPE_MISMATCH;
    }
    ptr++; // type
    ptr += decode_ber_length_integer(ptr, &_length, max_len);
    if((size_t)_length + 2 > max_len){
        // length of object is too big to read in
        return SNMP_BUFFER_ERROR_MAX_LEN_EXCEEDED;
    }

    return ptr - buf;
}

int NetworkAddress::fromBuffer(const uint8_t *buf, size_t max_len){
    int i = BER_CONTAINER::fromBuffer(buf, max_len);
    CHECK_DECODE_ERR(i);
    const uint8_t* ptr = buf + i;

    // byte tempAddress[4];
    // tempAddress[0] = *ptr++;
    // tempAddress[1] = *ptr++;
    // tempAddress[2] = *ptr++;
    // tempAddress[3] = *ptr++;

    _value = IPAddress(ptr);
    return ptr - buf;
}

int IntegerType::fromBuffer(const uint8_t *buf, size_t max_len){
    int i = BER_CONTAINER::fromBuffer(buf, max_len);
    CHECK_DECODE_ERR(i);
    const uint8_t* ptr = buf + i;

    unsigned short tempLength = _length;
    uint32_t tempVal = 0; 

    while(tempLength > 0){
        tempVal = tempVal << 8;
        tempVal = tempVal | *ptr++;
        tempLength--;
    }

    switch(_length){
        case 1:
            _value = (int8_t)tempVal;
        break;
        case 2:
            _value = (int16_t)tempVal;
        break;
        case 3:
            if(tempVal & 0x00800000){
                tempVal = tempVal |= 0xFF000000;
            }
            _value = (int32_t)tempVal;
        break;
        default:
            _value = (int32_t)tempVal;
    }
    
    return ptr - buf;
}

int OctetType::fromBuffer(const uint8_t *buf, size_t max_len){
    int i = BER_CONTAINER::fromBuffer(buf, max_len);
    CHECK_DECODE_ERR(i);
    const uint8_t* ptr = buf + i;
    if(_length > OCTET_TYPE_MAX_LENGTH) return SNMP_BUFFER_ERROR_OCTET_TOO_BIG;

    _value.assign((char*)ptr, _length);

    return _length + i;
}

int OpaqueType::fromBuffer(const uint8_t *buf, size_t max_len){
    int i = BER_CONTAINER::fromBuffer(buf, max_len);
    CHECK_DECODE_ERR(i);
    const uint8_t* ptr = buf + i;

    _value = (uint8_t*)calloc(_length, sizeof(char));
    memcpy(_value, (char*)ptr, _length);
    _dataLength = _length;

    return _length + i;
}

int OIDType::fromBuffer(const uint8_t *buf, size_t max_len){
    int j = BER_CONTAINER::fromBuffer(buf, max_len);
    CHECK_DECODE_ERR(j);
    const uint8_t* dataPtr = buf + j;

    if(*dataPtr != 0x2b) return SNMP_BUFFER_ERROR_INVALID_OID;
    this->data.reserve(_length);
    this->data.assign(dataPtr, dataPtr + _length);
    this->valid = true;

    return _length + 2;
}

static inline void long_to_buf(char* buf, long l, short r = 0){
    if (l > 9){
        long_to_buf(buf++, l / 10L, r + 1);
    }
    *buf++ = l % 10 + '0';
    if(!r) *buf = 0;
}

const std::string& OIDType::string() {
    if(!this->_value.length()){
        const uint8_t* dataPtr = this->data.data();

        this->_value = ".1.3";
        if(!this->valid) return this->_value;

        dataPtr++;

        int i = this->data.size() - 1;
        char buffer[16];

        while(i > 0){
            memset(buffer, 0, sizeof(buffer));
            long item = 0;
            int itemLength = decode_ber_longform_integer(dataPtr, &item, i);
            dataPtr += itemLength; i -= itemLength;

            buffer[0] = '.';
            long_to_buf(buffer+1, item);
            this->_value.append(buffer);
        }
    }
    return this->_value;
}

const std::vector<unsigned long> SortableOIDType::generateSortingMap() const {
    auto map = std::vector<unsigned long>();

    // maybe anice midway between speed and size?
    map.reserve(this->data.size() * 1);

    const uint8_t* ptr = this->data.data();

    ptr += 1; // skip to start of interesting differences
    int i = this->data.size() - 1;

    while(i > 0){
        long item;
        size_t len = decode_ber_longform_integer(ptr, &item, i);
        ptr += len; i -= len;
        map.push_back(item);
    }

    return map;
}

int NullType::fromBuffer(const uint8_t *, size_t){
    _length = 0;
    return 2;
}

int Counter64::fromBuffer(const uint8_t *buf, size_t max_len){
    int i = BER_CONTAINER::fromBuffer(buf, max_len);
    CHECK_DECODE_ERR(i);
    const uint8_t* ptr = buf + i;

    int tempLength = _length;
    _value = 0;
    while(tempLength > 0){
        _value = _value << 8U;
        _value = _value | *ptr++;
        tempLength--;
    }
    return _length + 2;
}

std::shared_ptr<BER_CONTAINER> ComplexType::createObjectForType(ASN_TYPE valueType){
    SNMP_LOGD("Creating object of type: %d\n", valueType);
    switch(valueType){
        case INTEGER:
            return std::shared_ptr<BER_CONTAINER>(new IntegerType());
        case STRING:
            return std::shared_ptr<BER_CONTAINER>(new OctetType());
        case OID: 
            return std::shared_ptr<BER_CONTAINER>(new OIDType());
        case NULLTYPE:
            return std::shared_ptr<BER_CONTAINER>(new NullType());

        case NOSUCHOBJECT:
            return std::shared_ptr<BER_CONTAINER>(new ImplicitNullType(NOSUCHOBJECT));
        case NOSUCHINSTANCE:
            return std::shared_ptr<BER_CONTAINER>(new ImplicitNullType(NOSUCHINSTANCE));
        case ENDOFMIBVIEW:
            return std::shared_ptr<BER_CONTAINER>(new ImplicitNullType(ENDOFMIBVIEW));

        // devired
        case NETWORK_ADDRESS:
            return std::shared_ptr<BER_CONTAINER>(new NetworkAddress());
        case TIMESTAMP:
            return std::shared_ptr<BER_CONTAINER>(new TimestampType());
        case COUNTER32:
            return std::shared_ptr<BER_CONTAINER>(new Counter32());
        case GAUGE32:
            return std::shared_ptr<BER_CONTAINER>(new Gauge());
        case COUNTER64:
            return std::shared_ptr<BER_CONTAINER>(new Counter64());
        case OPAQUE:
            return std::shared_ptr<BER_CONTAINER>(new OpaqueType());

        // Complex
        /* OPAQUE = 0x44 */
        case STRUCTURE:

        case GetRequestPDU:
        case GetNextRequestPDU:
        case GetResponsePDU:
        case SetRequestPDU:
        case GetBulkRequestPDU:

        //case TrapPDU: // should never get v1trap, but put it in anyway
        case InformRequestPDU:
        case Trapv2PDU:
            return std::shared_ptr<BER_CONTAINER>(new ComplexType(valueType));
        default:
            return nullptr;
    }
}

int ComplexType::fromBuffer(const uint8_t *buf, size_t max_len){
    int j = BER_CONTAINER::fromBuffer(buf, max_len);
    CHECK_DECODE_ERR(j);
    const uint8_t* ptr = buf + j;

    size_t i = 1;
    while(i < (size_t)_length && i <= max_len){
        ASN_TYPE valueType = (ASN_TYPE)*ptr;

        auto newObj = ComplexType::createObjectForType(valueType);
        if(!newObj){
            SNMP_LOGD("Couldn't create object of type: %d\n", valueType);
            return SNMP_BUFFER_ERROR_UNKNOWN_TYPE;
        }

        int used_length = newObj->fromBuffer(ptr, max_len - i);
        if(used_length < 0){
            // Problem de-serialising
            SNMP_LOGD("Problem deserialising structure of type: %d\n", valueType);
            return SNMP_BUFFER_ERROR_PROBLEM_DESERIALISING;
        }

        addValueToList(newObj);

        ptr += used_length; 
        i += used_length;
    }
    return _length + 2;
}