#include "include/BER.h"

static size_t recurse_longform(long integer, uint8_t* buf, int max){
    if(integer < 128){
        return 0;
    } else {
        int stuff = recurse_longform(integer / 128, buf, max - 1);
        buf[stuff] = ((integer / 128) | 0x80) & 0xFF;
        return stuff + 1;
    }
}

static size_t encode_ber_longform_integer(uint8_t* buf, long integer, int max_len){
    int bytes_used = recurse_longform(integer, buf, max_len);
    buf[bytes_used] = integer%128 & 0xFF;
    return bytes_used + 1;
}

static size_t encode_ber_length_integer(uint8_t* buf, size_t integer, int){
    int bytes_used = 1;
    if(integer < 128){
        *buf = integer & 0xFF;
    } else {
        if(integer > 256){
            *buf++ = (2 | 0x80) & 0xFF;
            *buf++ = integer/256;
            bytes_used += 2;
        } else {
            *buf++ = (1 | 0x80) & 0xFF;
            bytes_used++;
        }
        *buf++ = integer%256;
    }
    return bytes_used;
}

static size_t encode_ber_length_integer_count(size_t integer){
    int bytes_used = 1;
    if(integer >= 128){
        if(integer > 256){
            bytes_used += 2;
        } else {
            bytes_used++;
        }
    }
    return bytes_used;
}

int BER_CONTAINER::serialise(uint8_t* buf, size_t max_len){
    if(max_len < 2) return SNMP_BUFFER_ENCODE_ERR_LEN_EXCEEDED;
    *buf = _type;
    return 1;
}

int BER_CONTAINER::serialise(uint8_t* buf, size_t max_len, size_t known_length){
    int i = BER_CONTAINER::serialise(buf, max_len);
    CHECK_ENCODE_ERR(i);
    i += encode_ber_length_integer(buf+i, known_length, max_len - i);
    if(max_len < known_length + i) return SNMP_BUFFER_ENCODE_ERR_LEN_EXCEEDED;
    return i;
}

int NetworkAddress::serialise(uint8_t* buf, size_t max_len){
    int i = BER_CONTAINER::serialise(buf, max_len, 4);
    CHECK_ENCODE_ERR(i);
    uint8_t *ptr = buf + i;
    
    *ptr++ = _value[0];
    *ptr++ = _value[1];
    *ptr++ = _value[2];
    *ptr++ = _value[3];

    return ptr - buf;
}

int IntegerType::serialise(uint8_t* buf, size_t max_len){
    int i = BER_CONTAINER::serialise(buf, max_len, 4);
    CHECK_ENCODE_ERR(i);
    uint8_t *ptr = buf + i;

    *ptr++ = _value >> 24 & 0xFF;
    *ptr++ = _value >> 16 & 0xFF;
    *ptr++ = _value >> 8 & 0xFF;
    *ptr++ = _value & 0xFF;
    
    return ptr - buf;
}

int Counter64::serialise(uint8_t* buf, size_t max_len){
    int i = BER_CONTAINER::serialise(buf, max_len, 8);
    CHECK_ENCODE_ERR(i);
    uint8_t *ptr = buf + i;

    *ptr++ = _value >> 56 & 0xFF;
    *ptr++ = _value >> 48 & 0xFF;
    *ptr++ = _value >> 40 & 0xFF;
    *ptr++ = _value >> 32 & 0xFF;
    *ptr++ = _value >> 24 & 0xFF;
    *ptr++ = _value >> 16 & 0xFF;
    *ptr++ = _value >> 8 & 0xFF;
    *ptr++ = _value & 0xFF;
    
    return ptr - buf;
}

int NullType::serialise(uint8_t* buf, size_t max_len){
    return BER_CONTAINER::serialise(buf, max_len, 0);
}


int OctetType::serialise(uint8_t* buf, size_t max_len){
    int i = BER_CONTAINER::serialise(buf, max_len, _value.length());
    CHECK_ENCODE_ERR(i);
    uint8_t *ptr = buf + i;

    memcpy(ptr, _value.data(), _value.length());
    ptr += _value.length();

    return ptr - buf;
}

int OpaqueType::serialise(uint8_t* buf, size_t max_len){
    int i = BER_CONTAINER::serialise(buf, max_len, _dataLength);
    CHECK_ENCODE_ERR(i);
    uint8_t *ptr = buf + i;

    memcpy(ptr, _value, _dataLength);
    ptr += _dataLength;

    return ptr - buf;
}

int OIDType::serialise(uint8_t* buf, size_t max_len){
    int i = BER_CONTAINER::serialise(buf, max_len, this->data.size());
    CHECK_ENCODE_ERR(i);
    if(!this->valid) return SNMP_BUFFER_ENCODE_ERROR_INVALID_OID;

    uint8_t* ptr = buf + i;
    memcpy(ptr, this->data.data(), this->data.size());

    ptr += this->data.size();
    return ptr - buf;
}

bool OIDType::generateInternalData() {
    if(_value.find(".1.3.") != 0) { this->valid = false; return false; }; // Invalid OID

    this->data.clear();
    this->data.push_back(0x2b); // first byte

    char* valuePtr = &_value[5];

    while(*valuePtr != 0){
        bool toBreak = false;
        char* startNum = valuePtr;

        // Find the end of this item (next dot or end of string)
        char* endNum = strchr(startNum, '.');
        if(!endNum) {
            toBreak = true;
        }

        long tempVal;
        uint8_t temp[10] = {0};
        if(sscanf(startNum, "%ld.", &tempVal)){
            int encoded_length = encode_ber_longform_integer(temp, tempVal, 10);

            for(int i = 0; i < encoded_length; i++){
                this->data.push_back(temp[i]);
            }

            if(toBreak) break;
            valuePtr = endNum+1;
        } else {
            return false;
        }
    }

    this->_length = this->data.size();
    return true;
}

static inline void shift_arr_right(uint8_t* ptr, int num_length_bytes, size_t length){
    for(int l = length+num_length_bytes-1; l-num_length_bytes >= 0; l--){
        ptr[l] = ptr[l-num_length_bytes];
    }
}

int ComplexType::serialise(uint8_t* buf, size_t max_len){
    int i = BER_CONTAINER::serialise(buf, max_len);
    CHECK_ENCODE_ERR(i);

    uint8_t* ptr = buf + i;
    uint8_t* len_ptr = ptr++;

    uint8_t* internalPtr = ptr; // This is V*

    int internalLength = 0;

    for(const auto& item : values){
        if(!item) return SNMP_BUFFER_ENCODE_ERROR_INVALID_ITEM;
        int length = item->serialise(internalPtr, max_len - internalLength - 1);
        if(length < 0){
            SNMP_LOGD("Item failed to serialiseInto: %d, reason: %d\n", item->_type, length);
            CHECK_ENCODE_ERR(length);
        }
        internalPtr += length;
        internalLength += length;
    }

    int num_length_bytes = encode_ber_length_integer_count(internalLength);
    if(max_len < (size_t)i + internalLength + num_length_bytes) return SNMP_BUFFER_ENCODE_ERR_LEN_EXCEEDED;
    if(num_length_bytes > 1){
        shift_arr_right(ptr, num_length_bytes-1, internalLength);
    }

    // then write the length value
    i += encode_ber_length_integer(len_ptr, internalLength, num_length_bytes); // , max_len_bytes just to be safe
    return internalLength + i;
}