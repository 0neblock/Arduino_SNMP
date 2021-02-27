#ifndef BER_h
#define BER_h

#ifndef SNMP_OCTETSTRING_MAX_LENGTH
    #define SNMP_OCTETSTRING_MAX_LENGTH 1024
#endif

#include <Arduino.h>
#include <math.h>

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
    GUAGE32 = 0x42, // USIGNED32
    TIMESTAMP = 0x43,
    OPAQUE = 0x44,
	COUNTER64 = 0x46,

    GetRequestPDU = 0xA0,
    GetNextRequestPDU = 0xA1,
    GetResponsePDU = 0xA2,
    SetRequestPDU = 0xA3,
    TrapPDU = 0xA4,
    GetBulkRequestPDU = 0xA5,
    Trapv2PDU = 0xA7
} ASN_TYPE;

// Primitive types inherits straight off the container, complex come off complexType.
// All primitives have to serialise themselves (type, length, data), to be put straight into the packet.
// For deserialising from the parent container we check the type, then create an object of that type and call deSerialise,
// passing in the data, which pulls it out and saves it.
// If complexType, first split up its children into separate BERs, then passes the child with it's data using the same process.
// Complex types have a linked list of BER_CONTAINERS to hold its' children.

class BER_CONTAINER {
  public:
    BER_CONTAINER(bool isPrimative, ASN_TYPE type): _isPrimative(isPrimative), _type(type){};
    virtual ~BER_CONTAINER(){};
    bool _isPrimative;
    ASN_TYPE _type;
    unsigned short _length;
    virtual int serialise(unsigned char* buf) =0;
    virtual bool fromBuffer(unsigned char* buf) = 0;
    virtual int getLength() = 0;
};

class NetworkAddress: public BER_CONTAINER {
  public:
    NetworkAddress(): BER_CONTAINER(true, NETWORK_ADDRESS){};
    NetworkAddress(IPAddress ip): _value(ip), BER_CONTAINER(true, NETWORK_ADDRESS){};
    ~NetworkAddress(){};
    IPAddress _value;
    int serialise(unsigned char* buf){
        unsigned char* ptr = buf;
        *ptr++ = _type;
        
        _length = 4;
        
        *ptr++ = _length;
        *ptr++ = _value[0];
        *ptr++ = _value[1];
        *ptr++ = _value[2];
        *ptr++ = _value[3];
        return _length + 2;
    }
    bool fromBuffer(unsigned char* buf){
        buf++;// skip Type
        _length = *buf;
        buf++;
        byte tempAddress[4];
        tempAddress[0] = *buf++;
        tempAddress[1] = *buf++;
        tempAddress[2] = *buf++;
        tempAddress[3] = *buf++;
        _value = IPAddress(tempAddress);
        return true;
    }
    int getLength(){
        return _length;
    }
};


class IntegerType: public BER_CONTAINER {
  public:
    IntegerType(): BER_CONTAINER(true, INTEGER){};
    IntegerType(unsigned long value): _value(value), BER_CONTAINER(true, INTEGER){};
    ~IntegerType(){};
    unsigned long _value;
    int serialise(unsigned char* buf){
        // here we print out the BER encoded ASN.1 bytes, which includes type, length and value. we return the length of the entire block (TL&V) ni bytes;
        unsigned char* ptr = buf;
        *ptr = _type;
        ptr++;
        unsigned char* lengthPtr = ptr++;
        if(_value != 0){
            _length = 4; // FIXME: need to give this dynamic length
        //        while(_length > 1){
        //            if(_value >> 24 == 0){
        //                _length--;
        //                _value = _value << 8;
        //            } else {
        //                break;
        //            }
        //        }
            *ptr++ = _value >> 24 & 0xFF;
            *ptr++ = _value >> 16 & 0xFF;
            *ptr++ = _value >> 8 & 0xFF;
            *ptr++ = _value & 0xFF;

            
        } else {
            _length = 1;
            *ptr = 0;
        }
        *lengthPtr = _length;
        return _length + 2;
    }
    bool fromBuffer(unsigned char* buf){
        buf++;// skip Type
        _length = *buf;
        buf++;
        unsigned short tempLength = _length;
//        _value = *buf; // TODO: make work for integers more than 255
        _value = 0;
        while(tempLength > 0){
            _value = _value << 8;
            _value = _value | *buf++;
            tempLength--;
        }
        return true;
    }
    int getLength(){
        return _length;
    }
};

class TimestampType: public IntegerType {
  public:
    TimestampType(): IntegerType(){
        _type = TIMESTAMP;
    };
    TimestampType(unsigned long value): IntegerType(value){
        _type = TIMESTAMP;
    };
    ~TimestampType(){};
};

class OctetType: public BER_CONTAINER {
  public:
    OctetType(): BER_CONTAINER(true, STRING){};
    OctetType(char* value): BER_CONTAINER(true, STRING){
        strncpy(_value, value, sizeof(_value));
        _value[sizeof(_value)] = 0;
    };
    ~OctetType(){};
    char _value[SNMP_OCTETSTRING_MAX_LENGTH];
    int serialise(unsigned char* buf){
        // here we print out the BER encoded ASN.1 bytes, which includes type, length and value.
        char* ptr = (char*)buf;
        int numExtraBytes = 0;
        char temp[SNMP_OCTETSTRING_MAX_LENGTH];
        int valueLength = sprintf(temp, "%s", _value);

        *ptr++ = _type; // Set the type identifier
        // If > 127 first byte needs to be 0x8x where x is the how many bytes follow which defines string length
        if (valueLength > 127)
        {
            numExtraBytes++; // Need an extra byte
            if (valueLength > 256) // Max 65,536 characters, but likely will fail due to UDP packet fragmentation.
            {
                numExtraBytes++; // Need another extra byte to store the length
            }
            *ptr++ = (numExtraBytes | 0x80); // 0x8x where x is the number of bytes which provide the total string length
            if (valueLength > 256){
                *ptr++ = valueLength / 256;
                valueLength = valueLength % 256;
            }
            *ptr++ = valueLength;
        }
        else 
        {
            *ptr++ = valueLength;
        }
        _length = sprintf(ptr, "%s", _value);
        return _length + numExtraBytes + 2;
    }
    bool fromBuffer(unsigned char* buf){
        buf++; // skip Type
        _length = *buf;
        // length should be treated as: if first byte is 0x8x, the x is how many bytes follow
        if (_length > 127)
        {
            int numBytes = _length &= 0x7F;
            unsigned int special_length = 0;
            for(int k = 0; k < numBytes; k++){
                buf++;
                special_length <<= 8;
                special_length |= *buf;
            }
            _length = special_length;
        }
        buf++;
        memset(_value, 0, sizeof(_value));  // Null out _value
        if (_length < sizeof(_value))
        {
            strncpy(_value, (char *)buf, _length);  // Copy buffer to Value, using length from ASN structure.
        }
        else
        {
            Serial.println(F("OctetString too large, adjust SNMP_OCTETSTRING_MAX_LENGTH. String Truncated."));
            strncpy(_value, (char *)buf, 253);  // Copy truncated buffer to Value
        }
        return true;
    }
    int getLength(){
        return _length;
    }
};

class OIDType: public BER_CONTAINER {
  public:
    OIDType(): BER_CONTAINER(true, OID){};
    OIDType(char* value): BER_CONTAINER(true, OID){
        strncpy(_value, value, 128);
    };
    ~OIDType(){};
    char _value[128];
    int serialise(unsigned char* buf){
        // here we print out the BER encoded ASN.1 bytes, which includes type, length and value.
        char* ptr = (char*)buf;
        *ptr = _type;
        ptr++;
        char* lengthPtr = ptr;
        ptr++;
        *ptr = 0x2b;
        char* internalPtr = ++ptr;
        char* valuePtr = &_value[5];
        _length = 3;
        bool toBreak = false;
        while(true){
            char* start = valuePtr;
            char* end = strchr(start, '.');
            
            if(!end) {
                end = strchr(start, 0);
                toBreak = true;
            }
            char tempBuf[10];
            memset(tempBuf, 0, 10);
//            char* tempBuf = (char*) malloc(sizeof(char) * (end-start));
            strncpy(tempBuf, start, end-start+1);
            long tempVal;
            tempVal = atoi(tempBuf);
            if(tempVal > 127){
                // Serial.print("large num: ");Serial.println(tempVal);
                if(tempVal/128 > 128){
                    *ptr++ = ((tempVal/128/128) | 0x80) & 0xFF; // dodgy
                    _length += 1;
                }
                *ptr++ = ((tempVal/128) | 0x80) & 0xFF;
                *ptr++ = tempVal%128 & 0xFF;
                _length += 2;
            } else {
                _length += 1;
                *ptr++ = (char)tempVal;
            }
            
            valuePtr = end+1;
            
//            free(tempBuf);
            if(toBreak) break;
            // delay(1);
        }
        *lengthPtr = _length - 2;
        
        return _length;
    }
    bool fromBuffer(unsigned char* buf){
        buf++;// skip Type
        _length = *buf;
        buf++;
        buf++;
        memset(_value, 0, 128);
        _value[0] = '.';
        _value[1] = '1';
        _value[2] = '.';
        _value[3] = '3'; // we fill in the first two bytes already
        char* ptr = &_value[4];
        char i = _length -1;
        while(i > 0){
            if(*buf < 128){ // we can keep raw
                ptr += sprintf(ptr, ".%d", *buf);
                i--;
                buf++;
            } else { // we have to do the special >128 thing
                long value = 0; // keep track of the actual thing
                char n = 0; // count how many large bits have been set
                unsigned char tempBuf[6] = {0}; // nobigger than 4 bytes
                while(*buf > 127){
                    i--;
                    *buf &= 0x7F;
                    tempBuf[n] = *buf;
                    n++;
                    buf++;
                }
                value = *buf;
                buf++;
                i--;
                for(char k = 0; k < n; k++){
                    value += (pow(128,(n-k))) * tempBuf[k];
                    
                }
                ptr += sprintf(ptr, ".%d", value);
            }
            // delay(1);
        }
        Serial.print("OID: " );Serial.println(_value);
//        memcpy(_value, buf, _length);
        return true;
    }
    
    int getLength(){
        return _length;
    }
};

class NullType: public BER_CONTAINER {
  public:
    NullType(): BER_CONTAINER(true, NULLTYPE){};
    ~NullType(){
    };
    char _value = NULL;
    int serialise(unsigned char* buf){
        // here we print out the BER encoded ASN.1 bytes, which includes type, length and value.
        char* ptr = (char*)buf;
        *ptr = _type;
        ptr++;
        *ptr = 0;
        return 2;
    }
    bool fromBuffer(unsigned char* buf){
        _length = 0;
        return true;
    }
    
    int getLength(){
        return 0;
    }
};


class Counter64: public BER_CONTAINER {
  public:
    Counter64(): BER_CONTAINER(true, COUNTER64){};
    Counter64(uint64_t value): _value(value), BER_CONTAINER(true, COUNTER64){};
    ~Counter64(){};
    uint64_t _value;
    int serialise(unsigned char* buf){
        // here we print out the BER encoded ASN.1 bytes, which includes type, length and value. we return the length of the entire block (TL&V) ni bytes;
        unsigned char* ptr = buf;
        *ptr = _type;
        ptr++;
        unsigned char* lengthPtr = ptr++;
        if(_value != 0){
            _length = 8;
            *ptr++ = _value >> 56 & 0xFF;
            *ptr++ = _value >> 48 & 0xFF;
            *ptr++ = _value >> 40 & 0xFF;
            *ptr++ = _value >> 32 & 0xFF;
            *ptr++ = _value >> 24 & 0xFF;
            *ptr++ = _value >> 16 & 0xFF;
            *ptr++ = _value >> 8 & 0xFF;
            *ptr++ = _value & 0xFF;
        } else {
            _length = 1;
            *ptr = 0;
        }
        *lengthPtr = _length;
        return _length + 2;
    }
    bool fromBuffer(unsigned char* buf){
        buf++;// skip Type
        _length = *buf;
        buf++;
        unsigned short tempLength = _length;
//        _value = *buf; // TODO: make work for integers more than 255
        _value = 0;
        while(tempLength > 0){
            _value = _value << 8;
            _value = _value | *buf++;
            tempLength--;
        }
        return true;
    }
    int getLength(){
        return _length;
    }
};

class Counter32: public IntegerType {
  public:
    Counter32(): IntegerType(){
        _type = COUNTER32;
    };
    Counter32(unsigned int value): IntegerType(value){
        _type = COUNTER32;
    };
    ~Counter32(){};
};

class Guage: public IntegerType { // Unsigned int
  public:
    Guage(): IntegerType(){
        _type = GUAGE32;
    };
    Guage(unsigned int value): IntegerType(value){
        _type = GUAGE32;
    };
    ~Guage(){};
};

typedef struct BER_LINKED_LIST {
    ~BER_LINKED_LIST(){
        delete next; next = 0;
        delete value; value = 0;
    }
    BER_CONTAINER* value = 0;
    struct BER_LINKED_LIST* next = 0;
} ValuesList;

class ComplexType: public BER_CONTAINER {
  public:
    ComplexType(ASN_TYPE type): BER_CONTAINER(false, type){};
    ~ComplexType(){
        delete _values;
    }
    ValuesList* _values = 0;
    bool fromBuffer(unsigned char* buf){
        // the buffer we get passed in is the complete ASN Container, including the type header.
        buf++; // Skip our own type
        _length = *buf;
        // Serial.printf("%d, l\n", _length); // length should be treated as: if first byte is 0x8x, the x is how many bytes follow
        if(_length > 127){
            // do this
            int numBytes = _length &= 0x7F;
            unsigned int special_length = 0;
            for(int k = 0; k < numBytes; k++){
                buf++;
                special_length <<= 8;
                // Serial.printf("%d, b\n", *buf);
                special_length |= *buf;
            }
            _length = special_length;
        }
        // Serial.printf("%d, l\n", _length);
        buf++;
        // now we are at the front of a list of one or many other types, lets do our loop
        unsigned int i = 1;
        while(i < _length){
            ASN_TYPE valueType = (ASN_TYPE)*buf;
            buf++; i++;
            unsigned int valueLength = *buf;
            // Serial.print("valuelength: ");

            // Serial.println(valueLength);
            // Serial.printf("i: %d\n", i);
            // Serial.printf("length: %d\n", _length);

            int doubleL = 0;
            if(valueLength > 127){
                // also do this.
                int numBytes = valueLength &= 0x7F;
                unsigned int special_length = 0;
                for(int k = 0; k < numBytes; k++){
                    buf++;
                    i++;
                    special_length <<= 8;
                    // Serial.printf("%d, b\n", *buf);
                    special_length |= *buf;
                }
                valueLength = special_length;
                doubleL = numBytes;
            }
            buf++; i++;
            // Serial.print("Lenght:");
            // Serial.println(valueLength);
            // Serial.println("SUP");
//            char* newValue = (char*)malloc(sizeof(char) * valueLength + 2);
//            memset(newValue, 0, valueLength + 2);
//            memcpy(newValue, buf - 2, valueLength + 2);
//            buf += valueLength; i+= valueLength;
            BER_CONTAINER* newObj;
            switch(valueType){
                case STRUCTURE:
                case GetRequestPDU:
                case GetNextRequestPDU:
                case GetResponsePDU:
                case SetRequestPDU:
                case GetBulkRequestPDU:
                case TrapPDU: // should never get trap, but put it in anyway
                case Trapv2PDU:
                    newObj = new ComplexType(valueType);
                break;
                    // primitive
                case INTEGER:
                    newObj = new IntegerType();
                    break;
                case STRING:
                    newObj = new OctetType();
                    break;
                case OID: 
                    newObj = new OIDType();
                    break;
                case NULLTYPE:
                    newObj = new NullType();
                break;
                    // devired
                case NETWORK_ADDRESS:
                    newObj = new NetworkAddress();
                break;
                case TIMESTAMP:
                    newObj = new TimestampType();
                break;
                case COUNTER32:
                    newObj = new Counter32();
                break;
                case GUAGE32:
                    newObj = new Guage();
                break;
                case COUNTER64:
                    newObj = new Counter64();
                break;
                /* OPAQUE = 0x44 */
                
                default:
                    newObj = new ComplexType(valueType);
                break;
            }
            newObj->fromBuffer(buf - (2+doubleL));
            
            buf += valueLength; i+= valueLength;
            //newObj->fromBuffer(newValue);
//            free(newValue);
            addValueToList(newObj);
        }
        return true;
    }
    
    int serialise(unsigned char* buf){
        int actualLength = 0;
        unsigned char* ptr = buf;
        *ptr = _type;
        ptr++;
        unsigned char* lengthPtr = ptr++;
        *lengthPtr = 0;
        ValuesList* conductor = _values;
        int tempLength = 0;
        while(conductor){
//            Serial.print("about to serialise something of type: ");Serial.println(conductor->value->_type, HEX);
            delay(0);
            
            int length = conductor->value->serialise(ptr);
            ptr += length;
            actualLength += length;
            conductor = conductor->next;
        }
        // printf("Length to return: %d\n", actualLength);
        if(actualLength > 127){
//            Serial.println("TOO BIG");
            // bad, we have to add another byte and shift everything afterwards by 1 >>
              // first byte is 128 + (actualLength / 128)
              // second is actualLength % 128;
              int tempVal = 1;
            if(actualLength > 256){
                *lengthPtr++ = (2 | 0x80) & 0xFF; // dodgy
                
                tempLength += 1;
                unsigned char* endPtrPos = ++ptr;
                for(unsigned char* i = endPtrPos; i > buf + 1; i--){
                    // i is the char we are moving INTO
                    *i = *(i - 1);
                }
                tempVal = 2;
                *lengthPtr++ = actualLength/256;
            } else {
                *lengthPtr++ = (1 | 0x80)  & 0xFF;
            }
            

            // *lengthPtr = 129;
            // if(actualLength > 256){
            //     *lengthPtr = 130;
            // }
            // lets move everything right one byte, start from back..
            unsigned char* endPtrPos = ptr + 1;
            for(unsigned char* i = endPtrPos; i > buf + tempVal; i--){
                // i is the char we are moving INTO
                *i = *(i - 1);
            }
            *lengthPtr++ = actualLength%256;
            
            // *(lengthPtr+1) = (actualLength % 128)|0x80;
            tempLength += 1; // account for extra byte in Length param
        } else {
            *lengthPtr = actualLength;
        }
        return actualLength + 2 + tempLength;
    }
    
    int getLength(){
        return _length;
    }
    
    bool addValueToList(BER_CONTAINER* newObj){
        ValuesList* conductor = _values;
        if(_values != 0){
            while(conductor->next != 0){
                conductor = conductor->next;
                delay(0);
            }
            conductor->next = new ValuesList;
            conductor = conductor->next;
            conductor->value = newObj;
            conductor->next = 0;
        } else {
            _values = new ValuesList;
            _values->value = newObj;
            _values->next = 0;
        }
    }
};



#endif