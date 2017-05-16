#ifndef BER_h
#define BER_h

#include <Arduino.h>

typedef enum ASN_TYPE_WITH_VALUE {
    // Primatives
    INTEGER = 0x02,
    STRING = 0x04,
    NULLTYPE = 0x05,
    OID = 0x06,
    
    // Complex
    STRUCTURE = 0x30,
    GetRequestPDU = 0xA0,
    GetNextRequestPDU = 0xA1,
    GetResponsePDU = 0xA2,
    SetRequestPDU = 0xA3,
    TrapPDU = 0xA4
} ASN_TYPE;

// primitive types inherits straight off the container, complex come off complexType
// all primitives have to serialise themselves (type, length, data), to be put straight into the packet.
// for deserialising, from the parent container we check the type, then create anobject of that type and calls deSerialise, passing in the data, which pulls it out and saves, and if complex, first split up it schildren into seperate BERs, then creates and passes them creates a child with it's data using the same process.

// complex types have a linked list of BER_CONTAINERS to hold its' children.

class BER_CONTAINER {
  public:
    BER_CONTAINER(bool isPrimative, ASN_TYPE type): _isPrimative(isPrimative), _type(type){};
    virtual ~BER_CONTAINER(){};
    bool _isPrimative;
    ASN_TYPE _type;
    unsigned short _length;
    virtual int serialise(char* buf) =0;
    virtual bool fromBuffer(char* buf) = 0;
    virtual int getLength() = 0;
};



class IntegerType: public BER_CONTAINER {
  public:
    IntegerType(): BER_CONTAINER(true, INTEGER){};
    IntegerType(int value): _value(value), BER_CONTAINER(true, INTEGER){};
    ~IntegerType(){};
    int _value;
    int serialise(char* buf){
        // here we print out the BER encoded ASN.1 bytes, which includes type, length and value. we return the length of the entire block (TL&V) ni bytes;
        char* ptr = buf;
        *ptr = _type;
        ptr++;
        char* lengthPtr = ptr++;
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
    bool fromBuffer(char* buf){
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

class OctetType: public BER_CONTAINER {
  public:
    OctetType(): BER_CONTAINER(true, STRING){};
    OctetType(char* value): BER_CONTAINER(true, STRING){
        strncpy(_value, value, 40);
    };
    ~OctetType(){};
    char _value[40];
    int serialise(char* buf){
        // here we print out the BER encoded ASN.1 bytes, which includes type, length and value.
        char* ptr = buf;
        *ptr = _type;
        ptr++;
        _length = sprintf(ptr + 1, "%s", _value);
        *ptr = _length;
        return _length + 2;
    }
    bool fromBuffer(char* buf){
        buf++;// skip Type
        _length = *buf;
        buf++;
        memset(_value, 0, 40);
        strncpy(_value, buf, _length);
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
        strncpy(_value, value, 40);
    };
    ~OIDType(){};
    char _value[40];
    int serialise(char* buf){
        // here we print out the BER encoded ASN.1 bytes, which includes type, length and value.
        char* ptr = buf;
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
            *ptr++ = atoi(tempBuf);
            valuePtr = end+1;
            _length += 1;
//            free(tempBuf);
            if(toBreak) break;
            delay(1);
        }
        *lengthPtr = _length - 2;
        
        return _length;
    }
    bool fromBuffer(char* buf){
        buf++;// skip Type
        _length = *buf;
        buf++;
        buf++;
        memset(_value, 0, 40);
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
                int value = 0; // keep track of the actual thing
                char n = 0; // count how many large bits have been set
                char tempBuf[3]; // nobigger than 4 bytes
                while(*buf > 127){
                    i--;
                    *buf<<=1;
                    *buf>>=1;
                    tempBuf[n] = *buf;
                    n++;
                    buf++;
                }
                value = *buf;
                buf++;
                i--;
                for(char k = 0; k < n; k++){
                    value += (128 * (n-k)) * tempBuf[k];
                }
                ptr += sprintf(ptr, ".%d", value);
            }
            delay(1);
        }
//        //Serial.print("OID: " );//Serial.println(_value);
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
    int serialise(char* buf){
        // here we print out the BER encoded ASN.1 bytes, which includes type, length and value.
        char* ptr = buf;
        *ptr = _type;
        ptr++;
        *ptr = 0;
        return 2;
    }
    bool fromBuffer(char* buf){
        _length = 0;
        return true;
    }
    
    int getLength(){
        return 0;
    }
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
    bool fromBuffer(char* buf){
        // the buffer we get passed in is the complete ASN Container, including the type header.
        buf++; // Skip our own type
        _length = *buf;
        if(_length > 127){
            // do this
            _length -= 128;
            buf++;
            _length = (_length*128) + (*buf-128);
        }
        buf++;
        // now we are at the front of a list of one or many other types, lets do our loop
        unsigned char i = 0;
        while(i < _length){
            ASN_TYPE valueType = (ASN_TYPE)*buf;
            buf++; i++;
            unsigned short valueLength = *buf;
            if(valueLength > 127){
                // also do this.
                valueLength -= 128;
                buf++; i++;
                valueLength = (valueLength*128) + (*buf-128);
                Serial.println("DOUBLE LENGTH BYTES");
            }
            buf++; i++;
//            Serial.println("SUP");
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
                case TrapPDU:
                    newObj = new ComplexType(valueType);
                break;
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
            }
            newObj->fromBuffer(buf - 2);
            buf += valueLength; i+= valueLength;
            //newObj->fromBuffer(newValue);
//            free(newValue);
            addValueToList(newObj);
        }
        return true;
    }
    
    int serialise(char* buf){
        int actualLength = 0;
        char* ptr = buf;
        *ptr = _type;
        ptr++;
        char* lengthPtr = ptr++;
        *lengthPtr = 0;
        ValuesList* conductor = _values;
        while(conductor){
            delay(1);
            int length = conductor->value->serialise(ptr);
            ptr += length;
            actualLength += length;
            conductor = conductor->next;
        }
        if(actualLength > 127){
//            Serial.println("TOO BIG");
            // bad, we have to add another byte and shift everything afterwards by 1 >>
              // first byte is 128 + (actualLength / 128)
              // second is actualLength % 128;
            *lengthPtr = 129;
            // lets move everything right one byte, start from back..
            char* endPtrPos = ptr + 1;
            for(char* i = endPtrPos; i > buf +1; i--){
                // i is the char we are moving INTO
                *i = *(i - 1);
            }
            *(lengthPtr+1) = (actualLength % 128)|0x80;
            actualLength += 1; // account for extra byte in Length param
        } else {
            *lengthPtr = actualLength;
        }
        return actualLength + 2;
    }
    
    int getLength(){
        return _length;
    }
    
    bool addValueToList(BER_CONTAINER* newObj){
        ValuesList* conductor = _values;
        if(_values != 0){
            while(conductor->next != 0){
                conductor = conductor->next;
                delay(1);
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