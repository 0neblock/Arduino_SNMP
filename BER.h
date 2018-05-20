#ifndef BER_h
#define BER_h

#include <Arduino.h>

typedef enum ASN_TYPE_WITH_VALUE {
    // Primatives
    INTEGER = 0x02,
    STRING = 0x04,
    NULLTYPE = 0x05,
    OID = 0x06,
    
    // derived
    
    
    // Complex
    STRUCTURE = 0x30,
    NETWORK_ADDRESS = 0x40,
	COUNTER32 = 0x41,
    TIMESTAMP = 0x43,
    
    GetRequestPDU = 0xA0,
    GetNextRequestPDU = 0xA1,
    GetResponsePDU = 0xA2,
    SetRequestPDU = 0xA3,
    TrapPDU = 0xA4,
    Trapv2PDU = 0xA7
    
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
		//Serial.print("INTEGER length: ");
		//Serial.println(*lengthPtr);
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
		_value = *buf; // TODO: make work for integers more than 255
		
        _value = 0;
        while(tempLength > 0){
            _value = _value << 8;
            _value = _value | *buf++;
            tempLength--;
        }
		//Serial.print("Counter Value: "); Serial.println(_value);
        return true;
    }
    int getLength(){
        return _length;
    }
};

class Counter32 : public BER_CONTAINER {
public:
	Counter32() : BER_CONTAINER(true, INTEGER) {};
	Counter32(unsigned long value) : _value(value), BER_CONTAINER(true, INTEGER) {};
	~Counter32() {};
	unsigned long _value;
	int serialise(unsigned char* buf) {
		// here we print out the BER encoded ASN.1 bytes, which includes type, length and value. we return the length of the entire block (TL&V) ni bytes;
		unsigned char* ptr = buf;
		*ptr = _type;
		ptr++;
		unsigned char* lengthPtr = ptr++;
		Serial.print("INTEGER length: ");
		Serial.println(*lengthPtr);
		if (_value != 0) {
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


		}
		else {
			_length = 1;
			*ptr = 0;
		}
		*lengthPtr = _length;
		return _length + 2;
	}
	bool fromBuffer(unsigned char* buf) {
		buf++;// skip Type
		_length = *buf;

		buf++;

		unsigned short tempLength = _length;
		_value = *buf; // TODO: make work for integers more than 255

		_value = 0;
		while (tempLength > 0) {
			_value = _value << 8;
			_value = _value | *buf++;
			tempLength--;
		}
		//Serial.print("Counter Value: "); Serial.println(_value);
		return true;
	}
	int getLength() {
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
        strncpy(_value, value, 25);
    };
    ~OctetType(){};
    char _value[25];
    int serialise(unsigned char* buf){
        // here we print out the BER encoded ASN.1 bytes, which includes type, length and value.
        char* ptr = (char*)buf;
        *ptr = _type;
        ptr++;
        _length = sprintf(ptr + 1, "%s", _value);
        *ptr = _length;
        return _length + 2;
    }
    bool fromBuffer(unsigned char* buf){
        buf++;// skip Type
        _length = *buf;
        buf++;
        memset(_value, 0, 25);
        strncpy(_value, (char*)buf, _length);
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
        strncpy(_value, value, 50);
    };
    ~OIDType(){};
    char _value[50];
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
            delay(1);
        }
        *lengthPtr = _length - 2;
        
        return _length;
    }
    bool fromBuffer(unsigned char* buf){
        buf++;// skip Type
        _length = *buf;
        buf++;
        buf++;
        memset(_value, 0, 50);
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
                unsigned char tempBuf[4]; // nobigger than 4 bytes
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
        //Serial.print("OID: " );Serial.println(_value);
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

	// buf is an unsigned char pointer to an array that lists the bytes we got from the UDP packet 
    bool fromBuffer(unsigned char* buf){

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
                Serial.println(F("DOUBLE LENGTH BYTES"));
            }
            buf++; i++;
//            Serial.println("SUP");
//            char*	Value = (char*)malloc(sizeof(char) * valueLength + 2);
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
				case COUNTER32:
					//Serial.println("valueType is counter32");
					newObj = new Counter32();
					break;
                case OID: 
//					Serial.println("valueType is OID");
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
				
            }

            newObj->fromBuffer(buf - 2);
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
        while(conductor){
            //Serial.print("about to serialise something of type: ");Serial.println(conductor->value->_type, HEX);
            delay(0);
            
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
            unsigned char* endPtrPos = ptr + 1;
            for(unsigned char* i = endPtrPos; i > buf +1; i--){
                // i is the char we are moving INTO
                *i = *(i - 1);
            }
            *(lengthPtr+1) = (actualLength % 128)|0x80;
            actualLength += 1; // account for extra byte in Length param
        } else {
            *lengthPtr = actualLength;
        }
		delete conductor;
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