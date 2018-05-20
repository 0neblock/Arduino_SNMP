#ifndef SNMPGet_h
#define SNMPGet_h

class SNMPGet {
public:
	SNMPGet(const char* community, short version) : _community(community), _version(version) {
		if (version == 0) {
			version1 = true;
		}
		if (version == 1) {
			version2 = true;
		}
	};
	short _version;
	const char* _community;
	IPAddress agentIP;
	//OIDType* getOID;
	//TimestampCallback* uptimeCallback;
	short requestID;
	short errorID = 0;
	short errorIndex = 0;
	
	// the setters that need to be configured for each Get.
	void addOIDPointer(ValueCallback* callback);


	ValueCallbacks* callbacks = new ValueCallbacks();
	ValueCallbacks* callbacksCursor = callbacks;


	UDP* _udp = 0;
/*	void setGetOID(OIDType* oid) {
		getOID = oid;
	}
*/
	void setRequestID(short request) {
		requestID = request;
	}

	void setIP(IPAddress ip) {
		agentIP = ip;
	}

	void setUDP(UDP* udp) {
		_udp = udp;
	}

/*	void setUptimeCallback(TimestampCallback* uptime) {
		uptimeCallback = uptime;
	}
*/	

	

	ComplexType* packet = 0;
	bool build();

	bool version1 = false;
	bool version2 = false;

	bool sendTo(IPAddress ip) {
			if (!_udp) {
				return false;
			}
			if (!build()) {
				Serial.println("Failed Building packet..");
				delete packet;
				return false;
			}
			unsigned char _packetBuffer[SNMP_PACKET_LENGTH];
			memset(_packetBuffer, 0, SNMP_PACKET_LENGTH);
			int length = packet->serialise(_packetBuffer);
			delete packet;
			_udp->beginPacket(ip, 161);
			_udp->write(_packetBuffer, length);
			return _udp->endPacket();
		

		}

	void clearOIDList() { // this just removes the list, does not kill the values in the list
		callbacksCursor = callbacks;
		delete callbacksCursor;
		callbacks = new ValueCallbacks();
		callbacksCursor = callbacks;
	}

};

bool SNMPGet::build() {
	if (packet) { packet = 0; }
	packet = new ComplexType(STRUCTURE);
	packet->addValueToList(new IntegerType((int)_version));
	packet->addValueToList(new OctetType((char*)_community));
	ComplexType* getPDU;
	getPDU = new ComplexType(GetRequestPDU);
	
	getPDU->addValueToList(new IntegerType(requestID));
	getPDU->addValueToList(new IntegerType(errorID));
	getPDU->addValueToList(new IntegerType(errorIndex));
	ComplexType* varBindList = new ComplexType(STRUCTURE);
/*	getPDU->addValueToList(new TimestampType(*(uptimeCallback->value)));
	getPDU->addValueToList(new OIDType(getOID->_value));
	getPDU->addValueToList(new NetworkAddress(agentIP));
*/

	//getPDU->addValueToList(new TimestampType(*(uptimeCallback->value)));
	

	callbacksCursor = callbacks;
	if (callbacksCursor->value) {
		while (true) {
			ComplexType* varBind = new ComplexType(STRUCTURE);
			varBind->addValueToList(new OIDType(callbacksCursor->value->OID));
			BER_CONTAINER* value;
			//value = new NullType();
			
			switch (callbacksCursor->value->type) {
			case INTEGER:
			{
				value = new IntegerType(0);//*((IntegerCallback*)callbacksCursor->value)->value);
				
			}
			break;
			case TIMESTAMP:
			{
				value = new TimestampType(*((TimestampCallback*)callbacksCursor->value)->value);
			}
			break;
			case STRING:
			{
				value = new OctetType(*((StringCallback*)callbacksCursor->value)->value);
			}
			case COUNTER32: {

				value = new IntegerType(0);
				
			}
			break;
			}

			varBind->addValueToList(value);
			varBindList->addValueToList(varBind);

			if (callbacksCursor->next) {
				callbacksCursor = callbacksCursor->next;
			}
			else {
				break;
			}
		}
	}

	getPDU->addValueToList(varBindList);
	packet->addValueToList(getPDU);
	return true;
}

void SNMPGet::addOIDPointer(ValueCallback* callback) {
	callbacksCursor = callbacks;
	if (callbacksCursor->value) {
		while (callbacksCursor->next != 0) {
			callbacksCursor = callbacksCursor->next;
		}
		callbacksCursor->next = new ValueCallbacks();
		callbacksCursor = callbacksCursor->next;
		callbacksCursor->value = callback;
		callbacksCursor->next = 0;
	}
	else
		callbacks->value = callback;
}


#endif