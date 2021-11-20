#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "include/SNMPPacket.h"
#include "include/ValueCallbacks.h"
#include "include/SNMPParser.h"

#include "SNMPTrap.h"

#include <list>

static SNMPPacket* GenerateTestSNMPRequestPacket(){
    SNMPPacket* packet = new SNMPPacket();

    packet->setPDUType(GetRequestPDU);
    packet->setCommunityString("public");
    packet->setRequestID(random());
    packet->setVersion(SNMP_VERSION_1);

    packet->varbindList.push_back(VarBind(std::make_shared<SortableOIDType>(".1.3.6.1.4.1.5.1"),                  std::make_shared<IntegerType>(42)));
    packet->varbindList.push_back(VarBind(std::make_shared<SortableOIDType>(".1.3.6.1.4.1.5.2"),                  std::make_shared<OctetType>("test 123")));
    packet->varbindList.push_back(VarBind(std::make_shared<SortableOIDType>(".1.3.6.1.4.1.52420.9999999"),        std::make_shared<IntegerType>(0)));
    packet->varbindList.push_back(VarBind(std::make_shared<SortableOIDType>(".1.3.6.1.4.1.5.3"),                  std::make_shared<IntegerType>(-42)));
    packet->varbindList.push_back(VarBind(std::make_shared<SortableOIDType>(".1.3.6.1.4.1.5.4"),                  std::make_shared<IntegerType>(-420000)));

    return packet;
}

TEST_CASE( "Test handle failures when Encoding/Decoding", "[snmp]"){
    SNMPPacket *packet = GenerateTestSNMPRequestPacket();
    uint8_t buffer[500];
    int serialised_length = 0;

    SECTION( "Failed Serialisation" ){
        serialised_length = packet->serialiseInto(buffer, 132);
        REQUIRE( serialised_length <= 0 );
    }

    SECTION( "Suceed Serialisation" ){
        serialised_length = packet->serialiseInto(buffer, 133);
        REQUIRE( serialised_length == 133 );
    }

    uint8_t copyBuffer[500] = {0};

    memcpy(copyBuffer, buffer, 500);

    SECTION( "Should fail to parse a buffer too small"){
        SNMPPacket* readPack = new SNMPPacket();
        REQUIRE( readPack->parseFrom(buffer, 130) != SNMP_ERROR_OK );
    }

    SECTION( "Decoding should not modify the buffer"){
        REQUIRE( memcmp(copyBuffer, buffer, 500) == 0 );
    }
    
    SECTION( "Should be able to reparse the buffer with correct max_size"){
        SNMPPacket* readPack = new SNMPPacket();
        REQUIRE( readPack->parseFrom(buffer, 133) == SNMP_ERROR_OK );
    }

    SECTION( "Should fail to parse a corrupt buffer "){
        SNMPPacket* readPacket = new SNMPPacket();
        for(int i = 25; i < 133; i+= 10){
            char old[10] = {0};
            memcpy(old, &buffer[i], 10);
            long randomLong = random();
            memcpy(&buffer[i], &randomLong, 10);
            // This may SOMETIMES fail if the random gets lucky and makes something valid
            REQUIRE( readPacket->parseFrom(buffer, 200) != SNMP_ERROR_OK );

            memcpy(&buffer[i], old, 10);
            REQUIRE( readPacket->parseFrom(buffer, 200) == SNMP_ERROR_OK );
        }
    }
}

TEST_CASE( "Test Encoding/Decoding packet", "[snmp]" ) {
    // Build Packet
    SNMPPacket *packet = GenerateTestSNMPRequestPacket();
    uint8_t buffer[500];
    int serialised_length = 0;

    SECTION( "Serialisation" ){
        serialised_length = packet->serialiseInto(buffer, 500);
        REQUIRE( serialised_length == 133 );
    }
    // Read packet
    SNMPPacket* readPacket = new SNMPPacket();
    REQUIRE( readPacket->parseFrom(buffer, serialised_length) == SNMP_ERROR_OK);

    // Check Meta
    REQUIRE( (packet->communityString == readPacket->communityString) );
    REQUIRE( packet->requestID == readPacket->requestID );
    REQUIRE( packet->snmpVersion == readPacket->snmpVersion );

    // Check Varbinds
    REQUIRE( packet->varbindList.size() == 5 );

        // Integer
        REQUIRE( packet->varbindList[0].oid->string() == ".1.3.6.1.4.1.5.1" );
        REQUIRE( packet->varbindList[0].type == ASN_TYPE::INTEGER );
        REQUIRE( std::static_pointer_cast<IntegerType>(packet->varbindList[0].value)->_value == 42 );

        // String
        REQUIRE( (packet->varbindList[1].oid->string() == ".1.3.6.1.4.1.5.2") );
        REQUIRE( packet->varbindList[1].type == ASN_TYPE::STRING );
        REQUIRE( std::static_pointer_cast<OctetType>(packet->varbindList[1].value)->_value == "test 123" );

        // Long OID Integer
        REQUIRE( (packet->varbindList[2].oid->string() == ".1.3.6.1.4.1.52420.9999999") );
        REQUIRE( packet->varbindList[2].type == ASN_TYPE::INTEGER );
        REQUIRE( std::static_pointer_cast<IntegerType>(packet->varbindList[2].value)->_value == 0 );

        // Negative Integer
        REQUIRE( (packet->varbindList[3].oid->string() == ".1.3.6.1.4.1.5.3") );
        REQUIRE( packet->varbindList[3].type == ASN_TYPE::INTEGER );
        REQUIRE( std::static_pointer_cast<IntegerType>(packet->varbindList[3].value)->_value == -42 );

        // Large Negative Integer
        REQUIRE( (packet->varbindList[4].oid->string() == ".1.3.6.1.4.1.5.4") );
        REQUIRE( packet->varbindList[4].type == ASN_TYPE::INTEGER );
        REQUIRE( std::static_pointer_cast<IntegerType>(packet->varbindList[4].value)->_value == -420000 );
}

TEST_CASE( "Test GetRequestPDU", "[snmp]" ){
    std::deque<ValueCallback*> callbacks;

    int testInt = 23;
    ValueCallback* integer = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.1"), &testInt);
    callbacks.push_back(integer);

    SNMPPacket *requestPacket = GenerateTestSNMPRequestPacket();
    uint8_t buffer[500];
    int buf_len = requestPacket->serialiseInto(buffer, 500);
    REQUIRE( buf_len > 0 );

    int responseLength = 0;
    REQUIRE( handlePacket(buffer, buf_len, &responseLength, 500, callbacks, (char*)"public", (char*)"private") == SNMP_GET_OCCURRED );

    SNMPPacket* responsePacket = new SNMPPacket();
    REQUIRE( responsePacket->parseFrom(buffer, responseLength) == SNMP_ERROR_OK );

    REQUIRE( responsePacket->varbindList.at(0).type == INTEGER );
    REQUIRE( std::static_pointer_cast<IntegerType>(responsePacket->varbindList.at(0).value)->_value == 23 );
}

TEST_CASE( "Test GetNextRequestPDU", "[snmp]" ){
    std::deque<ValueCallback*> callbacks;

    int testInt = 23;
    IntegerCallback* integer = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.1"), &testInt);
    callbacks.push_back(integer);

    IntegerCallback* integer2 = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.2"), &testInt);
    callbacks.push_back(integer2);

    SNMPPacket *requestPacket = GenerateTestSNMPRequestPacket();
    requestPacket->setPDUType(GetNextRequestPDU);
    uint8_t buffer[500];
    int buf_len = requestPacket->serialiseInto(buffer, 500);
    REQUIRE( buf_len > 0 );

    int responseLength = 0;
    REQUIRE( handlePacket(buffer, buf_len, &responseLength, 500, callbacks, "public", "private") == SNMP_GETNEXT_OCCURRED );

    SNMPPacket* responsePacket = new SNMPPacket();
    REQUIRE( responsePacket->parseFrom(buffer, responseLength) == SNMP_ERROR_OK );

    REQUIRE( responsePacket->varbindList.at(0).type == INTEGER );
    REQUIRE( responsePacket->varbindList.at(0).oid->string() == ".1.3.6.1.4.1.5.2" );
}

TEST_CASE( "Test GetBulkRequestPDU", "[snmp]"){
    std::deque<ValueCallback*> callbacks;

    int testInt = 23;
    IntegerCallback* integer = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.1"), &testInt);
    callbacks.push_back(integer);

    IntegerCallback* integer2 = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.2"), &testInt);
    callbacks.push_back(integer2);

    SNMPPacket *requestPacket = GenerateTestSNMPRequestPacket();
    requestPacket->varbindList.pop_back();
    requestPacket->varbindList.pop_back();
    requestPacket->varbindList.pop_back();
    requestPacket->varbindList.pop_back();

    requestPacket->setVersion(SNMP_VERSION_2C);
    requestPacket->setPDUType(GetBulkRequestPDU);
    requestPacket->errorIndex.maxRepititions = 2;
    requestPacket->errorStatus.nonRepeaters = 0;

    uint8_t buffer[500];
    int buf_len = requestPacket->serialiseInto(buffer, 500);
    REQUIRE( buf_len > 0 );

    int responseLength = 0;
    REQUIRE( handlePacket(buffer, buf_len, &responseLength, 500, callbacks, (char*)"public", (char*)"private") == SNMP_GETBULK_OCCURRED );

    SNMPPacket* responsePacket = new SNMPPacket();
    REQUIRE( responsePacket->parseFrom(buffer, responseLength) == SNMP_ERROR_OK );

    REQUIRE( responsePacket->varbindList.size() == 2 );

    REQUIRE( responsePacket->varbindList.at(0).type == INTEGER );
    REQUIRE( responsePacket->varbindList.at(0).oid->string() == ".1.3.6.1.4.1.5.2" );

    REQUIRE( responsePacket->varbindList.at(1).type == ENDOFMIBVIEW );
}

TEST_CASE( "Test SetRequestPDU", "[snmp]" ){
    std::deque<ValueCallback*> callbacks;

    int testInt = 23;
    IntegerCallback* integerCallback = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.1"), &testInt);
    integerCallback->isSettable = false;
    callbacks.push_back(integerCallback);

    int testInt2 = 23;
    IntegerCallback* integerCallback2 = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.4"), &testInt2);
    integerCallback2->isSettable = true;
    callbacks.push_back(integerCallback2);

    uint8_t opaqueBuf[5] = { 1, 2, 3, 4, 5 };
    OpaqueCallback* opaqueCallback = new OpaqueCallback(new SortableOIDType(".1.3.6.1.4.1.5.7"), opaqueBuf, 5);
    opaqueCallback->isSettable = true;
    callbacks.push_back(opaqueCallback);

    SNMPPacket *requestPacket = GenerateTestSNMPRequestPacket();
    requestPacket->setPDUType(SetRequestPDU);

    uint8_t setOpaqueBuf[5] = { 5, 4, 3, 2, 1 };
    requestPacket->varbindList.push_back(VarBind(std::make_shared<SortableOIDType>(".1.3.6.1.4.1.5.7"),                  std::make_shared<OpaqueType>(setOpaqueBuf, 5)));

    uint8_t buffer[500];

    int buf_len = requestPacket->serialiseInto(buffer, 500);
    REQUIRE( buf_len > 0 );

    int responseLength = 0;
    REQUIRE( handlePacket(buffer, buf_len, &responseLength, 500, callbacks, (char*)"public", (char*)"public") == SNMP_SET_OCCURRED );

    SNMPPacket* responsePacket = new SNMPPacket();
    REQUIRE( responsePacket->parseFrom(buffer, responseLength) == SNMP_ERROR_OK );

    REQUIRE( integerCallback->setOccurred == false );
    REQUIRE( testInt == 23 );

    REQUIRE( integerCallback2->setOccurred == true );
    REQUIRE( testInt2 == -420000 );

    REQUIRE( opaqueCallback->setOccurred == true );
    REQUIRE( opaqueBuf[0] == 5 );
    REQUIRE( opaqueBuf[1] == 4 );
    REQUIRE( opaqueBuf[2] == 3 );
    REQUIRE( opaqueBuf[3] == 2 );
    REQUIRE( opaqueBuf[4] == 1 );

}


TEST_CASE( "sort/remove handlers ", "[snmp]"){
    std::deque<ValueCallback*> callbacks;

    callbacks.push_back(new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.51.2"), nullptr));
    ValueCallback* cb = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.510.2"), nullptr);
    callbacks.push_back(cb);
    callbacks.push_back(new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5100.2"), nullptr));
    callbacks.push_back(new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5100.1"), nullptr));
    callbacks.push_back(new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.51000.1"), nullptr));
    callbacks.push_back(new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.510.1"), nullptr));
    callbacks.push_back(new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.51.1"), nullptr));
    callbacks.push_back(new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1200.5100000.1"), nullptr));
    callbacks.push_back(new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.5.2"), nullptr));
    callbacks.push_back(new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1200.5.2"), nullptr));


    sort_handlers(callbacks);

    auto callbackIt = callbacks.begin();

    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1.5.2" );
    callbackIt++;
    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1.51.1" );
    callbackIt++;
    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1.51.2" );
    callbackIt++;
    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1.510.1" );
    callbackIt++;
    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1.510.2" );
    callbackIt++;
    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1.5100.1" );
    callbackIt++;
    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1.5100.2" );
    callbackIt++;
    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1.51000.1" );
    callbackIt++;
    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1200.5.2" );
    callbackIt++;
    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1200.5100000.1" );
    callbackIt++;

    REQUIRE( callbacks.size() == 10 );

    remove_handler(callbacks, cb);
    
    REQUIRE( callbacks.size() == 9 );

    for(auto callback : callbacks){
        REQUIRE( callback != cb );
    }

    // Removing CB Handler should not delete the Pointer (deleting handler deletes OID, so this should not crash)
    REQUIRE( cb->OID->string() == ".1.3.6.1.4.1.510.2" );

    callbackIt = callbacks.begin();

    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1.5.2" );
    callbackIt++;
    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1.51.1" );
    callbackIt++;
    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1.51.2" );
    callbackIt++;
    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1.510.1" );
    callbackIt++;
    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1.5100.1" );
    callbackIt++;
    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1.5100.2" );
    callbackIt++;
    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1.51000.1" );
    callbackIt++;
    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1200.5.2" );
    callbackIt++;
    REQUIRE( (*callbackIt)->OID->string() == ".1.3.6.1.4.1200.5100000.1" );
    callbackIt++;

}

TEST_CASE( "SNMPTraps ", "[snmp]"){
    SNMPTrap* settableNumberTrap = new SNMPTrap("public", SNMP_VERSION_1);

    uint32_t tensOfMillisCounter = 10;
    int changingNumber = 12;
    int settableNumber = 78;

    IntegerCallback* changingNumberOID = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.23.0"), &changingNumber);
    IntegerCallback* settableNumberOID = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.24.0"), &settableNumber);
    TimestampCallback* timestampCallbackOID = new TimestampCallback(new SortableOIDType(".1.3.6.1.2.1.1.3.0"), &tensOfMillisCounter);

    settableNumberTrap->setTrapOID(new OIDType(".1.3.6.1.2.1.33.2")); // OID of the trap
    settableNumberTrap->setSpecificTrap(1); 

    // Set the uptime counter to use in the trap
    settableNumberTrap->setUptimeCallback(timestampCallbackOID);

    // Set some previously set OID Callbacks to send these values with the trap
    settableNumberTrap->addOIDPointer(changingNumberOID);
    settableNumberTrap->addOIDPointer(settableNumberOID);

    settableNumberTrap->setIP(IPAddress(192, 168, 0, 1)); // Set our Source IP

    REQUIRE( settableNumberTrap->buildForSending() == true );


    uint8_t buffer[500] = {0};

    REQUIRE( settableNumberTrap->packet->serialise(buffer, 500) > 0 );


     ComplexType* trapBuffer = new ComplexType(STRUCTURE);
     REQUIRE( trapBuffer->fromBuffer(buffer, 150) == SNMP_BUFFER_ERROR_UNKNOWN_TYPE );

    // Traps cannot be parsed as regular packets and we'll make sure parsing fails'
//    SNMPPacket* trapPacket = new SNMPPacket();
//    REQUIRE( trapPacket->parseFrom(buffer, 150) == SNMP_PARSE_ERROR_AT_STATE(REQUESTID) );

}

TEST_CASE( "SNMPInform ", "[snmp]"){
    SNMPTrap* settableNumberTrap = new SNMPTrap("public", SNMP_VERSION_2C);
    settableNumberTrap->setInform(true);

    uint32_t tensOfMillisCounter = 10;
    int changingNumber = 12;
    int settableNumber = 78;

    IntegerCallback* changingNumberOID = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.23.0"), &changingNumber);
    IntegerCallback* settableNumberOID = new IntegerCallback(new SortableOIDType(".1.3.6.1.4.1.24.0"), &settableNumber);
    TimestampCallback* timestampCallbackOID = new TimestampCallback(new SortableOIDType(".1.3.6.1.2.1.1.3.0"), &tensOfMillisCounter);

    settableNumberTrap->setTrapOID(new OIDType(".1.3.6.1.2.1.33.2")); // OID of the trap

    // Set the uptime counter to use in the trap
    settableNumberTrap->setUptimeCallback(timestampCallbackOID);

    // Set some previously set OID Callbacks to send these values with the trap
    settableNumberTrap->addOIDPointer(changingNumberOID);
    settableNumberTrap->addOIDPointer(settableNumberOID);

    settableNumberTrap->setIP(IPAddress(192, 168, 0, 1)); // Set our Source IP

    REQUIRE( settableNumberTrap->buildForSending() == true );

    uint8_t buffer[500] = {0};

    REQUIRE( settableNumberTrap->packet->serialise(buffer, 500) > 0 );

    SNMPPacket* trapPacket = new SNMPPacket();
    REQUIRE(trapPacket->parseFrom(buffer, 150) == SNMP_ERROR_OK);

    REQUIRE( trapPacket->packetPDUType == InformRequestPDU );

}

TEST_CASE( "Test OID Validation ", "[snmp]"){
    REQUIRE( (new OIDType(".1.3.6.1.4.1.52420"))->valid );
    REQUIRE( (new OIDType(".1.3.6.1.4.1.52420."))->valid );
    REQUIRE( (new OIDType("1.3.6.1.4.1.52420"))->valid == false );
    REQUIRE( (new OIDType(".1.3.6.1.4.1..52420"))->valid == false );
}
