cmake_minimum_required(VERSION 3.16)
project(Arduino_SNMP2)

set(CMAKE_CXX_STANDARD 11)

include_directories(.)
include_directories(src)
include_directories(src/include)

add_definitions(-DCOMPILING_TESTS)
add_definitions(-Wall -Wpedantic -Wextra -Werror)

add_definitions(-Wno-error=sequence-point)          # UB for negative ints
#add_definitions(-Wno-error=macro-redefined)          # No Macro redefinitions


add_executable(MOCK
        tests/required/IPAddress.cpp
        tests/mock.cpp
        src/BERDecode.cpp
        src/BEREncode.cpp
        src/SNMPPacket.cpp
        src/SNMPParser.cpp
        src/SNMPInform.cpp
        src/SNMPPDUHandler.cpp
        src/SNMPResponse.cpp
        src/SNMPTrap.cpp
        src/ValueCallbacks.cpp)

add_executable(TESTS
        tests/required/IPAddress.cpp
        tests/tests.cpp
        src/Arduino_SNMP.cpp
        src/BERDecode.cpp
        src/BEREncode.cpp
        src/SNMPPacket.cpp
        src/SNMPParser.cpp
        src/SNMPInform.cpp
        src/SNMPPDUHandler.cpp
        src/SNMPResponse.cpp
        src/SNMPTrap.cpp
        src/ValueCallbacks.cpp )
