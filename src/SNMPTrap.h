// we're going to have a trap object, which is created in setup. it includes the main trapOID, other trap-ish options, and an attached list of the OIDCallback objects (the ones you get back from addIntegerHandler etc) to contain the values that need to be ent with this Trap.
// it ca then be called from code, trap->send or whatever. trap receivers should also be attached to a list that can be changed

#ifndef SNMPTrap_h
#define SNMPTrap_h

#include "include/SNMPPacket.h"
#include "include/ValueCallbacks.h"
#include "include/defs.h"
#include <list>

#include <stdlib.h>

#ifdef COMPILING_TESTS

#include "tests/required/IPAddress.h"
#include "tests/required/UDP.h"

#endif

class SNMPTrap : public SNMPPacket {
  public:
    SNMPTrap(const char *community, SNMP_VERSION version) {
        this->setVersion(version);
        // Version two will use the SNMPPacket builder which uses the member pduType
        // Version one will use special builder with hardcoded PDU Type
        this->setPDUType(Trapv2PDU);
        this->setCommunityString(community);
    };

    virtual ~SNMPTrap();

    IPAddress agentIP;
    OIDType *trapOID = nullptr;

    TimestampCallback *uptimeCallback = nullptr;
    short genericTrap = 6;
    short specificTrap = 1;

    short trapUdpPort = 162;

    bool inform = false;

    bool setInform(bool inf);
    // the setters that need to be configured for each trap.

    void setTrapOID(OIDType *oid) {
        trapOID = oid;
    }

    void setSpecificTrap(short num) {
        specificTrap = num;
    }

    void setIP(const IPAddress &ip) {// sets our IP
        agentIP = ip;
    }

    void setUDPport(short port) {
        trapUdpPort = port;
    }

    void setUDP(UDP *udp) {
        _udp = udp;
    }

    void setUptimeCallback(TimestampCallback *uptime) {
        uptimeCallback = uptime;
    }

    void addOIDPointer(ValueCallback *callback);

    UDP *_udp = nullptr;

    bool buildForSending();

    bool sendTo(const IPAddress &ip, bool skipBuild = false);

  protected:
    std::list<ValueCallback *> callbacks;

    std::shared_ptr<ComplexType> generateVarBindList() override;

    OIDType *timestampOID = new OIDType(".1.3.6.1.2.1.1.3.0");
    OIDType *snmpTrapOID = new OIDType(".1.3.6.1.2.1.1.2.0");

    friend class ValueCallback;

    bool build() override;
};

#endif
