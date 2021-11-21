//
// Created by Aidan on 20/11/2021.
//

#ifndef SNMPDEVICE_H
#define SNMPDEVICE_H

#include "defs.h"

class SNMPDevice {
  public:
    SNMPDevice(const IPAddress &ip, int port) : _ip(ip), _port(port){};

    SNMPDevice(const IPAddress &ip, int port, SNMP_VERSION version, const std::string &community) : _ip(ip),
                                                                                                    _port(port),
                                                                                                    _version(version),
                                                                                                    _community(
                                                                                                            community){};

    SNMPDevice(const SNMPDevice &device, SNMP_VERSION version, const std::string &community) : _ip(device._ip),
                                                                                               _port(device._port),
                                                                                               _version(version),
                                                                                               _community(community){};

    bool operator==(const SNMPDevice &other) const {
        return this->_ip == other._ip && this->_port == other._port;
    }

    const IPAddress _ip = INADDR_NONE;
    const int _port;
    const SNMP_VERSION _version = SNMP_VERSION_MAX;
    const std::string _community;
};

const SNMPDevice NO_DEVICE(INADDR_NONE, INT_MAX);

#endif//SNMPDEVICE_H
