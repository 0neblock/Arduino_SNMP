#define DEBUG 1

#include "include/SNMPPacket.h"
#include "include/SNMPParser.h"
#include "include/SNMPRequest.h"
#include "include/ValueCallbacks.h"

// Server side implementation of UDP client-server model
#include <arpa/inet.h>
#include <deque>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PORT 161
#define MAXLINE 1024

std::deque<ValueCallbackContainer> callbacks;
const uint8_t address[4] = {192, 168, 1, 88};
int testingInt = 0;

void runagent() {
    int sockfd;
    char buffer[MAXLINE];
    struct sockaddr_in servaddr, cliaddr;

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;// IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    // Bind the socket with the server address
    if (bind(sockfd, (const struct sockaddr *) &servaddr,
             sizeof(servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    int len, n;

    len = sizeof(cliaddr);//len is value/resuslt

    // IntegerCallback* intCallback = new IntegerCallback(new OIDType(".1.3.6.1.4.1.5.0"));
    // intCallback->value = &testingInt;
    // callbacks.push_back(intCallback);

    const char *prefix = ".1.3.6.1.4.1.5.";

    printf("creating objs\n");


    for (int i = 29999; i > 0; i--) {
        char buf[29] = {0};
        sprintf(buf, "%s%d", prefix, i);
        auto *oid = new SortableOIDType(buf);

        int *testInt = (int *) calloc(1, sizeof(int));
        *testInt = rand();
        IntegerCallback *cb = new IntegerCallback(oid, testInt);
        callbacks.emplace_back(cb);
    }

    printf("sorting\n");

    sort_handlers(callbacks);

    printf("ready\n");

    LiveRequestList liveRequests;

    while (true) {
        n = recvfrom(sockfd, (char *) buffer, MAXLINE,
                     MSG_WAITALL, (struct sockaddr *) &cliaddr,
                     (socklen_t *) &len);
        buffer[n] = '\0';

        int responseLength = 0;

        SNMP_ERROR_RESPONSE response = handlePacket((uint8_t *) buffer, n, &responseLength, 1024, callbacks, "public",
                                                    "pub", liveRequests, nullptr);

        printf("SNMP Packet : %d, len:%d\n", response, responseLength);
        if (response > 0) {
            sendto(sockfd, (const char *) buffer, responseLength,
                   0, (const struct sockaddr *) &cliaddr,
                   len);
        }
    }
}

bool responseCallback(const VarBind& responseVarBind, bool success, int errorStatus,
                 const ValueCallbackContainer &container) {
    SNMP_LOGI("Response callback for oid: %s, success: %s\n", responseVarBind.oid->string().c_str(), success ? "true" : "false");
    if (container) {
        SNMP_LOGI("Had matching callback\n");
    } else {
        SNMP_LOGW("Unsolicited OID response: %s\n", responseVarBind.oid->string().c_str());
        SNMP_LOGD("Error Status: %d\n", errorStatus);
    }
    return true;
}

void runmanager() {
    struct sockaddr_in senderaddr;
    struct sockaddr_in cliaddr;


    int sockfd, csockfd;
    uint8_t buffer[MAXLINE];

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Filling server information
    senderaddr.sin_family = AF_INET;// IPv4
    senderaddr.sin_port = htons(10062);
    senderaddr.sin_addr.s_addr = INADDR_ANY;


    // Bind the socket with the server address
    if (bind(sockfd, (const struct sockaddr *) &senderaddr,
             sizeof(senderaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Filling client information
    cliaddr.sin_family = AF_INET;// IPv4
    cliaddr.sin_port = htons(161);
    cliaddr.sin_addr.s_addr = INADDR_ANY;
    memcpy(&cliaddr.sin_addr.s_addr, address, 4);
    // Creating socket file descriptor
    if ((csockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    int len, n;

    len = sizeof(cliaddr);//len is value/resuslt

    // sockfd is our listening manager for responses, and our sending channel

    LiveRequestList liveRequests;

    SNMPDevice device(address, 161);


    while (true) {
        getchar();

        auto packet = SNMPRequest(GetNextRequestPDU);
        packet.setCommunityString("public");


        int testValue = 0;
        char oid[50] = {0};
        uint32_t r = rand() / 100000 * 2;
        snprintf(oid, 50, ".1.3.6.1.4.1.5.%d", r);
        auto testCallback = new IntegerCallback(new SortableOIDType(oid), &testValue);
        callbacks.emplace_back(&device, testCallback);
        packet.addValueCallback(testCallback);
        packet.setVersion(SNMP_VERSION_2C);

        auto serialized = packet.serialiseInto(buffer, MAXLINE);

        if (serialized > 0) {
            sendto(sockfd, (const char *) buffer, serialized,
                   0, (const struct sockaddr *) &cliaddr,
                   len);
            liveRequests.emplace_back(packet.requestID, packet.packetPDUType);
        }

        n = recvfrom(sockfd, (char *) buffer, MAXLINE,
                     MSG_WAITALL, (struct sockaddr *) &cliaddr,
                     (socklen_t *) &len);
        buffer[n] = '\0';

        int responseLength = 0;


        SNMPDevice incomingDevice(cliaddr.sin_addr.s_addr, 161);
        printf("Packet from: %s:%d\n", incomingDevice._ip.toString().c_str(), incomingDevice._port);
        SNMP_ERROR_RESPONSE response = handlePacket((uint8_t *) buffer, n, &responseLength, 1024, callbacks, "public",
                                                    "pub", liveRequests, nullptr, responseCallback, nullptr, incomingDevice);

        printf("SNMP Packet : %d, len:%d, requestId: %u\n", response, responseLength, packet.requestID);
        printf("int value: %d\n", testValue);
        printf("Live Requests: %lu\n", liveRequests.size());
        //        if(response > 0){
        //            sendto(sockfd, (const char *)buffer, responseLength,
        //                   0, (const struct sockaddr *) &cliaddr,
        //                   len);
        //        }
    }
}

// Driver code
int main(int argc, char **argv) {
    if (strcmp("agent", argv[argc - 1]) == 0) {
        runagent();
    } else {
        runmanager();
    }

    return 0;
}