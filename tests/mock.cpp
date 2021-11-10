#include "include/SNMPPacket.h"
#include "include/ValueCallbacks.h"
#include "include/SNMPParser.h"

// Server side implementation of UDP client-server model 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <deque>
  
#define PORT     161
#define MAXLINE 1024 

std::deque<ValueCallback*> callbacks;

int testingInt = 0;
  
// Driver code 
int main() { 
    int sockfd; 
    char buffer[MAXLINE]; 
    struct sockaddr_in servaddr, cliaddr; 
      
    // Creating socket file descriptor 
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
      
    memset(&servaddr, 0, sizeof(servaddr)); 
    memset(&cliaddr, 0, sizeof(cliaddr)); 
      
    // Filling server information 
    servaddr.sin_family    = AF_INET; // IPv4 
    servaddr.sin_addr.s_addr = INADDR_ANY; 
    servaddr.sin_port = htons(PORT); 
      
    // Bind the socket with the server address 
    if ( bind(sockfd, (const struct sockaddr *)&servaddr,  
            sizeof(servaddr)) < 0 ) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
      
    int len, n; 
  
    len = sizeof(cliaddr);  //len is value/resuslt 

    // IntegerCallback* intCallback = new IntegerCallback(new OIDType(".1.3.6.1.4.1.5.0"));
    // intCallback->value = &testingInt;
    // callbacks.push_back(intCallback);

    const char* prefix = ".1.3.6.1.4.1.5.";

    printf("creating objs\n");


    for(int i = 29999; i > 0; i--){
        char buf[29] = {0};
        sprintf(buf, "%s%d", prefix, i);
        auto* oid = new SortableOIDType(buf);

        int* testInt = (int*)calloc(1, sizeof(int));
        *testInt = rand();
        IntegerCallback* cb = new IntegerCallback(oid, testInt);
        callbacks.push_back(cb);
    }

    printf("sorting\n");

    sort_handlers(callbacks);

    printf("ready\n");

    while(true){
        n = recvfrom(sockfd, (char *)buffer, MAXLINE,  
                    MSG_WAITALL, ( struct sockaddr *) &cliaddr, 
                    (socklen_t*)&len); 
        buffer[n] = '\0'; 

        int responseLength = 0;

        SNMP_ERROR_RESPONSE response = handlePacket((uint8_t*)buffer, n, &responseLength, 1024, callbacks, "public", "pub");

        printf("SNMP Packet : %d, len:%d\n", response, responseLength); 
        if(response > 0){
            sendto(sockfd, (const char *)buffer, responseLength,  
            0, (const struct sockaddr *) &cliaddr, 
                len);
        }
        
    }
    return 0; 
} 