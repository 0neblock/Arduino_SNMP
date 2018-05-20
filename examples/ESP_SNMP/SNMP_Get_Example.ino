#include <WiFi.h>
#include <WiFiUdp.h>
#include <Arduino_SNMP.h>

//************************************
//* update this with your WiFi info  *
//************************************
const char* ssid = "networkName";
const char* password = "P@ssword";
//************************************

unsigned int byteUp = 0; //value in octets (we are counting them as bytes)
unsigned int byteDown = 0;
unsigned long timeLast = 0;
int timeDelay = 2000; // delay in milliseconds

// initialise objects needed for SNMP
WiFiUDP udp; // UDP object used to send and recieve packets

SNMPAgent snmp = SNMPAgent("public");  // Starts an SMMPAgent instance with the community string 'public'
SNMPGet GetRequestUp = SNMPGet("public", 0); // Starts an SMMPGet instance with the community string 'public'
SNMPGet GetRequestDown = SNMPGet("public", 0); // Starts an SMMPGet instance with the community string 'public'
ValueCallback* callbackDownLoad;//blank callback pointer. every OID that you want to send a Get-request for needs one
ValueCallback* callbackUpLoad;

IPAddress netAdd = IPAddress(192,168,1,1); // IP address object of the device you want to get info from

void setup() 
{
  // put your setup code here, to run once:
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  Serial.println("");
  // Wait for connection
  while (WiFi.status() != WL_CONNECTED) 
    {
      delay(500);
      Serial.print(".");
    }
  Serial.println("");
  Serial.print("Connected to ");
  Serial.println(ssid);
  Serial.print("my IP address: ");
  Serial.println(WiFi.localIP());

  snmp.setUDP(&udp);// give snmp a pointer to the UDP object
  snmp.begin();// start the SNMP listener
  snmp.beginMaster(); // start the SNMP sender

  // OID for download
  snmp.addIntegerHandler(".1.3.6.1.2.1.2.2.1.16.3", &byteUp, true);

  // OID for upload
  snmp.addIntegerHandler(".1.3.6.1.2.1.2.2.1.10.3", &byteDown, true);

  //Create the call back ID's you will need to pass to the SNMP function
  callbackDownLoad = snmp.findCallback(".1.3.6.1.2.1.2.2.1.16.3", false);    
  callbackUpLoad = snmp.findCallback(".1.3.6.1.2.1.2.2.1.10.3", false);

}

void loop() {
  // put your main code here, to run repeatedly:
  snmp.loop();
  getSNMP();
}

void getSNMP(){
  //check to see if it is time to send an SNMP request.
  //if you send requests to often it seens to cause some issues
  if((timeLast + timeDelay) <= millis()){
    
      //see the results of the get-request in the serial monitor
        Serial.print("byte Up: ");        
        Serial.print(byteUp);
        Serial.println();
        Serial.print("byte Down: ");
        Serial.print(byteDown);
        Serial.println();  
        Serial.println("----------------------");

      //build a SNMP get-request
      GetRequestDown.addOIDPointer(callbackDownLoad);                
      GetRequestDown.setIP(WiFi.localIP()); //IP of the arduino                
      GetRequestDown.setUDP(&udp);
      GetRequestDown.setRequestID(rand() % 5555);
      GetRequestDown.sendTo(netAdd); //IP of the remote client
      GetRequestDown.clearOIDList();   
      snmp.resetSetOccurred();
      
      GetRequestUp.addOIDPointer(callbackUpLoad);                
      GetRequestUp.setIP(WiFi.localIP());                 
      GetRequestUp.setUDP(&udp);
      GetRequestUp.setRequestID(rand() % 5555);                
      GetRequestUp.sendTo(netAdd);               
      GetRequestUp.clearOIDList();
      snmp.resetSetOccurred();
    
      timeLast = millis();
    }  
  
}
