#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <AsyncTCP.h>
#include <ArduinoJson.h>
#include <SPIFFS.h>
#include <HTTPClient.h>
#include "esp_log.h"

// ============================
// WIFI FIXO (TESTE)
// ============================
const char* ssid = "rede";
const char* password = "senha";

const char* DB_URL_VALUE = "";
const char* ANON_KEY = "";
// ============================
// SERVIDOR WEB
// ============================
AsyncWebServer server(80);

// ============================
// PORTAS PARA ESCANEAR
// ============================
const int ports[] = {
    21,   // FTP
    22,   // SSH
    23,   // Telnet
    53,   // DNS
    80,   // HTTP
    135,  // RPC
    139,  // NetBIOS
    443,  // HTTPS
    445,  // SMB
    8080  // HTTP Alt
};
const int totalPorts = sizeof(ports) / sizeof(ports[0]);

// ============================
// TIMEOUT TCP
// ============================
const int TCP_TIMEOUT = 50;

// ============================
// ESTRUTURA DOS DISPOSITIVOS
// ============================
struct Device {
    String ip;
    bool online;
    String openPorts;
    bool vulnerable;
};

std::vector<Device> devices;

// ============================
// VERIFICA PORTA
// ============================
bool isPortOpen(IPAddress ip, int port) {

    WiFiClient client;

    client.setTimeout(TCP_TIMEOUT);

    bool connected = false;

    // Evita spam de erro no serial
    connected = client.connect(ip, port);

    if (connected) {
        client.stop();
        return true;
    }

    client.stop();

    return false;
}
void sendToSupabase(Device device) {

    HTTPClient http;

    http.begin(DB_URL_VALUE);

    http.addHeader(
        "Content-Type",
        "application/json"
    );

    http.addHeader(
        "apikey",
        ANON_KEY
    );

    http.addHeader(
        "Authorization",
        String("Bearer ") + ANON_KEY
    );

    String json = "{";

    json += "\"ip\":\"" + device.ip + "\",";
    json += "\"ports\":\"" + device.openPorts + "\",";
    json += "\"vulnerable\":";

    json += (device.vulnerable ? "true" : "false");

    json += "}";

    int responseCode = http.POST(json);

    Serial.print("Supabase response: ");
    Serial.println(responseCode);

    String response = http.getString();

    Serial.println(response);

    http.end();
}
// ============================
// ESCANEAR REDE
// ============================
void scanNetwork() {

    devices.clear();

    IPAddress localIP = WiFi.localIP();

    Serial.println("================================");
    Serial.println("Iniciando varredura...");
    Serial.println("================================");

    for (int i = 1; i < 50; i++) {

        IPAddress targetIP(
            localIP[0],
            localIP[1],
            localIP[2],
            i
        );

        Device device;

        device.ip = targetIP.toString();
        device.online = false;
        device.openPorts = "";
        device.vulnerable = false;

        bool foundAnyPort = false;

        // Escaneia portas UMA VEZ
        for (int p = 0; p < totalPorts; p++) {

            if (isPortOpen(targetIP, ports[p])) {

                foundAnyPort = true;

                switch (ports[p]) {

                    case 21:
                        device.openPorts += "FTP(21) ";
                        device.vulnerable = true;
                        break;

                    case 22:
                        device.openPorts += "SSH(22) ";
                        break;

                    case 23:
                        device.openPorts += "TELNET(23) ";
                        device.vulnerable = true;
                        break;

                    case 53:
                        device.openPorts += "DNS(53) ";
                        break;

                    case 80:
                        device.openPorts += "HTTP(80) ";
                        break;

                    case 135:
                        device.openPorts += "RPC(135) ";
                        break;

                    case 139:
                        device.openPorts += "NETBIOS(139) ";
                        device.vulnerable = true;
                        break;

                    case 443:
                        device.openPorts += "HTTPS(443) ";
                        break;

                    case 445:
                        device.openPorts += "SMB(445) ";
                        break;

                    case 8080:
                        device.openPorts += "HTTP-ALT(8080) ";
                        break;

                    default:
                        device.openPorts += String(ports[p]) + " ";
                }
            
            }
        }

        // Se encontrou alguma porta
        if (foundAnyPort) {

            device.online = true;

            devices.push_back(device);
            sendToSupabase(device);

            Serial.print("Host encontrado: ");
            Serial.print(device.ip);
            Serial.print(" | Portas: ");
            Serial.println(device.openPorts);
        }

        delay(10);
    }

    Serial.println("================================");
    Serial.println("Varredura concluída");
    Serial.println("================================");
}
// ============================
// JSON PARA FRONTEND
// ============================
String getDevicesJSON() {

    DynamicJsonDocument doc(8192);

    JsonArray array = doc.to<JsonArray>();

    for (auto &device : devices) {

        JsonObject obj = array.createNestedObject();

        obj["ip"] = device.ip;
        obj["online"] = device.online;
        obj["ports"] = device.openPorts;
        obj["vulnerable"] = device.vulnerable;
    }

    String json;

    serializeJson(doc, json);

    return json;
}

// ============================
// SETUP
// ============================
void setup() {
    esp_log_level_set("wifi", ESP_LOG_NONE);
    esp_log_level_set("tcpip_adapter", ESP_LOG_NONE);
    esp_log_level_set("WiFiClient", ESP_LOG_NONE);
    Serial.begin(115200);

    // ============================
    // SPIFFS
    // ============================
    if (!SPIFFS.begin(true)) {

        Serial.println("Erro ao iniciar SPIFFS");
        return;
    }

    // ============================
    // WIFI
    // ============================
    WiFi.mode(WIFI_STA);

    WiFi.begin(ssid, password);

    Serial.print("Conectando ao WiFi");

    while (WiFi.status() != WL_CONNECTED) {

        delay(500);
        Serial.print(".");
    }

    Serial.println();
    Serial.println("================================");
    Serial.println("WiFi conectado!");
    Serial.print("IP ESP32: ");
    Serial.println(WiFi.localIP());
    Serial.println("================================");

    // ============================
    // FRONTEND
    // ============================
    server.serveStatic("/", SPIFFS, "/")
          .setDefaultFile("index.html");

    // ============================
    // ROTA ESCANEAR
    // ============================
    server.on(
        "/scan",
        WebRequestMethod::HTTP_GET,
        [](AsyncWebServerRequest *request) {

            scanNetwork();

            request->send(
                200,
                "application/json",
                getDevicesJSON()
            );
        }
    );

    // ============================
    // ROTA DEVICES
    // ============================
    server.on(
        "/devices",
        WebRequestMethod::HTTP_GET,
        [](AsyncWebServerRequest *request) {

            request->send(
                200,
                "application/json",
                getDevicesJSON()
            );
        }
    );

    // ============================
    // START SERVIDOR
    // ============================
    server.begin();

    Serial.println("Servidor Web iniciado!");

    // Primeira varredura automática
    scanNetwork();
}

// ============================
// LOOP
// ============================
void loop() {

}
