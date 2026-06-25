#include <Arduino.h>
#include <WiFi.h>
#include <WiFiManager.h> 
#include <vector>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include <SPIFFS.h>
#include <HTTPClient.h>

// Bibliotecas do kernel LwIP
#include "lwip/sockets.h"
#include <errno.h>
#include "lwip/etharp.h"
#include "lwip/ip4_addr.h"

// Bibliotecas para o display I2C
#include <Wire.h>
#include <LiquidCrystal_I2C.h>

// Instanciação do LCD I2C (Endereço padrão 0x27, 16 colunas, 2 linhas)
LiquidCrystal_I2C lcd(0x27, 16, 2);

// ============================
// CONFIGURAÇÕES GERAIS
// ============================
const char* DB_URL_VALUE = "https://cgrsawbvpzirtvmuftnw.supabase.co/rest/v1/rpc/insert_scan_data";
const char* ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNncnNhd2J2cHppcnR2bXVmdG53Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzkzOTkxNzEsImV4cCI6MjA5NDk3NTE3MX0.Ze9l_B4qPw5K8G62BcAPeP3YusJVsMqObsw-AwVUkDI";
const char* KNOWN_DEVICES_FILE = "/known_macs.json";

unsigned long lastScanTime = 0;
const unsigned long SCAN_INTERVAL = 3 * 60 * 1000; 

AsyncWebServer server(80);
std::vector<String> knownMACs; 

struct ServiceInfo {
  int port;
  String name;
  bool is_vulnerable;
};

const ServiceInfo target_services[] = {
  {80, "HTTP", false}, {443, "HTTPS", false}, {8080, "HTTP-Alt", false}, 
  {8443, "HTTPS-Alt", false}, {22, "SSH", false}, {23, "Telnet", true}, 
  {3389, "RDP", false}, {139, "NetBIOS", true}, {445, "SMB", false}, 
  {21, "FTP", true}, {9100, "RawPrint", false}, {515, "LPD", false}
};
const int num_services = sizeof(target_services) / sizeof(target_services[0]);

struct NetworkDevice {
  IPAddress ip;
  String mac;
  String status;
  bool vulnerable;
  bool is_new; 
  std::vector<ServiceInfo> active_ports;
};

std::vector<NetworkDevice> activeDevices;

// =========================================================================
// CONTROLE DO DISPLAY LCD FÍSICO
// =========================================================================
void lcdPrint(String line1, String line2) {
  lcd.clear();
  
  lcd.setCursor(0, 0);
  lcd.print(line1.substring(0, 16)); 
  
  lcd.setCursor(0, 1);
  lcd.print(line2.substring(0, 16));
  
  Serial.println("\n[LCD] " + line1 + " | " + line2);
}

// =========================================================================
// GESTÃO DE ESTADO (PERSISTÊNCIA SPIFFS)
// =========================================================================
void loadKnownDevices() {
  if (!SPIFFS.exists(KNOWN_DEVICES_FILE)) return;
  
  File file = SPIFFS.open(KNOWN_DEVICES_FILE, FILE_READ);
  DynamicJsonDocument doc(4096);
  DeserializationError error = deserializeJson(doc, file);
  file.close();

  if (!error) {
    JsonArray array = doc.as<JsonArray>();
    for (JsonVariant v : array) {
      knownMACs.push_back(v.as<String>());
    }
    Serial.printf("Memoria restaurada: %d dispositivos conhecidos.\n", knownMACs.size());
  }
}

void saveKnownDevices() {
  File file = SPIFFS.open(KNOWN_DEVICES_FILE, FILE_WRITE);
  DynamicJsonDocument doc(4096);
  JsonArray array = doc.to<JsonArray>();
  
  for (String mac : knownMACs) {
    array.add(mac);
  }
  
  serializeJson(doc, file);
  file.close();
}

bool isDeviceNew(String mac) {
  if (mac == "Desconhecido") return false; 
  for (String known : knownMACs) {
    if (known == mac) return false;
  }
  return true;
}

// =========================================================================
// FUNÇÃO DE BAIXO NÍVEL: Sockets POSIX
// =========================================================================
int checkSocketStatus(IPAddress ip, int port, int timeout_ms) {
  int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0) return 2;

  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);

  struct sockaddr_in dest_addr;
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(port);
  dest_addr.sin_addr.s_addr = static_cast<uint32_t>(ip);

  int res = connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
  
  if (res < 0 && errno == EINPROGRESS) {
    fd_set write_set;
    FD_ZERO(&write_set);
    FD_SET(sock, &write_set);
    
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = timeout_ms * 1000; 
    
    res = select(sock + 1, NULL, &write_set, NULL, &tv);
    
    if (res > 0) {
      int sock_err = 0;
      socklen_t optlen = sizeof(sock_err);
      getsockopt(sock, SOL_SOCKET, SO_ERROR, &sock_err, &optlen);
      close(sock); 
      
      if (sock_err == 0) return 0; 
      if (sock_err == ECONNREFUSED || sock_err == ECONNRESET) return 1; 
      return 2; 
    }
  }
  close(sock);
  return 2; 
}

// =========================================================================
// UPLOAD SUPABASE
// =========================================================================
// =========================================================================
// UPLOAD SUPABASE EM LOTES (ANTI-ESTOURO DE RAM)
// =========================================================================
void uploadToSupabase() {
  if (WiFi.status() != WL_CONNECTED) return;
  
  lcdPrint("Iniciando Upload", "Conectando API...");

  HTTPClient http;
  String scan_id = "";

  // -------------------------------------------------------------------------
  // FASE A: Criar o cabeçalho do Scan e recuperar o UUID gerado
  // -------------------------------------------------------------------------
  String startUrl = "https://cgrsawbvpzirtvmuftnw.supabase.co/rest/v1/rpc/start_scan";
  http.begin(startUrl);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("apikey", ANON_KEY);
  http.addHeader("Authorization", String("Bearer ") + ANON_KEY);

  DynamicJsonDocument docStart(512);
  docStart["p_network_ssid"] = WiFi.SSID();
  String startPayload;
  serializeJson(docStart, startPayload);

  int httpCode = http.POST(startPayload);
  
  if (httpCode >= 200 && httpCode < 300) {
    String response = http.getString();
    // O Supabase retorna o valor puro ou dentro de aspas. Limpamos as aspas para obter o UUID limpo
    response.replace("\"", "");
    scan_id = response;
    scan_id.trim();
    Serial.println("[Nuvem] Scan ID gerado: " + scan_id);
  } else {
    lcdPrint("Erro Inicializ.", "HTTP: " + String(httpCode));
    http.end();
    return;
  }
  http.end();

  // -------------------------------------------------------------------------
  // FASE B: Transmitir os Dispositivos em lotes (Chunks de 10 em 10)
  // -------------------------------------------------------------------------
  int totalDevices = activeDevices.size();
  int chunkSize = 10; // Tamanho ideal para manter o buffer JSON leve (~2.5KB)
  int totalBatches = (totalDevices + chunkSize - 1) / chunkSize;

  String batchUrl = "https://cgrsawbvpzirtvmuftnw.supabase.co/rest/v1/rpc/insert_scan_batch";

  for (int i = 0; i < totalDevices; i += chunkSize) {
    int currentBatch = (i / chunkSize) + 1;
    lcdPrint("Enviando Lote", String(currentBatch) + "/" + String(totalBatches));

    http.begin(batchUrl);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("apikey", ANON_KEY);
    http.addHeader("Authorization", String("Bearer ") + ANON_KEY);

    // Buffer controlado de 4KB - perfeitamente seguro para a Heap do ESP32
    DynamicJsonDocument docBatch(4096);
    docBatch["p_scan_id"] = scan_id;
    JsonArray devicesArr = docBatch.createNestedArray("p_devices");

    // Preenche o lote atual
    for (int j = i; j < i + chunkSize && j < totalDevices; j++) {
      const auto& dev = activeDevices[j];
      JsonObject devObj = devicesArr.createNestedObject();
      devObj["ip"] = dev.ip.toString();
      devObj["mac"] = dev.mac;
      devObj["status"] = dev.status;
      devObj["vulnerable"] = dev.vulnerable;
      devObj["is_new"] = dev.is_new;

      JsonArray portsArr = devObj.createNestedArray("open_ports");
      for (const auto& port : dev.active_ports) {
        JsonObject portObj = portsArr.createNestedObject();
        portObj["port"] = port.port;
        portObj["name"] = port.name;
        portObj["is_vulnerable"] = port.is_vulnerable;
      }
    }

    String batchPayload;
    serializeJson(docBatch, batchPayload);

    int batchHttpCode = http.POST(batchPayload);
    Serial.printf("[Lote %d/%d] Resposta HTTP: %d\n", currentBatch, totalBatches, batchHttpCode);
    
    if (batchHttpCode < 200 || batchHttpCode >= 300) {
      Serial.println("[Erro] Falha crítica ao enviar lote.");
      // Opcional: break; para interromper se a rede cair no meio
    }
    http.end();
    delay(100); // Pequeno respiro para estabilização do rádio e roteador
  }

  lcdPrint("Upload Concluido", "Hosts: " + String(totalDevices));
}
// =========================================================================
// MOTOR DE VARREDURA
// =========================================================================
void performDeepScan() {
  lcdPrint("Iniciando Scan", "Varrendo Rede...");
  
  activeDevices.clear();
  bool updatedKnownList = false;

  IPAddress localIP = WiFi.localIP();
  IPAddress subnetMask = WiFi.subnetMask();
  
  uint32_t ip_num = localIP[0] << 24 | localIP[1] << 16 | localIP[2] << 8 | localIP[3];
  uint32_t mask_num = subnetMask[0] << 24 | subnetMask[1] << 16 | subnetMask[2] << 8 | subnetMask[3];
  uint32_t network_num = ip_num & mask_num;
  uint32_t broadcast_num = network_num | (~mask_num);

  // --- FASE 1: DESCOBERTA ---
  for (uint32_t i = network_num + 1; i < broadcast_num; i++) {
    IPAddress targetIP(i >> 24, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF);
    if (targetIP == localIP) continue; 

    int trigger = checkSocketStatus(targetIP, 44444, 200);
    
    bool deviceIsAlive = false;
    String statusMsg = "";
    String macFound = "Desconhecido";

    if (trigger == 1 || trigger == 0) {
      deviceIsAlive = true;
      statusMsg = "Exposto";
    } 

    ip4_addr_t *ipaddr;
    struct netif *netif;
    struct eth_addr *eth_ret;

    for (int j = 0; j < ARP_TABLE_SIZE; j++) {
      if (etharp_get_entry(j, &ipaddr, &netif, &eth_ret)) {
        IPAddress cachedIP(ip4_addr1(ipaddr), ip4_addr2(ipaddr), ip4_addr3(ipaddr), ip4_addr4(ipaddr));
        if (cachedIP == targetIP) {
          deviceIsAlive = true;
          char macStr[18];
          snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                   eth_ret->addr[0], eth_ret->addr[1], eth_ret->addr[2],
                   eth_ret->addr[3], eth_ret->addr[4], eth_ret->addr[5]);
          macFound = String(macStr);
          if (trigger == 2) statusMsg = "Stealth";
          break; 
        }
      }
    }

    if (deviceIsAlive) {
      bool isNew = isDeviceNew(macFound);
      
      if (isNew && macFound != "Desconhecido") {
        lcdPrint("NOVO DETECTADO!", targetIP.toString());
        knownMACs.push_back(macFound);
        updatedKnownList = true;
        delay(1500); 
      }

      activeDevices.push_back({targetIP, macFound, statusMsg, false, isNew, std::vector<ServiceInfo>()});
    }
  }

  if (updatedKnownList) saveKnownDevices();

  // --- FASE 2: FINGERPRINTING ---
  lcdPrint("Analisando", "Portas e Vulns");
  
  for (auto& device : activeDevices) {
    lcdPrint("Checando IP:", device.ip.toString());

    for (int p = 0; p < num_services; p++) {
      int status = checkSocketStatus(device.ip, target_services[p].port, 300);
      
      if (status == 0) { 
        device.active_ports.push_back(target_services[p]);
        if (target_services[p].is_vulnerable) device.vulnerable = true;
      }
      delay(20); 
    }
  }
  
  lcdPrint("Scan Concluido", "Hosts: " + String(activeDevices.size()));
  delay(1000);
  uploadToSupabase();
  
  lcdPrint("Modo Standby", WiFi.localIP().toString());
}

// =========================================================================
// SETUP E LOOP
// =========================================================================
void setup() {
  Serial.begin(115200);
  
  // Inicialização obrigatória do Hardware I2C e Backlight
  lcd.init();
  lcd.backlight();
  
  lcdPrint("Iniciando", "Sistema...");

  if (!SPIFFS.begin(true)) {
    Serial.println("Erro ao iniciar SPIFFS");
  }
  loadKnownDevices(); 

  lcdPrint("Configurando", "Rede WiFi...");
  WiFiManager wm;
  
  bool res = wm.autoConnect("Netsweeper_AP", "admin123");

  if(!res) {
    lcdPrint("Falha na Rede", "Reiniciando...");
    delay(3000);
    ESP.restart();
  } 

  lcdPrint("Conectado!", WiFi.localIP().toString());
  delay(2000);

  server.begin();
  
  performDeepScan();
  lastScanTime = millis();
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    lcdPrint("Rede Perdida!", "Reconectando...");
    WiFi.reconnect();
    while (WiFi.status() != WL_CONNECTED) {
      delay(1000);
    }
    lcdPrint("Reconectado!", WiFi.localIP().toString());
  }

  if (millis() - lastScanTime >= SCAN_INTERVAL) {
    performDeepScan();
    lastScanTime = millis();
  }
}