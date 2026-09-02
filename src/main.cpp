// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include "esp_system.h"
#include "esp_task_wdt.h"
#include <stdarg.h>
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- config ----
static const IPAddress UPSTREAM(9, 9, 9, 9);     // Quad9
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const uint32_t DNS_FAILURE_WARN_THRESHOLD = 10;
static const uint32_t DNS_FAILURE_RESTART_THRESHOLD = 30;
static const uint32_t DNS_NO_SUCCESS_RESTART_MS = 60000;
static const uint32_t WIFI_DISCONNECTED_RESTART_MS = 30000;
static const size_t DIAG_LOG_MAX_BYTES = 12288;

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[600];
uint8_t upstreamBuf[600];
uint32_t dnsConsecutiveFailures = 0, dnsTotalFailures = 0, dnsTotalSuccesses = 0;
uint32_t lastSuccessfulDnsMs = 0, wifiDisconnectedSinceMs = 0;
bool littleFsReady = false, watchdogReady = false, restartPending = false;
String currentResetReason, previousRestartReason;

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

static void feedWatchdog() { if (watchdogReady) esp_task_wdt_reset(); }
static const char* resetReasonName(esp_reset_reason_t reason) {
  switch (reason) {
    case ESP_RST_POWERON: return "power on";
    case ESP_RST_SW: return "software";
    case ESP_RST_PANIC: return "panic";
    case ESP_RST_TASK_WDT: return "task watchdog";
    case ESP_RST_WDT: return "watchdog";
    case ESP_RST_BROWNOUT: return "brownout";
    default: return "other";
  }
}
static void diagLog(const char* format, ...) {
  char message[240]; va_list args; va_start(args, format); vsnprintf(message, sizeof(message), format, args); va_end(args);
  char line[280]; snprintf(line, sizeof(line), "[%lus] %s\n", millis() / 1000, message);
  Serial.print(line);
  if (!littleFsReady) return;
  File log = LittleFS.open("/diagnostics.log", "a"); if (!log) return;
  log.print(line); size_t size = log.size(); log.close();
  if (size <= DIAG_LOG_MAX_BYTES) return;
  log = LittleFS.open("/diagnostics.log", "r"); if (!log) return;
  String retained = log.readString(); log.close();
  size_t target = DIAG_LOG_MAX_BYTES - 1024;
  size_t cut = retained.length() > target ? retained.indexOf('\n', retained.length() - target) : 0;
  retained = cut == (size_t)-1 ? retained.substring(retained.length() - target) : retained.substring(cut + 1);
  log = LittleFS.open("/diagnostics.log", "w"); if (log) { log.print(retained); log.close(); }
}
static void loadRestartReason() {
  Preferences restartPrefs; restartPrefs.begin("reliability", false);
  previousRestartReason = restartPrefs.getString("lastReason", "");
  restartPrefs.remove("lastReason"); restartPrefs.end();
}
static void restartForReliability(const char* reason) {
  if (restartPending) return;
  restartPending = true;
  Preferences restartPrefs; restartPrefs.begin("reliability", false); restartPrefs.putString("lastReason", reason); restartPrefs.end();
  diagLog("[RELIABILITY] AUTOMATIC RESTART: %s; DNS failures %lu consecutive/%lu total, successes %lu, heap %u, WiFi %d",
          reason, dnsConsecutiveFailures, dnsTotalFailures, dnsTotalSuccesses, ESP.getFreeHeap(), WiFi.status());
  for (int i = 0; i < 30; i++) { feedWatchdog(); delay(10); }
  ESP.restart();
}

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static bool inFlash(uint64_t h) {
  int32_t lo = 0, hi = (int32_t)numHashes - 1; uint8_t b[HASH_BYTES];
  while (lo <= hi) {
    int32_t mid = (lo + hi) >> 1;
    blocklist.seek((uint32_t)mid * HASH_BYTES); blocklist.read(b, HASH_BYTES);
    uint64_t v = 0; for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
    if (v < h) lo = mid + 1; else if (v > h) hi = mid - 1; else return true;
  }
  return false;
}
static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }
static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (inFlash(h) || inCustom(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// ---------- persistence ----------
static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; saveCustom(); return true;
}
static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--; saveCustom(); return;
  }
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0; int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
static int forwardUpstream(int qlen) {
  while (upstreamCli.parsePacket() > 0) {
    while (upstreamCli.available()) upstreamCli.read(upstreamBuf, sizeof(upstreamBuf));
    upstreamCli.flush();
  }

  uint8_t query[sizeof(buf)];
  memcpy(query, buf, qlen);
  uint16_t clientId = ((uint16_t)query[0] << 8) | query[1];
  uint16_t upstreamId = (uint16_t)esp_random();
  query[0] = upstreamId >> 8; query[1] = upstreamId & 0xff;

  upstreamCli.beginPacket(UPSTREAM, 53); upstreamCli.write(query, qlen); upstreamCli.endPacket();
  uint32_t t0 = millis();
  while (millis() - t0 < 750) {
    int sz = upstreamCli.parsePacket();
    if (sz > 0) {
      IPAddress sourceIp = upstreamCli.remoteIP(); uint16_t sourcePort = upstreamCli.remotePort();
      int rlen = upstreamCli.read(upstreamBuf, sizeof(upstreamBuf));
      upstreamCli.flush();
      bool valid = sourceIp == UPSTREAM && sourcePort == DNS_PORT &&
                   rlen >= qlen && rlen <= (int)sizeof(buf) &&
                   upstreamBuf[0] == query[0] && upstreamBuf[1] == query[1] &&
                   memcmp(upstreamBuf + 12, query + 12, qlen - 12) == 0;
      if (valid) {
        memcpy(buf, upstreamBuf, rlen);
        buf[0] = clientId >> 8; buf[1] = clientId & 0xff;
        dnsTotalSuccesses++; dnsConsecutiveFailures = 0; lastSuccessfulDnsMs = millis();
        return rlen;
      }
    }
    feedWatchdog(); delay(1);
  }
  dnsTotalFailures++; dnsConsecutiveFailures++;
  if (dnsConsecutiveFailures == DNS_FAILURE_WARN_THRESHOLD)
    diagLog("[DNS] %lu consecutive upstream failures", dnsConsecutiveFailures);
  if (dnsConsecutiveFailures >= DNS_FAILURE_RESTART_THRESHOLD)
    restartForReliability("too many consecutive upstream DNS failures");
  return 0;
}
// Drain a whole RX burst per call (capped, so web/OTA still get a turn) instead of
// one packet per loop iteration. Returns true if any query was handled this call.
static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 8; budget++) {
    int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf));
    if (qlen >= 13) {
      char domain[256]; uint16_t qtype = 0; int qend = qlen;
      size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
      Dev* c = getClient((uint32_t)cip);
      bool ban = c && c->banned;
      bool blocked = ban || (blockingOn && dl && numHashes && isBlocked(domain));
      int rlen;
      if (blocked) { rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++; }
      else {
        rlen = forwardUpstream(qlen);
        if (rlen > 0) { totalAllowed++; if (c) c->allowed++; }
      }
      if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
    }
    feedWatchdog(); yield();
  }
  return did;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) { String o; for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; } return o; }
static String hesc(const String& s) {
  String o; for (char ch : s) { if (ch == '&') o += "&amp;"; else if (ch == '<') o += "&lt;"; else if (ch == '>') o += "&gt;"; else o += ch; } return o;
}

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"psram\":" + (psramFound() ? ESP.getFreePsram() : 0) +
             ",\"dnsFailures\":" + dnsTotalFailures + ",\"dnsSuccesses\":" + dnsTotalSuccesses +
             ",\"dnsConsecutiveFailures\":" + dnsConsecutiveFailures + ",\"resetReason\":\"" + jesc(currentResetReason) + "\"" +
             ",\"lastRestartReason\":\"" + jesc(previousRestartReason) + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "]}";
  web.send(200, "application/json", j);
}
static String readDiagnostics() {
  File log = LittleFS.open("/diagnostics.log", "r"); if (!log) return "No diagnostic events recorded.\n";
  String text = log.readString(); log.close(); return text;
}
static void handleLogs() {
  String page = "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
                "<title>AdBlock diagnostics</title><body style='font:14px system-ui;max-width:1000px;margin:24px auto;padding:0 16px'>"
                "<p><a href='/'>Dashboard</a> <button onclick=\"location.reload()\">Refresh</button> "
                "<button onclick=\"fetch('/logs/clear',{method:'POST'}).then(()=>location.reload())\">Clear</button></p>"
                "<p><b>Reset reason:</b> " + hesc(currentResetReason) + "<br><b>Previous automatic restart:</b> " +
                hesc(previousRestartReason.length() ? previousRestartReason : "none") + "</p><pre style='white-space:pre-wrap'>" +
                hesc(readDiagnostics()) + "</pre></body>";
  web.send(200, "text/html", page);
}
static void handleLogsJson() { web.send(200, "text/plain", readDiagnostics()); }
static void handleClearLogs() { LittleFS.remove("/diagnostics.log"); diagLog("[diagnostics] log cleared"); web.send(200, "text/plain", "cleared"); }
static void handleBan() {
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send(200, "text/plain", "ok");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// The partition holds one list, so we free the old one before writing the new.
// While swapping, numHashes=0 -> device fail-opens (forwards, no blocking).
static void reopenBlocklist() {
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
}
static void beginBlocklistSwap() {
  if (blocklist) blocklist.close();
  numHashes = 0;
  LittleFS.remove(BLOCKLIST_PATH);
  LittleFS.remove("/blocklist.new");
}
static bool commitNewBlocklist() {                  // /blocklist.new -> live (validated)
  File f = LittleFS.open("/blocklist.new", "r");
  size_t sz = f ? f.size() : 0; if (f) f.close();
  bool ok = sz > 0 && (sz % HASH_BYTES) == 0;       // sorted hash blob -> 5-byte multiple
  if (ok) LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  else    LittleFS.remove("/blocklist.new");
  reopenBlocklist();
  return ok;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static File upFile;
static void handleUploadDone() {
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: empty or size not a multiple of 5 (not a blocklist.bin?)");
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upOk = false; beginBlocklistSwap();
      upFile = LittleFS.open("/blocklist.new", "w");
      diagLog("[ota] receiving blocklist %s", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upFile) upFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (upFile) upFile.close();
      upOk = commitNewBlocklist();
      diagLog("[ota] blocklist %s -> %u domains", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new"); reopenBlocklist();
      diagLog("[ota] blocklist upload aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; diagLog("[remote] no update URL configured"); return false; }
  diagLog("[remote] GET %s", url.c_str());
  WiFiClientSecure cs; cs.setInsecure();            // blocklist isn't secret -> skip cert pinning
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; diagLog("[remote] begin failed"); return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); diagLog("[remote] %s", updateStatus.c_str()); return false; }
  beginBlocklistSwap();
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; reopenBlocklist(); diagLog("[remote] fs open failed"); return false; }
  WiFiClient* stream = http.getStreamPtr();
  int len = http.getSize(); uint8_t b[1024]; size_t total = 0; uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) { int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail); if (n > 0) { f.write(b, n); total += n; idle = millis(); } }
    else { if (millis() - idle > 15000) break; feedWatchdog(); delay(2); }
    feedWatchdog();
  }
  f.close(); http.end();
  bool ok = commitNewBlocklist();
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains") : ("bad data (" + String(total) + "B)");
  diagLog("[remote] %s", updateStatus.c_str());
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static void handleFwUpdateDone() {
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { diagLog("[fw-ota] update complete; restarting"); delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    diagLog("[fw-ota] receiving %s", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (Update.end(true)) diagLog("[fw-ota] %u bytes OK", u.totalSize);
    else { Update.printError(Serial); diagLog("[fw-ota] validation failed"); }
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    Update.abort(); diagLog("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) { feedWatchdog(); delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>C3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; C3 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
    "<form method=POST action=/wifisave>"
    "<input list=nets name=s placeholder='WiFi name' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<datalist id=nets>" + portalOpts + "</datalist>"
    "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  diagLog("[setup] WiFi credentials saved for %s", ss.c_str());
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + ss + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>c3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + jesc(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "C3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  diagLog("[setup] provisioning portal started: %s", ap);
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  while (true) { dnsPortal.processNextRequest(); web.handleClient(); feedWatchdog(); delay(2); }
}

void setup() {
  Serial.begin(115200); delay(300);
  currentResetReason = resetReasonName(esp_reset_reason());
  if (LittleFS.begin(true)) littleFsReady = true;
  else Serial.println("LittleFS FAILED");
  loadRestartReason();
  esp_err_t wdtInit = esp_task_wdt_init(5, true);
  esp_err_t wdtAdd = (wdtInit == ESP_OK || wdtInit == ESP_ERR_INVALID_STATE) ? esp_task_wdt_add(NULL) : wdtInit;
  watchdogReady = wdtAdd == ESP_OK || wdtAdd == ESP_ERR_INVALID_ARG;
  diagLog("[boot] reset=%s, watchdog=%s", currentResetReason.c_str(), watchdogReady ? "enabled" : "unavailable");
  if (previousRestartReason.length()) diagLog("[boot] previous automatic restart: %s", previousRestartReason.c_str());
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) { numHashes = blocklist.size() / HASH_BYTES; Serial.printf("blocklist: %u domains\n", numHashes); }
  loadCustom(); loadBanned(); loadUpdateCfg();
  Serial.printf("custom: %d, banned: %d\n", numCustom, numBanned);

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  if (MDNS.begin("c3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://c3adblock.local"); }

  dnsServer.begin(DNS_PORT); upstreamCli.begin(0);
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/logs", handleLogs);
  web.on("/logs.json", handleLogsJson);
  web.on("/logs/clear", HTTP_POST, handleClearLogs);
  web.on("/ban", handleBan);
  web.on("/addblock", []() { addCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/unblock", []() { removeCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { blockingOn = true; resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/reboot", HTTP_POST, []() {
    web.send(200, "text/plain", "rebooting");
    diagLog("[dashboard] manual reboot requested");
    delay(300);
    ESP.restart();
  });
  web.on("/forgetwifi", []() { web.send(200, "text/plain", "cleared — rebooting into setup portal");
    diagLog("[setup] WiFi credentials cleared from dashboard"); prefs.begin("wifi", false); prefs.clear(); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA
  web.on("/fetchnow", []() { fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus); });
  web.on("/setupdate", []() {
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) { updateIntervalH = web.arg("h").toInt(); if (updateIntervalH < 1) updateIntervalH = 1; }
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.begin();
  ArduinoOTA.setHostname("c3adblock");   // pio run -t upload --upload-port c3adblock.local
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  feedWatchdog();
  ArduinoOTA.handle();
  web.handleClient();
  bool busy = handleDns();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  if (WiFi.status() != WL_CONNECTED) {
    if (!wifiDisconnectedSinceMs) { wifiDisconnectedSinceMs = millis(); diagLog("[wifi] connection lost"); }
    else if (millis() - wifiDisconnectedSinceMs >= WIFI_DISCONNECTED_RESTART_MS)
      restartForReliability("WiFi disconnected for too long");
  } else if (wifiDisconnectedSinceMs) {
    diagLog("[wifi] connection recovered after %lus", (millis() - wifiDisconnectedSinceMs) / 1000);
    wifiDisconnectedSinceMs = 0;
  }
  if (dnsTotalSuccesses && dnsConsecutiveFailures && millis() - lastSuccessfulDnsMs >= DNS_NO_SUCCESS_RESTART_MS)
    restartForReliability("no successful upstream DNS response for 60 seconds");
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
