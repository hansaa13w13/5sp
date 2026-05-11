#ifndef WIFI_WEB_SERVER_H
#define WIFI_WEB_SERVER_H

// Arduino.h, WiFi.h üzerinden zaten dahil edilir — __FlashStringHelper ve String burada tanımlı
#include <WiFi.h>
#include <WiFiServer.h>
#include <WiFiClient.h>

#define HTTP_GET  0
#define HTTP_POST 1
#define HTTP_ANY  (-1)

#ifndef CONTENT_LENGTH_UNKNOWN
#define CONTENT_LENGTH_UNKNOWN ((size_t)-1)
#endif

class WiFiWebServer {
public:
    typedef void (*HandlerFunc)();

    struct Route {
        String      uri;
        int         method;
        HandlerFunc handler;
    };

    explicit WiFiWebServer(uint16_t port) : _server(port) {}

    // ── Route kayıt ──────────────────────────────────────────────────────────
    void on(const char*   uri, HandlerFunc h)              { _addRoute(uri, HTTP_ANY, h); }
    void on(const String& uri, HandlerFunc h)              { _addRoute(uri, HTTP_ANY, h); }
    void on(const char*   uri, int method, HandlerFunc h)  { _addRoute(uri, method,   h); }
    void on(const String& uri, int method, HandlerFunc h)  { _addRoute(uri, method,   h); }

    // Bilinmeyen URL işleyici
    void onNotFound(HandlerFunc h) { _notFoundHandler = h; }

    // collectHeaders: BW16'da tüm başlıklar zaten toplanıyor — no-op
    void collectHeaders(const char* [], int) {}

    // ── Sunucu kontrolü ───────────────────────────────────────────────────────
    void begin() { _server.begin(); }
    void stop()  { _server.stop();  }

    void handleClient() {
        WiFiClient client = _server.available();
        if (!client) return;

        unsigned long deadline = millis() + 2000;
        while (!client.available() && millis() < deadline) delay(1);
        if (!client.available()) { client.stop(); return; }

        _client         = client;
        _chunked        = false;
        _respStarted    = false;
        _pendingHeaders = "";
        _argCount       = 0;
        _hdrCount       = 0;
        _uri            = "";
        _method         = HTTP_GET;

        _parseRequest();

        HandlerFunc handler = nullptr;
        for (int i = 0; i < _routeCount; i++) {
            if (_routes[i].uri == _uri &&
                (_routes[i].method == HTTP_ANY || _routes[i].method == _method)) {
                handler = _routes[i].handler;
                break;
            }
        }

        if (handler) {
            handler();
        } else if (_notFoundHandler) {
            _notFoundHandler();
        } else {
            _client.print("HTTP/1.1 404 Not Found\r\n"
                          "Content-Length: 9\r\n"
                          "Connection: close\r\n\r\nNot Found");
        }

        if (_chunked && _respStarted) {
            _client.print("0\r\n\r\n");
        }

        _client.flush();
        _client.stop();
    }

    // ── Yanıt gönderme ────────────────────────────────────────────────────────
    void send(int code, const char* contentType, const String& body) {
        String resp = "HTTP/1.1 ";
        resp += String(code);
        resp += ' ';
        resp += _statusText(code);
        resp += "\r\nConnection: close\r\n";
        resp += _pendingHeaders;
        _pendingHeaders = "";

        if (contentType && *contentType) {
            resp += "Content-Type: ";
            resp += contentType;
            resp += "\r\n";
        }
        if (_chunked) {
            resp += "Transfer-Encoding: chunked\r\n\r\n";
        } else {
            resp += "Content-Length: ";
            resp += String(body.length());
            resp += "\r\n\r\n";
            resp += body;
        }
        _client.print(resp);
        _respStarted = true;
    }

    // const char* body overload (F() makrosundan gelebilir)
    void send(int code, const char* contentType, const char* body) {
        send(code, contentType, body ? String(body) : String(""));
    }

    // Body yok overload
    void send(int code) {
        send(code, nullptr, String(""));
    }

    // Chunked içerik parçası gönder (String)
    void sendContent(const String& chunk) {
        if (!_respStarted || chunk.length() == 0) return;
        char hex[10];
        snprintf(hex, sizeof(hex), "%X\r\n", (unsigned)chunk.length());
        _client.print(hex);
        _client.print(chunk);
        _client.print("\r\n");
    }

    // Chunked içerik parçası gönder (const char* — F() makrosu için)
    void sendContent(const char* chunk) {
        if (chunk && *chunk) sendContent(String(chunk));
    }

    // HTTP yanıt başlığı ekle (send() çağrısından önce çağrılmalı)
    void sendHeader(const String& name, const String& value) {
        _pendingHeaders += name + ": " + value + "\r\n";
    }

    // Chunked mod: CONTENT_LENGTH_UNKNOWN → chunked transfer, sayısal → normal
    void setContentLength(size_t len) {
        _chunked = (len == CONTENT_LENGTH_UNKNOWN);
    }

    // ── İstek bilgisi ─────────────────────────────────────────────────────────
    String arg(const String& name) const {
        for (int i = 0; i < _argCount; i++)
            if (_argKeys[i] == name) return _argVals[i];
        return "";
    }

    String header(const String& name) const {
        for (int i = 0; i < _hdrCount; i++)
            if (_hdrKeys[i].equalsIgnoreCase(name)) return _hdrVals[i];
        return "";
    }

    String uri() const { return _uri; }

private:
    WiFiServer  _server;
    WiFiClient  _client;
    HandlerFunc _notFoundHandler = nullptr;

    bool   _chunked      = false;
    bool   _respStarted  = false;
    String _pendingHeaders;

    int    _method = HTTP_GET;
    String _uri;

    static const int MAX_ARGS = 24;
    String _argKeys[MAX_ARGS];
    String _argVals[MAX_ARGS];
    int    _argCount = 0;

    static const int MAX_HDRS = 24;
    String _hdrKeys[MAX_HDRS];
    String _hdrVals[MAX_HDRS];
    int    _hdrCount = 0;

    static const int MAX_ROUTES = 50;
    Route _routes[MAX_ROUTES];
    int   _routeCount = 0;

    void _addRoute(const String& uri, int method, HandlerFunc h) {
        if (_routeCount >= MAX_ROUTES) return;
        _routes[_routeCount++] = {uri, method, h};
    }

    void _parseRequest() {
        String line = _readLine();
        int sp1 = line.indexOf(' ');
        int sp2 = line.lastIndexOf(' ');
        if (sp1 < 0 || sp1 == sp2) return;

        String methodStr = line.substring(0, sp1);
        String fullUri   = line.substring(sp1 + 1, sp2);
        _method = (methodStr == "POST") ? HTTP_POST : HTTP_GET;

        int qmark = fullUri.indexOf('?');
        if (qmark >= 0) {
            _uri = fullUri.substring(0, qmark);
            _parseParams(fullUri.substring(qmark + 1));
        } else {
            _uri = fullUri;
        }

        int contentLength = 0;
        while (_client.available()) {
            line = _readLine();
            if (line.length() == 0) break;
            int colon = line.indexOf(':');
            if (colon > 0 && _hdrCount < MAX_HDRS) {
                _hdrKeys[_hdrCount] = line.substring(0, colon);
                String val = line.substring(colon + 1);
                val.trim();
                _hdrVals[_hdrCount] = val;
                if (_hdrKeys[_hdrCount].equalsIgnoreCase("Content-Length"))
                    contentLength = val.toInt();
                _hdrCount++;
            }
        }

        if (_method == HTTP_POST && contentLength > 0) {
            String body;
            body.reserve(contentLength);
            unsigned long t = millis() + 2000;
            while ((int)body.length() < contentLength && millis() < t) {
                if (_client.available()) body += (char)_client.read();
                else delay(1);
            }
            _parseParams(body);
        }
    }

    void _parseParams(const String& str) {
        int start = 0;
        int len   = (int)str.length();
        while (start <= len) {
            int amp = str.indexOf('&', start);
            if (amp < 0) amp = len;
            String pair = str.substring(start, amp);
            int eq = pair.indexOf('=');
            if (eq >= 0 && _argCount < MAX_ARGS) {
                _argKeys[_argCount] = _urlDecode(pair.substring(0, eq));
                _argVals[_argCount] = _urlDecode(pair.substring(eq + 1));
                _argCount++;
            }
            start = amp + 1;
        }
    }

    String _readLine() {
        String line;
        unsigned long t = millis() + 1500;
        while (millis() < t) {
            if (!_client.available()) { delay(1); continue; }
            char c = (char)_client.read();
            if (c == '\n') break;
            if (c != '\r') line += c;
        }
        return line;
    }

    static String _urlDecode(const String& s) {
        String out;
        out.reserve(s.length());
        for (int i = 0; i < (int)s.length(); i++) {
            char c = s[i];
            if (c == '+') {
                out += ' ';
            } else if (c == '%' && i + 2 < (int)s.length()) {
                char hex[3] = { s[i+1], s[i+2], 0 };
                out += (char)strtol(hex, nullptr, 16);
                i += 2;
            } else {
                out += c;
            }
        }
        return out;
    }

    static const char* _statusText(int code) {
        switch (code) {
            case 200: return "OK";
            case 204: return "No Content";
            case 301: return "Moved Permanently";
            case 302: return "Found";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 500: return "Internal Server Error";
            default:  return "OK";
        }
    }
};

#endif // WIFI_WEB_SERVER_H
