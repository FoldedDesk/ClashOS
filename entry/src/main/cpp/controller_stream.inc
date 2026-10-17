// Read-only controller streams: HTTP NDJSON and RFC 6455 WebSocket.
// Stream workers use tracked sockets, so core shutdown cancels them with other IO.
bool controllerToken(const std::string& value, const std::string& expected)
{
    std::istringstream input(value); std::string token;
    while (std::getline(input, token, ',')) if (lower(trim(token)) == expected) return true;
    return false;
}

void controllerStreamError(int client, const std::string& status, const std::string& message, const std::string& extra = "")
{
    const std::string body = "{\"error\":\"" + jsonEscape(message) + "\"}";
    sendAll(client, "HTTP/1.1 " + status + "\r\nContent-Type: application/json\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\nConnection: close\r\n" + extra + "\r\n" + body);
}

bool controllerFrame(int client, unsigned char opcode, const std::string& payload)
{
    std::string frame(1, static_cast<char>(0x80 | opcode));
    if (payload.size() < 126) frame += static_cast<char>(payload.size());
    else if (payload.size() <= 65535) {
        frame += static_cast<char>(126); frame += static_cast<char>(payload.size() >> 8); frame += static_cast<char>(payload.size());
    } else {
        frame += static_cast<char>(127);
        for (int i = 7; i >= 0; --i) frame += static_cast<char>(static_cast<uint64_t>(payload.size()) >> (i * 8));
    }
    return sendAll(client, frame + payload); // Server frames must never be masked.
}

bool controllerUtf8(const std::string& text)
{
    for (size_t i = 0; i < text.size();) {
        const unsigned char first = text[i++];
        if (first < 0x80) continue;
        int following = 0; uint32_t code = 0, minimum = 0;
        if (first >= 0xc2 && first <= 0xdf) { following = 1; code = first & 31; minimum = 0x80; }
        else if (first >= 0xe0 && first <= 0xef) { following = 2; code = first & 15; minimum = 0x800; }
        else if (first >= 0xf0 && first <= 0xf4) { following = 3; code = first & 7; minimum = 0x10000; }
        else return false;
        if (text.size() - i < static_cast<size_t>(following)) return false;
        while (following--) {
            const unsigned char next = text[i++]; if ((next & 0xc0) != 0x80) return false;
            code = (code << 6) | (next & 63);
        }
        if (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return false;
    }
    return true;
}

bool controllerClose(int client, uint16_t code)
{
    controllerFrame(client, 8, std::string{static_cast<char>(code >> 8), static_cast<char>(code)}); return false;
}

bool controllerInput(int client, std::string& pending)
{
    while (pending.size() >= 2) {
        const auto first = static_cast<unsigned char>(pending[0]), second = static_cast<unsigned char>(pending[1]);
        const auto opcode = first & 15, size = second & 127;
        if ((first & 0x70) || !(second & 0x80)) return controllerClose(client, 1002);
        if (opcode == 1 || opcode == 2) return controllerClose(client, 1003); // No client data channel on this push API.
        if (!(first & 0x80) || (opcode != 8 && opcode != 9 && opcode != 10) || size > 125) return controllerClose(client, 1002);
        if (pending.size() < 6 + static_cast<size_t>(size)) return true;
        std::string payload = pending.substr(6, size);
        for (size_t i = 0; i < payload.size(); ++i) payload[i] ^= pending[2 + i % 4];
        pending.erase(0, 6 + size);
        if (opcode == 8) {
            if (payload.size() == 1) return controllerClose(client, 1002);
            if (payload.size() >= 2) {
                const unsigned code = (static_cast<unsigned char>(payload[0]) << 8) | static_cast<unsigned char>(payload[1]);
                if (!((code >= 1000 && code <= 1014 && code != 1004 && code != 1005 && code != 1006) || (code >= 3000 && code <= 4999)))
                    return controllerClose(client, 1002);
                if (!controllerUtf8(payload.substr(2))) return controllerClose(client, 1007);
            }
            controllerFrame(client, 8, payload); return false;
        }
        if (opcode == 9 && !controllerFrame(client, 10, payload)) return false;
    }
    return true;
}

struct ControllerTrafficSample {
    uint64_t up, down;
    HealthClock::time_point at;
    ControllerTrafficSample(uint64_t upload, uint64_t download, HealthClock::time_point time) : up(upload), down(download), at(time) {}
    std::string sample(uint64_t upload, uint64_t download, HealthClock::time_point time) {
        const long double seconds = std::chrono::duration<long double>(time - at).count();
        auto rate = [seconds](uint64_t current, uint64_t previous) -> uint64_t {
            if (seconds <= 0 || current < previous) return 0;
            return static_cast<uint64_t>(std::min(static_cast<long double>(UINT64_MAX), (current - previous) / seconds));
        };
        const std::string value = "{\"up\":" + std::to_string(rate(upload, up)) + ",\"down\":" + std::to_string(rate(download, down)) +
            ",\"upTotal\":" + std::to_string(upload) + ",\"downTotal\":" + std::to_string(download) + "}";
        up = upload; down = download; at = time; return value;
    }
};

void handleControllerStreamClient(int client, const std::string& path, const std::string& version,
    const std::map<std::string, std::string>& headers, const std::string& initial, uint64_t authEpoch)
{
    auto header = [&](const char* name) { auto it = headers.find(name); return it == headers.end() ? std::string{} : it->second; };
    const bool websocket = !header("upgrade").empty();
    ControllerStreamOptions options;
    if (!controllerStreamOptions(path, options)) { controllerStreamError(client, "400 Bad Request", "Invalid stream options"); return; }
    if ((!header("content-length").empty() && header("content-length") != "0") || !header("transfer-encoding").empty() ||
        (!websocket && (!initial.empty() || !header("sec-websocket-key").empty() || !header("sec-websocket-version").empty()))) {
        controllerStreamError(client, "400 Bad Request", "Stream requests must not have an HTTP body"); return;
    }
    uint64_t memory = 0;
    if (options.kind == ControllerStreamKind::Memory && !controllerMemoryBytes(memory)) {
        controllerStreamError(client, "503 Service Unavailable", "Process memory measurement unavailable"); return;
    }
    std::string accept;
    if (websocket) {
        if (version != "HTTP/1.1" || !controllerToken(header("upgrade"), "websocket") || !controllerToken(header("connection"), "upgrade") || header("host").empty()) {
            controllerStreamError(client, "400 Bad Request", "Invalid WebSocket upgrade"); return;
        }
        if (header("sec-websocket-version") != "13") {
            controllerStreamError(client, "426 Upgrade Required", "WebSocket version 13 is required", "Sec-WebSocket-Version: 13\r\n"); return;
        }
        const std::string key = header("sec-websocket-key");
        std::vector<unsigned char> decoded(32); size_t length = 0;
        if (mbedtls_base64_decode(decoded.data(), decoded.size(), &length, reinterpret_cast<const unsigned char*>(key.data()), key.size()) != 0 || length != 16) {
            controllerStreamError(client, "400 Bad Request", "Invalid WebSocket key"); return;
        }
        decoded.resize(length);
        if (vmBase64(decoded) != key) { controllerStreamError(client, "400 Bad Request", "Invalid WebSocket key"); return; }
        const std::string input = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        accept = vmBase64(sha1({input.begin(), input.end()}));
    }
    if (g_state.controllerAuthEpoch.load() != authEpoch) { controllerStreamError(client, "401 Unauthorized", "Unauthorized"); return; }
    struct Slot {
        bool held;
        Slot() : held(g_state.controllerStreams.fetch_add(1) < 16) { if (!held) g_state.controllerStreams.fetch_sub(1); }
        ~Slot() { if (held) g_state.controllerStreams.fetch_sub(1); }
    } slot;
    if (!slot.held) { controllerStreamError(client, "429 Too Many Requests", "Too many controller subscribers"); return; }
    uint64_t logCursor = 0;
    if (options.kind == ControllerStreamKind::Logs) {
        std::lock_guard<std::mutex> lock(g_state.sessionsMutex); logCursor = g_state.nextLogId - 1;
    }
    const std::string response = websocket ? "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n" :
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
    if (!sendAll(client, response)) return;
    socketTimeout(client, 1000); // A stalled receiver cannot retain a stream worker indefinitely.
    std::string pending = initial;
    auto now = HealthClock::now(), partialSince = now;
    auto next = options.kind == ControllerStreamKind::Connections || options.kind == ControllerStreamKind::Logs ? now : now + std::chrono::milliseconds(options.interval);
    ControllerTrafficSample sample(g_state.uploadTotal.load(), g_state.downloadTotal.load(), now);
    if (websocket && !controllerInput(client, pending)) return;
    while (g_state.running.load()) {
        if (g_state.controllerAuthEpoch.load() != authEpoch) { if (websocket) controllerClose(client, 1008); return; }
        now = HealthClock::now();
        if (!pending.empty() && now - partialSince >= std::chrono::seconds(5)) { controllerClose(client, 1002); return; }
        if (now >= next) {
            std::vector<std::string> values;
            if (options.kind == ControllerStreamKind::Traffic) values.push_back(sample.sample(g_state.uploadTotal.load(), g_state.downloadTotal.load(), now));
            else if (options.kind == ControllerStreamKind::Connections) values.push_back(connectionsJson());
            else if (options.kind == ControllerStreamKind::Memory) {
                if (!controllerMemoryBytes(memory)) return;
                values.push_back("{\"inuse\":" + std::to_string(memory) + ",\"oslimit\":0}");
            } else values = controllerLogSamples(logCursor, options);
            for (const std::string& value : values) {
                if (g_state.controllerAuthEpoch.load() != authEpoch) { if (websocket) controllerClose(client, 1008); return; }
                if (!(websocket ? controllerFrame(client, 1, value) : sendAll(client, value + "\n"))) return;
            }
            next = HealthClock::now() + std::chrono::milliseconds(options.interval);
        }
        const auto wait = std::chrono::duration_cast<std::chrono::milliseconds>(next - HealthClock::now()).count();
        pollfd event{client, POLLIN, 0};
        const int ready = poll(&event, 1, static_cast<int>(std::max<int64_t>(0, std::min<int64_t>(wait, 100))));
        if (ready < 0) { if (errno == EINTR) continue; return; }
        if (ready == 0) continue;
        char bytes[1024]; const ssize_t received = recv(client, bytes, sizeof(bytes), 0);
        if (received <= 0) { if (received < 0 && errno == EINTR) continue; return; }
        if (!websocket) return;
        if (pending.empty()) partialSince = HealthClock::now();
        pending.append(bytes, static_cast<size_t>(received));
        if (!controllerInput(client, pending)) return;
    }
}
