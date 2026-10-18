// Exercise production observations using actual socket traffic and QuickJS's
// independent JSON parser. All destinations and payloads are public fixtures.
namespace connection_trace_tests {
struct Json {
    JSRuntime* runtime = JS_NewRuntime();
    JSContext* context = JS_NewContext(runtime);
    JSValue value;
    explicit Json(const std::string& source) : value(JS_ParseJSON(context, source.data(), source.size(), "trace.json")) {
        if (JS_IsException(value)) {
            JS_FreeContext(context); JS_FreeRuntime(runtime);
            throw std::runtime_error("Connection trace must be strict JSON");
        }
    }
    ~Json() { JS_FreeValue(context, value); JS_FreeContext(context); JS_FreeRuntime(runtime); }
    std::string string(const char* name) {
        JSValue field = JS_GetPropertyStr(context, value, name);
        const char* encoded = JS_ToCString(context, field);
        std::string result = encoded ? encoded : "";
        JS_FreeCString(context, encoded); JS_FreeValue(context, field); return result;
    }
    int64_t number(const char* name) {
        JSValue field = JS_GetPropertyStr(context, value, name); int64_t result = -1;
        JS_ToInt64(context, &result, field); JS_FreeValue(context, field); return result;
    }
    bool boolean(const char* name) {
        JSValue field = JS_GetPropertyStr(context, value, name);
        const bool result = JS_ToBool(context, field) == 1; JS_FreeValue(context, field); return result;
    }
};
std::vector<std::string> traces(const std::string& id = "", const std::string& event = "") {
    std::vector<std::string> snapshot, result;
    {
        std::lock_guard<std::mutex> lock(g_state.sessionsMutex);
        for (const auto& log : g_state.logs)
            if (log.payload.rfind("[connection] ", 0) == 0) snapshot.push_back(log.payload.substr(13));
    }
    for (const auto& source : snapshot) {
        Json parsed(source);
        if ((id.empty() || parsed.string("id") == id) && (event.empty() || parsed.string("event") == event)) result.push_back(source);
    }
    return result;
}
struct State {
    int level = g_state.logLevel.exchange(0);
    uint64_t upload = g_state.uploadTotal.load(), download = g_state.downloadTotal.load();
    uint64_t logId = g_state.nextLogId;
    std::deque<CoreLog> logs;
    State() {
        std::lock_guard<std::mutex> lock(g_state.sessionsMutex);
        require(g_state.connections.empty() && g_state.workers.load() == 0, "Trace tests need idle connections");
        logs.swap(g_state.logs);
    }
    ~State() {
        std::lock_guard<std::mutex> lock(g_state.sessionsMutex);
        g_state.logs.swap(logs); g_state.nextLogId = logId; g_state.logLevel.store(level);
        g_state.uploadTotal.store(upload); g_state.downloadTotal.store(download);
    }
};
struct Relay {
    int client[2], upstream[2];
    ProxyStream stream;
    std::thread worker;
    std::thread sender;
    bool started = false;
    std::string id;
    Relay() {
        pairFor(client); pairFor(upstream); trackSocket(client[0]); trackSocket(upstream[0]);
        require(beginConnection(client[0], "trace.example", 443, {"PRIVATE_CHAIN"}, "PRIVATE_RULE"), "Begin real trace connection");
        id = connectionId("trace.example"); stream.fd = upstream[0]; attachUpstream(client[0], upstream[0]);
    }
    void start() { worker = std::thread([this] { relayStream(client[0], stream); closeSocket(client[0]); }); started = true; }
    void finish() { if (worker.joinable()) worker.join(); }
    ~Relay() {
        // Peer descriptors remain owned here; the worker's client number could
        // already be closed and reused, so never shut it down during cleanup.
        shutdown(client[1], SHUT_RDWR); shutdown(upstream[1], SHUT_RDWR);
        finish(); if (sender.joinable()) sender.join(); close(client[1]); close(upstream[1]);
        if (!started) closeSocket(client[0]);
    }
};
void metadata() {
    int pair[2]; pairFor(pair); trackSocket(pair[0]); g_state.logLevel.store(1);
    require(beginConnection(pair[0], "quiet.example", 80, {}, ""), "Open debug-disabled connection");
    traceConnection(pair[0], "hidden"); closeSocket(pair[0]); close(pair[1]);
    require(traces().empty(), "Normal log levels must not publish connection traces"); g_state.logLevel.store(0);
    pairFor(pair); trackSocket(pair[0]); const std::string host = "quoted\"\\\n.example";
    require(beginConnection(pair[0], host, 443, {"PRIVATE_CHAIN", "PRIVATE_PASSWORD"}, "PRIVATE_RULE"), "Open escaped-host connection");
    const auto id = connectionId(host);
    { std::lock_guard<std::mutex> lock(g_state.sessionsMutex); g_state.connections.at(pair[0]).startedAt -= std::chrono::milliseconds(123); }
    recordTransfer(pair[0], true, 517); recordTransfer(pair[0], false, 2818);
    errno = EACCES; traceConnection(pair[0], "probe", ECONNRESET);
    require(errno == EACCES, "Observing a connection must preserve caller errno");
    const auto samples = traces(id, "probe"); require(samples.size() == 1, "Exactly one requested observation"); Json sample(samples.front());
    require(sample.string("host") == host && sample.string("network") == "tcp", "Strict JSON roundtrip preserves escaped destination metadata");
    require(sample.number("elapsedMs") >= 123 && sample.number("errno") == ECONNRESET, "Monotonic elapsed time and numeric cause survive parsing");
    require(!sample.boolean("controllerCancelled"), "Ordinary observations do not claim cancellation");
    require(cancelConnections(id), "Controller cancellation matches the actual live socket"); closeSocket(pair[0]); close(pair[1]);
    require(connectionId(host).empty(), "Closing removes the live connection");
    const auto closed = traces(id, "close"); require(closed.size() == 1, "Final observation survives removal from live connections"); Json final(closed.front());
    require(final.number("upload") == 517 && final.number("download") == 2818 && final.boolean("controllerCancelled"), "Final counters and controller cancellation survive closure");
    for (const auto& source : traces(id)) require(source.find("PRIVATE_") == std::string::npos, "Traces must exclude routing chains, rule text and credentials");
}
void duplex() {
    Relay relay; relay.start(); const std::string first(128, 'f'), upload(1000, 'u'), last(70000, 'l');
    require(sendAll(relay.upstream[1], first), "Peer sends server-first response");
    require(receiveN(relay.client[1], first.size()) == first, "Server-first response reaches client");
    awaitCondition([&] { std::lock_guard<std::mutex> lock(g_state.sessionsMutex); return g_state.connections.at(relay.client[0]).download == first.size(); }, "Initial bytes accounted before active snapshot");
    uint64_t snapshot;
    { std::lock_guard<std::mutex> lock(g_state.sessionsMutex); snapshot = g_state.connections.at(relay.client[0]).download; }
    require(sendAll(relay.client[1], upload), "Client sends upload"); shutdown(relay.client[1], SHUT_WR);
    require(receiveN(relay.upstream[1], upload.size()) == upload, "Upstream receives exact uploaded payload"); char byte;
    require(recv(relay.upstream[1], &byte, 1, 0) == 0, "Client half-close reaches upstream independently of reply");
    auto sent = std::make_shared<std::atomic<bool>>(false);
    relay.sender = std::thread([fd = relay.upstream[1], last, sent] { sent->store(sendAll(fd, last)); shutdown(fd, SHUT_WR); });
    require(receiveN(relay.client[1], last.size()) == last, "Late multi-buffer response drains after half-close");
    require(recv(relay.client[1], &byte, 1, 0) == 0, "Remote EOF reaches client"); relay.finish();
    relay.sender.join(); require(sent->load(), "Peer sends response after last active snapshot under real backpressure");
    const auto closed = traces(relay.id, "close"); require(closed.size() == 1, "Duplex session has exactly one final observation"); Json final(closed.front());
    require(final.number("upload") == static_cast<int64_t>(upload.size()) && final.number("download") == static_cast<int64_t>(first.size() + last.size()), "Final counters include late bytes after active snapshot");
    require(final.number("download") > static_cast<int64_t>(snapshot), "Active snapshots must not substitute for final counters");
    require(traces(relay.id, "client-eof").size() == 1 && traces(relay.id, "upstream-eof").size() == 1, "Independent half-closes have distinct observations");
    for (const auto& source : traces(relay.id)) require(source.find(upload) == std::string::npos, "Payload bytes must never appear in traces");
}
void encryptedFailures() {
    {
        Relay relay; relay.stream.encrypted = true; relay.stream.ssCipher = SsCipher::Aes128Gcm;
        relay.stream.sendKey.assign(16, 7); relay.stream.sendNonce.assign(12, 0);
        relay.stream.shadowsocks = std::make_unique<ShadowsocksReader>(relay.stream.fd, SsCipher::Aes128Gcm, std::vector<unsigned char>(16, 7));
        relay.start(); require(sendAll(relay.client[1], std::string(517, 't')), "Client sends TLS-sized payload"); shutdown(relay.client[1], SHUT_WR);
        require(receiveN(relay.upstream[1], 2 + 16 + 517 + 16).size() == 551, "Encrypted record actually reaches upstream wire");
        shutdown(relay.upstream[1], SHUT_WR); char byte;
        require(recv(relay.client[1], &byte, 1, 0) == 0, "Early encrypted upstream EOF reaches client"); relay.finish();
        const auto ended = traces(relay.id, "upstream-eof"); require(ended.size() == 1, "Clean EOF is not reported as authentication failure"); Json final(ended.front());
        require(final.number("upload") == 517 && final.number("download") == 0 && final.number("errno") == 0, "Early EOF retains accounted upload and zero decoded reply");
        require(traces(relay.id, "upstream-read-error").empty(), "Clean EOF and decoder rejection remain distinct");
    }
    {
        Relay relay; relay.stream.encrypted = true;
        relay.stream.shadowsocks = std::make_unique<ShadowsocksReader>(relay.stream.fd, SsCipher::Aes256Gcm, evpBytesToKey(GOLDEN_PASSWORD, 32));
        auto packet = hex(GOLDEN_SERVER_PACKET); packet.at(32 + 18 + 5) ^= 1;
        require(sendAll(relay.upstream[1], packet), "Independent corrupted AEAD packet reaches wire"); shutdown(relay.upstream[1], SHUT_WR);
        shutdown(relay.client[1], SHUT_WR); relay.start(); relay.finish(); char byte;
        require(recv(relay.client[1], &byte, 1, 0) == 0, "Corrupt AEAD delivers no plaintext");
        const auto errors = traces(relay.id, "upstream-read-error"); require(errors.size() == 1, "Authentication rejection has a distinct error observation"); Json error(errors.front());
        require(error.number("errno") == EBADMSG && error.number("download") == 0, "Trace preserves AEAD failure errno and zero delivered bytes");
        std::lock_guard<std::mutex> lock(g_state.sessionsMutex);
        require(std::any_of(g_state.logs.begin(), g_state.logs.end(), [](const CoreLog& log) { return log.type == "warning" && log.payload == "Shadowsocks authentication failed"; }), "Trace does not disturb existing authentication warning");
    }
}
void concurrentRing() {
    for (int i = 0; i < 200; ++i) {
        int pair[2]; pairFor(pair); trackSocket(pair[0]);
        require(beginConnection(pair[0], "reuse.example", 443, {}, ""), "Open reused descriptor"); closeSocket(pair[0]); close(pair[1]);
    }
    auto logs = traces(); require(logs.size() == 300, "Trace shares bounded 300-entry log ring"); std::set<std::string> ids;
    for (const auto& source : logs) { Json parsed(source); if (parsed.string("event") == "close") ids.insert(parsed.string("id")); }
    require(ids.size() == 150, "Descriptor reuse never conflates independent session IDs");
    { std::lock_guard<std::mutex> lock(g_state.sessionsMutex); g_state.logs.clear(); }
    const auto up = g_state.uploadTotal.load(), down = g_state.downloadTotal.load();
    std::atomic<bool> ok{true}; std::vector<std::thread> threads;
    for (int producer = 0; producer < 4; ++producer) threads.emplace_back([&] {
        try {
            for (int i = 0; i < 32; ++i) {
                int pair[2]; pairFor(pair); trackSocket(pair[0]);
                if (!beginConnection(pair[0], "parallel.example", 80, {}, "")) ok.store(false);
                recordTransfer(pair[0], true, 3); recordTransfer(pair[0], false, 5); closeSocket(pair[0]); close(pair[1]);
            }
        } catch (...) { ok.store(false); }
    });
    for (auto& thread : threads) thread.join(); require(ok.load(), "Concurrent producers finish without deadlock");
    require(g_state.uploadTotal.load() - up == 128 * 3 && g_state.downloadTotal.load() - down == 128 * 5, "Concurrent tracing preserves traffic totals");
    logs = traces(); require(logs.size() == 256, "Concurrent sessions each have one open and close"); ids.clear();
    for (const auto& source : logs) {
        Json parsed(source);
        if (parsed.string("event") == "close") {
            require(parsed.number("upload") == 3 && parsed.number("download") == 5, "Concurrent final trace retains its own counters"); ids.insert(parsed.string("id"));
        }
    }
    require(ids.size() == 128, "Concurrent final IDs remain distinct");
    std::lock_guard<std::mutex> lock(g_state.sessionsMutex); require(g_state.connections.empty(), "Trace suite leaves no live connections");
}
} // namespace connection_trace_tests
void connectionTraceTests() {
    connection_trace_tests::State restore;
    std::cerr << "Trace: metadata/privacy/cancellation\n";
    connection_trace_tests::metadata();
    std::cerr << "Trace: server-first/half-close/late bytes\n";
    connection_trace_tests::duplex();
    std::cerr << "Trace: encrypted EOF/authentication rejection\n";
    connection_trace_tests::encryptedFailures();
    std::cerr << "Trace: bounded ring/concurrent producers\n";
    connection_trace_tests::concurrentRing();
}
