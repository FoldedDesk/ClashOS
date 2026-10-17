void snifferForwardTests(const std::string& directory)
{
    stopCore(); workersIdle(); setControllerSecret(""); g_testConnector = nullptr; g_udpTestHooks = {};
    const int port = dnsTestPort(), controller = dnsTestPort(); const std::string profile = directory + "/sniffer.yaml";
    const std::string source = "mixed-port: " + std::to_string(port) + "\nsniffer:\n  enable: true\n  override-destination: false\n  sniff:\n    HTTP: {ports: [1-65535]}\n    TLS: {ports: [1-65535]}\n    QUIC: {ports: [1-65535]}\nrules: ['DOMAIN,sniff.fixture.test,DIRECT', 'MATCH,REJECT']\n";
    { std::ofstream out(profile); out << source; }
    require(startCore(profile, controller), "Start live HTTP/SOCKS TCP/UDP sniffing fixture");
    ControllerConfigJson vectors; std::string error;
    require(vectors.parse(readTestFile(std::string(CLAHSOS_TEST_ROOT) + "/fixtures/sniffer/vectors.json"), error), "Read public forwarding vectors");
    const auto bytes = [&](const char* name) { std::string value; require(vectors.string(name, value, error), "Forwarding vector exists"); return text(hex(value)); };
    const auto tls = bytes("tls_records_split");
    const auto change = [&](const std::function<void(SnifferConfig&)>& edit) {
        SnifferConfig config; { std::lock_guard<std::mutex> lock(g_state.mutex); config = *g_state.sniffer; }
        edit(config);
        require(responseFor("PATCH", "/configs", "{\"sniffer\":" + snifferConfigJson(config) + "}") == "{}", "Controller applies a full validated sniffer config");
    };
    const auto tcp = [&](bool socks, const std::string& payload, const std::string& destination, bool ordinary = false, bool delayed = false) {
        int remote[2]; pairFor(remote); std::string contacted; std::atomic<int> connects{0};
        g_testConnector = [&](const std::string& host, int, int) { contacted = host; ++connects; const int result = remote[0]; remote[0] = -1; return result; };
        const int fd = dnsTestConnect(SOCK_STREAM, port); require(fd >= 0, "Connect a real TCP ingress socket");
        if (socks) {
            require(sendAll(fd, std::string("\5\1\0", 3)) && receiveN(fd, 2) == std::string("\5\0", 2), "Negotiate SOCKS before sniffing");
            const auto address = shadowsocksAddress("203.0.113.10", 443); std::string request("\5\1\0", 3); request.append(address.begin(), address.end());
            require(sendAll(fd, request), "Send IP-address SOCKS CONNECT");
            const auto ack = receiveN(fd, 10); require(ack.size() == 10 && ack[1] == 0, "SOCKS permits the client to send its handshake for sniffing");
        } else if (!ordinary) {
            require(sendAll(fd, "CONNECT 203.0.113.10:443 HTTP/1.1\r\nHost: 203.0.113.10\r\n\r\n") &&
                readUntilHeaders(fd).find("200 Connection Established") != std::string::npos, "CONNECT permits the client to send its TLS ClientHello");
        }
        if (delayed) {
            // A server-first connection must recover after the bounded sniff wait.
            require(sendAll(remote[1], "greeting"), "Queue a real upstream greeting before client application data");
            const auto start = HealthClock::now();
            require(receiveN(fd, 8) == "greeting" && HealthClock::now() - start < std::chrono::seconds(3), "Sniff timeout preserves server-first protocols");
        }
        if (!payload.empty()) {
            const size_t split = ordinary ? payload.size() : std::min<size_t>(7, payload.size());
            require(sendAll(fd, payload.substr(0, split)), "Send an initial application fragment");
            if (split < payload.size()) require(sendAll(fd, payload.substr(split)), "Send the remaining TLS/HTTP bytes");
            if (ordinary) {
                const auto forwarded = readUntilHeaders(remote[1]);
                require(forwarded.find("GET /path HTTP/1.1") == 0 && forwarded.find("Host: sniff.fixture.test") != std::string::npos,
                    "IP-address absolute HTTP requests route using their actual Host header");
            } else require(receiveN(remote[1], payload.size()) == payload, "Sniffed TCP prefix is forwarded once, byte for byte");
        }
        require(connects.load() == 1 && contacted == destination, "Sniff override policy controls the actual upstream destination");
        if (!delayed) require(connectionsJson().find("sniff.fixture.test") != std::string::npos, "Live connection metadata exposes the domain used for routing");
        require(sendAll(remote[1], "return-data") && receiveN(fd, 11) == "return-data", "Real upstream return data survives sniffing");
        close(fd); close(remote[1]); workersIdle(); g_testConnector = nullptr;
    };
    tcp(false, tls, "203.0.113.10");
    tcp(true, "GET /path HTTP/1.1\r\nHost: sniff.fixture.test\r\n\r\nbody", "203.0.113.10");
    tcp(false, "GET http://203.0.113.10/path HTTP/1.1\r\nHost: sniff.fixture.test\r\n\r\n", "203.0.113.10", true);
    change([](auto& config) { config.protocols["TLS"].overrideDestination = true; });
    tcp(true, tls, "sniff.fixture.test");
    // Rejection after early handshake acknowledgement closes the stream, never
    // injecting an HTTP error response into TLS application bytes.
    change([](auto& config) { config.skipDomain = {"+.fixture.test"}; });
    const int denied = dnsTestConnect(SOCK_STREAM, port);
    require(sendAll(denied, "CONNECT 203.0.113.10:443 HTTP/1.1\r\n\r\n") && readUntilHeaders(denied).find("200") != std::string::npos && sendAll(denied, tls), "Prepare excluded-domain traffic");
    char extra[32]; require(recv(denied, extra, sizeof(extra), 0) <= 0, "Excluded sniff result falls back to the original IP reject rule");
    close(denied); workersIdle();
    change([](auto& config) { config.skipDomain.clear(); config.protocols["TLS"].overrideDestination = false; });
    // UDP runs over actual TCP control and UDP relay sockets; only its destination
    // peer is a socketpair, so encrypted packet bytes stay independently inspectable.
    const auto udp = [&](const std::vector<std::string>& payloads, bool overrideDestination, bool sniffedDomain, bool timeout = false) {
        change([&](auto& config) { config.protocols["QUIC"].overrideDestination = overrideDestination; });
        { std::lock_guard<std::mutex> lock(g_state.mutex); g_state.rules = timeout || !sniffedDomain ? std::vector<ProxyRule>{{"match", "", "DIRECT"}} :
            std::vector<ProxyRule>{{"domain", "sniff.fixture.test", "DIRECT"}, {"match", "", "REJECT"}}; ++g_state.configRevision; }
        int remote[2]; require(socketpair(AF_UNIX, SOCK_DGRAM, 0, remote) == 0, "Create independent UDP destination peer");
        for (int socket : remote) { int size = 262144; setsockopt(socket, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)); setsockopt(socket, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)); }
        std::string destination; std::atomic<bool> opened{false};
        g_udpTestHooks.connect = [&](const std::string& host, int targetPort, UdpEndpoint& endpoint) {
            destination = host; endpoint = udpTestEndpoint("203.0.113.10", targetPort); const int result = remote[0]; remote[0] = -1; opened.store(true); return result;
        };
        const int fd = dnsTestConnect(SOCK_STREAM, port);
        require(fd >= 0 && sendAll(fd, std::string("\5\1\0", 3)) && receiveN(fd, 2) == std::string("\5\0", 2), "Negotiate actual UDP control socket");
        require(sendAll(fd, std::string("\5\3\0\1\0\0\0\0\0\0", 10)), "Request an actual SOCKS UDP relay");
        const auto reply = receiveN(fd, 10); require(reply.size() == 10 && reply[1] == 0, "UDP relay opens before first application datagram");
        const int relayPort = (static_cast<unsigned char>(reply[8]) << 8) | static_cast<unsigned char>(reply[9]);
        const int socket = dnsTestConnect(SOCK_DGRAM, relayPort); require(socket >= 0, "Connect to the actual loopback UDP relay");
        for (size_t i = 0; i < payloads.size(); ++i) {
            const auto packet = udpTestPacket("203.0.113.10", 443, payloads[i]);
            require(sendAll(socket, packet), "Send independent protected QUIC datagram to real ingress");
            if (i == 0 && payloads.size() > 1) {
                pollfd watch{remote[1], POLLIN, 0}; require(poll(&watch, 1, 100) == 0, "Incomplete QUIC ClientHello waits for another Initial without leaking a first packet");
            }
        }
        for (const auto& payload : payloads) require(text(receiveTestDatagram(remote[1])) == payload, "Reassembled and fallback QUIC datagrams are forwarded in their original boundaries and bytes");
        require(opened.load() && destination == (overrideDestination && sniffedDomain ? "sniff.fixture.test" : "203.0.113.10"), "UDP sniffing controls routing and destination rewriting independently");
        if (sniffedDomain) require(connectionsJson().find("sniff.fixture.test") != std::string::npos, "QUIC connection metadata contains its detected SNI");
        require(sendAll(remote[1], "udp-return"), "Return a real upstream datagram");
        const auto result = receiveTestDatagram(socket); UdpTarget target;
        require(parseSocksUdp(result, target) && target.host == "203.0.113.10" && text(std::vector<unsigned char>(result.begin() + 3 + target.headerSize, result.end())) == "udp-return",
            "Sniffed UDP responses retain the IP endpoint expected by the application");
        close(socket); close(fd); close(remote[1]); workersIdle(); g_udpTestHooks = {};
    };
    const auto head = bytes("quic_fragment_head"), tail = bytes("quic_fragment_tail");
    udp({head, tail}, false, true);
    udp({tail, head}, true, true);
    udp({head + tail}, true, true);
    auto damaged = bytes("quic_v2"); damaged.back() ^= 1;
    udp({damaged}, true, false);
    udp({head}, true, false, true);
    // Fallback for a TCP protocol that sends no recognizable application bytes.
    { std::lock_guard<std::mutex> lock(g_state.mutex); g_state.rules = {{"match", "", "DIRECT"}}; }
    tcp(true, "", "203.0.113.10", false, true);
    require(readTestFile(profile) == source, "Runtime sniffing settings never rewrite the saved source");
    const auto snapshot = responseFor("GET", "/configs", "");
    require(responseFor("PATCH", "/configs?revision=999999999", R"({"sniffing":false})").find("error") != std::string::npos && responseFor("GET", "/configs", "") == snapshot,
        "Stale sniffer edits cannot overwrite a changed configuration");
    stopCore(); require(startCore(profile, controller) && g_state.sniffer->enabled && !g_state.sniffer->protocols.at("TLS").overrideDestination,
        "Restart restores sniffer settings from the real saved configuration");
    const std::string emptyProtocols = "mixed-port: " + std::to_string(port) + "\nsniffer: {enable: true}\nrules: ['MATCH,DIRECT']\n";
    { std::ofstream out(profile); out << emptyProtocols; }
    require(responseFor("PUT", "/configs?force=true", "{}") == "{}" && g_state.sniffer->protocols.empty(), "A source with no configured sniffer protocols retains its exact meaning");
    require(responseFor("PATCH", "/configs", R"({"mode":"direct"})") == "{}" && g_state.sniffer->protocols.empty(), "Unrelated runtime settings cannot implicitly activate default sniffer protocols");
    require(responseFor("PATCH", "/configs", R"({"sniffing":true})") == "{}" && g_state.sniffer->protocols.size() == 3, "An explicit runtime enable action prepares HTTP/TLS/QUIC defaults");
    const auto valid = responseFor("GET", "/configs", "");
    for (const auto& invalid : {R"({"mode":"rule","sniffer":[]})", R"({"sniffer":{"enable":"true"}})", R"({"sniffer":{"sniff":{"TLS":{"ports":["443-80"]}}}})", R"({"sniffing":"true"})"})
        require(responseFor("PATCH", "/configs", invalid).find("error") != std::string::npos && responseFor("GET", "/configs", "") == valid, "Malformed sniffer patches leave every runtime field intact");
    { std::ofstream out(profile); out << source; }
    stopCore();
}
