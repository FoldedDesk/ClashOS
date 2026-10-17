#include "udp_vectors.h"

UdpEndpoint udpTestEndpoint(const std::string& host, int port)
{
    UdpEndpoint endpoint;
    if (host.find(':') == std::string::npos) {
        auto* address = reinterpret_cast<sockaddr_in*>(&endpoint.address);
        address->sin_family = AF_INET; address->sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &address->sin_addr); endpoint.length = sizeof(*address);
    } else {
        auto* address = reinterpret_cast<sockaddr_in6*>(&endpoint.address);
        address->sin6_family = AF_INET6; address->sin6_port = htons(port);
        inet_pton(AF_INET6, host.c_str(), &address->sin6_addr); endpoint.length = sizeof(*address);
    }
    return endpoint;
}

std::vector<unsigned char> udpTestPacket(const std::string& host, int port, const std::string& payload)
{
    std::vector<unsigned char> packet{0, 0, 0};
    const auto address = shadowsocksAddress(host, port);
    packet.insert(packet.end(), address.begin(), address.end());
    packet.insert(packet.end(), payload.begin(), payload.end());
    return packet;
}

std::vector<unsigned char> receiveTestDatagram(int fd)
{
    pollfd watch{fd, POLLIN, 0};
    require(poll(&watch, 1, 2000) > 0, "UDP packet did not arrive");
    std::vector<unsigned char> packet(65536);
    const ssize_t count = recv(fd, packet.data(), packet.size(), 0);
    require(count >= 0, "UDP read failed");
    packet.resize(static_cast<size_t>(count));
    return packet;
}

void udpProtocolTests()
{
    const auto master = hex(GOLDEN_MASTER);
    const std::pair<const char*, const char*> vectors[] = {
        {UDP_DOMAIN_PLAIN, UDP_DOMAIN_PACKET}, {UDP_IPV4_PLAIN, UDP_IPV4_PACKET},
        {UDP_IPV6_PLAIN, UDP_IPV6_PACKET}, {UDP_EMPTY_PLAIN, UDP_EMPTY_PACKET}
    };
    for (const auto& vector : vectors) {
        const auto expected = hex(vector.second), payload = hex(vector.first);
        std::vector<unsigned char> wire, plain;
        const std::vector<unsigned char> salt(expected.begin(), expected.begin() + 32);
        require(encryptShadowsocksUdp(master, salt, payload, wire) && wire == expected, "UDP AEAD wire differs from independent vector");
        require(decryptShadowsocksUdp(master, expected, plain) && plain == payload, "UDP independent server packet failed to decrypt");
        auto corrupt = expected; corrupt.back() ^= 1;
        require(!decryptShadowsocksUdp(master, corrupt, plain) && plain.empty(), "UDP corrupt tag released unauthenticated bytes");
    }
    UdpTarget target;
    const auto domain = udpTestPacket("www.google.com", 443, "payload");
    require(parseSocksUdp(domain, target) && target.host == "www.google.com" && target.port == 443 && target.headerSize == 18,
        "SOCKS UDP domain header differs from RFC format");
    require(parseSocksUdp(udpTestPacket("2001:db8::1", 53, ""), target) && target.host == "2001:db8::1" && target.headerSize == 19,
        "SOCKS UDP IPv6 and empty datagrams must be accepted");
    for (size_t length = 0; length < domain.size() - 7; length++) {
        std::vector<unsigned char> truncated(domain.begin(), domain.begin() + length);
        require(!parseSocksUdp(truncated, target), "Truncated SOCKS UDP address must be dropped");
    }
    for (int fragment : {1, 127, 128, 255}) {
        auto packet = domain; packet[2] = fragment;
        require(!parseSocksUdp(packet, target), "SOCKS UDP fragmentation must not be misread as a complete packet");
    }
    auto invalid = domain; invalid[0] = 1; require(!parseSocksUdp(invalid, target), "Nonzero UDP RSV must be rejected");
    invalid = domain; invalid[3] = 2; require(!parseSocksUdp(invalid, target), "Unknown UDP address family must be rejected");
    invalid = udpTestPacket("a", 0, ""); require(!parseSocksUdp(invalid, target), "Zero destination UDP port must be rejected");
    invalid = {0, 0, 0, 3, 2, 'a', 0, 0, 53}; require(!parseSocksUdp(invalid, target), "NUL in UDP domain must be rejected");
    std::vector<unsigned char> wire;
    require(encryptShadowsocksUdp(master, std::vector<unsigned char>(32, 9), std::vector<unsigned char>(UDP_MAX_PACKET - 48, 1), wire) &&
        wire.size() == UDP_MAX_PACKET, "Maximum UDP encrypted packet size must include salt and tag");
    require(!encryptShadowsocksUdp(master, std::vector<unsigned char>(32, 9), std::vector<unsigned char>(UDP_MAX_PACKET - 47, 1), wire),
        "Oversize UDP encrypted packet must be dropped before network I/O");
    {
        std::lock_guard<std::mutex> lock(g_udpSaltMutex); g_udpSalts.clear(); g_udpSaltOrder.clear();
    }
    require(rememberUdpSalt(master, hex(UDP_DOMAIN_PACKET)), "Fresh UDP salt must be accepted");
    require(!rememberUdpSalt(master, hex(UDP_DOMAIN_PACKET)), "Sent or received UDP salt must not be accepted twice");
    auto otherKey = master; otherKey[0] ^= 1;
    require(rememberUdpSalt(otherKey, hex(UDP_DOMAIN_PACKET)), "Replay cache must distinguish unrelated keys");
    UdpClientPin pin; pin.peer = udpTestEndpoint("127.0.0.1", 1234); pin.requestedPort = 4444;
    require(!pin.accepts(udpTestEndpoint("127.0.0.2", 4444)), "UDP relay must reject a different client IP");
    require(!pin.accepts(udpTestEndpoint("127.0.0.1", 5555)), "UDP relay must honor requested source port");
    require(pin.accepts(udpTestEndpoint("127.0.0.1", 4444)), "UDP relay must accept the expected client");
    UdpClientPin wildcard; wildcard.peer = pin.peer;
    require(wildcard.accepts(udpTestEndpoint("127.0.0.1", 4444)) && !wildcard.accepts(udpTestEndpoint("127.0.0.1", 5555)),
        "UDP association must pin its learned source endpoint");
    require(udpSameEndpoint(udpTestEndpoint("127.0.0.1", 4444), udpTestEndpoint("::ffff:127.0.0.1", 4444)),
        "IPv4 mapped IPv6 source must compare as the same IP");
    ParsedConfig config; std::string error;
    require(parseConfigText("proxies: [{name: a, type: ss, server: x, port: 1, udp: true}, {name: b, type: ss, server: x, port: 1}]", config, error) &&
        config.nodes[0].udp && !config.nodes[1].udp, "Clash UDP option and default must be preserved");
}

struct UdpHarness {
    int control = -1, relay = -1;
    std::mutex mutex;
    std::deque<UdpEndpoint> senders;
    std::map<std::string, std::deque<std::pair<int, UdpEndpoint>>> pending;
    std::vector<int> peers;
    std::vector<std::pair<std::string, int>> dials;
    std::atomic<int> consumed{0};
    UdpHarness() {
        int stream[2], datagrams[2]; pairFor(stream);
        require(socketpair(AF_UNIX, SOCK_DGRAM, 0, datagrams) == 0, "UDP relay pair unavailable");
        for(int socket:datagrams){int size=262144;setsockopt(socket,SOL_SOCKET,SO_SNDBUF,&size,sizeof(size));setsockopt(socket,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size));}
        control = stream[1]; relay = datagrams[1];
        g_udpTestHooks.relay = [fd = datagrams[0]](int, UdpEndpoint& bound, UdpEndpoint& peer) {
            bound = udpTestEndpoint("127.0.0.1", 30000); peer = udpTestEndpoint("127.0.0.1", 12345); return fd;
        };
        g_udpTestHooks.receive = [&](int fd, std::vector<unsigned char>& packet, UdpEndpoint& sender) {
            packet.resize(65536); const ssize_t n = recv(fd, packet.data(), packet.size(), 0);
            if (n >= 0) {
                packet.resize(n);
                std::lock_guard<std::mutex> guard(mutex);
                sender = senders.front(); senders.pop_front(); consumed.fetch_add(1);
            }
            return n;
        };
        g_udpTestHooks.send = [&](int fd, const std::vector<unsigned char>& packet, const UdpEndpoint& endpoint) {
            if (!udpSameEndpoint(endpoint, udpTestEndpoint("127.0.0.1", 40000))) { errno = EINVAL; return ssize_t(-1); }
            return send(fd, packet.data(), packet.size(), 0);
        };
        g_udpTestHooks.connect = [&](const std::string& host, int port, UdpEndpoint& remote) {
            std::lock_guard<std::mutex> guard(mutex);
            dials.push_back({host, port});
            auto& queue = pending[host + ":" + std::to_string(port)];
            if (queue.empty()) return -1;
            const auto value = queue.front(); queue.pop_front(); remote = value.second; return value.first;
        };
        dispatchWorker(stream[0], 1);
        const std::vector<unsigned char> request{5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0};
        require(sendAll(control, request), "UDP ASSOCIATE request send failed");
        require(receiveN(control, 2) == std::string("\5\0", 2), "UDP SOCKS authentication failed");
        const std::string reply = receiveN(control, 10);
        require(std::vector<unsigned char>(reply.begin(), reply.end()) == hex("050000017f0000017530"), "UDP ASSOCIATE must return actual relay IP and port");
    }
    ~UdpHarness() {
        if (control >= 0) { shutdown(control, SHUT_RDWR); close(control); }
        {
            std::unique_lock<std::mutex> guard(g_state.sessionsMutex);
            if (!g_state.workersDone.wait_for(guard, std::chrono::seconds(3), [] { return g_state.workers.load() == 0; })) std::terminate();
        }
        g_udpTestHooks = {};
        for (auto& entry : pending) for (auto& endpoint : entry.second) close(endpoint.first);
        for (int fd : peers) close(fd);
        close(relay);
    }
    int add(const std::string& host, int port, const std::string& resolved = "8.8.8.8") {
        int pair[2]; require(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0, "UDP outbound pair unavailable");
        std::lock_guard<std::mutex> guard(mutex);
        pending[host + ":" + std::to_string(port)].push_back({pair[0], udpTestEndpoint(resolved, port)}); peers.push_back(pair[1]);
        return pair[1];
    }
    void inject(const std::vector<unsigned char>& packet, const std::string& sender = "127.0.0.1", int port = 40000) {
        { std::lock_guard<std::mutex> guard(mutex); senders.push_back(udpTestEndpoint(sender, port)); }
        require(send(relay, packet.data(), packet.size(), 0) == packet.size(), "UDP request injection failed");
    }
};

void udpForwardingTests()
{
    setupRuntime();
    {
        std::lock_guard<std::mutex> lock(g_udpSaltMutex); g_udpSalts.clear(); g_udpSaltOrder.clear();
    }
    {
        UdpHarness harness;
        const auto up = g_state.uploadTotal.load(), down = g_state.downloadTotal.load();
        const int endpoint = harness.add("direct.test", 443);
        auto invalid = udpTestPacket("direct.test", 443, "ignored"); invalid[2] = 1;
        harness.inject(invalid); harness.inject(udpTestPacket("direct.test", 443, "wrong IP"), "127.0.0.2");
        harness.inject(udpTestPacket("direct.test", 443, "client request"));
        require(text(receiveTestDatagram(endpoint)) == "client request", "UDP direct route must strip SOCKS header and drop bad sources/fragments");
        require(send(endpoint, "server reply", 12, 0) == 12, "UDP server response send failed");
        const auto response = receiveTestDatagram(harness.relay);
        UdpTarget source; require(parseSocksUdp(response, source) && source.host == "8.8.8.8" && source.port == 443 &&
            text({response.begin() + 3 + source.headerSize, response.end()}) == "server reply", "UDP response must carry actual remote address and payload");
        const std::string snapshot = connectionsJson();
        require(snapshot.find("\"network\":\"udp\"") != std::string::npos && snapshot.find("direct.test") != std::string::npos,
            "UDP flow must be visible in connection metadata");
        require(g_state.uploadTotal.load() == up + 14 && g_state.downloadTotal.load() == down + 12,
            "UDP counters must count plaintext payload, not SOCKS headers");
        harness.inject(udpTestPacket("direct.test", 443, "wrong port"), "127.0.0.1", 40001);
        harness.inject(udpTestPacket("direct.test", 443, ""));
        require(receiveTestDatagram(endpoint).empty(), "Zero-length UDP datagram must survive after wrong-port rejection");
        send(endpoint, "", 0, 0);
        const auto empty = receiveTestDatagram(harness.relay);
        require(parseSocksUdp(empty, source) && empty.size() == 3 + source.headerSize, "Zero-length UDP reply must remain a datagram");
        const int v6 = harness.add("2001:db8::2", 53, "2001:db8::2");
        harness.inject(udpTestPacket("2001:db8::2", 53, "v6"));
        require(text(receiveTestDatagram(v6)) == "v6", "IPv6 UDP target routing failed");
        send(v6, "v6 reply", 8, 0);
        const auto v6reply = receiveTestDatagram(harness.relay);
        require(parseSocksUdp(v6reply, source) && source.host == "2001:db8::2", "IPv6 UDP remote address must be retained");
        const std::string id = connectionId("direct.test");
        require(!id.empty(), "UDP test needs live flow ID");
        controlRequest("DELETE", "/connections/" + id);
        awaitCondition([] { return connectionId("direct.test").empty(); }, "Individual UDP close did not remove selected flow");
        require(!connectionId("2001:db8::2").empty(), "Individual UDP close must preserve other flows in association");
        controlRequest("DELETE", "/connections");
        char byte; require(recv(harness.control, &byte, 1, 0) == 0, "Disconnect all must terminate UDP association control socket");
    }
    require(g_state.connections.empty() && g_state.sockets.empty(), "UDP association shutdown leaked flows or descriptors");
    {
        ProxyNode node; node.name = "SS UDP"; node.type = "ss"; node.cipher = "aes-256-gcm";
        node.server = "ss.test"; node.port = 443; node.password = GOLDEN_PASSWORD; node.udp = true;
        { std::lock_guard<std::mutex> lock(g_state.mutex); g_state.mode = "Rule"; g_state.nodes = {node};
            g_state.groups = {{"UDP group", "Selector", "SS UDP", {"SS UDP", "DIRECT"}}}; g_state.rules = {{"match", "", "UDP group"}}; }
        UdpHarness harness; const int endpoint = harness.add("ss.test", 443);
        const auto requestPlain = hex(UDP_DOMAIN_PLAIN);
        std::vector<unsigned char> request{0, 0, 0}; request.insert(request.end(), requestPlain.begin(), requestPlain.end());
        harness.inject(request); const auto first = receiveTestDatagram(endpoint);
        std::vector<unsigned char> plain;
        require(decryptShadowsocksUdp(hex(GOLDEN_MASTER), first, plain) && plain == requestPlain, "UDP selected SS node must receive authenticated destination and payload");
        harness.inject(request); const auto second = receiveTestDatagram(endpoint);
        require(!std::equal(first.begin(), first.begin() + 32, second.begin()), "Each outgoing SS UDP datagram needs a fresh salt");
        require(decryptShadowsocksUdp(hex(GOLDEN_MASTER), second, plain) && plain == requestPlain, "Independent UDP packets must reset nonce to zero");
        const auto good = hex(UDP_IPV4_PACKET); auto corrupt = good; corrupt.back() ^= 1;
        send(endpoint, corrupt.data(), corrupt.size(), 0); send(endpoint, good.data(), good.size(), 0);
        auto reply = receiveTestDatagram(harness.relay);
        require(std::vector<unsigned char>(reply.begin() + 3, reply.end()) == hex(UDP_IPV4_PLAIN), "Bad SS UDP tag must be dropped without poisoning next valid packet");
        send(endpoint, good.data(), good.size(), 0);
        const auto next = hex(UDP_IPV6_PACKET); send(endpoint, next.data(), next.size(), 0);
        reply = receiveTestDatagram(harness.relay);
        require(std::vector<unsigned char>(reply.begin() + 3, reply.end()) == hex(UDP_IPV6_PLAIN), "Replayed SS UDP packet must be dropped before forwarding next valid IPv6 response");
        const auto snapshot = connectionsJson();
        require(snapshot.find("SS UDP") != std::string::npos && snapshot.find("UDP group") != std::string::npos,
            "UDP connection must retain selected node and group chain");
        require(proxiesJson().find("\"udp\":true") != std::string::npos, "Proxy metadata must expose actual UDP support");
    }
    require(g_state.connections.empty() && g_state.sockets.empty(), "Encrypted UDP cleanup leaked descriptors");
    { std::lock_guard<std::mutex> lock(g_state.mutex); g_state.mode = "Rule"; g_state.rules = {{"network", "UDP", "DIRECT"}, {"match", "", "REJECT"}}; }
    require(activeProxyNode("x.test", 443, "udp").type == "direct" && activeProxyNode("x.test", 443).type == "reject",
        "NETWORK rule must distinguish UDP from TCP");
    UdpTarget target{"x.test", 443, 0}; ProxyNode unsupported; unsupported.type = "vmess"; unsupported.udp = true;
    require(openUdpFlow(-1, target, unsupported) == nullptr, "Unsupported UDP protocol must never fall through to direct");
    unsupported.type = "ss"; unsupported.cipher = "aes-256-gcm"; unsupported.udp = false;
    require(openUdpFlow(-1, target, unsupported) == nullptr, "udp:false must disable Shadowsocks datagrams");
    stopCore(); g_testConnector = nullptr;
}
