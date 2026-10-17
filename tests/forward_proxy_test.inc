ProxyNode forwardTestNode(const std::string& kind, int scenario = 0)
{
    ProxyNode node; node.name = "Forward fixture"; node.type = kind.rfind("http", 0) == 0 ? "http" : "socks5";
    node.server = "forward.invalid"; node.port = 443; node.tls = kind.find("tls") != std::string::npos;
    node.serverName = "vmess.test"; node.username = scenario == 1 ? "" : scenario == 5 ? std::string(255, 'U') : "fixture用户";
    node.password = scenario == 1 ? "" : scenario == 5 ? std::string(255, 'P') : "p@ss:word测试";
    node.udp = node.type == "socks5";
    if (node.type == "http") node.httpHeaders = {{"X-Test", "native-peer"}};
    return node;
}

void forwardProxyTests(const std::string& directory)
{
    const auto roots = readTestFile(std::string(CLAHSOS_TEST_ROOT) + "/fixtures/vmess/ca.pem");
    const auto savedDns = g_state.dns; g_testVmessTrust = roots.c_str(); g_state.running.store(true);
    VmBytes payload(50000); for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<unsigned char>(i * 19 + 7);
    VmBytes expected = vmBytes("forward-response:"); expected.insert(expected.end(), payload.rbegin(), payload.rend());
    const std::string mappedProfile = "hosts: {target.test: 192.0.2.9}\n"; ParsedConfig mapped; std::string error;
    require(parseConfigText(mappedProfile, mapped, error), "Forward proxy hosts fixture must parse");
    for (const std::string kind : {"http-tcp", "http-tls", "socks5-tcp", "socks5-tls"}) {
        for (int scenario : {0, 1, 2, 3, 4, 5}) {
            std::cerr << "Forward peer: " << kind << " scenario=" << scenario << '\n';
            VmessReferencePeer peer(scenario, kind, "", "forward_reference_peer.py");
            g_testConnector = [&](const std::string& host, int port, int) { require(host == "forward.invalid" && port == 443, "Forward proxy must dial configured server, not target"); return peer.take(); };
            auto node = forwardTestNode(kind, scenario); if (scenario == 4) node.destinationDns = mapped.dns;
            {
                ProxyStream stream; std::string error;
                const auto host = scenario == 2 ? "192.0.2.9" : scenario == 3 ? "2001:db8::9" : "target.test";
                require(openProxyStream(node, host, 443, stream, error, 5000), "HTTP/SOCKS fixture failed to start");
                require(streamWrite(stream, reinterpret_cast<const char*>(payload.data()), payload.size()) && stream.forward->finish(), "Forward proxy large upload or half-close failed");
                VmBytes response, part; while (streamRead(stream, part)) vmAppend(response, part);
                require(response == expected && errno == 0, "Forward proxy response changed or lost data");
            }
            g_testConnector = nullptr; peer.finish();
        }
        const bool http = kind.rfind("http", 0) == 0;
        const std::vector<std::string> failures = http ? std::vector<std::string>{"auth-fail", "status", "bad-status", "short-header", "oversize-header", "many-interim"} :
            std::vector<std::string>{"auth-fail", "method", "version", "auth-version", "reply-version", "reply-status", "reply-reserved", "reply-atyp", "reply-short", "reply-domain-empty"};
        for (const auto& fault : failures) {
            VmessReferencePeer peer(0, kind, fault, "forward_reference_peer.py");
            g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
            { ProxyStream stream; std::string error;
              require(!openProxyStream(forwardTestNode(kind), "target.test", 443, stream, error, 5000) && !error.empty() && error.find("public-secret") == std::string::npos && error.find("p@ss") == std::string::npos,
                  "Forward authentication/response failures must reject before payload and redact secrets"); }
            g_testConnector = nullptr; peer.finish();
        }
        for (const std::string fault : http ? std::vector<std::string>{"interim", "success-201", "server-first"} : std::vector<std::string>{"server-first"}) {
            VmessReferencePeer peer(0, kind, fault, "forward_reference_peer.py"); g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
            { ProxyStream stream; std::string error; VmBytes response, part;
              require(openProxyStream(forwardTestNode(kind), "target.test", 443, stream, error, 5000), "Forward informational/server-first fixture failed");
              if (fault == "server-first") require(streamRead(stream, part) && text(part) == "greeting", "Handshake-coalesced greeting must remain application data");
              require(streamWrite(stream, reinterpret_cast<const char*>(payload.data()), payload.size()), "Forward follow-up upload failed");
              while (streamRead(stream, part)) vmAppend(response, part);
              require(response == expected && errno == 0, "HTTP 2xx tunnel must ignore framing headers and preserve response data"); }
            g_testConnector = nullptr; peer.finish();
        }
        for (int protocol : {0, 1}) {
            VmessReferencePeer peer(0, kind, "", "forward_reference_peer.py"); g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
            auto node = forwardTestNode(kind);
            { std::lock_guard<std::mutex> lock(g_state.mutex); g_state.mode = "Rule"; g_state.nodes = {node}; g_state.groups.clear(); g_state.rules = {{"match", "", node.name}}; g_state.dns = savedDns; }
            const auto up = g_state.uploadTotal.load(), down = g_state.downloadTotal.load(); int client[2]; pairFor(client); socketTimeout(client[1], 5000); dispatchWorker(client[0], protocol);
            if (protocol == 0) {
                sendAll(client[1], "CONNECT target.test:443 HTTP/1.1\r\nHost: target.test\r\n\r\n");
                require(readUntilHeaders(client[1]).find("200 Connection Established") != std::string::npos, "HTTP ingress to forward proxy failed");
            } else {
                VmBytes request{5,1,0,5,1,0}; vmAppend(request, shadowsocksAddress("target.test",443)); sendAll(client[1], request);
                require(receiveN(client[1],2) == std::string("\5\0",2) && receiveN(client[1],10)[1] == 0, "SOCKS ingress to forward proxy failed");
            }
            require(!connectionId("target.test").empty(), "Forward TCP metadata must be visible");
            sendAll(client[1], payload); shutdown(client[1], SHUT_WR);
            require(receiveN(client[1], expected.size()) == text(expected), "Actual HTTP/SOCKS ingress payload changed"); char byte;
            require(recv(client[1], &byte, 1, 0) == 0, "Forward response EOF missing"); close(client[1]); workersIdle(); g_testConnector = nullptr; peer.finish();
            require(g_state.uploadTotal.load() - up == payload.size() && g_state.downloadTotal.load() - down == expected.size(), "Forward counters must exclude authentication and tunneling bytes");
        }
        {
            VmessReferencePeer peer(0, kind, "plain-http", "forward_reference_peer.py"); g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
            int client[2]; pairFor(client); socketTimeout(client[1], 5000); dispatchWorker(client[0], 0);
            sendAll(client[1], "GET http://target.test/verify HTTP/1.1\r\nHost: target.test\r\nAuthorization: Bearer public-origin\r\nProxy-Authorization: Basic cHVibGljLWluYm91bmQ6c2VjcmV0\r\nProxy-Connection: keep-alive\r\n\r\n");
            require(readUntilHeaders(client[1]).find("204 No Content") != std::string::npos, "Plain HTTP ingress must strip proxy credentials while retaining origin authorization");
            close(client[1]); workersIdle(); g_testConnector = nullptr; peer.finish();
        }
    }
    for (const std::string kind : {"http-tcp", "socks5-tcp"}) {
        VmessReferencePeer peer(0, kind, "remote-half-close", "forward_reference_peer.py"); g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
        { ProxyStream stream; std::string error; VmBytes part;
          require(openProxyStream(forwardTestNode(kind), "target.test", 443, stream, error, 5000) && streamRead(stream, part) && text(part) == "greeting" && !streamRead(stream, part) && errno == 0, "Forward server-first remote half-close must remain clean EOF");
          require(streamWrite(stream, reinterpret_cast<const char*>(payload.data()), payload.size()), "Remote half-close must keep the upload direction usable"); }
        g_testConnector = nullptr; peer.finish();
    }
    for (const std::string kind : {"http-tls", "socks5-tls"}) for (const std::string fault : {"tls-reject-ca", "tls-reject-host", "skip-cert", "tls-corrupt"}) {
        VmessReferencePeer peer(0, kind, fault, "forward_reference_peer.py"); g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
        auto node = forwardTestNode(kind); if (fault == "tls-reject-host") node.serverName = "wrong.test"; node.skipCertVerify = fault == "skip-cert";
        g_testVmessTrust = fault == "tls-reject-ca" || node.skipCertVerify ? nullptr : roots.c_str();
        { ProxyStream stream; std::string error; const bool opened = openProxyStream(node, "target.test", 443, stream, error, 5000);
          if (fault == "tls-reject-ca" || fault == "tls-reject-host") require(!opened && !error.empty(), "Forward TLS must reject bad CA/host");
          else { require(opened && streamWrite(stream, reinterpret_cast<const char*>(payload.data()), payload.size()), "Forward TLS fixture upload failed");
                 VmBytes response, part; while (streamRead(stream, part)) vmAppend(response, part);
                 require(fault == "skip-cert" ? response == expected : response.empty() && errno != 0, "Forward TLS authentication failure exposed data or explicit skip failed"); } }
        g_testConnector = nullptr; peer.finish();
    }
    g_testVmessTrust = roots.c_str();
    for (const std::string kind : {"socks5-tcp", "socks5-tls"}) for (int scenario : {0, 1, 4, 6, 7, 8}) {
        std::cerr << "SOCKS UDP: " << kind << " scenario=" << scenario << '\n';
        int datagrams[2]; require(socketpair(AF_UNIX, SOCK_DGRAM, 0, datagrams) == 0, "Independent SOCKS UDP socket pair unavailable");
        for (int fd : datagrams) { int size = 262144; setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)); setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)); }
        const std::string fault = scenario == 8 ? "udp-control-close" : "udp";
        const std::string marker = directory + "/forward-udp-ack"; unlink(marker.c_str());
        VmessReferencePeer peer(scenario, kind, fault + "|" + std::to_string(datagrams[1]) + ":" + std::to_string(datagrams[0]) + (scenario == 8 ? "|" + marker : ""), "forward_reference_peer.py"); close(datagrams[1]); int outbound = datagrams[0];
        g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
        auto node = forwardTestNode(kind, scenario);
        { std::lock_guard<std::mutex> lock(g_state.mutex); g_state.mode = "Rule"; g_state.nodes = {node}; g_state.groups.clear(); g_state.rules = {{"match", "", node.name}}; g_state.dns = scenario == 4 ? mapped.dns : savedDns; }
        const std::string expectedRelay = scenario % 4 == 0 ? "192.0.2.1" : scenario % 4 == 1 ? "forward.invalid" : scenario % 4 == 2 ? "relay.test" : "2001:db8::9";
        const auto up = g_state.uploadTotal.load(), down = g_state.downloadTotal.load();
        {
            UdpHarness harness;
            g_udpTestHooks.connect = [&](const std::string& host, int port, UdpEndpoint& remote) { require(host == expectedRelay && port == 18096, "SOCKS UDP must use server's relay, with wildcard peer fallback"); remote = udpTestEndpoint("192.0.2.1", 18096); int fd = outbound; outbound = -1; return fd; };
            for (int index = 0; index < 4; ++index) {
                std::string body = index == 0 ? "packet-0" : index == 2 ? std::string(4096, 'P') : "";
                if (index == 3) { body.resize(65489); for (size_t i = 0; i < body.size(); ++i) body[i] = static_cast<char>(i); }
                harness.inject(udpTestPacket("target.test", 443, body)); auto packet = receiveTestDatagram(harness.relay); UdpTarget source;
                require(parseSocksUdp(packet, source) && source.host == (index == 1 ? "2001:db8::1" : index == 2 ? "answer.test" : "8.8.8.8") && source.port == 53 + index, "SOCKS UDP must preserve actual response source and drop invalid/fragmented packets");
                const auto response = index == 1 ? "" : index == 3 ? body : "udp-response:" + std::string(body.rbegin(), body.rend());
                require(text({packet.begin() + 3 + source.headerSize, packet.end()}) == response, "SOCKS UDP lost empty/large packet data");
            }
            if (scenario == 8) {
                { std::ofstream ack(marker); ack << "delivered"; }
                awaitCondition([] { return connectionId("target.test").empty(); }, "SOCKS UDP control close must remove the live flow");
                pollfd quiet{harness.relay, POLLIN, 0}; require(poll(&quiet, 1, 100) == 0, "SOCKS UDP replies after control closure must not reach inbound client");
            }
            awaitCondition([&] { return g_state.uploadTotal.load() - up == 69593 && g_state.downloadTotal.load() - down == 69619; }, "SOCKS UDP counters must exclude all relay and address framing");
        }
        if (outbound >= 0) close(outbound); g_testConnector = nullptr; peer.finish(); unlink(marker.c_str()); require(g_state.connections.empty(), "SOCKS UDP flow leaked control/session metadata");
    }
    g_state.dns = savedDns;
    {
        std::vector<ProxyNode> invalid;
        auto node = forwardTestNode("socks5-tcp"); node.username = std::string(256, 'U'); invalid.push_back(node);
        node = forwardTestNode("socks5-tcp"); node.password.clear(); invalid.push_back(node);
        node = forwardTestNode("http-tcp"); node.username = "invalid:username"; invalid.push_back(node);
        node = forwardTestNode("http-tcp"); node.password = "public-secret\r\nInjected: true"; invalid.push_back(node);
        node = forwardTestNode("http-tls"); node.alpn = {"h2"}; invalid.push_back(node);
        node = forwardTestNode("http-tcp"); node.httpHeaders = {{"X-Test", "one"}, {"x-test", "two"}}; invalid.push_back(node);
        node = forwardTestNode("http-tcp"); node.httpHeaders = {{"Proxy-Authorization", "public-secret"}}; invalid.push_back(node);
        node = forwardTestNode("http-tcp"); node.httpHeaders = {{"Content-Length", "0"}}; invalid.push_back(node);
        node = forwardTestNode("http-tcp"); node.httpHeaders = {{"X-Test", "one\r\nInjected: true"}}; invalid.push_back(node);
        node = forwardTestNode("socks5-tcp"); node.network = "ws"; invalid.push_back(node);
        for (const auto& rejected : invalid) {
            bool dialed = false; g_testConnector = [&](const std::string&, int, int) { dialed = true; return -1; };
            ProxyStream stream; std::string error;
            require(!openProxyStream(rejected, "target.test", 443, stream, error) && !error.empty() && !dialed && error.find("public-secret") == std::string::npos && !supportsUdp(rejected), "Invalid forward credentials/options/headers must reject before dialing and redact values");
            g_testConnector = nullptr;
        }
        for (const std::string type : {"http", "socks5"}) for (const std::string option : {"tls: invalid", "skip-cert-verify: []", "username: {}"}) {
            ParsedConfig parsed; std::string error;
            require(!parseConfigText("proxies: [{name: fixture, type: " + type + ", server: forward.invalid, port: 443, " + option + "}]", parsed, error), "Malformed forward security fields must not silently change authentication/TLS");
        }
    }
    for (const std::string kind : {"forward-http-tcp", "forward-http-tls", "forward-socks5-tcp", "forward-socks5-tls"}) for (const std::string fault : {"", "untrusted", "wronghost", "status"}) {
        VmessReferencePeer peer(0, kind, fault, "https_reference_peer.py"); g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
        g_testVmessTrust = fault == "untrusted" ? nullptr : roots.c_str(); auto node = forwardTestNode(kind.substr(8)); node.skipCertVerify = true;
        TestTarget target; parseTestUrl("https://" + std::string(fault == "wronghost" ? "wrong.test" : "vmess.test") + "/probe?ok=1", target);
        std::string error; const int delay = probeNode(node, target, 5000, "204", error);
        require(fault.empty() ? delay > 0 : delay == 0 && !error.empty(), "Forward HTTPS latency must verify website independently of proxy TLS policy");
        g_testConnector = nullptr; peer.finish();
    }
    // Updating only credentials or custom headers must replace actual routed
    // provider nodes, invalidate health history and survive a cache-only reload.
    const std::string profile = directory + "/forward-provider.yaml", source = directory + "/forward-provider-source.yaml";
    const auto body = [](const std::string& user, const std::string& header) {
        return "proxies: [{name: provider-forward, type: http, server: forward.invalid, port: 443, username: " + shareQuoted(user) +
            ", password: " + shareQuoted("p@ss:word测试") + ", headers: {X-Test: " + shareQuoted(header) + "}}]\n";
    };
    { std::ofstream file(source); file << body("fixture用户", "native-peer"); }
    const std::string providerConfig = "proxy-providers: {feed: {type: file, path: forward-provider-source.yaml}}\nproxy-groups: [{name: Route, type: select, use: [feed]}]\nrules: ['MATCH,Route']\n";
    loadProviderProfile(profile, providerConfig);
    const auto exchange = [&](const std::string& fault) {
        VmessReferencePeer peer(0, "http-tcp", fault, "forward_reference_peer.py"); g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
        {
            ProxyStream stream; std::string error; const auto node = activeProxyNode("target.test", 443);
            require(node.provider == "feed" && openProxyStream(node, "target.test", 443, stream, error), "Updated provider route must open actual HTTP tunnel");
            require(streamWrite(stream, reinterpret_cast<const char*>(payload.data()), payload.size()), "Provider HTTP upload failed");
            VmBytes response, part; while (streamRead(stream, part)) vmAppend(response, part);
            require(response == expected && errno == 0, "Provider must use updated username/headers on the wire");
        }
        g_testConnector = nullptr; peer.finish();
    };
    exchange("");
    for (int step : {0, 1}) {
        const auto revision = g_state.configRevision;
        { std::lock_guard<std::mutex> lock(g_state.mutex);
          require(importProviderFileLocked("feed", body("updated-user", step == 0 ? "native-peer" : "updated-peer")) == "{}", "File provider forward credentials/header update must commit"); }
        require(g_state.configRevision == revision + 1 && activeProxyNode("target.test", 443).username == "updated-user", "Credential/header-only provider changes must rebuild live routes and revisions");
        exchange(step == 0 ? "provider-user" : "provider-headers");
    }
    const std::string metadata = responseFor("GET", "/providers/proxies", "");
    require(metadata.find("updated-user") == std::string::npos && metadata.find("updated-peer") == std::string::npos && metadata.find("p@ss") == std::string::npos, "Provider API must not expose new credentials or custom headers");
    loadProviderProfile(profile, providerConfig); exchange("provider-headers");
    g_testVmessTrust = nullptr;
}
