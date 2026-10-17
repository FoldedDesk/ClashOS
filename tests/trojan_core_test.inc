ProxyNode trojanTestNode(const std::string& transport = "tls")
{
    ProxyNode node;
    node.name = "Trojan fixture"; node.type = "trojan"; node.server = "trojan.invalid"; node.port = 443;
    node.password = "pässword-测试"; node.serverName = "vmess.test"; node.udp = true;
    node.network = transport == "ws-tls" ? "ws" : "tcp";
    node.wsPath = "/trojan?test=1"; node.wsHeaders = {{"Host", "cdn.test"}, {"X-Test", "native-peer"}};
    return node;
}

void trojanTests(const std::string& directory)
{
    const std::string roots = readTestFile(std::string(CLAHSOS_TEST_ROOT) + "/fixtures/vmess/ca.pem");
    require(trojanCryptoSelfTest(), "Trojan device diagnostic must validate the independent SHA224/request vector");
    g_testVmessTrust = roots.c_str(); g_state.running.store(true);
    VmBytes payload(50000);
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<unsigned char>(i * 17 + 3);
    VmBytes expected = vmBytes("trojan-response:"); expected.insert(expected.end(), payload.rbegin(), payload.rend());
    auto exercise = [&](int scenario, const std::string& transport, const std::string& fault) {
        std::cerr << "Trojan peer: scenario=" << scenario << " transport=" << transport << " fault=" << fault << '\n';
        VmessReferencePeer peer(scenario, transport, fault, "trojan_reference_peer.py");
        g_testConnector = [&](const std::string& host, int port, int) {
            require(host == "trojan.invalid" && port == 443, "Trojan must dial the configured endpoint, never the target");
            return peer.take();
        };
        ProxyNode node = trojanTestNode(transport);
        if (scenario == 1) node.alpn = {"h2", "http/1.1"};
        if (fault == "tls-reject-host") node.serverName = "wrong.test";
        if (fault == "bad-password") node.password = "wrong-secret";
        if (fault == "skip-cert") node.skipCertVerify = true;
        g_testVmessTrust = fault == "tls-reject-ca" || fault == "skip-cert" ? nullptr : roots.c_str();
        const std::string destination = scenario == 2 ? "192.0.2.9" : scenario == 3 ? "2001:db8::9" : "target.test";
        {
            ProxyStream stream; std::string error;
            const bool opened = openProxyStream(node, destination, 443, stream, error, 5000);
            const bool rejected = fault == "tls-reject-host" || fault == "tls-reject-ca" || fault == "ws-accept";
            require(rejected ? !opened && !error.empty() : opened, "Trojan TLS identity or WS upgrade validation failed");
            if (!rejected) {
                require(streamWrite(stream, reinterpret_cast<const char*>(payload.data()), payload.size()), "Trojan large request write failed");
                if (fault != "tls-corrupt" && fault != "bad-password") require(stream.trojan->finish(), "Trojan request half-close failed");
                VmBytes response, chunk{1};
                while (streamRead(stream, chunk)) vmAppend(response, chunk);
                if (fault == "tls-corrupt" || fault == "bad-password")
                    require(response.empty() && chunk.empty(), "Trojan TLS/authentication failure must never expose application data");
                else require(response == expected && errno == 0, "Trojan fragmented TLS/WS reply or EOF changed payload");
            }
        }
        g_testConnector = nullptr; peer.finish();
    };
    for (const std::string transport : {"tls", "ws-tls"}) {
        for (int scenario : {0, 1, 2, 3}) exercise(scenario, transport, "");
        for (const std::string fault : {"tls-reject-ca", "tls-reject-host", "skip-cert", "bad-password", "tls-corrupt"}) exercise(0, transport, fault);
    }
    exercise(0, "ws-tls", "ws-accept");
    g_testVmessTrust = roots.c_str();

    // Both real inbound protocols must carry data, connection metadata and plaintext counters.
    for (int protocol : {0, 1}) for (const std::string transport : {"tls", "ws-tls"}) {
        std::cerr << "Trojan forwarding: inbound=" << protocol << " transport=" << transport << '\n';
        VmessReferencePeer peer(0, transport, "", "trojan_reference_peer.py");
        g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
        ProxyNode node = trojanTestNode(transport);
        {
            std::lock_guard<std::mutex> lock(g_state.mutex);
            g_state.mode = "Rule"; g_state.nodes = {node}; ProxyGroup group;
            group.name = "PROXY"; group.now = node.name; group.proxies = {node.name};
            g_state.groups = {group}; g_state.rules = {{"match", "", "PROXY"}};
        }
        const auto up = g_state.uploadTotal.load(), down = g_state.downloadTotal.load();
        int client[2]; pairFor(client); socketTimeout(client[1], 5000); dispatchWorker(client[0], protocol);
        if (protocol == 0) {
            sendAll(client[1], "CONNECT target.test:443 HTTP/1.1\r\nHost: target.test\r\n\r\n");
            require(readUntilHeaders(client[1]).find("200 Connection Established") != std::string::npos, "Trojan HTTP CONNECT failed");
        } else {
            VmBytes greeting{5,1,0,5,1,0}; vmAppend(greeting, shadowsocksAddress("target.test",443)); sendAll(client[1], greeting);
            require(receiveN(client[1],2) == std::string("\5\0",2) && receiveN(client[1],10)[1] == 0, "Trojan SOCKS CONNECT failed");
        }
        require(!connectionId("target.test").empty(), "Trojan request missing from actual connection list");
        require(sendAll(client[1], payload), "Trojan inbound large payload failed"); shutdown(client[1], SHUT_WR);
        require(receiveN(client[1], expected.size()) == text(expected), "HTTP/SOCKS to Trojan forwarding changed payload");
        char byte; require(recv(client[1], &byte, 1, 0) == 0, "Trojan response EOF did not reach client");
        close(client[1]); workersIdle(); g_testConnector = nullptr; peer.finish();
        require(g_state.uploadTotal.load() - up == payload.size() && g_state.downloadTotal.load() - down == expected.size(),
            "Trojan counters must exclude TLS, WebSocket and authentication/framing bytes");
    }

    for (const std::string transport : {"tls", "ws-tls"}) {
        std::cerr << "Trojan UDP forwarding: transport=" << transport << '\n';
        VmessReferencePeer peer(0, transport, "udp", "trojan_reference_peer.py");
        g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
        ProxyNode node = trojanTestNode(transport);
        { std::lock_guard<std::mutex> lock(g_state.mutex); g_state.nodes = {node}; g_state.mode = "Rule"; }
        const auto up = g_state.uploadTotal.load(), down = g_state.downloadTotal.load();
        {
            UdpHarness harness;
            for (int index = 0; index < 4; ++index) {
                std::string body = index == 0 ? "packet-0" : index == 2 ? std::string(4096, 'P') : "";
                if (index == 3) { body.resize(65507 - 3 - shadowsocksAddress("target.test", 443).size()); for (size_t i=0;i<body.size();++i) body[i]=static_cast<char>(i); }
                harness.inject(udpTestPacket("target.test", 443, body));
                const auto reply = receiveTestDatagram(harness.relay); UdpTarget source;
                const std::string host = index == 1 ? "2001:db8::1" : index == 2 ? "answer.test" : "8.8.8.8";
                std::string expectedBody = "udp-response:" + std::string(body.rbegin(), body.rend());
                if (index == 3) { expectedBody.resize(65497); for (size_t i=0;i<expectedBody.size();++i) expectedBody[i]=static_cast<char>(i); }
                require(parseSocksUdp(reply, source) && source.host == host && source.port == 53 + index &&
                    text({reply.begin() + 3 + source.headerSize, reply.end()}) == expectedBody,
                    "Trojan UDP must preserve source address, empty/large datagrams and packet boundaries");
                if (index == 0) require(!connectionId("target.test").empty(), "Active Trojan UDP flow must appear in connection list");
            }
            require(g_state.uploadTotal.load() > up && g_state.downloadTotal.load() > down, "Trojan UDP must record actual payload traffic");
        }
        g_testConnector = nullptr; peer.finish();
        require(g_state.connections.empty(), "Trojan UDP association did not release connection records");
    }

    for (const std::string fault : {"udp-atyp", "udp-domain-empty", "udp-domain-nul", "udp-port", "udp-crlf", "udp-short-address", "udp-short-payload", "udp-oversize"}) {
        VmessReferencePeer peer(0, "tls", fault, "trojan_reference_peer.py");
        g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
        ProxyStream stream; ProxyNode node = trojanTestNode(); std::string error;
        stream.fd = connectUpstream(node.server, node.port, 5000); stream.trojan = std::make_unique<TrojanSession>(stream.fd);
        require(stream.trojan->start(node, "target.test", 443, true, error), "Trojan UDP invalid frame fixture failed to open");
        require(stream.trojan->writeDatagram("target.test", 443, vmBytes("packet-0")), "Trojan UDP invalid frame fixture write failed");
        VmBytes output{1};
        require(!stream.trojan->readDatagram(output) && output.empty() && errno != 0, "Invalid or truncated Trojan UDP packet leaked data");
        if (fault == "udp-oversize") {
            require(errno == EMSGSIZE && stream.trojan->readDatagram(output) &&
                output == VmBytes({1,8,8,8,8,0,53,'g','o','o','d'}), "Oversized Trojan datagram must be consumed without losing the next packet");
        }
        stream.trojan.reset(); closeSocket(stream.fd); stream.fd = -1; g_testConnector = nullptr; peer.finish();
    }

    for (const std::string kind : {"trojan-tls", "trojan-ws-tls"}) for (const std::string fault : {"", "untrusted", "wronghost", "status"}) {
        std::cerr << "Trojan HTTPS probe: " << kind << " fault=" << fault << '\n';
        VmessReferencePeer peer(0, kind, fault, "https_reference_peer.py");
        g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
        g_testVmessTrust = fault == "untrusted" ? nullptr : roots.c_str();
        ProxyNode node = trojanTestNode(kind == "trojan-ws-tls" ? "ws-tls" : "tls");
        node.password = "probe-password"; node.skipCertVerify = true;
        TestTarget target; parseTestUrl("https://" + std::string(fault == "wronghost" ? "wrong.test" : "vmess.test") + "/probe?ok=1", target);
        std::string error;
        const int delay = probeNode(node, target, 5000, "204", error);
        if (fault.empty() && delay == 0) std::cerr << "Trojan HTTPS probe failed: " << error << '\n';
        require(fault.empty() ? delay > 0 : delay == 0 && !error.empty(), "Trojan HTTPS probe must validate the website independently of outbound skip-cert-verify");
        g_testConnector = nullptr; peer.finish();
    }
    {
        const std::string source = directory + "/trojan-provider-source.yaml";
        const std::string node = "name: provider-trojan, type: trojan, server: trojan.invalid, port: 443, password: fixture, udp: true";
        { std::ofstream file(source); file << "proxies: [{" << node << ", alpn: [h2]}]"; }
        const std::string profile = directory + "/trojan-provider.yaml";
        const std::string content = "proxy-providers: {feed: {type: file, path: trojan-provider-source.yaml}}\nproxy-groups: [{name: Route, type: select, use: [feed]}]\nrules: ['MATCH,Route']\n";
        loadProviderProfile(profile, content);
        require(activeProxyNode("target.test", 443).alpn == std::vector<std::string>{"h2"}, "Trojan provider must load the configured ALPN");
        const auto revision = g_state.configRevision;
        const std::string api = "/clahsos/providers/feed/file?profile=" + urlEncode(profile);
        const std::string updated = "proxies: [{" + node + ", alpn: [http/1.1]}]";
        require(responseFor("PUT", api, updated) == "{}" && g_state.configRevision > revision &&
            activeProxyNode("target.test", 443).alpn == std::vector<std::string>{"http/1.1"},
            "Changing only provider ALPN must update actual routing, invalidate old UDP flow keys and persist the new snapshot");
        require(responseFor("PUT", api, "proxies: [{" + node + ", alpn: [http/1.1], client-fingerprint: chrome}]") == "{}" &&
            !supportsUdp(activeProxyNode("target.test", 443, "udp")), "An unsupported option introduced by a provider refresh must not keep using the old supported node");
        loadProviderProfile(profile, content);
        require(!activeProxyNode("target.test", 443).transportError.empty(), "Updated Trojan provider options must survive cached reload");
        require(responseFor("PUT", api, updated) == "{}" && supportsUdp(activeProxyNode("target.test", 443, "udp")) &&
            g_state.groups[0].now == "provider-trojan", "Removing the unsupported provider option must restore forwarding and preserve the selected member");
        require(responseFor("GET", "/providers/proxies/feed/provider-trojan", "").find("\"type\":\"Trojan\"") != std::string::npos,
            "Trojan providers must publish the same proxy type as local Trojan nodes");
    }
    ParsedConfig config; std::string error;
    const std::string base = "name: trojan, type: trojan, server: trojan.invalid, port: 443, password: fixture";
    require(parseConfigText("proxies: [{" + base + ", udp: true, sni: vmess.test, alpn: [h2, http/1.1]}]", config, error) &&
        config.nodes[0].tls && config.nodes[0].serverName == "vmess.test" && config.nodes[0].alpn.size() == 2 && supportsUdp(config.nodes[0]),
        "Trojan YAML must preserve password, UDP, implicit TLS, SNI and ALPN");
    for (const std::string extra : {", alpn: h2", ", alpn: ['']", ", ws-opts: {path: 'bad path'}", ", ws-opts: {headers: {'Bad Header': x}}"})
        require(!parseConfigText("proxies: [{" + base + extra + "}]", config, error), "Invalid Trojan transport fields must fail validation");
    require(!parseConfigText("proxies: [{name: bad, type: trojan, server: x, port: 443}]", config, error), "Trojan without password must fail validation");
    for (const std::string extra : {", network: grpc", ", network: ws, alpn: [h2]", ", smux: {enabled: true}", ", ss-opts: {enabled: true}",
        ", reality-opts: {public-key: fixture}", ", fingerprint: fixture", ", client-fingerprint: chrome", ", dialer-proxy: DIRECT"}) {
        require(parseConfigText("proxies: [{" + base + ", udp: true" + extra + "}]", config, error), "Unsupported Trojan option should remain inspectable in the profile");
        bool dialed = false; g_testConnector = [&](const std::string&, int, int) { dialed = true; return -1; };
        ProxyStream stream;
        require(!openProxyStream(config.nodes[0], "target.test", 443, stream, error) && !error.empty() && !supportsUdp(config.nodes[0]) && !dialed,
            "Unsupported Trojan extension must fail explicitly before dialing, without DIRECT fallback");
        g_testConnector = nullptr;
    }
    require(responseFor("GET", "/version", "").find("\"trojan\"") != std::string::npos, "Core capabilities must expose Trojan support");
    g_testVmessTrust = nullptr; stopCore();
    require(g_state.sockets.empty() && g_state.connections.empty(), "Trojan tests leaked sockets or connection metadata");
}
