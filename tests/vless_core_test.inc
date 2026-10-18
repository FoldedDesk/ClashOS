ProxyNode vlessTestNode(const std::string& transport = "tcp")
{
    ProxyNode node; node.name = "VLESS fixture"; node.type = "vless"; node.server = "vless.invalid"; node.port = 443;
    node.uuid = "11111111-2222-4333-8444-555555555555"; node.udp = true;
    node.tls = transport.find("tls") != std::string::npos; node.network = transport.find("ws") != std::string::npos ? "ws" : "tcp";
    node.serverName = "vmess.test"; node.wsPath = "/vless?test=1"; node.wsHeaders = {{"Host", "cdn.test"}, {"X-Test", "native-peer"}};
    return node;
}

void vlessTests(const std::string& directory)
{
    require(vlessProtocolSelfTest(), "Device VLESS diagnostic must validate public independent request vectors");
    const auto roots = readTestFile(std::string(CLAHSOS_TEST_ROOT) + "/fixtures/vmess/ca.pem");
    g_testVmessTrust = roots.c_str(); g_state.running.store(true);
    VmBytes payload(50000); for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<unsigned char>(i * 17 + 3);
    VmBytes expected = vmBytes("vless-response:"); expected.insert(expected.end(), payload.rbegin(), payload.rend());
    for (const std::string transport : {"tcp", "tls", "ws", "ws-tls"}) {
        for (int scenario : {0, 1, 2, 3, 4}) {
            std::cerr << "VLESS stream: " << transport << " address=" << scenario << '\n';
            VmessReferencePeer peer(scenario, transport, "", "vless_reference_peer.py");
            g_testConnector = [&](const std::string& host, int port, int) {
                require(host == "vless.invalid" && port == 443, "VLESS must dial its configured endpoint, not the destination"); return peer.take();
            };
            auto node = vlessTestNode(transport); if (scenario == 1) node.alpn = {"h2", "http/1.1"};
            if (scenario == 4) {
                ParsedConfig mapped; std::string error;
                require(parseConfigText("hosts: {target.test: 192.0.2.9}\n", mapped, error), "VLESS hosts fixture must use production parser");
                node.destinationDns = mapped.dns;
            }
            {
                ProxyStream stream; std::string error;
                const auto host = scenario == 2 ? "192.0.2.9" : scenario == 3 ? "2001:db8::9" : "target.test";
                require(openProxyStream(node, host, 443, stream, error, 5000), "VLESS fixture startup failed");
                require(streamWrite(stream, reinterpret_cast<const char*>(payload.data()), payload.size()), "VLESS large write failed");
                require(stream.vless->finish(), "VLESS half-close failed");
                VmBytes response, chunk; while (streamRead(stream, chunk)) vmAppend(response, chunk);
                require(response == expected && errno == 0, "VLESS fragmented response or half-close changed data");
            }
            g_testConnector = nullptr; peer.finish();
        }
        for (const std::string fault : {"version", "short-header", "short-addons", "invalid-addons", "vision-response", "addons", "addons-max", "server-first"}) {
            std::cerr << "VLESS response: " << transport << " fault=" << fault << '\n';
            VmessReferencePeer peer(0, transport, fault, "vless_reference_peer.py");
            g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
            {
                ProxyStream stream; std::string error; VmBytes response, chunk;
                require(openProxyStream(vlessTestNode(transport), "target.test", 443, stream, error, 5000), "VLESS response fixture startup failed");
                if (fault == "server-first") require(streamRead(stream, chunk) && text(chunk) == "greeting", "VLESS must send its header before application data for server-first protocols");
                require(streamWrite(stream, reinterpret_cast<const char*>(payload.data()), payload.size()), "VLESS response fixture write failed");
                while (streamRead(stream, chunk)) vmAppend(response, chunk);
                const bool valid = fault == "addons" || fault == "addons-max" || fault == "server-first";
                require(valid ? response == expected && errno == 0 : response.empty() && chunk.empty() && errno == EPROTO,
                    "VLESS invalid/truncated header must reject before exposing data, valid addons must preserve payload");
            }
            g_testConnector = nullptr; peer.finish();
        }
        // Real HTTP and SOCKS ingress, worker dispatch, counters and connection records.
        for (int protocol : {0, 1}) for (const std::string partial : {"duplex-version", "duplex-addons", "duplex-payload"}) {
            const std::string marker = directory + "/vless-ready"; unlink(marker.c_str());
            VmessReferencePeer peer(0, transport, partial + "|" + marker, "vless_reference_peer.py");
            g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
            auto node = vlessTestNode(transport);
            { std::lock_guard<std::mutex> lock(g_state.mutex); g_state.mode = "Rule"; g_state.nodes = {node};
              g_state.groups.clear(); g_state.rules = {{"match", "", node.name}}; }
            const auto up = g_state.uploadTotal.load(), down = g_state.downloadTotal.load();
            int client[2]; pairFor(client); socketTimeout(client[1], 5000); dispatchWorker(client[0], protocol);
            if (protocol == 0) {
                sendAll(client[1], "CONNECT target.test:443 HTTP/1.1\r\nHost: target.test\r\n\r\n");
                require(readUntilHeaders(client[1]).find("200 Connection Established") != std::string::npos, "VLESS HTTP CONNECT failed");
            } else {
                VmBytes greeting{5, 1, 0, 5, 1, 0}; vmAppend(greeting, shadowsocksAddress("target.test", 443)); sendAll(client[1], greeting);
                require(receiveN(client[1], 2) == std::string("\5\0", 2) && receiveN(client[1], 10)[1] == 0, "VLESS SOCKS CONNECT failed");
            }
            require(sendAll(client[1], reinterpret_cast<const char*>(payload.data()), 16), "VLESS first duplex write failed");
            awaitCondition([&] { return access(marker.c_str(), F_OK) == 0; }, "Independent peer did not send partial VLESS header");
            require(sendAll(client[1], reinterpret_cast<const char*>(payload.data() + 16), payload.size() - 16), "VLESS later duplex write failed");
            shutdown(client[1], SHUT_WR);
            require(receiveN(client[1], expected.size()) == text(expected), "Partial VLESS responses must not block later HTTP/SOCKS writes");
            char byte; require(recv(client[1], &byte, 1, 0) == 0, "VLESS EOF did not reach inbound client");
            close(client[1]); workersIdle(); g_testConnector = nullptr; peer.finish(); unlink(marker.c_str());
            require(g_state.uploadTotal.load() - up == payload.size() && g_state.downloadTotal.load() - down == expected.size(), "VLESS traffic counters must exclude protocol framing");
        }
        std::cerr << "VLESS UDP forwarding: " << transport << '\n';
        VmessReferencePeer peer(0, transport, "udp", "vless_reference_peer.py");
        g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
        { std::lock_guard<std::mutex> lock(g_state.mutex); auto node = vlessTestNode(transport); g_state.nodes = {node};
          g_state.mode = "Rule"; g_state.groups.clear(); g_state.rules = {{"match", "", node.name}}; }
        {
            UdpHarness harness;
            for (int i = 0; i < 4; ++i) {
                std::string body = i == 0 ? "packet-0" : i == 2 ? std::string(4096, 'P') : "";
                if (i == 3) { body.resize(65507 - 3 - shadowsocksAddress("target.test", 443).size()); for (size_t j = 0; j < body.size(); ++j) body[j] = static_cast<char>(j); }
                harness.inject(udpTestPacket("target.test", 443, body));
                auto packet = receiveTestDatagram(harness.relay); UdpTarget source;
                require(parseSocksUdp(packet, source) && source.host == "target.test" && source.port == 443, "VLESS UDP must preserve original SOCKS target");
                const std::string reply = i == 3 ? body : "udp-response:" + std::string(body.rbegin(), body.rend());
                require(text({packet.begin() + 3 + source.headerSize, packet.end()}) == reply, "VLESS empty/large UDP packet changed");
            }
            for (const std::string expectedBody : {"A", "", "B"}) {
                auto packet = receiveTestDatagram(harness.relay); UdpTarget source;
                require(parseSocksUdp(packet, source) && text({packet.begin() + 3 + source.headerSize, packet.end()}) == expectedBody, "VLESS coalesced replies must retain empty packet and boundaries");
            }
        }
        g_testConnector = nullptr; peer.finish(); require(g_state.connections.empty(), "VLESS UDP association leaked connection records");
    }
    for (const std::string transport : {"tls", "ws-tls"}) for (const std::string fault : {"tls-reject-ca", "tls-reject-host", "skip-cert", "tls-corrupt"}) {
        VmessReferencePeer peer(0, transport, fault, "vless_reference_peer.py");
        g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
        auto node = vlessTestNode(transport); if (fault == "tls-reject-host") node.serverName = "wrong.test";
        node.skipCertVerify = fault == "skip-cert"; g_testVmessTrust = fault == "tls-reject-ca" || node.skipCertVerify ? nullptr : roots.c_str();
        {
            ProxyStream stream; std::string error; const bool opened = openProxyStream(node, "target.test", 443, stream, error, 5000);
            if (fault == "tls-reject-ca" || fault == "tls-reject-host") require(!opened && !error.empty(), "VLESS TLS must reject wrong host/CA");
            else {
                require(opened && streamWrite(stream, reinterpret_cast<const char*>(payload.data()), payload.size()), "VLESS TLS fixture write failed");
                VmBytes response, chunk; while (streamRead(stream, chunk)) vmAppend(response, chunk);
                require(fault == "skip-cert" ? response == expected : response.empty() && errno != 0, "VLESS TLS corrupted data leaked or explicit skip-cert did not work");
            }
        }
        g_testConnector = nullptr; peer.finish();
    }
    g_testVmessTrust = roots.c_str();
    {
        VmessReferencePeer peer(0, "tcp", "remote-half-close", "vless_reference_peer.py");
        g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
        {
            ProxyStream stream; std::string error; VmBytes chunk;
            require(openProxyStream(vlessTestNode(), "target.test", 443, stream, error, 5000), "VLESS remote half-close fixture must start");
            require(streamRead(stream, chunk) && text(chunk) == "greeting" && !streamRead(stream, chunk) && errno == 0, "Remote VLESS TCP half-close must reach client as clean EOF");
            require(streamWrite(stream, reinterpret_cast<const char*>(payload.data()), payload.size()), "Remote TCP half-close must retain the upload direction");
            stream.vless->finish(); // Peer may already have fully closed after verifying the upload.
        }
        g_testConnector = nullptr; peer.finish();
    }
    for (const std::string transport : {"tcp", "ws-tls"}) for (const std::string fault : {"udp-short-length", "udp-short-payload", "udp-oversize"}) {
        VmessReferencePeer peer(0, transport, fault, "vless_reference_peer.py");
        g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
        {
            auto node = vlessTestNode(transport); std::string error; ProxyStream stream;
            stream.fd = connectUpstream(node.server, node.port, 5000); socketTimeout(stream.fd, 5000);
            stream.vless = std::make_unique<VlessSession>(stream.fd);
            require(stream.vless->start(node, "target.test", 443, true, error) && stream.vless->writeDatagram(vmBytes("packet-0")), "VLESS malformed UDP fixture failed to start");
            VmBytes output{1}; const bool ok = stream.vless->read(output);
            if (fault == "udp-oversize") {
                require(ok && output == VmBytes(65535, 'X') && stream.vless->read(output) && text(output) == "good", "Protocol-sized VLESS packets must not desynchronize the next packet; SOCKS layer enforces its own envelope limit");
            } else require(!ok && output.empty() && errno == EPROTO, "Truncated VLESS UDP must not expose partial payload");
        }
        g_testConnector = nullptr; peer.finish();
    }
    for (const std::string kind : {"vless-tcp", "vless-tls", "vless-ws", "vless-ws-tls"}) for (const std::string fault : {"", "untrusted", "wronghost", "status"}) {
        VmessReferencePeer peer(0, kind, fault, "https_reference_peer.py");
        g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
        g_testVmessTrust = fault == "untrusted" ? nullptr : roots.c_str();
        auto node = vlessTestNode(kind.substr(6)); node.skipCertVerify = true;
        TestTarget target; parseTestUrl("https://" + std::string(fault == "wronghost" ? "wrong.test" : "vmess.test") + "/probe?ok=1", target);
        std::string error; const int delay = probeNode(node, target, 5000, "204", error);
        require(fault.empty() ? delay > 0 : delay == 0 && !error.empty(), "VLESS HTTPS probe must verify destination identity independently of proxy TLS policy");
        g_testConnector = nullptr; peer.finish();
    }
    const std::string base = "{name: fixture, type: vless, server: vless.invalid, port: 443, uuid: 11111111-2222-4333-8444-555555555555, udp: true";
    for (const std::string option : {"flow: xtls-rprx-vision", "reality-opts: {public-key: public}", "packet-encoding: packetaddr", "encryption: mlkem768x25519plus", "network: grpc", "client-fingerprint: chrome", "smux: {enabled: true}", "ws-opts: {max-early-data: 2048}", "network: ws, alpn: [h2]"}) {
        const auto content = base + ", " + option + "}"; EditorYaml yaml; std::string error; ProxyNode node;
        require(yaml.parse(content, 4096, error) && parseProxyNode(yaml.document, yaml_document_get_root_node(&yaml.document), node, error), "Unsupported VLESS options must remain inspectable as nodes");
        bool dialed = false; g_testConnector = [&](const std::string&, int, int) { dialed = true; return -1; };
        ProxyStream stream; require(!openProxyStream(node, "target.test", 443, stream, error) && !error.empty() && !dialed && !supportsUdp(node), "Unsupported VLESS options must reject before dialing, never silently DIRECT");
        require(!editorObjectValid({"fixture", content}, false, error), "Visual VLESS save must reject unsupported options");
        g_testConnector = nullptr;
    }
    for (const std::string option : {"tls: maybe", "skip-cert-verify: 1", "udp: []"}) {
        ParsedConfig parsed; std::string error;
        require(!parseConfigText("proxies: [" + base.substr(0, base.rfind(", udp:")) + ", " + option + "}]", parsed, error) && !error.empty(), "Malformed VLESS security flags must not silently disable TLS or change UDP policy");
    }
    g_testVmessTrust = nullptr;
}
