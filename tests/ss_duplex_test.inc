void ssIncrementalTests()
{
    require(shadowsocksTcpSelfTest(), "Device SS TCP diagnostics must verify independent byte-fragmented vectors and negative controls");
    const std::string first = "HTTP/1.1 204 No Content\r\n\r\n", second = "server data", expected = first + second;
    for (const auto& vector : SS_AEAD_VECTORS) {
        const auto method = shadowsocksCipher(vector.method); const auto master = hex(vector.master), wire = hex(vector.server);
        const size_t firstEnd = master.size() + 18 + first.size() + 16;
        for (size_t cut = 0; cut <= wire.size(); ++cut) {
            int pair[2]; pairFor(pair); socketTimeout(pair[0], 500);
            ShadowsocksReader reader(pair[0], method, master); VmBytes plain{1}; std::string received;
            require(sendAll(pair[1], reinterpret_cast<const char*>(wire.data()), cut), "Send independent partial SS vector");
            const auto started = HealthClock::now();
            while (reader.read(plain, true)) received += text(plain);
            const std::string prefix = cut >= firstEnd ? first + (cut == wire.size() ? second : "") : "";
            require(received == prefix && plain.empty() && errno == EAGAIN && HealthClock::now() - started < std::chrono::milliseconds(250), "Every SS salt/length/payload/tag split must yield promptly and expose only authenticated chunks");
            require(sendAll(pair[1], reinterpret_cast<const char*>(wire.data() + cut), wire.size() - cut), "Send remaining independent SS vector");
            shutdown(pair[1], SHUT_WR);
            while (reader.read(plain, cut % 2 == 0)) received += text(plain);
            require(received == expected && plain.empty() && errno == 0, "Incremental SS state must survive EAGAIN and resume through blocking/nonblocking reads without nonce drift");
            close(pair[0]); close(pair[1]);

            pairFor(pair); ShadowsocksReader truncated(pair[0], method, master); received.clear();
            require(sendAll(pair[1], reinterpret_cast<const char*>(wire.data()), cut), "Send EOF control at each independent SS vector offset"); shutdown(pair[1], SHUT_WR);
            while (truncated.read(plain, true)) received += text(plain);
            const bool boundary = cut == 0 || cut == master.size() || cut == firstEnd || cut == wire.size();
            require(received == prefix && plain.empty() && errno == (boundary ? 0 : ECONNRESET), "Only record boundaries are clean EOF; missing payload after a complete length must be a truncation error");
            close(pair[0]); close(pair[1]);
        }
        for (size_t position : {master.size(), master.size() + 17, master.size() + 18, firstEnd - 1}) {
            int pair[2]; pairFor(pair); ShadowsocksReader rejected(pair[0], method, master); auto corrupt = wire; corrupt[position] ^= 1;
            require(sendAll(pair[1], corrupt), "Send corrupted independent SS length/payload/tag vector");
            VmBytes plain{1}; require(!rejected.read(plain, true) && plain.empty() && errno == EBADMSG, "SS authentication failures must not release plaintext");
            plain = {1}; require(!rejected.read(plain, true) && plain.empty() && errno == EBADMSG, "An SS authentication failure is terminal and cannot resume at attacker-controlled bytes");
            close(pair[0]); close(pair[1]);
        }
        {
            int pair[2]; pairFor(pair); ShadowsocksReader invalid(pair[0], method, master);
            auto packet = hex(vector.salt); vmAppend(packet, hex(vector.reservedLength)); require(sendAll(pair[1], packet), "Send authenticated reserved SS length bits");
            VmBytes plain{1}; require(!invalid.read(plain, true) && plain.empty() && errno == EPROTO, "Authenticated SS lengths still enforce their reserved high bits"); close(pair[0]); close(pair[1]);
        }
        for (unsigned char low : {0xfe, 0xff}) {
            ShadowsocksReader exhausted(-1, method, master); exhausted.stage = ShadowsocksReader::Stage::Length; exhausted.packet.resize(18); exhausted.nonce.assign(12, 0xff); exhausted.nonce[0] = low;
            VmBytes plain{1}; require(!exhausted.read(plain, true) && plain.empty() && errno == EOVERFLOW, "Incremental SS must reject nonce exhaustion before attempting any socket read");
        }
    }
}

void ssDuplexTests(const std::string& directory)
{
    const std::string marker = directory + "/ss-duplex-ready";
    for (const std::string cipher : {"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"})
    for (int protocol : {0, 1})
    for (const std::string phase : {"salt", "salt-end", "length", "length-tag", "payload-start", "payload", "payload-tag", "second-length", "second-payload", "empty-run", "server-first-salt", "server-first-payload"}) {
        std::cerr << "SS duplex: " << cipher << " ingress=" << protocol << " partial=" << phase << '\n';
        unlink(marker.c_str());
        ProxyNode node; node.name = "SS duplex"; node.type = "ss"; node.server = "ss-interop.test"; node.port = 443;
        node.cipher = cipher; node.password = "pässword-测试";
        { std::lock_guard<std::mutex> lock(g_state.mutex); g_state.mode = "Rule"; g_state.nodes = {node}; g_state.groups.clear(); g_state.rules = {{"match", "", node.name}}; g_state.dns = std::make_shared<DnsConfig>(); }
        g_state.running.store(true);
        VmessReferencePeer peer(0, cipher, phase + "|" + marker, "ss_duplex_reference_peer.py");
        g_testConnector = [&](const std::string&, int, int) { return peer.take(); };
        int client[2]; pairFor(client); socketTimeout(client[1], 2000); dispatchWorker(client[0], protocol);
        if (protocol == 0) {
            require(sendAll(client[1], "CONNECT target.test:443 HTTP/1.1\r\nHost: target.test\r\n\r\n") && readUntilHeaders(client[1]).find("200 Connection Established") != std::string::npos, "SS partial-response HTTP ingress must open");
        } else {
            VmBytes request{5, 1, 0, 5, 1, 0}; vmAppend(request, shadowsocksAddress("target.test", 443));
            require(sendAll(client[1], request) && receiveN(client[1], 2) == std::string("\5\0", 2) && receiveN(client[1], 10)[1] == 0, "SS partial-response SOCKS ingress must open");
        }
        const bool serverFirst = phase.rfind("server-first-", 0) == 0;
        if (!serverFirst) require(sendAll(client[1], "first"), "SS first request bytes must be sent");
        const auto deadline = HealthClock::now() + std::chrono::seconds(2);
        while (access(marker.c_str(), F_OK) != 0 && HealthClock::now() < deadline) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        require(access(marker.c_str(), F_OK) == 0, "Independent peer must confirm the partial SS reply");
        if (phase.rfind("second-", 0) == 0) require(receiveN(client[1], 4) == "head", "A complete SS chunk before the partial one must remain readable");
        pollfd watch{client[1], POLLIN, 0}; require(poll(&watch, 1, 50) == 0, "Incomplete SS salt/length/payload must not release unauthenticated bytes");
        if (serverFirst) require(sendAll(client[1], "first"), "Server-first partial SS replies must permit the initial client write");
        require(sendAll(client[1], "tail"), "A partial SS reply must permit later client writes"); shutdown(client[1], SHUT_WR);
        require(receiveN(client[1], 4) == "done", "Partial SS reads must not block later client payloads");
        char byte; require(recv(client[1], &byte, 1, 0) == 0, "SS duplex response must retain clean EOF after client half-close");
        close(client[1]); workersIdle(); g_testConnector = nullptr; peer.finish(); unlink(marker.c_str());
    }
    stopCore();
}
