Bytes bridgeHex(const char* source) {
    Bytes result;
    for (size_t i = 0; source[i] != 0; i += 2) result.push_back(std::stoul(std::string(source + i, 2), nullptr, 16));
    return result;
}
UdpEndpoint bridgeEndpoint(int port) {
    UdpEndpoint endpoint;
    auto* address = reinterpret_cast<sockaddr_in*>(&endpoint.address);
    address->sin_family = AF_INET; address->sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &address->sin_addr); endpoint.length = sizeof(*address);
    return endpoint;
}
Bytes receiveBridgeDatagram(int fd) {
    pollfd watch{fd, POLLIN, 0}; check(poll(&watch, 1, 2000) > 0, "UDP bridge server receives packet");
    Bytes packet(65536); const ssize_t count = recv(fd, packet.data(), packet.size(), 0);
    check(count >= 0, "read UDP bridge datagram"); packet.resize(count); return packet;
}
void tunneledUdp(int packetFd, const std::string& fakeAddress, int round) {
    int control[2], relay[2], remote[2];
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, control) == 0 && socketpair(AF_UNIX, SOCK_DGRAM, 0, relay) == 0 &&
        socketpair(AF_UNIX, SOCK_DGRAM, 0, remote) == 0, "create TUN/core/SOCKS/SS transport pairs");
    const Bytes requestPlain = bridgeHex(UDP_DOMAIN_PLAIN);
    const Bytes requestPayload(requestPlain.begin() + 18, requestPlain.end());
    ProxyNode node; node.name = "QUIC SS"; node.type = "ss"; node.server = "ss.test"; node.port = 443;
    node.cipher = "aes-256-gcm"; node.password = GOLDEN_PASSWORD; node.udp = true;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        g_state.mode = "Rule"; g_state.nodes = {node};
        g_state.groups = {{"QUIC group", "Selector", node.name, {node.name}}};
        g_state.rules = {{"domain", "www.google.com", "QUIC group"}, {"match", "", "REJECT"}};
        g_state.running.store(true);
    }
    g_udpTestHooks.relay = [fd = relay[0]](int, UdpEndpoint& bound, UdpEndpoint& peer) {
        bound = bridgeEndpoint(30000); peer = bridgeEndpoint(12345); return fd;
    };
    g_udpTestHooks.receive = [](int fd, Bytes& packet, UdpEndpoint& sender) {
        packet.resize(65536); const ssize_t count = recv(fd, packet.data(), packet.size(), 0);
        if (count >= 0) { packet.resize(count); sender = bridgeEndpoint(40000); }
        return count;
    };
    g_udpTestHooks.send = [](int fd, const Bytes& packet, const UdpEndpoint& endpoint) {
        if (udpEndpointPort(endpoint) != 40000) { errno = EINVAL; return ssize_t(-1); }
        return send(fd, packet.data(), packet.size(), 0);
    };
    g_udpTestHooks.connect = [fd = remote[0]](const std::string& host, int port, UdpEndpoint& endpoint) {
        if (host != "ss.test" || port != 443) return -1;
        endpoint = bridgeEndpoint(443); return fd;
    };
    connector.store(control[0]); udpConnector.store(relay[1]);
    dispatchWorker(control[1], 1);
    const auto uploaded = g_state.uploadTotal.load(), downloaded = g_state.downloadTotal.load();
    const char* replyVector = round == 0 ? UDP_IPV4_PACKET : round == 1 ? UDP_BRIDGE_REPLY_2 : UDP_BRIDGE_REPLY_3;
    const char* emptyReplyVector = round == 0 ? UDP_BRIDGE_EMPTY_REPLY_1 : round == 1 ? UDP_BRIDGE_EMPTY_REPLY_2 : UDP_BRIDGE_EMPTY_REPLY_3;
    const Bytes expectedPlain = bridgeHex(UDP_IPV4_PLAIN);
    const Bytes replyPayload(expectedPlain.begin() + 7, expectedPlain.end());
    std::thread server([&] {
        const Bytes packet = receiveBridgeDatagram(remote[1]);
        Bytes plain;
        check(decryptShadowsocksUdp(bridgeHex(GOLDEN_MASTER), packet, plain) && plain == requestPlain,
            "TUN UDP restores original domain and routes encrypted datagram through selected SS node");
        const Bytes response = bridgeHex(replyVector);
        check(send(remote[1], response.data(), response.size(), 0) == response.size(), "send independent SS UDP server response");
        const Bytes empty = receiveBridgeDatagram(remote[1]);
        check(decryptShadowsocksUdp(bridgeHex(GOLDEN_MASTER), empty, plain) && plain == Bytes(requestPlain.begin(), requestPlain.begin() + 18),
            "Zero-length application UDP datagram survives TUN and SOCKS encapsulation");
        const Bytes emptyResponse = bridgeHex(emptyReplyVector);
        check(send(remote[1], emptyResponse.data(), emptyResponse.size(), 0) == emptyResponse.size(), "send independent empty SS UDP reply");
    });
    Bytes udp(8, 0); put16(udp, 0, 33447); put16(udp, 2, 443); put16(udp, 4, 8 + requestPayload.size());
    udp.insert(udp.end(), requestPayload.begin(), requestPayload.end());
    const Bytes reply = exchangePacket(packetFd, ipv4(udp, 17, fakeAddress));
    check(reply.size() >= 28 && reply[9] == 17, "TUN bridge returns IPv4 UDP packet");
    const size_t ip = (reply[0] & 15) * 4;
    char source[INET_ADDRSTRLEN]{}; inet_ntop(AF_INET, reply.data() + 12, source, sizeof(source));
    check(source == fakeAddress, "UDP response restores fake IP expected by application socket");
    check(u16(reply, ip) == 443 && u16(reply, ip + 2) == 33447, "UDP bridge restores source and destination ports");
    check(Bytes(reply.begin() + ip + 8, reply.end()) == replyPayload, "UDP response retains authenticated payload byte for byte");
    Bytes pseudo(reply.begin() + 12, reply.begin() + 20); pseudo.resize(12, 0); pseudo[9] = 17;
    put16(pseudo, 10, reply.size() - ip); pseudo.insert(pseudo.end(), reply.begin() + ip, reply.end());
    check(checksum(pseudo) == 0, "TUN UDP response checksum is valid for application network stack");
    check(g_state.uploadTotal.load() == uploaded + requestPayload.size() && g_state.downloadTotal.load() == downloaded + replyPayload.size(),
        "TUN UDP uses native plaintext traffic counters");
    check(connectionsJson().find("QUIC group") != std::string::npos && connectionsJson().find("\"network\":\"udp\"") != std::string::npos,
        "TUN UDP exposes real selected group and protocol in connections");
    udp.resize(8); put16(udp, 4, 8);
    const Bytes emptyReply = exchangePacket(packetFd, ipv4(udp, 17, fakeAddress));
    server.join();
    check(emptyReply.size() == 28 && emptyReply[9] == 17 && u16(emptyReply, 24) == 8,
        "Zero-length UDP reply must be delivered as a real IP datagram");
    stopCore();
    check(g_state.workers.load() == 0 && g_state.connections.empty() && g_state.sockets.empty(), "TUN UDP control close cleans native workers and flows");
    g_udpTestHooks = {}; close(remote[1]);
}
