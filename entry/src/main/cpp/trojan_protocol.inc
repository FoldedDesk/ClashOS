// Trojan TCP and UDP framing over verified TLS, optionally inside RFC 6455 WebSocket.
// https://trojan-gfw.github.io/trojan/protocol
struct TrojanSession {
    VmessTransport transport;
    std::vector<unsigned char> requestHeader;
    std::vector<unsigned char> datagramInput;
    bool datagram = false, sentEof = false;
    explicit TrojanSession(int fd) : transport(fd) {}

    static bool validate(const ProxyNode& node, std::string& error) {
        if (supportsTrojan(node)) return true;
        error = !node.transportError.empty() ? node.transportError : node.password.empty() ?
            "Trojan password is required" : node.network == "ws" ?
            "Trojan WebSocket requires HTTP/1.1 ALPN" : "Unsupported Trojan transport: " + node.network;
        return false;
    }
    static std::vector<unsigned char> address(const std::string& host, int port) {
        if (host.empty() || host.find('\0') != std::string::npos || port < 1 || port > 65535) return {};
        return shadowsocksAddress(host, port);
    }
    static std::vector<unsigned char> header(const std::string& password, const std::string& host, int port, bool udp) {
        const auto destination = address(host, port);
        const auto hash = digestBytes("SHA224", {password.begin(), password.end()});
        if (destination.empty() || hash.size() != 28) return {};
        static const char* alphabet = "0123456789abcdef";
        std::vector<unsigned char> output;
        for (const unsigned char byte : hash) { output.push_back(alphabet[byte >> 4]); output.push_back(alphabet[byte & 15]); }
        output.insert(output.end(), {'\r', '\n', static_cast<unsigned char>(udp ? 3 : 1)});
        output.insert(output.end(), destination.begin(), destination.end());
        output.insert(output.end(), {'\r', '\n'});
        return output;
    }
    bool start(const ProxyNode& node, const std::string& host, int port, bool udp, std::string& error) {
        if (!validate(node, error)) return false;
        requestHeader = header(node.password, host, port, udp);
        if (requestHeader.empty()) { error = "Invalid Trojan destination or unavailable SHA224"; return false; }
        datagram = udp;
        const char* roots = nullptr;
#ifdef CLAHSOS_HOST_TEST
        roots = g_testVmessTrust;
#endif
        const auto protocols = node.network == "ws" ? std::vector<std::string>{"http/1.1"} : node.alpn;
        // Trojan always uses TLS, even when a profile omits the optional VMess-style tls field.
        if (!transport.channel.start(node.serverName.empty() ? node.server : node.serverName,
            node.skipCertVerify, error, roots, protocols)) return false;
        return node.network != "ws" || transport.startWebSocket(node, error);
    }
    bool write(const unsigned char* data, size_t size) {
        if (sentEof) { errno = EPIPE; return false; }
        if (size == 0 && requestHeader.empty()) return true;
        if (!requestHeader.empty()) {
            // The password hash, request and first payload travel in one TLS/WS write.
            auto packet = requestHeader;
            if (size > 0) packet.insert(packet.end(), data, data + size);
            if (!transport.write(packet)) return false;
            requestHeader.clear();
            return true;
        }
        return transport.write({data, data + size});
    }
    bool read(std::vector<unsigned char>& output, bool nonblocking = false) {
        output.clear(); errno = 0;
        return nonblocking ? transport.tryReadSome(output) : transport.readSome(output);
    }
    bool finish() {
        if (sentEof) return true;
        sentEof = true;
        // RFC 6455 has no write-only close: a close frame would discard the target's pending reply.
        return transport.websocket || transport.closeWrite();
    }
    bool pending() const {
        size_t addressSize = 0, packetSize = 0;
        return (datagram && inspectDatagram(addressSize, packetSize) != 0) || transport.pending();
    }

    bool writeDatagram(const std::string& host, int port, const std::vector<unsigned char>& payload) {
        const auto destination = address(host, port);
        if (!datagram || destination.empty() || payload.size() > 65535) { errno = EMSGSIZE; return false; }
        auto packet = destination;
        packet.push_back(static_cast<unsigned char>(payload.size() >> 8));
        packet.push_back(static_cast<unsigned char>(payload.size()));
        packet.insert(packet.end(), {'\r', '\n'});
        packet.insert(packet.end(), payload.begin(), payload.end());
        return write(packet.data(), packet.size());
    }
    // 0: incomplete, -1: invalid, 1: complete. Inspect without consuming partial packets.
    int inspectDatagram(size_t& headerSize, size_t& packetSize) const {
        if (datagramInput.empty()) return 0;
        const unsigned char kind = datagramInput[0];
        size_t addressSize = kind == 1 ? 4 : kind == 4 ? 16 : 0, offset = 1;
        if (kind == 3) {
            if (datagramInput.size() < 2) return 0;
            addressSize = datagramInput[1]; offset = 2;
            if (addressSize == 0) return -1;
        } else if (addressSize == 0) return -1;
        headerSize = offset + addressSize + 2;
        if (datagramInput.size() < headerSize) return 0;
        if ((kind == 3 && std::find(datagramInput.begin() + offset, datagramInput.begin() + offset + addressSize, 0) != datagramInput.begin() + offset + addressSize) ||
            (datagramInput[headerSize - 2] == 0 && datagramInput[headerSize - 1] == 0)) return -1;
        if (datagramInput.size() < headerSize + 4) return 0;
        if (datagramInput[headerSize + 2] != '\r' || datagramInput[headerSize + 3] != '\n') return -1;
        const size_t length = (static_cast<size_t>(datagramInput[headerSize]) << 8) | datagramInput[headerSize + 1];
        packetSize = headerSize + 4 + length;
        return datagramInput.size() >= packetSize ? 1 : 0;
    }
    bool readDatagram(std::vector<unsigned char>& output, bool nonblocking = false) {
        output.clear(); errno = 0;
        if (!datagram) { errno = EPROTO; return false; }
        for (;;) {
            size_t addressSize = 0, packetSize = 0;
            const int status = inspectDatagram(addressSize, packetSize);
            if (status < 0) { errno = EPROTO; return false; }
            if (status > 0) {
                const bool oversize = packetSize - 4 > 65507 - 3;
                if (!oversize) {
                    output.assign(datagramInput.begin(), datagramInput.begin() + addressSize);
                    output.insert(output.end(), datagramInput.begin() + addressSize + 4, datagramInput.begin() + packetSize);
                }
                datagramInput.erase(datagramInput.begin(), datagramInput.begin() + packetSize);
                if (oversize) { errno = EMSGSIZE; return false; }
                return true;
            }
            std::vector<unsigned char> chunk;
            if (!read(chunk, nonblocking)) {
                if (errno == 0 && !datagramInput.empty()) errno = EPROTO;
                return false;
            }
            datagramInput.insert(datagramInput.end(), chunk.begin(), chunk.end());
        }
    }
};

bool trojanCryptoSelfTest()
{
    const auto expected = decodeHex("64363364633931396532303164376263346338323536333064326366323566646339336434623266306434363730366432393033386430310d0a01030c6578616d706c652e7465737401bb0d0a");
    return digestBytes("SHA224", {'a','b','c'}) == decodeHex("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7") &&
        TrojanSession::header("password", "example.test", 443, false) == expected &&
        TrojanSession::address(std::string(256, 'x'), 443).empty() && TrojanSession::address("", 443).empty() &&
        TrojanSession::address("valid.test", 0).empty();
}
