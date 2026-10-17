// VLESS version 0, standard TCP / length-prefixed UDP over TCP, TLS and WebSocket.
// Wire reference: XTLS/Xray-core proxy/vless/encoding/{encoding,addons}.go.
struct VlessSession {
    VmessTransport transport;
    VmBytes input;
    size_t offset = 0;
    bool responseReady = false, datagram = false, sentEof = false, failed = false;
    explicit VlessSession(int fd) : transport(fd) {}

    static bool validate(const ProxyNode& node, std::string& error) {
        if (!node.transportError.empty()) error = node.transportError;
        else if (vmUuid(node.uuid).size() != 16) error = "VLESS requires a valid 16-byte UUID";
        else if (node.network != "tcp" && node.network != "ws") error = "Unsupported VLESS transport: " + node.network;
        else if (node.network == "ws" && !node.alpn.empty() &&
            std::find(node.alpn.begin(), node.alpn.end(), "http/1.1") == node.alpn.end()) error = "VLESS WebSocket requires HTTP/1.1 ALPN";
        else return true;
        errno = EPROTONOSUPPORT; return false;
    }
    static VmBytes header(const std::string& uuid, const std::string& host, int port, bool udp) {
        const auto id = vmUuid(uuid);
        if (id.size() != 16 || host.empty() || host.find('\0') != std::string::npos || port < 1 || port > 65535) return {};
        VmBytes result{0}; vmAppend(result, id); result.push_back(0); result.push_back(udp ? 2 : 1);
        vmUint(result, port, 2);
        unsigned char address[16];
        if (inet_pton(AF_INET, host.c_str(), address) == 1) {
            result.push_back(1); result.insert(result.end(), address, address + 4);
        } else if (inet_pton(AF_INET6, host.c_str(), address) == 1) {
            result.push_back(3); result.insert(result.end(), address, address + 16);
        } else {
            if (host.size() > 255) return {};
            result.push_back(2); result.push_back(static_cast<unsigned char>(host.size()));
            result.insert(result.end(), host.begin(), host.end());
        }
        return result;
    }
    bool start(const ProxyNode& node, const std::string& host, int port, bool udp, std::string& error) {
        if (!validate(node, error)) return false;
        const auto request = header(node.uuid, host, port, udp);
        if (request.empty()) { error = "Invalid VLESS destination"; return false; }
        datagram = udp;
        const char* roots = nullptr;
#ifdef CLAHSOS_HOST_TEST
        roots = g_testVmessTrust;
#endif
        const auto protocols = node.network == "ws" ? std::vector<std::string>{"http/1.1"} : node.alpn;
        if (node.tls && !transport.channel.start(node.serverName.empty() ? node.server : node.serverName,
            node.skipCertVerify, error, roots, protocols)) return false;
        if (node.network == "ws" && !transport.startWebSocket(node, error)) return false;
        // Send immediately so server-first application protocols can receive a greeting.
        if (!transport.write(request)) { error = "Cannot write VLESS request header"; return false; }
        return true;
    }
    bool write(const unsigned char* data, size_t size) {
        if (sentEof || failed) { errno = EPIPE; return false; }
        if (size == 0) return true;
        return transport.write({data, data + size});
    }
    bool writeDatagram(const VmBytes& payload) {
        if (!datagram || payload.size() > 65535) { errno = EMSGSIZE; return false; }
        VmBytes packet; vmUint(packet, payload.size(), 2); vmAppend(packet, payload);
        return write(packet.data(), packet.size());
    }
    size_t available() const { return input.size() - offset; }
    bool fill(size_t needed, bool nonblocking) {
        while (available() < needed) {
            VmBytes part;
            const bool ok = nonblocking ? transport.tryReadSome(part) : transport.readSome(part);
            if (!ok) {
                if (errno == 0 && (!responseReady || available() != 0)) errno = EPROTO;
                if (errno != 0 && errno != EAGAIN && errno != EWOULDBLOCK) failed = true;
                return false;
            }
            if (offset) { input.erase(input.begin(), input.begin() + offset); offset = 0; }
            vmAppend(input, part);
        }
        return true;
    }
    // Bounded protobuf addon validation: no Vision flow was requested. Unknown fields
    // are skipped according to their wire type, never delivered as application data.
    static bool addons(const unsigned char* bytes, size_t size) {
        size_t pos = 0;
        auto varint = [&](uint64_t& value) {
            value = 0;
            for (unsigned int i = 0; i < 10 && pos < size; ++i) {
                const unsigned char byte = bytes[pos++];
                if (i == 9 && byte > 1) return false;
                value |= static_cast<uint64_t>(byte & 127) << (i * 7);
                if (!(byte & 128)) return true;
            }
            return false;
        };
        while (pos < size) {
            uint64_t tag = 0, length = 0;
            if (!varint(tag) || tag >> 3 == 0 || tag >> 3 > 0x1fffffff) return false;
            const auto kind = tag & 7;
            if ((tag >> 3) == 1 && kind != 2) return false;
            if (kind == 0) { if (!varint(length)) return false; }
            else if (kind == 1 || kind == 5) { if (size - pos < (kind == 1 ? 8 : 4)) return false; pos += kind == 1 ? 8 : 4; }
            else if (kind == 2) {
                if (!varint(length) || length > size - pos || ((tag >> 3) == 1 && length != 0)) return false;
                pos += static_cast<size_t>(length);
            } else return false;
        }
        return true;
    }
    bool responseHeader(bool nonblocking) {
        if (!fill(2, nonblocking)) return false;
        if (input[offset] != 0) { errno = EPROTO; failed = true; return false; }
        const size_t length = input[offset + 1];
        if (!fill(2 + length, nonblocking)) return false;
        if (!addons(input.data() + offset + 2, length)) { errno = EPROTO; failed = true; return false; }
        offset += 2 + length; responseReady = true; return true;
    }
    bool read(VmBytes& output, bool nonblocking = false) {
        output.clear(); errno = 0;
        if (failed) { errno = EPROTO; return false; }
        if (!responseReady && !responseHeader(nonblocking)) return false;
        if (!datagram) {
            if (!fill(1, nonblocking)) return false;
            const size_t size = std::min<size_t>(16384, available());
            output.assign(input.begin() + offset, input.begin() + offset + size); offset += size;
            return true;
        }
        if (!fill(2, nonblocking)) return false;
        const size_t size = (static_cast<size_t>(input[offset]) << 8) | input[offset + 1];
        if (!fill(2 + size, nonblocking)) return false;
        output.assign(input.begin() + offset + 2, input.begin() + offset + 2 + size); offset += size + 2;
        return true; // An empty UDP packet is not TCP EOF.
    }
    bool pending() const {
        if (failed) return false;
        size_t needed = 1;
        if (!responseReady) needed = available() < 2 ? 2 : 2 + input[offset + 1];
        else if (datagram) needed = available() < 2 ? 2 : 2 + (static_cast<size_t>(input[offset]) << 8) + input[offset + 1];
        return available() >= needed || transport.pending();
    }
    bool finish() {
        if (sentEof) return true;
        sentEof = true;
        return transport.websocket || transport.closeWrite();
    }
};

bool vlessProtocolSelfTest()
{
    const std::string uuid = "11111111-2222-4333-8444-555555555555";
    return VlessSession::header(uuid, "example.test", 443, false) ==
        decodeHex("0011111111222243338444555555555555000101bb020c6578616d706c652e74657374") &&
        VlessSession::header(uuid, "192.0.2.1", 53, true) ==
        decodeHex("00111111112222433384445555555555550002003501c0000201") &&
        VlessSession::header("invalid", "example.test", 443, false).empty() &&
        VlessSession::header(uuid, std::string(256, 'x'), 443, false).empty();
}
