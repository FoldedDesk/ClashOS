// Shared VMess/Trojan byte transport: TCP, verified TLS and RFC 6455 WebSocket.
#include "third_party/ca_bundle/trust_bundle.inc"

struct TlsChannel {
    int fd;
    bool enabled = false;
    bool cleanEof = false;
    bool nonblockingRead = false;
    std::function<ssize_t(unsigned char*, size_t)> readTransport;
    std::function<ssize_t(const unsigned char*, size_t)> writeTransport;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_x509_crt localRoots;
    std::vector<std::string> alpnNames;
    std::vector<const char*> alpnPointers;
    explicit TlsChannel(int socket) : fd(socket) {
        mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&config); mbedtls_x509_crt_init(&localRoots);
    }
    ~TlsChannel() { mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&config); mbedtls_x509_crt_free(&localRoots); }
    TlsChannel(const TlsChannel&) = delete;
    TlsChannel& operator=(const TlsChannel&) = delete;
    static int rng(void*, unsigned char* target, size_t size) {
        std::vector<unsigned char> bytes(size);
        if (!randomBytes(bytes)) return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        std::copy(bytes.begin(), bytes.end(), target); return 0;
    }
    static int writeBio(void* context, const unsigned char* bytes, size_t size) {
        auto* channel = static_cast<TlsChannel*>(context);
        if (!prepareSocketIo(channel->fd)) return MBEDTLS_ERR_SSL_TIMEOUT;
        if (channel->writeTransport) {
            const ssize_t result=channel->writeTransport(bytes,size);
            return result>=0 ? static_cast<int>(result) : MBEDTLS_ERR_NET_SEND_FAILED;
        }
        ssize_t result;
#ifdef MSG_NOSIGNAL
        do { result = send(channel->fd, bytes, size, MSG_NOSIGNAL); } while (result < 0 && errno == EINTR);
#else
        do { result = send(channel->fd, bytes, size, 0); } while (result < 0 && errno == EINTR);
#endif
        return result >= 0 ? static_cast<int>(result) : MBEDTLS_ERR_NET_SEND_FAILED;
    }
    static int readBio(void* context, unsigned char* bytes, size_t size) {
        auto* channel = static_cast<TlsChannel*>(context);
        if (!prepareSocketIo(channel->fd)) return MBEDTLS_ERR_SSL_TIMEOUT;
        if (channel->readTransport) {
            const ssize_t result=channel->readTransport(bytes,size);
            return result>=0 ? static_cast<int>(result) : (errno==ETIMEDOUT ? MBEDTLS_ERR_SSL_TIMEOUT : MBEDTLS_ERR_NET_RECV_FAILED);
        }
        ssize_t result;
        do { result = recv(channel->fd, bytes, size, channel->nonblockingRead ? MSG_DONTWAIT : 0); } while (result < 0 && errno == EINTR);
        if (result < 0) return errno == EAGAIN || errno == EWOULDBLOCK ?
            (channel->nonblockingRead ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_SSL_TIMEOUT) : MBEDTLS_ERR_NET_RECV_FAILED;
        return static_cast<int>(result);
    }
    bool start(const std::string& host, bool skipVerify, std::string& error, const char* trustOverride = nullptr,
        const std::vector<std::string>& protocols = {}) {
        struct RootStore {
            mbedtls_x509_crt roots;
            int status;
            RootStore() {
                mbedtls_x509_crt_init(&roots);
                status = psa_crypto_init() == PSA_SUCCESS ?
                    mbedtls_x509_crt_parse(&roots, reinterpret_cast<const unsigned char*>(CLAHSOS_CA_BUNDLE), sizeof(CLAHSOS_CA_BUNDLE)) : -1;
            }
            ~RootStore() { mbedtls_x509_crt_free(&roots); }
        };
        static RootStore store;
        mbedtls_x509_crt* roots = &store.roots;
        if (store.status < 0) { error = "Cannot initialize TLS trust store"; return false; }
        if (trustOverride != nullptr) {
            if (mbedtls_x509_crt_parse(&localRoots, reinterpret_cast<const unsigned char*>(trustOverride), std::strlen(trustOverride) + 1) != 0) {
                error = "Cannot read TLS CA certificate"; return false;
            }
            roots = &localRoots;
        }
        int result = mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
        if (result != 0) { error = "Cannot initialize TLS client"; return false; }
        mbedtls_ssl_conf_authmode(&config, skipVerify ? MBEDTLS_SSL_VERIFY_NONE : MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&config, roots, nullptr);
        mbedtls_ssl_conf_rng(&config, rng, nullptr);
        alpnNames = protocols.empty() ? std::vector<std::string>{"http/1.1"} : protocols;
        alpnPointers.clear();
        for (const auto& name : alpnNames) alpnPointers.push_back(name.c_str());
        alpnPointers.push_back(nullptr);
        // SSL retains both the list and its strings for the whole connection lifetime.
        if ((result = mbedtls_ssl_conf_alpn_protocols(&config, alpnPointers.data())) != 0 ||
            (result = mbedtls_ssl_setup(&ssl, &config)) != 0 ||
            (result = mbedtls_ssl_set_hostname(&ssl, host.c_str())) != 0) {
            error = "Cannot configure TLS hostname"; return false;
        }
        mbedtls_ssl_set_bio(&ssl, this, writeBio, readBio, nullptr);
        do { result = mbedtls_ssl_handshake(&ssl); }
        while (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE);
        if (result != 0 || (!skipVerify && mbedtls_ssl_get_verify_result(&ssl) != 0)) {
            error = "TLS handshake or certificate verification failed (" + std::to_string(result) + ")";
            errno = EPROTO; return false;
        }
        enabled = true; return true;
    }
    ssize_t readBytes(unsigned char* output, size_t size) {
        if (!prepareSocketIo(fd)) return -1;
        if (!enabled) {
            ssize_t result;
            do { result = recv(fd, output, size, nonblockingRead ? MSG_DONTWAIT : 0); } while (result < 0 && errno == EINTR);
            return result;
        }
        int result;
        do {
            result = mbedtls_ssl_read(&ssl, output, size);
            if (nonblockingRead && (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE)) { errno = EAGAIN; return -1; }
        } while (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE || result == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET);
        if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) { cleanEof=true;return 0; }
        if (result < 0) { errno = result == MBEDTLS_ERR_SSL_TIMEOUT ? ETIMEDOUT : EPROTO; return -1; }
        return result;
    }
    bool writeBytes(const unsigned char* data, size_t size) {
        if (!enabled) return sendAll(fd, reinterpret_cast<const char*>(data), size);
        while (size > 0) {
            const int result = mbedtls_ssl_write(&ssl, data, std::min<size_t>(size, 16384));
            if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            if (result <= 0) { errno = EPROTO; return false; }
            data += result; size -= static_cast<size_t>(result);
        }
        return true;
    }
    bool pending() const { return enabled && mbedtls_ssl_check_pending(&ssl) != 0; }
    ssize_t readAvailable(unsigned char* output, size_t size) {
        nonblockingRead = true;
        const ssize_t count = readBytes(output, size);
        nonblockingRead = false;
        return count;
    }
};

std::string vmBase64(const std::vector<unsigned char>& data)
{
    std::vector<unsigned char> encoded((data.size() + 2) / 3 * 4 + 1);
    size_t length = 0;
    if (mbedtls_base64_encode(encoded.data(), encoded.size(), &length, data.data(), data.size()) != 0) return {};
    return {encoded.begin(), encoded.begin() + length};
}

struct VmessTransport {
    TlsChannel channel;
    bool websocket = false, fragmented = false;
    size_t messageSize = 0, readOffset = 0;
    std::vector<unsigned char> buffered;
    std::vector<unsigned char> frameInput;
    explicit VmessTransport(int fd) : channel(fd) {}
    bool rawExact(unsigned char* target, size_t size) {
        while (size > 0) {
            const ssize_t count = channel.readBytes(target, size);
            if (count <= 0) { if (count == 0) errno = 0; return false; }
            target += count; size -= static_cast<size_t>(count);
        }
        return true;
    }
    bool frame(unsigned char opcode, const unsigned char* data, size_t size) {
        std::vector<unsigned char> mask(4);
        if (!randomBytes(mask) || size > 8 * 1024 * 1024) return false;
        std::vector<unsigned char> packet{static_cast<unsigned char>(0x80 | opcode)};
        if (size < 126) packet.push_back(static_cast<unsigned char>(0x80 | size));
        else if (size <= 65535) { packet.push_back(0xfe); packet.push_back(size >> 8); packet.push_back(size); }
        else { packet.push_back(0xff); for (int i = 7; i >= 0; --i) packet.push_back(static_cast<unsigned char>(static_cast<uint64_t>(size) >> (i * 8))); }
        packet.insert(packet.end(), mask.begin(), mask.end());
        for (size_t i = 0; i < size; ++i) packet.push_back(data[i] ^ mask[i % 4]);
        return channel.writeBytes(packet.data(), packet.size());
    }
    bool startWebSocket(const ProxyNode& node, std::string& error) {
        std::vector<unsigned char> nonce(16);
        if (!randomBytes(nonce)) { error = "WebSocket random source failed"; return false; }
        const std::string key = vmBase64(nonce);
        std::string host = node.server.find(':') == std::string::npos ? node.server : "[" + node.server + "]";
        host += ":" + std::to_string(node.port);
        for (const auto& header : node.wsHeaders) if (lower(header.first) == "host") host = header.second;
        std::string request = "GET " + node.wsPath + " HTTP/1.1\r\nHost: " + host +
            "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n";
        for (const auto& header : node.wsHeaders) {
            const std::string name = lower(header.first);
            if (name != "host" && name != "upgrade" && name != "connection" && name.rfind("sec-websocket-", 0) != 0)
                request += header.first + ": " + header.second + "\r\n";
        }
        request += "\r\n";
        if (!channel.writeBytes(reinterpret_cast<const unsigned char*>(request.data()), request.size())) return false;
        std::string response;
        unsigned char byte;
        while (response.size() < 16384 && response.find("\r\n\r\n") == std::string::npos) {
            if (!rawExact(&byte, 1)) { error = "WebSocket upgrade was interrupted"; return false; }
            response += static_cast<char>(byte);
        }
        std::istringstream input(response);
        std::string version; int status = 0;
        input >> version >> status;
        std::string line; std::getline(input, line);
        std::map<std::string, std::string> headers;
        while (std::getline(input, line) && line != "\r") {
            const size_t colon = line.find(':');
            if (colon != std::string::npos) {
                const std::string name = lower(trim(line.substr(0, colon)));
                const std::string value = trim(line.substr(colon + 1));
                if (headers.count(name)) headers[name] += "," + value; else headers[name] = value;
            }
        }
        auto containsToken = [](const std::string& list, const std::string& token) {
            std::istringstream stream(lower(list)); std::string value;
            while (std::getline(stream, value, ',')) if (trim(value) == token) return true;
            return false;
        };
        const std::string accept = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        if (version != "HTTP/1.1" || status != 101 || response.find("\r\n\r\n") == std::string::npos ||
            !containsToken(headers["upgrade"], "websocket") || !containsToken(headers["connection"], "upgrade") ||
            headers["sec-websocket-accept"] != vmBase64(sha1({accept.begin(), accept.end()})) ||
            !headers["sec-websocket-extensions"].empty() || !headers["sec-websocket-protocol"].empty()) {
            error = "Invalid WebSocket upgrade response"; errno = EPROTO; return false;
        }
        websocket = true; return true;
    }
    bool write(const std::vector<unsigned char>& data) {
        return websocket ? frame(2, data.data(), data.size()) : channel.writeBytes(data.data(), data.size());
    }
    bool nextFrame() {
        for (int attempts = 0; attempts < 64; ++attempts) {
            unsigned char header[2];
            if (!rawExact(header, 2)) return false;
            const unsigned char opcode = header[0] & 15;
            const bool final = (header[0] & 0x80) != 0;
            uint64_t length = header[1] & 0x7f;
            if ((header[0] & 0x70) || (header[1] & 0x80)) { errno = EPROTO; return false; }
            if (length >= 126) {
                unsigned char bytes[8]; const size_t count = length == 126 ? 2 : 8;
                if (!rawExact(bytes, count)) return false;
                length = 0; for (size_t i = 0; i < count; ++i) length = (length << 8) | bytes[i];
                if ((count == 2 && length < 126) || (count == 8 && length <= 65535)) { errno = EPROTO; return false; }
            }
            if (length > 8 * 1024 * 1024 || ((opcode & 8) && (!final || length > 125))) { errno = EPROTO; return false; }
            std::vector<unsigned char> payload(static_cast<size_t>(length));
            if (!rawExact(payload.data(), payload.size())) return false;
            if (opcode == 8) {
                frame(8, payload.data(), payload.size()); errno = 0; return false;
            }
            if (opcode == 9) { if (!frame(10, payload.data(), payload.size())) return false; continue; }
            if (opcode == 10) continue;
            if ((opcode != 0 && opcode != 2) || (opcode == 0 && !fragmented) || (opcode == 2 && fragmented)) { errno = EPROTO; return false; }
            messageSize = opcode == 2 ? payload.size() : messageSize + payload.size();
            if (messageSize > 8 * 1024 * 1024) { errno = EPROTO; return false; }
            fragmented = !final;
            buffered = std::move(payload); readOffset = 0;
            if (!buffered.empty()) return true;
        }
        errno = EPROTO; return false;
    }
    bool exact(unsigned char* output, size_t size) {
        if (!websocket) return rawExact(output, size);
        while (size > 0) {
            if (readOffset == buffered.size() && !nextFrame()) return false;
            const size_t count = std::min(size, buffered.size() - readOffset);
            std::copy_n(buffered.data() + readOffset, count, output);
            readOffset += count; output += count; size -= count;
        }
        return true;
    }
    bool readSome(std::vector<unsigned char>& output) {
        output.clear();
        if (!websocket) {
            output.resize(16384); const ssize_t count = channel.readBytes(output.data(), output.size());
            if (count <= 0) { if (count == 0) errno = 0; output.clear(); return false; }
            output.resize(static_cast<size_t>(count)); return true;
        }
        if (readOffset == buffered.size() && !nextFrame()) return false;
        const size_t count = std::min<size_t>(16384, buffered.size() - readOffset);
        output.assign(buffered.begin() + readOffset, buffered.begin() + readOffset + count); readOffset += count; return true;
    }
    bool bufferedFrameReady() const {
        if (frameInput.size() < 2) return false;
        uint64_t length = frameInput[1] & 127;
        size_t header = 2;
        if ((frameInput[0] & 0x70) || (frameInput[1] & 0x80)) return true;
        if (length >= 126) {
            const size_t count = length == 126 ? 2 : 8;
            if (frameInput.size() < 2 + count) return false;
            length = 0; for (size_t i = 0; i < count; ++i) length = (length << 8) | frameInput[2 + i];
            if ((count == 2 && length < 126) || (count == 8 && length <= 65535)) return true;
            header += count;
        }
        return length > 8 * 1024 * 1024 || length <= frameInput.size() - header;
    }
    bool tryReadSome(std::vector<unsigned char>& output) {
        output.clear(); errno = 0;
        if (!websocket) {
            output.resize(16384); const ssize_t count = channel.readAvailable(output.data(), output.size());
            if (count <= 0) { if (count == 0) errno = 0; output.clear(); return false; }
            output.resize(static_cast<size_t>(count)); return true;
        }
        if (readOffset < buffered.size()) {
            const size_t count = std::min<size_t>(16384, buffered.size() - readOffset);
            output.assign(buffered.begin() + readOffset, buffered.begin() + readOffset + count); readOffset += count;
            return true;
        }
        for (int controlFrames = 0; controlFrames < 64;) {
            if (!bufferedFrameReady()) {
                unsigned char bytes[16384]; const ssize_t count = channel.readAvailable(bytes, sizeof(bytes));
                if (count <= 0) { if (count == 0) errno = frameInput.empty() ? 0 : EPROTO; return false; }
                frameInput.insert(frameInput.end(), bytes, bytes + count);
                continue;
            }
            const unsigned char opcode = frameInput[0] & 15;
            const bool final = (frameInput[0] & 0x80) != 0;
            uint64_t length = frameInput[1] & 127; size_t header = 2;
            if ((frameInput[0] & 0x70) || (frameInput[1] & 0x80)) { errno = EPROTO; return false; }
            if (length >= 126) {
                const size_t count = length == 126 ? 2 : 8; header += count;
                length = 0; for (size_t i=0; i<count; ++i) length = (length << 8) | frameInput[2 + i];
                if ((count == 2 && length < 126) || (count == 8 && length <= 65535)) { errno=EPROTO;return false; }
            }
            if (length > 8 * 1024 * 1024 || ((opcode & 8) && (!final || length > 125))) { errno = EPROTO; return false; }
            std::vector<unsigned char> payload(frameInput.begin() + header, frameInput.begin() + header + length);
            frameInput.erase(frameInput.begin(), frameInput.begin() + header + length);
            if (opcode == 8) { frame(8, payload.data(), payload.size()); errno = 0; return false; }
            if (opcode == 9) { if (!frame(10, payload.data(), payload.size())) return false; ++controlFrames; continue; }
            if (opcode == 10) { ++controlFrames; continue; }
            if ((opcode != 0 && opcode != 2) || (opcode == 0 && !fragmented) || (opcode == 2 && fragmented)) { errno = EPROTO; return false; }
            messageSize = opcode == 2 ? payload.size() : messageSize + payload.size();
            if (messageSize > 8 * 1024 * 1024) { errno = EPROTO; return false; }
            fragmented = !final; buffered = std::move(payload); readOffset = 0;
            if (buffered.empty()) { ++controlFrames; continue; }
            const size_t count = std::min<size_t>(16384, buffered.size());
            output.assign(buffered.begin(), buffered.begin() + count); readOffset = count; return true;
        }
        errno = EPROTO; return false;
    }
    bool closeWrite() {
        if (websocket) return frame(8, nullptr, 0);
        if (channel.enabled) return mbedtls_ssl_close_notify(&channel.ssl) == 0;
        return shutdown(channel.fd, SHUT_WR) == 0;
    }
    bool pending() const { return readOffset < buffered.size() || bufferedFrameReady() || channel.pending(); }
};
