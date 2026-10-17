// Incremental SIP004/SIP007 receive state. Read only the current record's
// remaining bytes so poll() stays authoritative for the following record.
// MSG_DONTWAIT affects this read, never the socket's concurrent write behavior.
struct ShadowsocksReader {
    enum class Stage { Salt, Length, Payload };
    int fd, failure = 0;
    SsCipher method;
    Stage stage = Stage::Salt;
    bool eof = false;
    size_t received = 0, payloadLength = 0;
    std::vector<unsigned char> master, key, nonce = std::vector<unsigned char>(12, 0), packet;

    ShadowsocksReader(int socket, SsCipher cipher, std::vector<unsigned char> masterKey)
        : fd(socket), method(cipher), master(std::move(masterKey)), packet(shadowsocksKeySize(cipher)) {}
    bool fail(int code) { failure = code ? code : EIO; errno = failure; return false; }
    void next(Stage value, size_t size) { stage = value; received = 0; packet.resize(size); }

    bool read(std::vector<unsigned char>& output, bool nonblocking)
    {
        output.clear(); errno = 0;
        if (failure) { errno = failure; return false; }
        if (eof) return false;
        if (method == SsCipher::Unsupported || master.size() != shadowsocksKeySize(method) || packet.empty()) return fail(EINVAL);
        unsigned emptyFrames = 0;
        for (;;) {
            if (stage == Stage::Length && received == 0 && !validShadowsocksNonce(nonce)) return fail(errno ? errno : EINVAL);
            while (received < packet.size()) {
                if (!prepareSocketIo(fd)) return fail(errno);
                const auto count = recv(fd, packet.data() + received, packet.size() - received, nonblocking ? MSG_DONTWAIT : 0);
                if (count < 0) {
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        if (nonblocking) { errno = EAGAIN; return false; }
                        return fail(ETIMEDOUT);
                    }
                    return fail(errno);
                }
                if (!count) {
                    if (received || stage == Stage::Payload) return fail(ECONNRESET);
                    eof = true; errno = 0; return false;
                }
                received += static_cast<size_t>(count);
            }
            if (stage == Stage::Salt) {
                key = hkdfSha1(packet, master, "ss-subkey", shadowsocksKeySize(method));
                if (key.size() != master.size()) return fail(EPROTO);
                next(Stage::Length, 18);
            } else if (stage == Stage::Length) {
                std::vector<unsigned char> encrypted(packet.begin(), packet.begin() + 2), tag(packet.begin() + 2, packet.end()), length;
                if (!shadowsocksAead(false, method, key, nonce, encrypted, length, tag) || length.size() != 2) return fail(EBADMSG);
                incrementNonce(nonce);
                payloadLength = (static_cast<size_t>(length[0]) << 8) | length[1];
                if (payloadLength > 0x3fff) return fail(EPROTO);
                next(Stage::Payload, payloadLength + 16);
            } else {
                std::vector<unsigned char> encrypted(packet.begin(), packet.begin() + payloadLength), tag(packet.begin() + payloadLength, packet.end());
                if (!shadowsocksAead(false, method, key, nonce, encrypted, output, tag) || output.size() != payloadLength) { output.clear(); return fail(EBADMSG); }
                incrementNonce(nonce); next(Stage::Length, 18);
                if (!output.empty()) { errno = 0; return true; }
                // Authenticated empty records consume nonces, not application
                // bytes. Yield after a bounded batch so clients can still send.
                if (nonblocking && ++emptyFrames >= 32) { errno = EAGAIN; return false; }
            }
        }
    }
};
