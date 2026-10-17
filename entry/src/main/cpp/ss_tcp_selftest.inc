// Public known-answer packets from tests/generate_ss_aead_vectors.py (Python
// cryptography/OpenSSL), independent of this reader. No user profile is read.
bool shadowsocksTcpSelfTest()
{
    const struct Vector { SsCipher method; const char* wire; } vectors[] = {
        {SsCipher::Aes128Gcm, "808182838485868788898a8b8c8d8e8f9b04a63766ee982ae8045ec55b3dc454158d0c9d8f865f32c2d98f65edec95e3b6f913d25ac77d0958a99d209976caa64112d82e720ba36816d09dd1c608a090f2649fb5613f795d9aa550842d7300886395ca653d44047daefa3c419061b9dc96c7f499169c7c5a22c0"},
        {SsCipher::Aes256Gcm, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fd9450bd0daf1afc0ed35294c89fce16c19a64d326472f19538eab999fdd8d63abb5f4599b008627cbfc5dad5b1aeb883aed37dd1dba187c231994ee448e920c08ead75be441c19b615a2e92b5e832eb90c612388f60916aeb080ba2e4830591f00527dd1c28dd36ab4a0"},
        {SsCipher::ChaCha20Poly1305, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f951ba30134877748290a44686ed3d117c88d5735a482df65d2f4c2ee1e653468bf2a9be4a86cf08d105e3a28057b95a269bea0dba50eec02cb32b24422e552c8124f240741cc42f6ce96883db86fd98c72fa24b67585e95da6fab76e8b80bfd81a9715820c228f7a7154"},
    };
    struct Pair {
        int fd[2] = {-1, -1};
        Pair() { if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0) for (int value : fd) socketTimeout(value, 100); }
        ~Pair() { for (int value : fd) if (value >= 0) close(value); }
        bool valid() const { return fd[0] >= 0 && fd[1] >= 0; }
    };
    const std::string first = "HTTP/1.1 204 No Content\r\n\r\n", second = "server data";
    for (const auto& vector : vectors) {
        const auto wire = decodeHex(vector.wire);
        const auto master = evpBytesToKey("pässword-测试", shadowsocksKeySize(vector.method));
        const size_t firstEnd = master.size() + 18 + first.size() + 16;
        Pair sockets; if (!sockets.valid()) return false;
        ShadowsocksReader reader(sockets.fd[0], vector.method, master); size_t records = 0;
        for (size_t offset = 0; offset < wire.size(); ++offset) {
            if (!sendAll(sockets.fd[1], reinterpret_cast<const char*>(wire.data() + offset), 1)) return false;
            std::vector<unsigned char> plain{1, 2, 3};
            const bool complete = reader.read(plain, true);
            if (offset + 1 == firstEnd || offset + 1 == wire.size()) {
                const std::string expected = records++ ? second : first;
                if (!complete || std::string(plain.begin(), plain.end()) != expected) return false;
            } else if (complete || !plain.empty() || errno != EAGAIN) return false;
            if (offset == 0) {
                char reply = 0;
                if (!sendAll(sockets.fd[0], "x", 1) || !readExact(sockets.fd[1], &reply, 1) || reply != 'x') return false;
            }
        }
        std::vector<unsigned char> plain{1};
        shutdown(sockets.fd[1], SHUT_WR);
        if (records != 2 || reader.read(plain, true) || !plain.empty() || errno != 0) return false;
        Pair truncated; if (!truncated.valid()) return false;
        ShadowsocksReader incomplete(truncated.fd[0], vector.method, master);
        if (!sendAll(truncated.fd[1], reinterpret_cast<const char*>(wire.data()), master.size() + 18)) return false;
        shutdown(truncated.fd[1], SHUT_WR);
        if (incomplete.read(plain, true) || !plain.empty() || errno != ECONNRESET) return false;
        Pair corrupted; if (!corrupted.valid()) return false;
        ShadowsocksReader rejected(corrupted.fd[0], vector.method, master);
        auto damaged = wire; damaged[firstEnd - 1] ^= 1;
        if (!sendAll(corrupted.fd[1], reinterpret_cast<const char*>(damaged.data()), firstEnd)) return false;
        if (rejected.read(plain, true) || !plain.empty() || errno != EBADMSG) return false;
    }
    return true;
}
