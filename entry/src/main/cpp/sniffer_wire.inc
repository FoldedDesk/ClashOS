// Bounded, passive parsers. No application data is decrypted except the public
// QUIC Initial protection defined by RFC 9001/9369; TLS remains end-to-end.
constexpr size_t SNIFF_LIMIT = 65536;
enum class SniffStatus { No, Need, Found };
struct SniffRead {
    SniffStatus status = SniffStatus::No;
    size_t wanted = 0;
    std::string host;
};
SniffRead sniffNeed(size_t count) { return count <= SNIFF_LIMIT ? SniffRead{SniffStatus::Need, count, ""} : SniffRead{}; }

std::string sniffValidDomain(std::string host)
{
    host = lower(host); if (!host.empty() && host.back() == '.') host.pop_back();
    if (host.empty() || host.size() > 253) return "";
    int family = 0; std::array<unsigned char, 16> ip{};
    if (ruleIpAddress(host, family, ip)) return "";
    size_t start = 0;
    while (start < host.size()) {
        const size_t end = host.find('.', start), stop = end == std::string::npos ? host.size() : end;
        if (stop == start || stop - start > 63 || host[start] == '-' || host[stop - 1] == '-') return "";
        for (size_t i = start; i < stop; ++i) if (!((host[i] >= 'a' && host[i] <= 'z') || (host[i] >= '0' && host[i] <= '9') || host[i] == '-' || host[i] == '_')) return "";
        start = stop + 1;
    }
    return host;
}

SniffRead sniffHttp(std::string_view data)
{
    if (data.empty()) return sniffNeed(1);
    if (!((data[0] >= 'A' && data[0] <= 'Z') || (data[0] >= 'a' && data[0] <= 'z'))) return {};
    const size_t first = data.find("\r\n");
    if (first == std::string_view::npos) return data.size() < 8192 ? sniffNeed(data.size() + 1) : SniffRead{};
    std::istringstream request(std::string(data.substr(0, first))); std::string method, target, version, extra;
    if (!(request >> method >> target >> version) || (request >> extra) || (version != "HTTP/1.1" && version != "HTTP/1.0") || method.size() > 32) return {};
    const size_t end = data.find("\r\n\r\n");
    if (end == std::string_view::npos) return sniffNeed(data.size() + 1);
    std::string host; unsigned hosts = 0;
    for (size_t cursor = first + 2; cursor < end;) {
        const size_t stop = data.find("\r\n", cursor);
        if (stop == std::string_view::npos || stop > end || data[cursor] == ' ' || data[cursor] == '\t') return {};
        const auto line = data.substr(cursor, stop - cursor); const auto colon = line.find(':');
        if (colon == std::string_view::npos) return {};
        if (lower(trim(std::string(line.substr(0, colon)))) == "host") {
            int ignored = 0; std::string authority;
            if (++hosts > 1 || !splitHostPort(trim(std::string(line.substr(colon + 1))), authority, ignored, 80)) return {};
            host = sniffValidDomain(authority);
        }
        cursor = stop + 2;
    }
    return hosts == 1 && !host.empty() ? SniffRead{SniffStatus::Found, 0, host} : SniffRead{};
}

uint16_t sniff16(std::string_view bytes, size_t at)
{
    return static_cast<unsigned char>(bytes[at]) * 256u + static_cast<unsigned char>(bytes[at + 1]);
}

SniffRead sniffClientHello(std::string_view bytes)
{
    if (bytes.empty()) return sniffNeed(4);
    if (static_cast<unsigned char>(bytes[0]) != 1) return {};
    if (bytes.size() < 4) return sniffNeed(4);
    const size_t length = (static_cast<unsigned char>(bytes[1]) << 16) | (static_cast<unsigned char>(bytes[2]) << 8) | static_cast<unsigned char>(bytes[3]);
    if (length < 41 || length > SNIFF_LIMIT - 4) return {};
    const size_t end = length + 4;
    if (bytes.size() < end) return sniffNeed(end);
    bytes = bytes.substr(0, end);
    if (static_cast<unsigned char>(bytes[4]) != 3) return {};
    size_t cursor = 38;
    const size_t session = static_cast<unsigned char>(bytes[cursor++]);
    if (session > 32 || session > end - cursor) return {};
    cursor += session;
    if (end - cursor < 2) return {};
    const size_t ciphers = sniff16(bytes, cursor); cursor += 2;
    if (ciphers < 2 || ciphers % 2 || ciphers > end - cursor) return {};
    cursor += ciphers;
    if (cursor == end) return {};
    const size_t compression = static_cast<unsigned char>(bytes[cursor++]);
    if (compression == 0 || compression > end - cursor) return {};
    cursor += compression;
    if (end - cursor < 2) return {};
    const size_t extensions = sniff16(bytes, cursor); cursor += 2;
    if (extensions != end - cursor) return {};
    std::set<uint16_t> seen; std::string host;
    while (cursor < end) {
        if (end - cursor < 4) return {};
        const auto type = sniff16(bytes, cursor); const size_t size = sniff16(bytes, cursor + 2); cursor += 4;
        if (!seen.insert(type).second || size > end - cursor) return {};
        if (type == 0) {
            if (size < 5 || sniff16(bytes, cursor) != size - 2) return {};
            const size_t stop = cursor + size; size_t item = cursor + 2; unsigned names = 0;
            while (item < stop) {
                if (stop - item < 3) return {};
                const unsigned char kind = bytes[item++]; const size_t count = sniff16(bytes, item); item += 2;
                if (count == 0 || count > stop - item) return {};
                if (kind == 0) { if (++names > 1) return {}; host = sniffValidDomain(std::string(bytes.substr(item, count))); }
                item += count;
            }
        }
        cursor += size;
    }
    return host.empty() ? SniffRead{} : SniffRead{SniffStatus::Found, 0, host};
}

SniffRead sniffTls(std::string_view bytes)
{
    std::string handshake; size_t cursor = 0;
    while (cursor < SNIFF_LIMIT) {
        if (bytes.size() <= cursor) return sniffNeed(cursor + 1);
        if (static_cast<unsigned char>(bytes[cursor]) != 22) return {};
        if (bytes.size() - cursor < 5) return sniffNeed(cursor + 5);
        if (static_cast<unsigned char>(bytes[cursor + 1]) != 3 || static_cast<unsigned char>(bytes[cursor + 2]) > 4) return {};
        const size_t count = sniff16(bytes, cursor + 3);
        if (count == 0 || count > 18432 || count > SNIFF_LIMIT - cursor - 5) return {};
        if (bytes.size() - cursor - 5 < count) return sniffNeed(cursor + 5 + count);
        handshake.append(bytes.substr(cursor + 5, count)); cursor += 5 + count;
        const auto result = sniffClientHello(handshake);
        if (result.status != SniffStatus::Need) return result;
    }
    return {};
}

bool sniffVarint(std::string_view input, size_t& at, uint64_t& value)
{
    if (at >= input.size()) return false;
    const size_t count = size_t(1) << (static_cast<unsigned char>(input[at]) >> 6);
    if (count > input.size() - at) return false;
    value = static_cast<unsigned char>(input[at++]) & 63;
    for (size_t i = 1; i < count; ++i) value = (value << 8) | static_cast<unsigned char>(input[at++]);
    return true;
}

std::string sniffHmac(const std::string& key, const std::string& input)
{
    std::string output(32, '\0'); const auto* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md || mbedtls_md_hmac(md, reinterpret_cast<const unsigned char*>(key.data()), key.size(),
        reinterpret_cast<const unsigned char*>(input.data()), input.size(), reinterpret_cast<unsigned char*>(output.data())) != 0) return "";
    return output;
}

std::string sniffExpand(const std::string& key, const std::string& label, size_t count)
{
    const auto name = "tls13 " + label;
    std::string info; info += static_cast<char>(count >> 8); info += static_cast<char>(count); info += static_cast<char>(name.size()); info += name; info += '\0'; info += '\1';
    const auto result = sniffHmac(key, info); return result.size() >= count ? result.substr(0, count) : "";
}

struct QuicSniffState {
    std::string dcid;
    uint32_t version = 0;
    uint64_t largest = 0;
    bool havePacket = false;
    std::vector<unsigned char> bytes, filled;
    size_t contiguous = 0;
};

SniffRead sniffQuic(std::string_view packet, QuicSniffState& state)
{
    if (packet.size() < 7 || (static_cast<unsigned char>(packet[0]) & 0xc0) != 0xc0) return {};
    const uint32_t version = (uint32_t(sniff16(packet, 1)) << 16) | sniff16(packet, 3);
    const bool v2 = version == 0x6b3343cf;
    if ((!v2 && version != 1) || (static_cast<unsigned char>(packet[0]) & 0x30) != (v2 ? 0x10 : 0)) return {};
    size_t at = 5; const size_t dcidSize = static_cast<unsigned char>(packet[at++]);
    if (dcidSize == 0 || dcidSize > 20 || dcidSize >= packet.size() - at) return {};
    const std::string dcid(packet.substr(at, dcidSize)); at += dcidSize;
    const size_t scidSize = static_cast<unsigned char>(packet[at++]);
    if (scidSize > 20 || scidSize > packet.size() - at) return {};
    at += scidSize; uint64_t token = 0, length = 0;
    if (!sniffVarint(packet, at, token) || token > packet.size() - at) return {};
    at += static_cast<size_t>(token);
    if (!sniffVarint(packet, at, length) || length > packet.size() - at || length < 20) return {};
    const size_t pnOffset = at, end = at + static_cast<size_t>(length);
    if (end - pnOffset < 20) return {};
    static const unsigned char saltV1[] = {0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a};
    static const unsigned char saltV2[] = {0x0d,0xed,0xe3,0xde,0xf7,0x00,0xa6,0xdb,0x81,0x93,0x81,0xbe,0x6e,0x26,0x9d,0xcb,0xf9,0xbd,0x2e,0xd9};
    const std::string salt(reinterpret_cast<const char*>(v2 ? saltV2 : saltV1), 20);
    const auto initial = sniffHmac(salt, dcid), client = sniffExpand(initial, "client in", 32);
    const auto key = sniffExpand(client, v2 ? "quicv2 key" : "quic key", 16), iv = sniffExpand(client, v2 ? "quicv2 iv" : "quic iv", 12), hp = sniffExpand(client, v2 ? "quicv2 hp" : "quic hp", 16);
    if (initial.size() != 32 || client.size() != 32 || key.size() != 16 || iv.size() != 12 || hp.size() != 16) return {};
    unsigned char mask[16]; mbedtls_aes_context aes; mbedtls_aes_init(&aes);
    const bool masked = mbedtls_aes_setkey_enc(&aes, reinterpret_cast<const unsigned char*>(hp.data()), 128) == 0 &&
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, reinterpret_cast<const unsigned char*>(packet.data() + pnOffset + 4), mask) == 0;
    mbedtls_aes_free(&aes); if (!masked) return {};
    const unsigned char first = static_cast<unsigned char>(packet[0]) ^ (mask[0] & 15);
    if (first & 0x0c) return {};
    const size_t pnSize = (first & 3) + 1;
    if (pnSize + 16 > length) return {};
    std::string aad(packet.substr(0, pnOffset + pnSize)); aad[0] = first;
    uint64_t truncated = 0;
    for (size_t i = 0; i < pnSize; ++i) { aad[pnOffset + i] = static_cast<unsigned char>(packet[pnOffset + i]) ^ mask[i + 1]; truncated = (truncated << 8) | static_cast<unsigned char>(aad[pnOffset + i]); }
    const bool same = state.version == version && state.dcid == dcid;
    const uint64_t expected = same && state.havePacket ? state.largest + 1 : 0, window = uint64_t(1) << (8 * pnSize), half = window / 2;
    uint64_t pn = (expected & ~(window - 1)) | truncated;
    if (pn + half <= expected && pn < (uint64_t(1) << 62) - window) pn += window;
    else if (pn > expected + half && pn >= window) pn -= window;
    std::string nonce = iv;
    for (size_t i = 0; i < 8; ++i) nonce[nonce.size() - i - 1] ^= static_cast<char>(pn >> (8 * i));
    const size_t plainSize = end - aad.size() - 16; std::string plain(plainSize, '\0');
    mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
    const bool decrypted = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, reinterpret_cast<const unsigned char*>(key.data()), 128) == 0 &&
        mbedtls_gcm_auth_decrypt(&gcm, plainSize, reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size(),
            reinterpret_cast<const unsigned char*>(aad.data()), aad.size(), reinterpret_cast<const unsigned char*>(packet.data() + end - 16), 16,
            reinterpret_cast<const unsigned char*>(packet.data() + aad.size()), reinterpret_cast<unsigned char*>(plain.data())) == 0;
    mbedtls_gcm_free(&gcm); if (!decrypted) return {};
    // Commit fragment state only after both AEAD and every frame boundary passed.
    std::vector<std::pair<size_t, std::string_view>> fragments; at = 0;
    while (at < plain.size()) {
        uint64_t type = 0; if (!sniffVarint(plain, at, type)) return {};
        if (type == 0 || type == 1) continue;
        if (type == 2 || type == 3) {
            uint64_t ignored = 0, ranges = 0;
            if (!sniffVarint(plain, at, ignored) || !sniffVarint(plain, at, ignored) || !sniffVarint(plain, at, ranges) || ranges > 256 || !sniffVarint(plain, at, ignored)) return {};
            for (uint64_t i = 0; i < ranges; ++i) if (!sniffVarint(plain, at, ignored) || !sniffVarint(plain, at, ignored)) return {};
            if (type == 3) for (int i = 0; i < 3; ++i) if (!sniffVarint(plain, at, ignored)) return {};
        } else if (type == 6) {
            uint64_t offset = 0, count = 0;
            if (!sniffVarint(plain, at, offset) || !sniffVarint(plain, at, count) || offset > SNIFF_LIMIT || count > SNIFF_LIMIT - offset || count > plain.size() - at || fragments.size() >= 256) return {};
            fragments.emplace_back(static_cast<size_t>(offset), std::string_view(plain).substr(at, static_cast<size_t>(count))); at += static_cast<size_t>(count);
        } else return {};
    }
    QuicSniffState next = same ? state : QuicSniffState{}; next.version = version; next.dcid = dcid;
    for (const auto& fragment : fragments) {
        const size_t end = fragment.first + fragment.second.size();
        if (next.bytes.size() < end) { next.bytes.resize(end); next.filled.resize(end); }
        for (size_t i = 0; i < fragment.second.size(); ++i) {
            const size_t target = fragment.first + i; const unsigned char byte = fragment.second[i];
            if (next.filled[target] && next.bytes[target] != byte) return {};
            next.bytes[target] = byte; next.filled[target] = 1;
        }
    }
    next.havePacket = true; next.largest = same ? std::max(state.largest, pn) : pn;
    while (next.contiguous < next.filled.size() && next.filled[next.contiguous]) ++next.contiguous;
    state = std::move(next);
    return sniffClientHello(state.contiguous == 0 ? std::string_view{} : std::string_view(reinterpret_cast<const char*>(state.bytes.data()), state.contiguous));
}

size_t sniffQuicInitialSize(std::string_view packet)
{
    if (packet.size() < 7 || (static_cast<unsigned char>(packet[0]) & 0xc0) != 0xc0) return 0;
    const auto version = (uint32_t(sniff16(packet, 1)) << 16) | sniff16(packet, 3);
    if ((version != 1 && version != 0x6b3343cf) || (static_cast<unsigned char>(packet[0]) & 0x30) != (version == 1 ? 0 : 0x10)) return 0;
    size_t at = 5; const size_t dcid = static_cast<unsigned char>(packet[at++]);
    if (dcid == 0 || dcid > 20 || dcid >= packet.size() - at) return 0;
    at += dcid; const size_t scid = static_cast<unsigned char>(packet[at++]);
    if (scid > 20 || scid > packet.size() - at) return 0;
    at += scid; uint64_t token = 0, length = 0;
    if (!sniffVarint(packet, at, token) || token > packet.size() - at) return 0;
    at += static_cast<size_t>(token);
    if (!sniffVarint(packet, at, length) || length < 20 || length > packet.size() - at) return 0;
    return at + static_cast<size_t>(length);
}

SniffRead sniffQuicDatagram(std::string_view packet, QuicSniffState& state)
{
    SniffRead result;
    for (unsigned count = 0; !packet.empty() && count < 32; ++count) {
        const auto length = sniffQuicInitialSize(packet);
        if (!length) return result;
        result = sniffQuic(packet.substr(0, length), state);
        if (result.status != SniffStatus::Need) return result;
        packet.remove_prefix(length);
    }
    return result;
}
