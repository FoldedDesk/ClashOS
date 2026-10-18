// VMess v1 client framing. Wire constants follow the V2Fly protocol specification.
using VmBytes = std::vector<unsigned char>;
using VmHash = std::function<VmBytes(const VmBytes&)>;
#ifdef CLAHSOS_HOST_TEST
const char* g_testVmessTrust = nullptr;
#endif
VmBytes vmBytes(const std::string& text) { return {text.begin(), text.end()}; }
VmBytes vmDigest(mbedtls_md_type_t type, const VmBytes& input) {
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(type);
    if (info == nullptr) return {};
    VmBytes output(mbedtls_md_get_size(info));
    return mbedtls_md(info, input.data(), input.size(), output.data()) == 0 ? output : VmBytes{};
}
VmBytes vmHmac(const VmHash& hash, VmBytes key, const VmBytes& message) {
    if (key.size() > 64) key = hash(key);
    key.resize(64, 0); VmBytes inner(64), outer(64);
    for (size_t i = 0; i < 64; ++i) { inner[i] = key[i] ^ 0x36; outer[i] = key[i] ^ 0x5c; }
    inner.insert(inner.end(), message.begin(), message.end());
    const VmBytes digest = hash(inner); outer.insert(outer.end(), digest.begin(), digest.end());
    return hash(outer);
}
VmBytes vmKdf(const VmBytes& key, std::vector<VmBytes> paths, size_t size = 32) {
    paths.insert(paths.begin(), vmBytes("VMess AEAD KDF"));
    VmHash hash = [](const VmBytes& input) { return vmDigest(MBEDTLS_MD_SHA256, input); };
    for (const VmBytes& path : paths) {
        const VmHash parent = hash;
        hash = [parent, path](const VmBytes& input) { return vmHmac(parent, path, input); };
    }
    VmBytes output = hash(key); if (output.size() < size) return {}; output.resize(size); return output;
}
VmBytes vmMd5(const VmBytes& input) { return vmDigest(MBEDTLS_MD_MD5, input); }
void vmAppend(VmBytes& destination, const VmBytes& source) { destination.insert(destination.end(), source.begin(), source.end()); }
void vmUint(VmBytes& output, uint64_t value, size_t bytes) {
    for (size_t i = bytes; i > 0; --i) output.push_back(static_cast<unsigned char>(value >> ((i - 1) * 8)));
}
uint32_t vmFnv(const VmBytes& bytes) {
    uint32_t result = 2166136261u;
    for (unsigned char byte : bytes) result = (result ^ byte) * 16777619u;
    return result;
}
uint32_t vmCrc32(const VmBytes& bytes) {
    uint32_t result = 0xffffffffu;
    for (unsigned char byte : bytes) {
        result ^= byte;
        for (int bit = 0; bit < 8; ++bit) result = (result >> 1) ^ (0xedb88320u & (0u - (result & 1u)));
    }
    return result ^ 0xffffffffu;
}
VmBytes vmUuid(const std::string& uuid) {
    std::string compact;
    for (char ch : uuid) if (ch != '-') compact += ch;
    if (compact.size() != 32 || !std::all_of(compact.begin(), compact.end(), [](unsigned char ch) { return std::isxdigit(ch); })) return {};
    return decodeHex(compact);
}
VmBytes vmCommandKey(VmBytes id) {
    vmAppend(id, vmBytes("c48619fe-8f02-49e0-b9e9-edf763e17e21")); return vmMd5(id);
}
VmBytes vmAlterId(VmBytes previous) {
    const VmBytes original = previous;
    vmAppend(previous, vmBytes("16167dc8-16b6-4e6d-b8bb-65dd68113a81"));
    for (;;) {
        VmBytes result = vmMd5(previous);
        if (result != original) return result;
        vmAppend(previous, vmBytes("533eff8a-4113-4b10-b5ce-0f5d76b98cd2"));
    }
}
bool vmCfb(bool encrypt, const VmBytes& key, VmBytes iv, const VmBytes& input, VmBytes& output) {
    if (key.size() != 16 || iv.size() != 16) return false;
    mbedtls_aes_context context; mbedtls_aes_init(&context);
    size_t offset = 0; output.resize(input.size());
    const bool ok = mbedtls_aes_setkey_enc(&context, key.data(), 128) == 0 &&
        mbedtls_aes_crypt_cfb128(&context, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
            input.size(), &offset, iv.data(), input.data(), output.data()) == 0;
    mbedtls_aes_free(&context); if (!ok) output.clear(); return ok;
}
// GCM/ChaCha functions accept and return ciphertext with its 16-byte tag appended.
bool vmAead(bool encrypt, const VmBytes& key, const VmBytes& nonce, const VmBytes& aad,
    const VmBytes& input, VmBytes& output, bool chacha = false) {
    output.clear();
    if (nonce.size() != 12 || (!encrypt && input.size() < 16) || (chacha ? key.size() != 32 : key.size() != 16)) return false;
    const size_t size = encrypt ? input.size() : input.size() - 16;
    output.resize(size + 16); int result;
    if (chacha) {
        mbedtls_chachapoly_context context; mbedtls_chachapoly_init(&context);
        result = mbedtls_chachapoly_setkey(&context, key.data());
        if (result == 0) result = encrypt ?
            mbedtls_chachapoly_encrypt_and_tag(&context, size, nonce.data(), aad.data(), aad.size(), input.data(), output.data(), output.data() + size) :
            mbedtls_chachapoly_auth_decrypt(&context, size, nonce.data(), aad.data(), aad.size(), input.data() + size, input.data(), output.data());
        mbedtls_chachapoly_free(&context);
    } else {
        mbedtls_gcm_context context; mbedtls_gcm_init(&context);
        result = mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, key.data(), 128);
        if (result == 0) result = encrypt ?
            mbedtls_gcm_crypt_and_tag(&context, MBEDTLS_GCM_ENCRYPT, size, nonce.data(), nonce.size(), aad.data(), aad.size(),
                input.data(), output.data(), 16, output.data() + size) :
            mbedtls_gcm_auth_decrypt(&context, size, nonce.data(), nonce.size(), aad.data(), aad.size(), input.data() + size, 16,
                input.data(), output.data());
        mbedtls_gcm_free(&context);
    }
    if (result != 0) { output.clear(); errno = EBADMSG; return false; }
    output.resize(encrypt ? size + 16 : size); return true;
}
struct VmessMask {
    sha3_ctx_t state{};
    void init(const VmBytes& iv) { shake128_init(&state); shake_update(&state, iv.data(), iv.size()); shake_xof(&state); }
    uint16_t next() { unsigned char bytes[2]; shake_out(&state, bytes, 2); return static_cast<uint16_t>((bytes[0] << 8) | bytes[1]); }
};
VmBytes vmBodyKey(const VmBytes& key, int security) {
    if (security != 4) return key;
    VmBytes result = vmMd5(key); vmAppend(result, vmMd5(result)); return result;
}
struct VmessSession {
    VmessTransport transport;
    VmBytes requestKey, requestIv, responseKey, responseIv;
    VmessMask sendMask, receiveMask;
    uint32_t sendCounter = 0, receiveCounter = 0;
    unsigned char responseAuth = 0;
    int security = 3;
    bool aead = true, responseReady = false, sentEof = false, receivedEof = false, raw = false;
    VmBytes receiveInput, responsePrefix;
    size_t receiveOffset=0, responseLength=65536, frameLength=65536, framePadding=0;
    explicit VmessSession(int fd) : transport(fd) {}
    bool makeHeader(const ProxyNode& node, const std::string& host, int port, bool udp, uint64_t timestamp,
        const VmBytes& random, VmBytes& wire, bool mux = false) {
        const VmBytes id = vmUuid(node.uuid);
        if (id.size() != 16 || random.size() != 64 || (!mux && (port < 1 || port > 65535))) return false;
        const std::string cipher = lower(node.cipher);
        if (cipher.empty() || cipher == "auto" || cipher == "aes-128-gcm") security = 3;
        else if (cipher == "chacha20-poly1305") security = 4;
        else if (cipher == "none" || cipher == "zero") { security = 5; raw = cipher == "zero" && (!udp || mux); }
        else return false;
        aead = node.alterId == 0;
        requestKey.assign(random.begin(), random.begin() + 16);
        requestIv.assign(random.begin() + 16, random.begin() + 32);
        responseAuth = random[32];
        responseKey = aead ? vmDigest(MBEDTLS_MD_SHA256, requestKey) : vmMd5(requestKey); responseKey.resize(16);
        responseIv = aead ? vmDigest(MBEDTLS_MD_SHA256, requestIv) : vmMd5(requestIv); responseIv.resize(16);
        sendMask.init(requestIv); receiveMask.init(responseIv);
        VmBytes command{1}; vmAppend(command, requestIv); vmAppend(command, requestKey);
        command.push_back(responseAuth); command.push_back(raw ? 0 : security == 5 ? 5 : 13);
        const unsigned char padding = random[33] & 15;
        command.push_back(static_cast<unsigned char>((padding << 4) | security));
        command.push_back(0); command.push_back(mux ? 3 : udp ? 2 : 1);
        if (!mux) {
        vmUint(command, port, 2);
        in_addr ipv4{}; in6_addr ipv6{};
        if (inet_pton(AF_INET, host.c_str(), &ipv4) == 1) {
            command.push_back(1); const auto* bytes = reinterpret_cast<const unsigned char*>(&ipv4); command.insert(command.end(), bytes, bytes + 4);
        } else if (inet_pton(AF_INET6, host.c_str(), &ipv6) == 1) {
            command.push_back(3); const auto* bytes = reinterpret_cast<const unsigned char*>(&ipv6); command.insert(command.end(), bytes, bytes + 16);
        } else {
            if (host.empty() || host.size() > 255 || host.find('\0') != std::string::npos) return false;
            command.push_back(2); command.push_back(host.size()); vmAppend(command, vmBytes(host));
        }
        }
        command.insert(command.end(), random.begin() + 49, random.begin() + 49 + padding);
        vmUint(command, vmFnv(command), 4);
        const VmBytes key = vmCommandKey(id); wire.clear();
        if (!aead) {
            VmBytes authId = id;
            const int choice = ((random[46] << 8) | random[47]) % node.alterId;
            for (int i = 0; i <= choice; ++i) authId = vmAlterId(authId);
            VmBytes time; vmUint(time, timestamp, 8);
            wire = vmHmac(vmMd5, authId, time);
            VmBytes repeated; for (int i = 0; i < 4; ++i) vmAppend(repeated, time);
            VmBytes encrypted; if (!vmCfb(true, key, vmMd5(repeated), command, encrypted)) return false;
            vmAppend(wire, encrypted); return true;
        }
        VmBytes auth; vmUint(auth, timestamp, 8); auth.insert(auth.end(), random.begin() + 34, random.begin() + 38);
        vmUint(auth, vmCrc32(auth), 4);
        VmBytes authKey = vmKdf(key, {vmBytes("AES Auth ID Encryption")}, 16);
        mbedtls_aes_context aes; mbedtls_aes_init(&aes); wire.resize(16);
        const bool valid = mbedtls_aes_setkey_enc(&aes, authKey.data(), 128) == 0 &&
            mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, auth.data(), wire.data()) == 0;
        mbedtls_aes_free(&aes); if (!valid) return false;
        const VmBytes encryptedAuth = wire;
        const VmBytes nonce(random.begin() + 38, random.begin() + 46);
        VmBytes length; vmUint(length, command.size(), 2); VmBytes encrypted;
        if (!vmAead(true, vmKdf(key, {vmBytes("VMess Header AEAD Key_Length"), encryptedAuth, nonce}, 16),
            vmKdf(key, {vmBytes("VMess Header AEAD Nonce_Length"), encryptedAuth, nonce}, 12), encryptedAuth, length, encrypted)) return false;
        vmAppend(wire, encrypted); vmAppend(wire, nonce);
        if (!vmAead(true, vmKdf(key, {vmBytes("VMess Header AEAD Key"), encryptedAuth, nonce}, 16),
            vmKdf(key, {vmBytes("VMess Header AEAD Nonce"), encryptedAuth, nonce}, 12), encryptedAuth, command, encrypted)) return false;
        vmAppend(wire, encrypted); return true;
    }
    bool start(const ProxyNode& node, const std::string& host, int port, bool udp, std::string& error, bool mux = false) {
        if (!node.transportError.empty()) { error = node.transportError; return false; }
        VmBytes random(64), header;
        if (!randomBytes(random)) { error = "VMess random source failed"; return false; }
        const uint64_t timestamp = static_cast<uint64_t>(std::time(nullptr));
        if (!makeHeader(node, host, port, udp, timestamp, random, header, mux)) { error = "Unsupported VMess cipher or invalid UUID/target"; return false; }
        if (node.network != "tcp" && node.network != "ws") { error = "Unsupported VMess transport: " + node.network; return false; }
        const char* roots = nullptr;
#ifdef CLAHSOS_HOST_TEST
        roots = g_testVmessTrust;
#endif
        if (node.tls && !transport.channel.start(node.serverName.empty() ? node.server : node.serverName, node.skipCertVerify, error, roots)) return false;
        if (node.network == "ws" && !transport.startWebSocket(node, error)) return false;
        // Validate before the handshake, then refresh the unsent authentication
        // header. Legacy servers can discard older timestamp keys on rotation.
        const uint64_t sendTimestamp = static_cast<uint64_t>(std::time(nullptr));
        if (sendTimestamp != timestamp && !makeHeader(node, host, port, udp, sendTimestamp, random, header, mux)) {
            error = "Cannot refresh VMess request authentication"; return false;
        }
        if (!transport.write(header)) { error = "Cannot write VMess request header"; return false; }
        return true;
    }
    size_t available() const { return receiveInput.size()-receiveOffset; }
    bool fill(size_t count,bool nonblocking) {
        if(count>65535){errno=EPROTO;return false;}
        while(available()<count) {
            VmBytes part;
            if(!(nonblocking?transport.tryReadSome(part):transport.readSome(part))) {
                if(errno==0)errno=EPROTO;
                return false;
            }
            if(receiveOffset){receiveInput.erase(receiveInput.begin(),receiveInput.begin()+receiveOffset);receiveOffset=0;}
            vmAppend(receiveInput,part);
        }
        return true;
    }
    VmBytes take(size_t count) {
        VmBytes result(receiveInput.begin()+receiveOffset,receiveInput.begin()+receiveOffset+count);receiveOffset+=count;
        if(receiveOffset==receiveInput.size()){receiveInput.clear();receiveOffset=0;}
        return result;
    }
    bool responseHeader(bool nonblocking=false) {
        VmBytes header;
        if(responseLength==65536) {
            if(!fill(aead?18:4,nonblocking))return false;
            responsePrefix=take(aead?18:4);
            if(aead) {
                VmBytes length;
                if(!vmAead(false,vmKdf(responseKey,{vmBytes("AEAD Resp Header Len Key")},16),
                    vmKdf(responseIv,{vmBytes("AEAD Resp Header Len IV")},12),{},responsePrefix,length))return false;
                const size_t size=(length[0]<<8)|length[1];
                if(size<4||size>4096){errno=EBADMSG;return false;}
                responseLength=size+16;
            } else {
                if(!vmCfb(false,responseKey,responseIv,responsePrefix,header))return false;
                responseLength=header[3];
            }
        }
        if(!fill(responseLength,nonblocking))return false;
        VmBytes encrypted=take(responseLength);
        if(aead) {
            if(!vmAead(false,vmKdf(responseKey,{vmBytes("AEAD Resp Header Key")},16),
                vmKdf(responseIv,{vmBytes("AEAD Resp Header IV")},12),{},encrypted,header))return false;
        } else {
            vmAppend(responsePrefix,encrypted);
            if(!vmCfb(false,responseKey,responseIv,responsePrefix,header))return false;
        }
        if(header.size()!=static_cast<size_t>(4+header[3])||header[0]!=responseAuth){errno=EBADMSG;return false;}
        responsePrefix.clear();responseReady=true;return true;
    }
    VmBytes nonce(const VmBytes& iv, uint32_t count) {
        VmBytes result(iv.begin(), iv.begin() + 12); result[0] = count >> 8; result[1] = count; return result;
    }
    bool chunk(const unsigned char* data, size_t size) {
        if (sentEof || (security != 5 && sendCounter >= 65536) || size > 65535 - 16 - 63) { errno = EOVERFLOW; return false; }
        const size_t padding = security == 5 ? 0 : sendMask.next() % 64;
        VmBytes payload(data, data + size), encrypted;
        if (security == 5) encrypted = payload;
        else if (!vmAead(true, vmBodyKey(requestKey, security), nonce(requestIv, sendCounter), {}, payload, encrypted, security == 4)) return false;
        VmBytes wire; vmUint(wire, (encrypted.size() + padding) ^ sendMask.next(), 2); vmAppend(wire, encrypted);
        VmBytes paddingBytes(padding); if (!randomBytes(paddingBytes)) return false; vmAppend(wire, paddingBytes);
        ++sendCounter;
        if (!transport.write(wire)) return false;
        if (size == 0) sentEof = true;
        return true;
    }
    bool write(const unsigned char* data, size_t size) {
        if (sentEof) return false;
        if (raw) return transport.write(VmBytes(data, data + size));
        // V2Fly's standard writer caps frames to its 2048-byte buffer including all overhead.
        for (size_t offset = 0; offset < size;) {
            const size_t length = std::min<size_t>(1966, size - offset);
            if (!chunk(data + offset, length)) return false;
            offset += length;
        }
        return true;
    }
    bool finish() {
        if (sentEof) return true;
        if (raw) { sentEof = true; return transport.closeWrite(); }
        const unsigned char empty = 0; return chunk(&empty, 0);
    }
    bool read(VmBytes& output,bool nonblocking=false) {
        output.clear();errno=0;
        if(receivedEof)return false;
        if(!responseReady&&!responseHeader(nonblocking))return false;
        if(raw) {
            if(available()){output=take(std::min<size_t>(16384,available()));return true;}
            return nonblocking?transport.tryReadSome(output):transport.readSome(output);
        }
        if(security!=5&&receiveCounter>=65536){errno=EOVERFLOW;return false;}
        if(frameLength==65536) {
            if(!fill(2,nonblocking))return false;
            const auto bytes=take(2);
            framePadding=security==5?0:receiveMask.next()%64;
            frameLength=static_cast<size_t>(((bytes[0]<<8)|bytes[1])^receiveMask.next());
            if(frameLength<framePadding+(security==5?0:16)){errno=EBADMSG;return false;}
        }
        if(!fill(frameLength,nonblocking))return false;
        auto encrypted=take(frameLength);encrypted.resize(frameLength-framePadding);
        if(security==5)output=std::move(encrypted);
        else if(!vmAead(false,vmBodyKey(responseKey,security),nonce(responseIv,receiveCounter),{},encrypted,output,security==4))return false;
        ++receiveCounter;frameLength=65536;
        if(output.empty()){receivedEof=true;errno=0;return false;}
        return true;
    }
    bool pending() const {
        const size_t needed=!responseReady?(responseLength==65536?(aead?18:4):responseLength):raw?1:frameLength==65536?2:frameLength;
        return (!receivedEof&&available()>=needed)||transport.pending();
    }

};

bool vmessCryptoSelfTest()
{
    const VmBytes key(16,0), iv(12,0), message(2,0);
    VmBytes encrypted, plain;
    if (!vmAead(true,key,iv,{},message,encrypted) || encrypted!=decodeHex("038893dcdd26f79ec1dd9bff57204d9b33f5") ||
        !vmAead(false,key,iv,{},encrypted,plain) || plain!=message) return false;
    encrypted.back()^=1;
    if (vmAead(false,key,iv,{},encrypted,plain) || !plain.empty()) return false;
    VmBytes bytes(32);for(size_t i=0;i<bytes.size();++i)bytes[i]=i;
    if (!vmCfb(true,key,key,bytes,encrypted) || encrypted!=decodeHex("66e849d7eb8f2a3c8045f052c63925214accf1be6ae82b294d4d3c0a85ace012")) return false;
    const VmBytes command=vmCommandKey(vmUuid("11111111-2222-4333-8444-555555555555"));
    if (vmKdf(command,{vmBytes("VMess Header AEAD Key"),VmBytes(16,1),VmBytes(8,2)})!=
        decodeHex("b94f1937547dca019ef31e11256f127421704bdfeb8d8f35e9afc5cbadcc366d")) return false;
    VmessMask mask;VmBytes seed(16);for(size_t i=0;i<seed.size();++i)seed[i]=i;mask.init(seed);
    return mask.next()==0x9848 && mask.next()==0x1946;
}
bool vmessTrustStoreSelfTest()
{
    mbedtls_x509_crt roots;mbedtls_x509_crt_init(&roots);
    const int result=mbedtls_x509_crt_parse(&roots,reinterpret_cast<const unsigned char*>(CLAHSOS_CA_BUNDLE),sizeof(CLAHSOS_CA_BUNDLE));
    const bool ready=result>=0 && roots.raw.p!=nullptr;
    mbedtls_x509_crt_free(&roots);return ready;
}
