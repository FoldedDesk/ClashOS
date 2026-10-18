// Internal implementation, included in clash_core.cpp after the shared protocol helpers.
constexpr size_t UDP_MAX_PACKET = 65507;
// Internal AF_UNIX carriers may retain a SOCKS source envelope around a full
// physical datagram. It is stripped before transmission on a real UDP socket.
constexpr size_t UDP_MAX_ENVELOPE = UDP_MAX_PACKET + 262;
#ifdef MSG_NOSIGNAL
constexpr int UDP_SEND_FLAGS = MSG_NOSIGNAL;
#else
constexpr int UDP_SEND_FLAGS = 0;
#endif
using UdpClock = std::chrono::steady_clock;

struct UdpEndpoint {
    sockaddr_storage address{};
    socklen_t length = 0;
};

std::string udpEndpointHost(const UdpEndpoint& endpoint)
{
    char text[INET6_ADDRSTRLEN] = {};
    if (endpoint.address.ss_family == AF_INET) {
        inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(&endpoint.address)->sin_addr, text, sizeof(text));
    } else if (endpoint.address.ss_family == AF_INET6) {
        const auto* address = &reinterpret_cast<const sockaddr_in6*>(&endpoint.address)->sin6_addr;
        if (IN6_IS_ADDR_V4MAPPED(address)) inet_ntop(AF_INET, address->s6_addr + 12, text, sizeof(text));
        else inet_ntop(AF_INET6, address, text, sizeof(text));
    }
    return text;
}

int udpEndpointPort(const UdpEndpoint& endpoint)
{
    if (endpoint.address.ss_family == AF_INET) return ntohs(reinterpret_cast<const sockaddr_in*>(&endpoint.address)->sin_port);
    if (endpoint.address.ss_family == AF_INET6) return ntohs(reinterpret_cast<const sockaddr_in6*>(&endpoint.address)->sin6_port);
    return 0;
}

bool udpSameEndpoint(const UdpEndpoint& first, const UdpEndpoint& second)
{
    return !udpEndpointHost(first).empty() && udpEndpointHost(first) == udpEndpointHost(second) &&
        udpEndpointPort(first) == udpEndpointPort(second);
}

struct UdpTarget {
    std::string host;
    int port = 0;
    size_t headerSize = 0;
    std::string sniffHost;
    bool overrideDestination = false;
};

std::string udpRouteHost(const UdpTarget& target) { return target.sniffHost.empty() ? target.host : target.sniffHost; }
std::string udpDestinationHost(const UdpTarget& target) { return target.overrideDestination ? udpRouteHost(target) : target.host; }

bool parseUdpAddress(const std::vector<unsigned char>& packet, size_t offset, UdpTarget& target)
{
    target = {};
    if (offset >= packet.size()) return false;
    size_t cursor = offset + 1;
    const unsigned char type = packet[offset];
    if (type == 1 || type == 4) {
        const size_t length = type == 1 ? 4 : 16;
        if (packet.size() - cursor < length + 2) return false;
        char host[INET6_ADDRSTRLEN] = {};
        if (inet_ntop(type == 1 ? AF_INET : AF_INET6, packet.data() + cursor, host, sizeof(host)) == nullptr) return false;
        target.host = host;
        cursor += length;
    } else if (type == 3) {
        if (cursor >= packet.size()) return false;
        const size_t length = packet[cursor++];
        if (length == 0 || packet.size() - cursor < length + 2) return false;
        target.host.assign(packet.begin() + cursor, packet.begin() + cursor + length);
        if (target.host.find('\0') != std::string::npos) return false;
        cursor += length;
    } else return false;
    target.port = (static_cast<int>(packet[cursor]) << 8) | packet[cursor + 1];
    target.headerSize = cursor + 2 - offset;
    return target.port > 0;
}

bool parseSocksUdp(const std::vector<unsigned char>& packet, UdpTarget& target)
{
    return packet.size() <= UDP_MAX_PACKET && packet.size() >= 4 && packet[0] == 0 && packet[1] == 0 &&
        packet[2] == 0 && parseUdpAddress(packet, 3, target);
}

bool encryptShadowsocksUdp(const std::vector<unsigned char>& master, const std::vector<unsigned char>& salt,
    const std::vector<unsigned char>& plain, std::vector<unsigned char>& packet,SsCipher method=SsCipher::Aes256Gcm)
{
    packet.clear();
    const size_t keySize=shadowsocksKeySize(method);
    if (keySize==0||master.size() != keySize || salt.size() != keySize || plain.empty() || plain.size() > UDP_MAX_PACKET - keySize - 16) return false;
    const auto key = hkdfSha1(salt, master, "ss-subkey", keySize);
    std::vector<unsigned char> cipher, tag(16);
    if (!shadowsocksAead(true,method,key,std::vector<unsigned char>(12,0),plain,cipher,tag)) return false;
    packet = salt;
    packet.insert(packet.end(), cipher.begin(), cipher.end());
    packet.insert(packet.end(), tag.begin(), tag.end());
    return true;
}

bool decryptShadowsocksUdp(const std::vector<unsigned char>& master, const std::vector<unsigned char>& packet,
    std::vector<unsigned char>& plain,SsCipher method=SsCipher::Aes256Gcm)
{
    plain.clear();
    const size_t keySize=shadowsocksKeySize(method);
    if (keySize==0||master.size() != keySize || packet.size() < keySize+16+5 || packet.size() > UDP_MAX_PACKET) return false;
    const std::vector<unsigned char> salt(packet.begin(), packet.begin() + keySize);
    const auto key = hkdfSha1(salt, master, "ss-subkey", keySize);
    std::vector<unsigned char> cipher(packet.begin() + keySize, packet.end() - 16), tag(packet.end() - 16, packet.end());
    if (!shadowsocksAead(false,method,key,std::vector<unsigned char>(12,0),cipher,plain,tag)) { plain.clear(); return false; }
    UdpTarget target;
    if (!parseUdpAddress(plain, 0, target)) { plain.clear(); return false; }
    return true;
}

// Bounded recent-salt cache shared across flows and associations; includes sent salts to reject reflections.
std::mutex g_udpSaltMutex;
std::set<std::string> g_udpSalts;
std::deque<std::string> g_udpSaltOrder;
bool rememberUdpSalt(const std::vector<unsigned char>& master, const std::vector<unsigned char>& packet,SsCipher method=SsCipher::Aes256Gcm)
{
    const size_t keySize=shadowsocksKeySize(method);
    if (keySize==0||master.size() != keySize || packet.size() < keySize) return false;
    std::string key(1,static_cast<char>(method));
    key.append(master.begin(),master.end());key.append(packet.begin(), packet.begin() + keySize);
    std::lock_guard<std::mutex> lock(g_udpSaltMutex);
    if (!g_udpSalts.insert(key).second) return false;
    g_udpSaltOrder.push_back(key);
    if (g_udpSaltOrder.size() > 8192) { g_udpSalts.erase(g_udpSaltOrder.front()); g_udpSaltOrder.pop_front(); }
    return true;
}

#ifdef CLAHSOS_HOST_TEST
struct UdpTestHooks {
    std::function<int(int, UdpEndpoint&, UdpEndpoint&)> relay;
    std::function<int(const std::string&, int, UdpEndpoint&)> connect;
    std::function<ssize_t(int, std::vector<unsigned char>&, UdpEndpoint&)> receive;
    std::function<ssize_t(int, const std::vector<unsigned char>&, const UdpEndpoint&)> send;
} g_udpTestHooks;
#endif

void prepareUdpSocket(int fd)
{
    trackSocket(fd);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

int openUdpAssociation(int client, UdpEndpoint& bound, UdpEndpoint& peer)
{
#ifdef CLAHSOS_HOST_TEST
    if (g_udpTestHooks.relay) {
        const int fd = g_udpTestHooks.relay(client, bound, peer);
        if (fd >= 0) prepareUdpSocket(fd);
        return fd;
    }
#endif
    peer.length = sizeof(peer.address);
    bound.length = sizeof(bound.address);
    if (getpeername(client, reinterpret_cast<sockaddr*>(&peer.address), &peer.length) != 0 ||
        getsockname(client, reinterpret_cast<sockaddr*>(&bound.address), &bound.length) != 0 ||
        udpEndpointHost(peer).empty()) return -1;
    if (bound.address.ss_family == AF_INET) reinterpret_cast<sockaddr_in*>(&bound.address)->sin_port = 0;
    else if (bound.address.ss_family == AF_INET6) reinterpret_cast<sockaddr_in6*>(&bound.address)->sin6_port = 0;
    else return -1;
    const int fd = socket(bound.address.ss_family, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    if (bind(fd, reinterpret_cast<sockaddr*>(&bound.address), bound.length) != 0 ||
        getsockname(fd, reinterpret_cast<sockaddr*>(&bound.address), &bound.length) != 0) { closeSocket(fd); return -1; }
    prepareUdpSocket(fd);
    return fd;
}

int connectUdpOutbound(const std::string& host, int port, UdpEndpoint& endpoint,DnsPurpose purpose=DnsPurpose::Direct)
{
    if (!g_state.running.load()) return -1;
#ifdef CLAHSOS_HOST_TEST
    if (g_udpTestHooks.connect) {
        const int fd = g_udpTestHooks.connect(host, port, endpoint);
        if (fd >= 0) prepareUdpSocket(fd);
        return fd;
    }
#endif
    const auto addresses=resolveDnsAddresses(host,purpose,HealthClock::now()+std::chrono::milliseconds(6000));
    int fd = -1;
    for (const auto& ip:addresses) {
        if (!g_state.running.load()) break;
        sockaddr_storage address{};socklen_t length=0;
        if(inet_pton(AF_INET,ip.c_str(),&reinterpret_cast<sockaddr_in*>(&address)->sin_addr)==1){auto* a=reinterpret_cast<sockaddr_in*>(&address);a->sin_family=AF_INET;a->sin_port=htons(port);length=sizeof(*a);}
        else if(inet_pton(AF_INET6,ip.c_str(),&reinterpret_cast<sockaddr_in6*>(&address)->sin6_addr)==1){auto* a=reinterpret_cast<sockaddr_in6*>(&address);a->sin6_family=AF_INET6;a->sin6_port=htons(port);length=sizeof(*a);}
        if(!length)continue;
        fd = socket(address.ss_family, SOCK_DGRAM, 0);
        if (fd < 0) continue;
        prepareUdpSocket(fd);
        if (connect(fd, reinterpret_cast<sockaddr*>(&address), length) == 0) {
            endpoint.address=address;
            endpoint.length = length;
            break;
        }
        closeSocket(fd);
        fd = -1;
    }
    return fd;
}

ssize_t receiveUdpRelay(int fd, std::vector<unsigned char>& packet, UdpEndpoint& sender)
{
#ifdef CLAHSOS_HOST_TEST
    if (g_udpTestHooks.receive) return g_udpTestHooks.receive(fd, packet, sender);
#endif
    packet.resize(65536);
    sender.length = sizeof(sender.address);
    iovec buffer{packet.data(), packet.size()};
    msghdr message{};
    message.msg_name = &sender.address;
    message.msg_namelen = sender.length;
    message.msg_iov = &buffer;
    message.msg_iovlen = 1;
    const ssize_t count = recvmsg(fd, &message, 0);
    sender.length = message.msg_namelen;
    if (count < 0 || (message.msg_flags & MSG_TRUNC) || static_cast<size_t>(count) > UDP_MAX_PACKET) {
        packet.clear(); return -1;
    }
    packet.resize(static_cast<size_t>(count));
    return count;
}

bool sendUdpReply(int fd, const std::vector<unsigned char>& packet, const UdpEndpoint& endpoint)
{
    if (packet.size() > UDP_MAX_PACKET) return false;
    ssize_t sent;
    do {
#ifdef CLAHSOS_HOST_TEST
        if (g_udpTestHooks.send) sent = g_udpTestHooks.send(fd, packet, endpoint);
        else
#endif
        sent = sendto(fd, packet.data(), packet.size(), UDP_SEND_FLAGS, reinterpret_cast<const sockaddr*>(&endpoint.address), endpoint.length);
    } while (sent < 0 && errno == EINTR);
    return sent >= 0 && static_cast<size_t>(sent) == packet.size();
}

struct UdpClientPin {
    UdpEndpoint peer;
    UdpEndpoint endpoint;
    int requestedPort = 0;
    bool pinned = false;
    bool accepts(const UdpEndpoint& sender) {
        if (udpEndpointHost(sender).empty() || udpEndpointHost(sender) != udpEndpointHost(peer) ||
            (requestedPort > 0 && udpEndpointPort(sender) != requestedPort) ||
            (pinned && !udpSameEndpoint(sender, endpoint))) return false;
        endpoint = sender;
        pinned = true;
        return true;
    }
};

bool udpConnectionCancelled(int fd)
{
    std::lock_guard<std::mutex> lock(g_state.sessionsMutex);
    const auto found = g_state.connections.find(fd);
    return found == g_state.connections.end() || found->second.cancelled;
}

struct DialerDatagramBridge;
int openDialerDatagramTransport(const ProxyNode&,const std::string&,int,bool,std::shared_ptr<DialerDatagramBridge>&,size_t&,std::string&);
void activateDialerDatagram(const std::shared_ptr<DialerDatagramBridge>&,bool);
bool dialerDatagramClosed(const std::shared_ptr<DialerDatagramBridge>&,bool drained=false);
void consumeDialerDatagram(const std::shared_ptr<DialerDatagramBridge>&);

struct UdpFlow {
    int fd = -1;
    ProxyNode node;
    UdpEndpoint remote;
    std::string host, originalHost, routeHost;
    int port = 0;
    std::vector<unsigned char> master;
    std::unique_ptr<Ss2022Datagram> ss2022;
    UdpClock::time_point lastActivity = UdpClock::now();
    bool failed = false;
    bool internal = false;
    size_t carrierLimit=UDP_MAX_PACKET;
    std::shared_ptr<DialerBridge> streamDialer;
    std::shared_ptr<DialerDatagramBridge> datagramDialer;
    std::unique_ptr<VmessSession> vmess;
    std::unique_ptr<TrojanSession> trojan;
    std::unique_ptr<VlessSession> vless;
    std::unique_ptr<XudpSession> xudp;
    std::unique_ptr<ForwardProxySession> socksControl;
    int socksControlFd = -1;
    std::thread streamThread;
    int notifyMain = -1, notifyWorker = -1;
    std::mutex streamMutex;
    std::deque<VmBytes> streamInput, streamOutput;
    std::atomic<bool> streamStopping{false}, streamStopped{false};
    std::atomic<int> streamError{0};
    bool cancelled() const { return internal ? streamStopping.load()||!g_state.running.load() : udpConnectionCancelled(fd); }
    void transferred(bool up,size_t bytes){if(!internal)recordTransfer(fd,up,bytes);}
    size_t payloadLimit() const {
        if(xudp)return UDP_MAX_PACKET;
        if(vmess)return 1966;
        if(vless||trojan)return UDP_MAX_PACKET;
        const size_t overhead=node.type=="ss"?(ss2022?ss2022->overhead():shadowsocksKeySize(shadowsocksCipher(node.cipher))+16)+shadowsocksAddress(host,port).size():socksControl?3+shadowsocksAddress(host,port).size():0;
        return carrierLimit>=overhead?carrierLimit-overhead:0;
    }
    static void notify(int socket) {
        const unsigned char byte = 1;
        const ssize_t ignored = send(socket, &byte, 1, UDP_SEND_FLAGS); (void)ignored;
    }
    bool streamPending() {
        std::lock_guard<std::mutex> lock(streamMutex); return !streamOutput.empty() || streamStopped.load();
    }
    bool streamed() const { return vmess != nullptr || trojan != nullptr || vless != nullptr || socksControl != nullptr; }
    void runSocksStream() {
        while (g_state.running.load() && !streamStopping.load() && !cancelled() && !dialerDatagramClosed(datagramDialer,true)) {
            bool queued; { std::lock_guard<std::mutex> lock(streamMutex); queued = !streamInput.empty(); }
            pollfd watches[3] = {{fd, POLLIN, 0}, {notifyWorker, POLLIN, 0}, {socksControlFd, POLLIN, 0}};
            const bool pending = socksControl->pending();
            const int ready = poll(watches, 3, queued || pending ? 0 : 1000);
            if (ready < 0) { if (errno == EINTR) continue; streamError.store(errno); break; }
            // RFC 1928: the TCP/TLS control channel owns the UDP association.
            // Observe its closure before sending queued datagrams or exposing replies.
            if (pending || watches[2].revents) {
                VmBytes unexpected;
                const bool data = socksControl->read(unexpected, true);
                if (data || (errno != EAGAIN && errno != EWOULDBLOCK)) { streamError.store(data ? EPROTO : errno); break; }
            }
            if (streamStopping.load() || cancelled() || dialerDatagramClosed(datagramDialer,true)) break;
            if (watches[1].revents) { unsigned char drain[128]; while (recv(notifyWorker, drain, sizeof(drain), 0) > 0) {} }
            bool ok = true;
            for (int burst = 0; burst < 16; ++burst) {
                VmBytes payload;
                { std::lock_guard<std::mutex> lock(streamMutex); if (streamInput.empty()) break; payload = std::move(streamInput.front()); streamInput.pop_front(); }
                VmBytes packet(3, 0); vmAppend(packet, shadowsocksAddress(host, port)); vmAppend(packet, payload);
                ssize_t sent;
                do { sent = send(fd, packet.data(), packet.size(), UDP_SEND_FLAGS); } while (sent < 0 && errno == EINTR);
                if (sent < 0 || static_cast<size_t>(sent) != packet.size()) { streamError.store(errno); ok = false; break; }
                transferred(true, payload.size());
            }
            if (!ok) break;
            if (watches[0].revents) {
                VmBytes packet(65536); iovec buffer{packet.data(), packet.size()}; msghdr message{}; message.msg_iov = &buffer; message.msg_iovlen = 1;
                const auto count = recvmsg(fd, &message, 0);
                if (count < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue; streamError.store(errno); break; }
                consumeDialerDatagram(datagramDialer);
                if ((message.msg_flags & MSG_TRUNC) || static_cast<size_t>(count) > UDP_MAX_PACKET) continue;
                packet.resize(static_cast<size_t>(count)); UdpTarget source;
                if (!parseSocksUdp(packet, source)) continue; // Unsupported fragments and malformed replies are dropped.
                packet.erase(packet.begin(), packet.begin() + 3);
                { std::lock_guard<std::mutex> lock(streamMutex); if (streamOutput.size() >= 64) streamOutput.pop_front(); streamOutput.push_back(std::move(packet)); }
                notify(notifyWorker);
            }
        }
        streamStopped.store(true); notify(notifyWorker);
    }
    void runStream() {
        bool ok = true;
        while (ok && g_state.running.load() && !streamStopping.load()) {
            const bool buffered = xudp ? xudp->pending() : vmess ? vmess->pending() : vless ? vless->pending() : trojan->pending();
            bool queued;
            { std::lock_guard<std::mutex> lock(streamMutex); queued = !streamInput.empty(); }
            pollfd watches[2] = {{fd, POLLIN, 0}, {notifyWorker, POLLIN, 0}};
            const int ready = poll(watches, 2, buffered || queued ? 0 : 1000);
            if (ready < 0 && errno == EINTR) continue;
            if (ready < 0) break;
            if (watches[1].revents) { unsigned char drain[128]; while (recv(notifyWorker, drain, sizeof(drain), 0) > 0) {} }
            for (int count = 0; count < 16; ++count) {
                VmBytes packet;
                { std::lock_guard<std::mutex> lock(streamMutex); if (streamInput.empty()) break; packet=std::move(streamInput.front()); streamInput.pop_front(); }
                const bool written = xudp ? xudp->writeDatagram(packet) : vmess ? vmess->chunk(packet.data(), packet.size()) : vless ? vless->writeDatagram(packet) : trojan->writeDatagram(host, port, packet);
                if (!written) { streamError.store(errno); ok=false; break; }
                transferred(true, packet.size());
            }
            if (!ok || streamStopping.load()) break;
            if (buffered || watches[0].revents) {
                VmBytes packet;
                const bool read = xudp ? xudp->readDatagram(packet, true) : vmess ? vmess->read(packet, true) : vless ? vless->read(packet, true) : trojan->readDatagram(packet, true);
                if (!read) { if (errno == EAGAIN || errno == EWOULDBLOCK || (trojan && errno == EMSGSIZE)) continue; streamError.store(errno); break; }
                if (packet.size() <= (xudp ? UDP_MAX_ENVELOPE : UDP_MAX_PACKET - (trojan ? 3 : 0))) {
                    { std::lock_guard<std::mutex> lock(streamMutex); if (streamOutput.size() >= 64) streamOutput.pop_front(); streamOutput.push_back(std::move(packet)); }
                    notify(notifyWorker);
                }
            }
        }
        streamStopped.store(true); notify(notifyWorker);
    }
    bool startStreamWorker() {
        int pair[2]; if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return false;
        notifyMain=pair[0];notifyWorker=pair[1];
        for (int socket : pair) fcntl(socket, F_SETFL, fcntl(socket, F_GETFL, 0) | O_NONBLOCK);
        try { streamThread=std::thread([this]() { if (socksControl) runSocksStream(); else runStream(); }); } catch (...) { return false; }
        return true;
    }
    ~UdpFlow() {
        streamStopping.store(true);
        if (streamThread.joinable()) { shutdown(fd, SHUT_RDWR); notify(notifyMain); streamThread.join(); }
        if (notifyMain >= 0) close(notifyMain);
        if (notifyWorker >= 0) close(notifyWorker);
        if (socksControlFd >= 0) closeSocket(socksControlFd);
        if (fd >= 0) closeSocket(fd);
    }
};

std::string udpFlowKey(const UdpTarget& target, const ProxyNode& node)
{
    return target.host + '\0' + target.sniffHost + '\0' + std::to_string(target.port) + '\0' + node.name + '\0' +
        std::to_string(node.revision) + '\0' + node.matchedRule;
}

std::unique_ptr<UdpFlow> openUdpFlow(int owner, const UdpTarget& target, const ProxyNode& node,bool internal=false,const VmBytes& globalId={})
{
    if (!supportsUdp(node)) return nullptr;
    DestinationDnsScope dnsScope(node);
    DialerHandshakeDeadline handshake(!node.dialerProxy.empty(),6000);
    auto flow = std::make_unique<UdpFlow>();
    flow->internal=internal;
    flow->node = node;
    flow->originalHost = target.host; flow->host = udpDestinationHost(target); flow->routeHost = udpRouteHost(target);
    flow->port = target.port;
    std::string destination,error;
    if(!proxyDestination(node,flow->host,destination,error)){coreLog("warning","UDP hosts mapping failed: "+error);return nullptr;}
    flow->host=destination;
    const bool chained=!node.dialerProxy.empty()&&node.dialerProxy!="DIRECT";
    auto tcp=[&]() {
        return chained ? openDialerTransport(*node.dialerNode,node.server,node.port,6000,flow->streamDialer,error) :
            connectUpstream(node.server,node.port,6000,DnsPurpose::Proxy);
    };
    auto datagram=[&](const std::string& host,int port,DnsPurpose purpose) {
        return chained ? openDialerDatagramTransport(*node.dialerNode,host,port,node.type=="direct",flow->datagramDialer,flow->carrierLimit,error) :
            connectUdpOutbound(host,port,flow->remote,purpose);
    };
    if (node.type == "ss") {
        const auto method=shadowsocksCipher(node.cipher);const size_t keySize=shadowsocksKeySize(method);
        if(isSs2022(method)) {
            const auto keys=ss2022Keys(method,node.password);if(keys.empty())return nullptr;
            flow->ss2022=std::make_unique<Ss2022Datagram>(method,keys);if(flow->ss2022->clientId.empty())return nullptr;
        } else {
        flow->master = evpBytesToKey(node.password,keySize);
        if (keySize==0||flow->master.size()!=keySize) return nullptr;
        }
    }
    if (node.type == "socks5") {
        flow->socksControlFd = tcp();
        if (flow->socksControlFd < 0) return nullptr;
        socketTimeout(flow->socksControlFd, 6000);
        flow->socksControl = std::make_unique<ForwardProxySession>(flow->socksControlFd);
        if (!flow->socksControl->start(node, "0.0.0.0", 0, true, error)) { coreLog("warning", "SOCKS5 UDP startup failed: " + error); return nullptr; }
        flow->fd = datagram(flow->socksControl->boundHost, flow->socksControl->boundPort, DnsPurpose::Proxy);
    } else if (node.type == "vmess" || node.type == "trojan" || node.type == "vless") {
        flow->fd = tcp();
        if (flow->fd < 0) return nullptr;
        socketTimeout(flow->fd, 6000);
        std::string error;
        bool opened;
        if (node.type == "vmess") {
            flow->vmess = std::make_unique<VmessSession>(flow->fd);
            opened = flow->vmess->start(node, flow->host, target.port, true, error, node.packetEncoding == "xudp");
        } else if (node.type == "vless") {
            flow->vless = std::make_unique<VlessSession>(flow->fd);
            opened = flow->vless->start(node, flow->host, target.port, true, error, node.packetEncoding == "xudp");
        } else {
            flow->trojan = std::make_unique<TrojanSession>(flow->fd);
            opened = flow->trojan->start(node, flow->host, target.port, true, error);
        }
        if (!opened) {
            coreLog("warning", node.type + " UDP startup failed: " + error); return nullptr;
        }
        // One worker owns both TLS directions; mbedtls_ssl_context is never shared concurrently.
        if(node.packetEncoding == "xudp" && (flow->vmess || flow->vless)) {
            UdpFlow* session=flow.get();
            flow->xudp=std::make_unique<XudpSession>(flow->host,target.port,flow->originalHost,globalId,
                [session](const unsigned char* data,size_t size){return session->vmess?session->vmess->write(data,size):session->vless->write(data,size);},
                [session](VmBytes& bytes,bool nonblocking){return session->vmess?session->vmess->read(bytes,nonblocking):session->vless->read(bytes,nonblocking);},
                [session](){return session->vmess?session->vmess->pending():session->vless->pending();});
        }
        socketTimeout(flow->fd, 60000);
    } else flow->fd = datagram(node.type == "direct" ? flow->host : node.server,
        node.type == "direct" ? target.port : node.port, node.type=="direct"?DnsPurpose::Direct:DnsPurpose::Proxy);
    if (flow->fd < 0 || !g_state.running.load() || (!internal&&
        !beginConnection(flow->fd, flow->routeHost, target.port, node.chain, node.matchedRule, "udp", owner))) return nullptr;
    activateDialerDatagram(flow->datagramDialer,internal);
    if (flow->streamed() && !flow->startStreamWorker()) return nullptr;
    if(!internal)coreLog("info", "UDP " + target.host + ":" + std::to_string(target.port) + " via " + node.name);
    return flow;
}

bool writeUdpFlow(UdpFlow& flow, const std::vector<unsigned char>& packet, const UdpTarget& target)
{
    if (!g_state.running.load() || flow.cancelled() || dialerDatagramClosed(flow.datagramDialer)) return false;
    const size_t payloadOffset = 3 + target.headerSize;
    if (packet.size() < payloadOffset) return false;
    std::vector<unsigned char> wire(packet.begin() + payloadOffset, packet.end());
    if(wire.size()>flow.payloadLimit())return false;
    if (flow.streamed()) {
        if ((flow.vmess && !flow.xudp && (wire.empty() || wire.size() > 1966)) || wire.size() > 65535 ||
            (flow.socksControl && wire.size() + 3 + shadowsocksAddress(flow.host, flow.port).size() > UDP_MAX_PACKET) || flow.streamStopped.load()) return false;
        { std::lock_guard<std::mutex> lock(flow.streamMutex); if (flow.streamInput.size() >= 64) return false; flow.streamInput.push_back(std::move(wire)); }
        UdpFlow::notify(flow.notifyMain); flow.lastActivity = UdpClock::now(); return true;
    }
    if (flow.node.type == "ss") {
        const SsCipher method=shadowsocksCipher(flow.node.cipher);
        std::vector<unsigned char> plain = shadowsocksAddress(flow.host, flow.port), salt(shadowsocksKeySize(method));
        plain.insert(plain.end(), packet.begin() + payloadOffset, packet.end());
        if(flow.ss2022) { if(!flow.ss2022->encode(plain,wire)||wire.size()>flow.carrierLimit)return false; }
        else {
        if (!randomBytes(salt) || !encryptShadowsocksUdp(flow.master,salt,plain,wire,method) || wire.size()>flow.carrierLimit || !rememberUdpSalt(flow.master,wire,method)) return false;
        }
    }
    ssize_t sent;
    do { sent = send(flow.fd, wire.data(), wire.size(), UDP_SEND_FLAGS); } while (sent < 0 && errno == EINTR);
    if (sent < 0 || static_cast<size_t>(sent) != wire.size()) return false;
    flow.transferred(true, packet.size() - payloadOffset);
    flow.lastActivity = UdpClock::now();
    return true;
}

bool readUdpFlow(UdpFlow& flow, std::vector<unsigned char>& reply, size_t& payloadSize)
{
    if (flow.streamed()) {
        unsigned char drain[128]; while (recv(flow.notifyMain, drain, sizeof(drain), 0) > 0) {}
        VmBytes packet;
        { std::lock_guard<std::mutex> lock(flow.streamMutex);
          if (flow.streamOutput.empty()) {
              flow.failed=flow.streamStopped.load(); errno=flow.failed ? flow.streamError.load() : EAGAIN; return false;
          }
          packet=std::move(flow.streamOutput.front());flow.streamOutput.pop_front(); }
        reply.assign(3,0);
        if (flow.trojan || flow.socksControl || flow.xudp) {
            UdpTarget source;
            if (!parseUdpAddress(packet, 0, source)) { errno = EPROTO; return false; }
            payloadSize = packet.size() - source.headerSize;
        } else {
            const auto address=shadowsocksAddress(flow.originalHost,flow.port);
            reply.insert(reply.end(),address.begin(),address.end()); payloadSize=packet.size();
        }
        reply.insert(reply.end(),packet.begin(),packet.end());
        if (reply.size()>(flow.internal?UDP_MAX_ENVELOPE:UDP_MAX_PACKET)) { errno=EMSGSIZE;return false; } return true;
    }
    if(dialerDatagramClosed(flow.datagramDialer,true)){flow.failed=true;errno=ECONNRESET;return false;}
    const size_t limit=flow.internal&&flow.datagramDialer&&flow.node.type=="direct"?UDP_MAX_ENVELOPE:UDP_MAX_PACKET;
    std::vector<unsigned char> packet(std::max<size_t>(65536,limit));
    iovec buffer{packet.data(), packet.size()};
    msghdr message{};
    message.msg_iov = &buffer; message.msg_iovlen = 1;
    errno = 0;
    const ssize_t count = recvmsg(flow.fd, &message, 0);
    if (count < 0) return false;
    consumeDialerDatagram(flow.datagramDialer);
    if ((message.msg_flags & MSG_TRUNC) || static_cast<size_t>(count) > limit) { errno = EMSGSIZE; return false; }
    packet.resize(static_cast<size_t>(count));
    if(flow.datagramDialer&&flow.node.type=="direct") {
        UdpTarget source;if(packet.size()<4||packet[0]||packet[1]||packet[2]||!parseUdpAddress(packet,3,source)){errno=EPROTO;return false;}
        payloadSize=packet.size()-3-source.headerSize;reply=std::move(packet);return true;
    }
    reply.assign(3, 0);
    if (flow.node.type == "ss") {
        std::vector<unsigned char> plain;
        const SsCipher method=shadowsocksCipher(flow.node.cipher);
        if(flow.ss2022) { if(!flow.ss2022->decode(packet,plain))return false; }
        else {
        if (!decryptShadowsocksUdp(flow.master,packet,plain,method)) { errno = EBADMSG; return false; }
        if (!rememberUdpSalt(flow.master,packet,method)) { errno = EALREADY; return false; }
        }
        UdpTarget source;
        if (!parseUdpAddress(plain, 0, source)) return false;
        payloadSize = plain.size() - source.headerSize;
        reply.insert(reply.end(), plain.begin(), plain.end());
    } else {
        const auto address = shadowsocksAddress(udpEndpointHost(flow.remote), udpEndpointPort(flow.remote));
        if (address.empty()) return false;
        reply.insert(reply.end(), address.begin(), address.end());
        reply.insert(reply.end(), packet.begin(), packet.end());
        payloadSize = packet.size();
    }
    if (reply.size() > (flow.internal?UDP_MAX_ENVELOPE:UDP_MAX_PACKET)) { errno = EMSGSIZE; return false; }
    return true;
}

#include "dialer_udp.inc"

bool aliasSniffedUdpReply(const UdpFlow& flow, std::vector<unsigned char>& reply)
{
    if (flow.routeHost == flow.originalHost) return true;
    UdpTarget source;
    if (!parseSocksUdp(reply, source)) return false;
    auto header = shadowsocksAddress(flow.originalHost, flow.port);
    if (header.empty()) return false;
    std::vector<unsigned char> result(3, 0); result.insert(result.end(), header.begin(), header.end());
    result.insert(result.end(), reply.begin() + 3 + source.headerSize, reply.end());
    if (result.size() > UDP_MAX_PACKET) return false;
    reply = std::move(result); return true;
}

struct UdpSniffEntry {
    SniffPlan plan;
    QuicSniffState quic;
    std::vector<std::vector<unsigned char>> pending;
    size_t pendingBytes = 0;
    UdpEndpoint sender;
    HealthClock::time_point started{}, used{};
    uint64_t revision = 0;
    bool decided = false;
};

struct UdpRelayOwner {
    int fd;
    ~UdpRelayOwner() { if (fd >= 0) closeSocket(fd); }
};

void handleUdpAssociate(int client, const std::string& requestedHost, int requestedPort)
{
    UdpEndpoint bound, peer;
    UdpRelayOwner relay{openUdpAssociation(client, bound, peer)};
    if (relay.fd < 0) { socksReply(client, 1); return; }
    if (requestedHost != "0.0.0.0" && requestedHost != "::" && requestedHost != "localhost" && requestedHost != udpEndpointHost(peer)) {
        socksReply(client, 2); return;
    }
    auto address = shadowsocksAddress(udpEndpointHost(bound), udpEndpointPort(bound));
    std::vector<unsigned char> response{5, 0, 0};
    response.insert(response.end(), address.begin(), address.end());
    if (address.empty() || !sendAll(client, response)) return;
    UdpClientPin pin;
    pin.peer = peer; pin.requestedPort = requestedPort;
    std::map<std::string, std::unique_ptr<UdpFlow>> flows;
    VmBytes xudpGlobalId; // One random identity per pinned SOCKS association; never persisted or logged.
    auto lastActivity = UdpClock::now();
    auto lastWarning = UdpClock::time_point::min();
    auto warn = [&](const std::string& message) {
        const auto now = UdpClock::now();
        if (lastWarning == UdpClock::time_point::min() || now - lastWarning >= std::chrono::seconds(5)) {
            coreLog("warning", message); lastWarning = now;
        }
    };
    const auto routePacket = [&](const UdpTarget& target, const std::vector<unsigned char>& packet, const UdpEndpoint& sender) {
        ProxyNode node;bool retained=false;
        // Select a load-balanced outbound once per target flow, not once per datagram.
        // Reloads and explicit disconnects release the pin; established flows survive health sweeps.
        for(const auto& entry:flows) {
            const UdpFlow& flow=*entry.second;
            if(!flow.node.loadBalanced||flow.failed||flow.originalHost!=target.host||flow.routeHost!=udpRouteHost(target)||flow.port!=target.port||udpConnectionCancelled(flow.fd))continue;
            {std::lock_guard<std::mutex> lock(g_state.mutex);if(flow.node.revision!=g_state.configRevision)continue;}
            node=flow.node;retained=true;break;
        }
        if (!retained) {
            std::vector<std::string> known; int family = 0; std::array<unsigned char,16> ip{};
            if (!target.overrideDestination && ruleIpAddress(target.host, family, ip)) known.push_back(target.host);
            node = activeProxyNode(udpRouteHost(target), target.port, "udp", udpEndpointHost(sender), known.empty() ? nullptr : &known);
        }
        if (!supportsUdp(node)) {
            warn("UDP " + target.host + ":" + std::to_string(target.port) + " is disabled or unsupported via " + node.name);
            return;
        }
        std::string destination,error;
        if(!proxyDestination(node,udpDestinationHost(target),destination,error)){warn("UDP hosts mapping failed: "+error);return;}
        if (node.type == "ss" && packet.size() - 3 - target.headerSize + shadowsocksAddress(destination, target.port).size() > UDP_MAX_PACKET - ss2022UdpOverhead(node)) return;
        if (node.type == "socks5" && packet.size() - target.headerSize + shadowsocksAddress(destination, target.port).size() > UDP_MAX_PACKET) return;
        if (node.type == "vmess" && node.packetEncoding != "xudp" && (packet.size() == 3 + target.headerSize || packet.size() - 3 - target.headerSize > 1966)) {
            warn("VMess UDP payload must be between 1 and 1966 bytes"); return;
        }
        const std::string key = udpFlowKey(target, node);
        auto found = flows.find(key);
        if (found != flows.end() && (found->second->failed || udpConnectionCancelled(found->second->fd))) {
            flows.erase(found); found = flows.end();
        }
        if (found == flows.end()) {
            if (flows.size() >= 64) {
                const auto oldest = std::min_element(flows.begin(), flows.end(), [](const auto& left, const auto& right) {
                    return left.second->lastActivity < right.second->lastActivity;
                });
                flows.erase(oldest);
            }
            if(node.packetEncoding == "xudp" && xudpGlobalId.empty()) {
                xudpGlobalId.resize(8);
                if(!randomBytes(xudpGlobalId)){xudpGlobalId.clear();warn("XUDP random source unavailable");return;}
            }
            auto flow = openUdpFlow(client, target, node, false, xudpGlobalId);
            if (flow == nullptr) { warn("Cannot open UDP outbound via " + node.name); return; }
            found = flows.emplace(key, std::move(flow)).first;
        }
        if (writeUdpFlow(*found->second, packet, target)) lastActivity = UdpClock::now();
    };
    std::map<std::string, UdpSniffEntry> sniffed;
    const auto flushSniffed = [&](UdpSniffEntry& entry) {
        for (const auto& packet : entry.pending) {
            UdpTarget target;
            if (!parseSocksUdp(packet, target)) continue;
            if (!entry.plan.protocol.empty()) { target.sniffHost = entry.plan.route; target.overrideDestination = entry.plan.destination != entry.plan.original; }
            routePacket(target, packet, entry.sender);
        }
        entry.pending.clear(); entry.pendingBytes = 0; entry.decided = true;
        entry.quic.bytes.clear(); entry.quic.bytes.shrink_to_fit(); entry.quic.filled.clear(); entry.quic.filled.shrink_to_fit(); entry.quic.contiguous = 0;
    };
    while (g_state.running.load()) {
        const auto now = UdpClock::now();
        uint64_t revision;
        { std::lock_guard<std::mutex> lock(g_state.mutex); revision = g_state.configRevision; }
        for (auto item = sniffed.begin(); item != sniffed.end();) {
            auto& entry = item->second;
            if (!entry.decided && (entry.revision != revision || now - entry.started >= std::chrono::seconds(1))) flushSniffed(entry);
            if (entry.revision != revision || now - entry.used > std::chrono::seconds(60)) item = sniffed.erase(item);
            else ++item;
        }
        for (auto item = flows.begin(); item != flows.end();) {
            if (item->second->failed || udpConnectionCancelled(item->second->fd) || now - item->second->lastActivity > std::chrono::seconds(60)) item = flows.erase(item);
            else ++item;
        }
        if (now - lastActivity > std::chrono::seconds(120)) break;
        std::vector<pollfd> watches{{client, POLLIN, 0}, {relay.fd, POLLIN, 0}};
        std::vector<UdpFlow*> active;
        bool buffered=false;
        for (auto& item : flows) {
            active.push_back(item.second.get()); watches.push_back({item.second->streamed() ? item.second->notifyMain : item.second->fd, POLLIN, 0});
            if (item.second->streamed() && item.second->streamPending()) buffered=true;
        }
        int timeout = buffered ? 0 : 1000;
        for (const auto& item : sniffed) if (!item.second.decided) timeout = std::min(timeout, static_cast<int>(std::max<int64_t>(1,
            std::chrono::duration_cast<std::chrono::milliseconds>(item.second.started + std::chrono::seconds(1) - UdpClock::now()).count())));
        const int ready = poll(watches.data(), watches.size(), timeout);
        for (size_t i=0;i<active.size();++i) if (active[i]->streamed() && active[i]->streamPending()) watches[i+2].revents|=POLLIN;
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || !g_state.running.load()) break;
        if (watches[0].revents != 0) break; // TCP control lifetime owns the UDP association.
        // Read old flows before accepting packets that can add/evict their descriptors.
        for (size_t i = 0; i < active.size(); ++i) {
            UdpFlow& flow = *active[i];
            if (watches[i + 2].revents == 0 || udpConnectionCancelled(flow.fd)) continue;
            if (watches[i + 2].revents & (POLLHUP | POLLNVAL)) { flow.failed = true; continue; }
            std::vector<unsigned char> reply;
            size_t payloadSize = 0;
            if (!readUdpFlow(flow, reply, payloadSize)) {
                if (errno == EBADMSG) warn(flow.vmess ? "VMess UDP authentication failed" : "Invalid or unauthenticated Shadowsocks UDP packet dropped");
                else if (errno == EALREADY) warn("Replayed Shadowsocks UDP packet dropped");
                else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR && errno != EMSGSIZE) flow.failed = true;
                continue;
            }
            if (pin.pinned && aliasSniffedUdpReply(flow, reply) && sendUdpReply(relay.fd, reply, pin.endpoint)) {
                recordTransfer(flow.fd, false, payloadSize);
                flow.lastActivity = lastActivity = UdpClock::now();
            }
        }
        if (watches[1].revents & (POLLHUP | POLLERR | POLLNVAL)) break;
        if (!(watches[1].revents & POLLIN)) continue;
        for (int burst = 0; burst < 16; ++burst) {
            UdpEndpoint sender;
            std::vector<unsigned char> packet;
            if (receiveUdpRelay(relay.fd, packet, sender) < 0) break;
            UdpTarget target;
            if (!parseSocksUdp(packet, target) || !pin.accepts(sender)) continue;
            const std::string sniffKey = target.host + '\0' + std::to_string(target.port);
            auto decided = sniffed.find(sniffKey);
            const size_t payload = 3 + target.headerSize;
            const std::string_view data(reinterpret_cast<const char*>(packet.data() + payload), packet.size() - payload);
            if (decided != sniffed.end() && decided->second.decided && sniffQuicInitialSize(data) > 0 &&
                decided->second.quic.dcid != data.substr(6, static_cast<unsigned char>(data[5]))) {
                // A new QUIC connection may use a different SNI on the same UDP
                // target. Its Initial gets a fresh decision; active flows survive.
                sniffed.erase(decided); decided = sniffed.end();
            }
            if (decided == sniffed.end()) {
                auto plan = sniffPlan(target.host, target.port, udpEndpointHost(sender), true);
                if (!plan.eligible) { routePacket(target, packet, sender); continue; }
                if (sniffed.size() >= 64) {
                    const auto oldest = std::min_element(sniffed.begin(), sniffed.end(), [](const auto& a, const auto& b) { return a.second.used < b.second.used; });
                    if (!oldest->second.decided) flushSniffed(oldest->second);
                    sniffed.erase(oldest);
                }
                if (std::count_if(sniffed.begin(), sniffed.end(), [](const auto& entry) { return !entry.second.decided; }) >= 4) {
                    auto pending = std::find_if(sniffed.begin(), sniffed.end(), [](const auto& entry) { return !entry.second.decided; });
                    flushSniffed(pending->second);
                }
                UdpSniffEntry entry; entry.plan = std::move(plan); entry.sender = sender; entry.started = entry.used = UdpClock::now();
                { std::lock_guard<std::mutex> lock(g_state.mutex); entry.revision = g_state.configRevision; }
                decided = sniffed.emplace(sniffKey, std::move(entry)).first;
            }
            auto& entry = decided->second; entry.used = UdpClock::now();
            if (entry.decided) {
                if (!entry.plan.protocol.empty()) { target.sniffHost = entry.plan.route; target.overrideDestination = entry.plan.destination != entry.plan.original; }
                routePacket(target, packet, sender); continue;
            }
            const auto result = sniffQuicDatagram(data, entry.quic);
            if (entry.pending.size() >= 8 || packet.size() > SNIFF_LIMIT - entry.pendingBytes) {
                flushSniffed(entry); routePacket(target, packet, sender); continue;
            }
            entry.pendingBytes += packet.size(); entry.pending.push_back(std::move(packet));
            if (result.status == SniffStatus::Found) sniffApply(entry.plan, "QUIC", result);
            if (result.status != SniffStatus::Need) flushSniffed(entry);
        }
    }
}
