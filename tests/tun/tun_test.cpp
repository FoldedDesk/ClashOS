#include "clahsos_tun.h"
#define CLAHSOS_HOST_TEST
#include "../../entry/src/main/cpp/clash_core.cpp"
#include "../ss_vectors.h"
#include "../udp_vectors.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
extern "C" {
#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
}

using Bytes = std::vector<uint8_t>;
std::atomic<int> checks{0};
std::atomic<int> connector{-1};
std::atomic<int> udpConnector{-1};
std::string expectedSocksAddress = "127.0.0.1";
std::atomic<bool> socksAddressCorrect{true};
extern "C" int clahsos_test_socket(int type) {
    int fd = type == SOCK_DGRAM ? udpConnector.exchange(-1) : connector.exchange(-1);
    if (fd < 0) return -1;
    fcntl(fd, F_SETFL, O_NONBLOCK);
    hev_task_add_fd(hev_task_self(), fd, POLLIN | POLLOUT);
    return fd;
}
extern "C" int clahsos_test_connect(int fd, const sockaddr* address, socklen_t size,
    HevTaskIOYielder yielder, void* data) {
    int type = 0; socklen_t typeSize = sizeof(type);
    getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &typeSize);
    if (type != SOCK_STREAM) return 0; // UDP relay address is supplied by the SOCKS server.
    char text[INET6_ADDRSTRLEN]{};
    if (address->sa_family == AF_INET) inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(address)->sin_addr, text, sizeof(text));
    else if (address->sa_family == AF_INET6) {
        const auto& ip = reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr;
        if (IN6_IS_ADDR_V4MAPPED(&ip)) inet_ntop(AF_INET, &ip.s6_addr[12], text, sizeof(text));
        else inet_ntop(AF_INET6, &ip, text, sizeof(text));
    }
    if (expectedSocksAddress != text) socksAddressCorrect.store(false);
    return 0;
}
void check(bool value, const char* message) {
    if (!value) { std::cerr << "FAIL: " << message << '\n'; clahsos::stopTunnel(); std::exit(1); }
    ++checks;
}
uint16_t u16(const Bytes& b, size_t i) { return uint16_t(b[i]) << 8 | b[i + 1]; }
uint32_t u32(const Bytes& b, size_t i) { return uint32_t(u16(b, i)) << 16 | u16(b, i + 2); }
void put16(Bytes& b, size_t i, uint16_t value) { b[i] = value >> 8; b[i + 1] = value; }
void put32(Bytes& b, size_t i, uint32_t value) { b[i] = value >> 24; b[i + 1] = value >> 16; b[i + 2] = value >> 8; b[i + 3] = value; }
uint16_t checksum(const Bytes& b) {
    uint32_t sum = 0;
    for (size_t i = 0; i < b.size(); i += 2) sum += uint16_t(b[i]) << 8 | (i + 1 < b.size() ? b[i + 1] : 0);
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return ~sum;
}
Bytes dns(const std::string& name, uint16_t type, uint16_t id = 0x1234) {
    Bytes result(12, 0); put16(result, 0, id); put16(result, 2, 0x100); put16(result, 4, 1);
    for (size_t start = 0; start < name.size();) {
        const size_t end = name.find('.', start);
        const size_t length = (end == std::string::npos ? name.size() : end) - start;
        result.push_back(length);
        result.insert(result.end(), name.begin() + start, name.begin() + start + length);
        start += length + 1;
    }
    result.push_back(0); result.push_back(type >> 8); result.push_back(type); result.push_back(0); result.push_back(1);
    return result;
}
Bytes ipv4(const Bytes& payload, uint8_t protocol, const std::string& destination) {
    Bytes packet(20, 0); packet[0] = 0x45; packet[8] = 64; packet[9] = protocol;
    put16(packet, 2, 20 + payload.size());
    inet_pton(AF_INET, "198.18.0.3", packet.data() + 12);
    inet_pton(AF_INET, destination.c_str(), packet.data() + 16);
    put16(packet, 10, checksum(packet)); packet.insert(packet.end(), payload.begin(), payload.end());
    return packet;
}
Bytes query(const std::string& name, uint16_t type, uint16_t id = 0x1234) {
    const Bytes question = dns(name, type, id);
    Bytes udp(8, 0); put16(udp, 0, 54321); put16(udp, 2, 53); put16(udp, 4, question.size() + 8);
    udp.insert(udp.end(), question.begin(), question.end());
    return ipv4(udp, 17, "198.18.0.2");
}
Bytes exchangePacket(int fd, const Bytes& request) {
    check(send(fd, request.data(), request.size(), 0) == request.size(), "inject raw IP packet");
    pollfd p{fd, POLLIN, 0}; check(poll(&p, 1, 2000) > 0, "engine replies to TUN packet");
    Bytes reply(65536); ssize_t n = recv(fd, reply.data(), reply.size(), 0);
    check(n > 0, "read raw IP response"); reply.resize(n); return reply;
}
std::string dnsReply(int fd, const std::string& name, uint16_t type, uint16_t id) {
    const Bytes reply = exchangePacket(fd, query(name, type, id));
    check(reply.size() >= 40 && (reply[0] >> 4) == 4 && reply[9] == 17, "DNS reply uses raw IPv4 UDP");
    const size_t ip = (reply[0] & 15) * 4;
    check(u16(reply, 2) == reply.size(), "IPv4 length covers DNS response");
    check(checksum(Bytes(reply.begin(), reply.begin() + ip)) == 0, "IPv4 response checksum valid");
    check(u16(reply, ip) == 53 && u16(reply, ip + 2) == 54321, "DNS response reverses UDP ports");
    const size_t off = ip + 8;
    check(u16(reply, off) == id && (reply[off + 2] & 0x80), "DNS response retains transaction ID and response flag");
    if (type == 28) { check(u16(reply, off + 6) == 0, "AAAA responds NODATA so clients can use IPv4 mapping"); return ""; }
    check(u16(reply, off + 6) == 1, "A question has one answer");
    check(reply[reply.size() - 4] == 198 && reply[reply.size() - 3] == 19, "fake IP range does not collide with TUN or DNS address");
    char address[INET_ADDRSTRLEN]{}; inet_ntop(AF_INET, reply.data() + reply.size() - 4, address, sizeof(address));
    return address;
}
Bytes tcpPacket(const std::string& destination, uint32_t seq, uint32_t ack, uint8_t flags, const Bytes& payload = {}) {
    Bytes tcp(20, 0); put16(tcp, 0, 33445); put16(tcp, 2, 443); put32(tcp, 4, seq); put32(tcp, 8, ack);
    tcp[12] = 0x50; tcp[13] = flags; put16(tcp, 14, 65535); tcp.insert(tcp.end(), payload.begin(), payload.end());
    Bytes pseudo(12, 0); inet_pton(AF_INET, "198.18.0.3", pseudo.data()); inet_pton(AF_INET, destination.c_str(), pseudo.data() + 4);
    pseudo[9] = 6; put16(pseudo, 10, tcp.size()); pseudo.insert(pseudo.end(), tcp.begin(), tcp.end()); put16(tcp, 16, checksum(pseudo));
    return ipv4(tcp, 6, destination);
}
void ipv6Handshake(int packetFd) {
    Bytes packet(60, 0); packet[0] = 0x60; put16(packet, 4, 20); packet[6] = 6; packet[7] = 64;
    inet_pton(AF_INET6, "fdfe:dcba:9876::3", packet.data() + 8);
    inet_pton(AF_INET6, "2001:db8::1234", packet.data() + 24);
    put16(packet, 40, 33446); put16(packet, 42, 443); put32(packet, 44, 23456);
    packet[52] = 0x50; packet[53] = 2; put16(packet, 54, 65535);
    Bytes pseudo(packet.begin() + 8, packet.begin() + 40); pseudo.resize(40, 0);
    put32(pseudo, 32, 20); pseudo[39] = 6; pseudo.insert(pseudo.end(), packet.begin() + 40, packet.end());
    put16(packet, 56, checksum(pseudo));
    const Bytes reply = exchangePacket(packetFd, packet);
    check(reply.size() >= 60 && (reply[0] >> 4) == 6 && reply[6] == 6, "IPv6 TUN stack handles raw TCP packet");
    check((reply[53] & 0x12) == 0x12 && u32(reply, 48) == 23457, "IPv6 SYN ACK retains TCP sequence");
    check(u16(reply, 40) == 443 && u16(reply, 42) == 33446, "IPv6 response reverses ports");
    Bytes checkBytes(reply.begin() + 8, reply.begin() + 40); checkBytes.resize(40, 0);
    put32(checkBytes, 32, reply.size() - 40); checkBytes[39] = 6; checkBytes.insert(checkBytes.end(), reply.begin() + 40, reply.end());
    check(checksum(checkBytes) == 0, "IPv6 TCP response checksum valid");
}
bool readExactly(int fd, Bytes& bytes, size_t length) {
    bytes.resize(length);
    for (size_t offset = 0; offset < length;) {
        const ssize_t n = recv(fd, bytes.data() + offset, length - offset, 0);
        if (n <= 0) return false;
        offset += n;
    }
    return true;
}

void tunneledTcp(int packetFd, const std::string& destination, const std::string& username, const std::string& password) {
    const Bytes synack = exchangePacket(packetFd, tcpPacket(destination, 12345, 0, 2));
    check(synack.size() >= 40 && synack[9] == 6, "TUN TCP engine handles SYN packet");
    const size_t offset = (synack[0] & 15) * 4;
    check((synack[offset + 13] & 0x12) == 0x12, "TCP stack produces SYN ACK");
    check(u16(synack, offset) == 443 && u16(synack, offset + 2) == 33445, "TCP reply reverses ports");
    check(u32(synack, offset + 8) == 12346, "SYN ACK acknowledges client sequence");
    const uint32_t remoteSequence = u32(synack, offset + 4) + 1;
    int stream[2]; check(socketpair(AF_UNIX, SOCK_STREAM, 0, stream) == 0, "create SOCKS transport pair");
    timeval timeout{3, 0}; setsockopt(stream[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    connector.store(stream[0]);
    const Bytes request{'C','L','I','E','N','T',0,'T','C','P'};
    Bytes response(5000); for (size_t i = 0; i < response.size(); i++) response[i] = i % 251;
    std::atomic<bool> serverOk{false};
    std::thread server([&] {
        Bytes b;
        if (!readExactly(stream[1], b, 2) || b[0] != 5 || b[1] == 0) return;
        const auto count = b[1];
        if (!readExactly(stream[1], b, count)) return;
        const uint8_t selected = username.empty() ? 0 : 2;
        if (std::find(b.begin(), b.end(), selected) == b.end()) return;
        const char method[] = {5, static_cast<char>(selected)}; send(stream[1], method, 2, 0);
        if (selected == 2) {
            if (!readExactly(stream[1], b, 2) || b[0] != 1 || b[1] != username.size()) return;
            if (!readExactly(stream[1], b, username.size()) || std::string(b.begin(), b.end()) != username) return;
            if (!readExactly(stream[1], b, 1) || b[0] != password.size()) return;
            if (!readExactly(stream[1], b, password.size()) || std::string(b.begin(), b.end()) != password) return;
            send(stream[1], "\1\0", 2, 0);
        }
        if (!readExactly(stream[1], b, 5) || b[0] != 5 || b[1] != 1 || b[3] != 3) return;
        const size_t length = b[4];
        if (!readExactly(stream[1], b, length + 2) || std::string(b.begin(), b.begin() + length) != "www.google.com" || u16(b, length) != 443) return;
        const Bytes connected{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}; send(stream[1], connected.data(), connected.size(), 0);
        if (!readExactly(stream[1], b, request.size()) || b != request) return;
        size_t sent = 0;
        while (sent < response.size()) {
            const ssize_t n = send(stream[1], response.data() + sent, response.size() - sent, 0);
            if (n <= 0) return;
            sent += n;
        }
        serverOk = true;
    });
    const Bytes data = tcpPacket(destination, 12346, remoteSequence, 0x18, request);
    check(send(packetFd, data.data(), data.size(), 0) == data.size(), "inject TCP handshake ACK with payload");
    Bytes received;
    for (int count = 0; count < 30 && received.size() < response.size(); count++) {
        pollfd p{packetFd, POLLIN, 0}; if (poll(&p, 1, 3000) <= 0) break;
        Bytes packet(65536); const ssize_t n = recv(packetFd, packet.data(), packet.size(), 0); if (n < 40) break;
        packet.resize(n);
        const size_t ip = (packet[0] & 15) * 4;
        const size_t start = ip + ((packet[ip + 12] >> 4) * 4);
        if (start >= packet.size()) continue;
        if (u32(packet, ip + 4) == remoteSequence + received.size()) received.insert(received.end(), packet.begin() + start, packet.end());
        const Bytes ack = tcpPacket(destination, 12346 + request.size(), remoteSequence + received.size(), 0x10);
        send(packetFd, ack.data(), ack.size(), 0);
    }
    server.join(); close(stream[1]);
    check(serverOk, "SOCKS CONNECT receives original mapped domain, port and client payload");
    check(received == response, "TCP response is preserved across multiple IP packets");
}
#include "udp_bridge_test.inc"

int main() {
    check(!clahsos::startTunnel(-1, 1080), "invalid fd rejected");
    for (int round = 0; round < 3; round++) {
        int pair[2]; check(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0, "create packet device without network permission");
        const std::string username = round == 0 ? "" : "tun'用户", password = round == 0 ? "" : "p'#: public";
        expectedSocksAddress = round == 2 ? "::1" : "127.0.0.1"; socksAddressCorrect.store(true);
        { std::lock_guard<std::mutex> lock(g_state.mutex); g_state.inbound = InboundConfig{};
          if (round > 0) g_state.inbound.users = {{username, password}}; }
        check(!clahsos::startTunnel(pair[0], 1080, "not-an-ip") && !clahsos::startTunnel(pair[0], 1080, "127.0.0.1", "user", ""), "Invalid addresses and incomplete credentials fail before engine startup");
        check(clahsos::startTunnel(pair[0], 1080, expectedSocksAddress, username, password), "production tunnel starts with the chosen address and credentials");
        check(clahsos::tunnelStatus().find("\"running\":true") != std::string::npos, "ready state requires engine initialization");
        check(!clahsos::startTunnel(pair[0], 1080), "second start preserves live tunnel");
        const std::string first = dnsReply(pair[1], "www.google.com", 1, 0x1234);
        check(first == dnsReply(pair[1], "www.google.com", 1, 0x4321), "same domain keeps mapping");
        check(first != dnsReply(pair[1], "www.example.com", 1, 0x2222), "different domains have different fake addresses");
        dnsReply(pair[1], "www.google.com", 28, 0x3333);
        tunneledUdp(pair[1], first, round);
        ipv6Handshake(pair[1]);
        tunneledTcp(pair[1], first, username, password);
        check(socksAddressCorrect.load(), "TUN connections use the selected IPv4 or IPv6 local SOCKS listener");
        clahsos::stopTunnel();
        check(clahsos::tunnelStatus().find("\"running\":false") != std::string::npos, "stop joins tunnel worker");
        check(fcntl(pair[0], F_GETFD) >= 0, "engine preserves caller ownership of original fd");
        clahsos::stopTunnel();
        close(pair[0]); close(pair[1]);
    }
    std::cout << "TUN packet checks passed: " << checks << '\n';
}
