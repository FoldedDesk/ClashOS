// RFC 9110 CONNECT and RFC 1928/1929 clients, over TCP or verified TLS.
struct ForwardProxySession {
    TlsChannel channel;
    VmBytes buffered;
    std::string boundHost;
    int boundPort = 0;
    bool sentEof = false;
    explicit ForwardProxySession(int fd) : channel(fd) {}
    bool exact(unsigned char* target, size_t size) {
        while (size) {
            const auto n = channel.readBytes(target, size);
            if (n <= 0) { if (n == 0) errno = EPROTO; return false; }
            target += n; size -= static_cast<size_t>(n);
        }
        return true;
    }
    bool socks(const ProxyNode& node, const std::string& host, int port, bool udp, std::string& error) {
        const bool auth = !node.username.empty() || !node.password.empty();
        const unsigned char method = auth ? 2 : 0;
        const unsigned char hello[] = {5, 1, method}; unsigned char response[4];
        if (!channel.writeBytes(hello, sizeof(hello)) || !exact(response, 2) || response[0] != 5 || response[1] != method) {
            error = "SOCKS5 server rejected the requested authentication method"; return false;
        }
        if (auth) {
            VmBytes login{1, static_cast<unsigned char>(node.username.size())}; vmAppend(login, vmBytes(node.username));
            login.push_back(static_cast<unsigned char>(node.password.size())); vmAppend(login, vmBytes(node.password));
            if (!channel.writeBytes(login.data(), login.size()) || !exact(response, 2) || response[0] != 1 || response[1] != 0) {
                error = "SOCKS5 username/password authentication failed"; return false;
            }
        }
        VmBytes request{5, static_cast<unsigned char>(udp ? 3 : 1), 0};
        vmAppend(request, shadowsocksAddress(udp ? "0.0.0.0" : host, udp ? 0 : port));
        if (!channel.writeBytes(request.data(), request.size()) || !exact(response, 4) || response[0] != 5 || response[1] != 0 || response[2] != 0) {
            error = udp ? "SOCKS5 UDP ASSOCIATE failed" : "SOCKS5 CONNECT failed"; return false;
        }
        const size_t size = response[3] == 1 ? 4 : response[3] == 4 ? 16 : 0;
        if (size) {
            unsigned char bytes[16]; char text[INET6_ADDRSTRLEN]{};
            if (!exact(bytes, size) || !inet_ntop(size == 4 ? AF_INET : AF_INET6, bytes, text, sizeof(text))) return false;
            boundHost = text;
        } else if (response[3] == 3) {
            unsigned char length;
            if (!exact(&length, 1) || length == 0) { error = "Invalid SOCKS5 bound address"; return false; }
            boundHost.resize(length);
            if (!exact(reinterpret_cast<unsigned char*>(boundHost.data()), length) || boundHost.find('\0') != std::string::npos) return false;
        } else { error = "Invalid SOCKS5 reply address type"; return false; }
        if (!exact(response, 2)) return false;
        boundPort = (static_cast<int>(response[0]) << 8) | response[1];
        if (udp && boundPort == 0) { error = "SOCKS5 UDP relay returned port zero"; return false; }
        if (udp && (boundHost == "0.0.0.0" || boundHost == "::")) {
            sockaddr_storage peer{}; socklen_t length = sizeof(peer); char text[INET6_ADDRSTRLEN]{};
            boundHost = node.server;
            if (getpeername(channel.fd, reinterpret_cast<sockaddr*>(&peer), &length) == 0) {
                if (peer.ss_family == AF_INET && inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(&peer)->sin_addr, text, sizeof(text))) boundHost = text;
                else if (peer.ss_family == AF_INET6 && inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(&peer)->sin6_addr, text, sizeof(text))) boundHost = text;
            }
        }
        return true;
    }
    bool http(const ProxyNode& node, const std::string& host, int port, std::string& error) {
        const std::string authority = (host.find(':') == std::string::npos ? host : "[" + host + "]") + ":" + std::to_string(port);
        std::string request = "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\nProxy-Connection: Keep-Alive\r\n";
        if (!node.username.empty() || !node.password.empty()) request += "Proxy-Authorization: Basic " + vmBase64(vmBytes(node.username + ":" + node.password)) + "\r\n";
        for (const auto& field : node.httpHeaders) request += field.first + ": " + field.second + "\r\n";
        request += "\r\n";
        if (!channel.writeBytes(reinterpret_cast<const unsigned char*>(request.data()), request.size())) return false;
        std::string input; size_t consumed = 0;
        for (unsigned int interim = 0; interim < 8; ++interim) {
            size_t end;
            while ((end = input.find("\r\n\r\n")) == std::string::npos) {
                unsigned char bytes[16384]; const auto n = channel.readBytes(bytes, sizeof(bytes));
                if (n <= 0) { error = "HTTP proxy closed before a CONNECT response"; return false; }
                input.append(reinterpret_cast<const char*>(bytes), static_cast<size_t>(n));
                if (input.find("\r\n\r\n") == std::string::npos && consumed + input.size() > 65536) { error = "HTTP proxy response headers are too large"; return false; }
            }
            consumed += end + 4;
            const auto lineEnd = input.find("\r\n"); const auto line = input.substr(0, lineEnd);
            if (consumed > 65536 || line.size() < 12 || (line.substr(0, 9) != "HTTP/1.1 " && line.substr(0, 9) != "HTTP/1.0 ") ||
                !std::all_of(line.begin() + 9, line.begin() + 12, [](unsigned char ch) { return ch >= '0' && ch <= '9'; }) ||
                (line.size() > 12 && line[12] != ' ') || input.substr(0, end).find('\0') != std::string::npos) {
                error = "Malformed HTTP proxy CONNECT response"; return false;
            }
            const int status = std::atoi(line.substr(9, 3).c_str());
            input.erase(0, end + 4);
            if (status >= 200 && status <= 299) { buffered.assign(input.begin(), input.end()); return true; }
            if (status < 100 || status >= 200 || status == 101) {
                error = status == 407 ? "HTTP proxy authentication required or rejected" : "HTTP proxy CONNECT was rejected (" + std::to_string(status) + ")"; return false;
            }
        }
        error = "Too many HTTP proxy informational responses"; return false;
    }
    bool start(const ProxyNode& node, const std::string& host, int port, bool udp, std::string& error) {
        error = forwardProxyError(node); if (!error.empty()) return false;
        if ((!udp && (host.empty() || host.find_first_of("\r\n \t") != std::string::npos || host.find('\0') != std::string::npos || host.size() > 255 || port < 1 || port > 65535)) ||
            (udp && node.type != "socks5")) { error = "Invalid forward proxy destination or UDP protocol"; return false; }
        if (!udp && node.type == "http" && (host.find_first_of("/@#?\\") != std::string::npos ||
            std::any_of(host.begin(), host.end(), [](unsigned char ch) { return ch < 32 || ch == 127; }))) { error = "Invalid HTTP CONNECT authority"; return false; }
        const char* roots = nullptr;
#ifdef CLAHSOS_HOST_TEST
        roots = g_testVmessTrust;
#endif
        if (node.tls && !channel.start(node.serverName.empty() ? node.server : node.serverName, node.skipCertVerify,
            error, roots, node.type == "http" ? std::vector<std::string>{"http/1.1"} : node.alpn)) return false;
        const bool ok = node.type == "http" ? http(node, host, port, error) : socks(node, host, port, udp, error);
        if (!ok) { if (error.empty()) error = "Forward proxy handshake was interrupted"; errno = EPROTO; }
        return ok;
    }
    bool write(const unsigned char* bytes, size_t size) {
        if (sentEof) { errno = EPIPE; return false; }
        return size == 0 || channel.writeBytes(bytes, size);
    }
    bool read(VmBytes& output, bool nonblocking = false) {
        output.clear(); errno = 0;
        if (!buffered.empty()) { output.swap(buffered); return true; }
        output.resize(16384); const auto n = nonblocking ? channel.readAvailable(output.data(), output.size()) : channel.readBytes(output.data(), output.size());
        if (n <= 0) { if (n == 0) errno = 0; output.clear(); return false; }
        output.resize(static_cast<size_t>(n)); return true;
    }
    bool pending() const { return !buffered.empty() || channel.pending(); }
    bool finish() {
        if (sentEof) return true; sentEof = true;
        return channel.enabled ? mbedtls_ssl_close_notify(&channel.ssl) == 0 : shutdown(channel.fd, SHUT_WR) == 0;
    }
};
