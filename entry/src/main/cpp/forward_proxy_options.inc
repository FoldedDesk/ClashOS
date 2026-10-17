// Shared configuration and programmatic-node preflight. Never echo credentials.
std::string forwardProxyError(const ProxyNode& node)
{
    if (!node.transportError.empty()) return node.transportError;
    if (node.network != "tcp") return "HTTP and SOCKS5 outbounds require TCP transport";
    const auto control = [](const std::string& text) { return std::any_of(text.begin(), text.end(), [](unsigned char ch) { return ch < 32 || ch == 127; }); };
    if (node.serverName.find('\0') != std::string::npos || control(node.serverName)) return "Invalid proxy TLS server name";
    const bool auth = !node.username.empty() || !node.password.empty();
    if (node.type == "socks5" && auth && (node.username.empty() || node.password.empty() || node.username.size() > 255 || node.password.size() > 255))
        return "SOCKS5 username and password must each contain 1 to 255 bytes";
    if (node.type == "http" && (node.username.find(':') != std::string::npos || control(node.username) || control(node.password) || node.username.size() + node.password.size() > 4096))
        return "Invalid HTTP proxy username or password";
    if (node.type == "http" && !node.alpn.empty() && std::find(node.alpn.begin(), node.alpn.end(), "http/1.1") == node.alpn.end())
        return "HTTP CONNECT requires HTTP/1.1 ALPN";
    std::set<std::string> found; size_t total = 0;
    for (const auto& header : node.httpHeaders) {
        const auto name = lower(header.first); total += header.first.size() + header.second.size() + 4;
        if (node.type != "http" || header.first.empty() || header.first.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`|~") != std::string::npos ||
            control(header.second) || total > 16384 || !found.insert(name).second) return "Invalid or duplicate HTTP proxy header";
        if (name == "host" || name == "content-length" || name == "transfer-encoding" || name == "connection" || name == "proxy-connection" || name == "upgrade" || (name == "proxy-authorization" && auth))
            return "HTTP proxy header conflicts with managed CONNECT headers";
    }
    return {};
}
