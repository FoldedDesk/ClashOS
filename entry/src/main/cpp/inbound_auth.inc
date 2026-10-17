// A single policy snapshot governs each new ingress handshake. Established relays
// continue when listeners, ACLs or accounts are changed.
bool inboundHandshakePolicy(int client, InboundConfig& policy, std::string& source)
{
    { std::lock_guard<std::mutex> lock(g_state.mutex); policy = g_state.inbound; }
    bool localUnix = false; source = inboundSourceAddress(client, localUnix);
    return inboundClientAllowed(policy, source, localUnix);
}

bool inboundHttpAuthenticated(const InboundConfig& policy, const std::string& source, const std::string& request)
{
    if (!inboundRequiresAuth(policy, source)) return true;
    const auto end = request.find("\r\n\r\n"), first = request.find("\r\n");
    if (end == std::string::npos || first == std::string::npos) return false;
    std::istringstream headers(request.substr(first + 2, end - first - 2));
    std::string line, authorization; unsigned count = 0;
    while (std::getline(headers, line)) {
        const auto colon = line.find(':');
        if (colon != std::string::npos && lower(trim(line.substr(0, colon))) == "proxy-authorization") {
            authorization = trim(line.substr(colon + 1)); ++count;
        }
    }
    const auto space = authorization.find(' ');
    if (count != 1 || space == std::string::npos || lower(authorization.substr(0, space)) != "basic") return false;
    const auto token = trim(authorization.substr(space + 1));
    if (token.empty() || token.size() > 684 || token.size() % 4 != 0) return false;
    const auto padding = token.find('=');
    const auto dataEnd = padding == std::string::npos ? token.size() : padding;
    if (token.size() - dataEnd > 2 || token.find_first_not_of("=", dataEnd) != std::string::npos ||
        token.substr(0, dataEnd).find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") != std::string::npos) return false;
    std::string credentials;
    if (!shareBase64(token, credentials)) return false;
    const auto colon = credentials.find(':');
    return colon != std::string::npos && inboundAuthenticate(policy, credentials.substr(0, colon), credentials.substr(colon + 1));
}

bool inboundSocksAuthenticate(int client, const InboundConfig& policy, const std::string& source)
{
    unsigned char greeting[2];
    if (!readExact(client, reinterpret_cast<char*>(greeting), 2) || greeting[0] != 5 || greeting[1] == 0) return false;
    std::vector<unsigned char> methods(greeting[1]);
    if (!readExact(client, reinterpret_cast<char*>(methods.data()), methods.size())) return false;
    const bool required = inboundRequiresAuth(policy, source);
    const bool anonymous = std::find(methods.begin(), methods.end(), 0) != methods.end();
    const bool password = std::find(methods.begin(), methods.end(), 2) != methods.end() && !policy.users.empty();
    const unsigned char selected = !required && anonymous ? 0 : password ? 2 : 0xff;
    const unsigned char reply[] = {5, selected};
    if (!sendAll(client, reinterpret_cast<const char*>(reply), sizeof(reply)) || selected == 0xff) return false;
    if (selected == 0) return true;
    unsigned char header[2], length = 0;
    if (!readExact(client, reinterpret_cast<char*>(header), 2) || header[0] != 1 || header[1] == 0) return false;
    std::string username(header[1], '\0');
    if (!readExact(client, username.data(), username.size()) || !readExact(client, reinterpret_cast<char*>(&length), 1) || length == 0) return false;
    std::string secret(length, '\0');
    if (!readExact(client, secret.data(), secret.size())) return false;
    const bool accepted = inboundAuthenticate(policy, username, secret);
    const unsigned char result[] = {1, static_cast<unsigned char>(accepted ? 0 : 1)};
    return sendAll(client, reinterpret_cast<const char*>(result), sizeof(result)) && accepted;
}
