bool inboundCredentialPart(const std::string& text, bool username)
{
    return !text.empty() && text.size() <= 255 && shareUtf8(text) &&
        std::none_of(text.begin(), text.end(), [&](unsigned char ch) { return ch < 32 || ch == 127 || (username && ch == ':'); });
}

bool normalizeInboundConfig(InboundConfig& config, std::string& error)
{
    std::string address = config.bindAddress;
    if (address.size() >= 2 && address.front() == '[' && address.back() == ']') address = address.substr(1, address.size() - 2);
    if (address == "localhost") address = "127.0.0.1";
    int family = 0; std::array<unsigned char, 16> bytes{};
    if (address != "*" && !ruleIpAddress(address, family, bytes)) { error = "bind-address must be *, an IPv4 address or an IPv6 address"; return false; }
    if (address != "*") {
        char normalized[INET6_ADDRSTRLEN]{};
        if (!inet_ntop(family == 4 ? AF_INET : AF_INET6, bytes.data() + (family == 4 ? 12 : 0), normalized, sizeof(normalized))) { error = "Invalid inbound address"; return false; }
        address = normalized;
    }
    config.bindAddress = address;
    if (config.users.size() > 128) { error = "At most 128 proxy authentication accounts are supported"; return false; }
    std::set<std::string> names;
    for (const auto& user : config.users) {
        if (!inboundCredentialPart(user.first, true) || !inboundCredentialPart(user.second, false) || !names.insert(user.first).second) {
            error = "Proxy accounts require unique usernames and nonempty UTF-8 credentials up to 255 bytes; control characters are not allowed"; return false;
        }
    }
    auto ranges = [&](const std::vector<std::string>& source, std::vector<RuleIpRange>& destination, const char* name) {
        if (source.size() > 256) { error = std::string(name) + " has too many prefixes"; return false; }
        destination.clear();
        for (const auto& text : source) {
            RuleIpRange range;
            if (!parseRuleCidr(text, range)) { error = std::string(name) + " requires valid IPv4/IPv6 CIDR prefixes"; return false; }
            destination.push_back(range);
        }
        return true;
    };
    return ranges(config.skipAuth, config.skipRanges, "skip-auth-prefixes") && ranges(config.allowed, config.allowedRanges, "lan-allowed-ips") &&
        ranges(config.denied, config.deniedRanges, "lan-disallowed-ips");
}

bool parseInboundConfig(yaml_document_t& document, yaml_node_t* root, InboundConfig& config, std::string& error)
{
    auto* lan = yamlValue(document, root, "allow-lan");
    if (lan) {
        const auto value = lower(yamlText(lan));
        if (lan->type != YAML_SCALAR_NODE || (value != "true" && value != "false")) { error = "allow-lan must be true or false"; return false; }
        config.allowLan = value == "true";
    }
    if (auto* bind = yamlValue(document, root, "bind-address")) {
        if (bind->type != YAML_SCALAR_NODE) { error = "bind-address must be a string"; return false; }
        config.bindAddress = yamlText(bind);
    }
    auto list = [&](const char* key, std::vector<std::string>& output) {
        auto* node = yamlValue(document, root, key); if (!node) return true;
        if (node->type != YAML_SEQUENCE_NODE) { error = std::string(key) + " must be a list"; return false; }
        output.clear();
        for (auto* item = node->data.sequence.items.start; item < node->data.sequence.items.top; ++item) {
            auto* value = yaml_document_get_node(&document, *item);
            if (!value || value->type != YAML_SCALAR_NODE || output.size() >= 256) { error = std::string("Invalid ") + key + " list"; return false; }
            output.push_back(yamlText(value));
        }
        return true;
    };
    std::vector<std::string> authentication;
    if (!list("authentication", authentication) || !list("skip-auth-prefixes", config.skipAuth) ||
        !list("lan-allowed-ips", config.allowed) || !list("lan-disallowed-ips", config.denied)) return false;
    config.users.clear();
    for (const auto& value : authentication) {
        const auto colon = value.find(':');
        if (colon == std::string::npos) { error = "authentication entries require username:password"; return false; }
        config.users.emplace_back(value.substr(0, colon), value.substr(colon + 1));
    }
    return normalizeInboundConfig(config, error);
}

std::string inboundSourceAddress(int client, bool& localUnix)
{
    sockaddr_storage address{}; socklen_t size = sizeof(address); localUnix = false;
    if (getpeername(client, reinterpret_cast<sockaddr*>(&address), &size) != 0) return "";
    char text[INET6_ADDRSTRLEN]{};
    if (address.ss_family == AF_INET) inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(&address)->sin_addr, text, sizeof(text));
    else if (address.ss_family == AF_INET6) {
        const auto& ip = reinterpret_cast<sockaddr_in6*>(&address)->sin6_addr;
        if (IN6_IS_ADDR_V4MAPPED(&ip)) inet_ntop(AF_INET, &ip.s6_addr[12], text, sizeof(text));
        else inet_ntop(AF_INET6, &ip, text, sizeof(text));
    } else if (address.ss_family == AF_UNIX) localUnix = true;
    return text;
}

bool inboundLoopback(const std::string& source)
{
    int family = 0; std::array<unsigned char, 16> ip{};
    if (!ruleIpAddress(source, family, ip)) return false;
    if (family == 4) return ip[12] == 127;
    return std::all_of(ip.begin(), ip.end() - 1, [](unsigned char ch) { return ch == 0; }) && ip[15] == 1;
}

bool inboundClientAllowed(const InboundConfig& config, const std::string& source, bool localUnix = false)
{
    if (localUnix) return true;
    if (!config.allowLan) return inboundLoopback(source);
    return !ruleRangesMatch(config.deniedRanges, source) && ruleRangesMatch(config.allowedRanges, source);
}

bool inboundRequiresAuth(const InboundConfig& config, const std::string& source)
{
    return !config.users.empty() && !ruleRangesMatch(config.skipRanges, source);
}

bool inboundAccountEqual(const std::string& first, const std::string& second)
{
    unsigned difference = static_cast<unsigned>(first.size() ^ second.size());
    for (size_t i = 0; i < 256; ++i) difference |= (i < first.size() ? static_cast<unsigned char>(first[i]) : 0) ^
        (i < second.size() ? static_cast<unsigned char>(second[i]) : 0);
    return difference == 0;
}

bool inboundAuthenticate(const InboundConfig& config, const std::string& username, const std::string& password)
{
    if (username.size() > 255 || password.size() > 255) return false;
    unsigned matched = 0;
    for (const auto& user : config.users) matched |= inboundAccountEqual(user.first, username) & inboundAccountEqual(user.second, password);
    return matched != 0;
}

std::string inboundLocalAddress(const InboundConfig& config)
{
    return !config.allowLan || config.bindAddress == "*" || config.bindAddress == "0.0.0.0" ? "127.0.0.1" :
        config.bindAddress == "::" ? "::1" : config.bindAddress;
}

std::vector<std::string> inboundBindAddresses(const InboundConfig& config)
{
    if (!config.allowLan) return {"127.0.0.1"};
    if (config.bindAddress == "*") return {"0.0.0.0", "::"};
    return {config.bindAddress};
}
