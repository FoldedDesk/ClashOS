// Application-managed controller credentials. Never serialize these in runtime,
// config, VPN state, node metadata or logs; only trusted NAPI callers can read/write.
bool setControllerSecret(const std::string& secret)
{
    if (secret.size() > 256 || !std::all_of(secret.begin(), secret.end(), [](unsigned char ch) { return ch >= 0x21 && ch <= 0x7e; })) return false;
    std::string prepared = secret;
    std::lock_guard<std::mutex> lock(g_state.mutex);
    if (g_state.controllerSecret != prepared) { g_state.controllerSecret.swap(prepared); g_state.controllerAuthEpoch.fetch_add(1); }
    return true;
}

std::string controllerSecret()
{
    std::lock_guard<std::mutex> lock(g_state.mutex); return g_state.controllerSecret;
}

bool controllerSecretEqual(const std::string& a, const std::string& b)
{
    if (a.size() > 256 || b.size() > 256) return false;
    unsigned difference = static_cast<unsigned>(a.size() ^ b.size());
    for (size_t i = 0; i < 256; ++i) difference |= (i < a.size() ? static_cast<unsigned char>(a[i]) : 0) ^
        (i < b.size() ? static_cast<unsigned char>(b[i]) : 0);
    return difference == 0;
}

bool controllerAuthTokenQuery(const std::string& path, std::string& token)
{
    auto decode = [](const std::string& raw, std::string& value) {
        value.clear();
        auto hex = [](char ch) { if (ch >= '0' && ch <= '9') return ch - '0'; if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10; if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10; return -1; };
        for (size_t i = 0; i < raw.size(); ++i) {
            unsigned char ch = raw[i];
            if (ch == '%') {
                if (i + 2 >= raw.size() || hex(raw[i+1]) < 0 || hex(raw[i+2]) < 0) return false;
                ch = static_cast<unsigned char>((hex(raw[i+1]) << 4) | hex(raw[i+2])); i += 2;
            } else if (ch == '+') ch = ' ';
            if (ch < 0x20 || ch == 0x7f) return false;
            value += static_cast<char>(ch);
        }
        return true;
    };
    const auto question = path.find('?'); if (question == std::string::npos) return true;
    bool seen = false; std::istringstream query(path.substr(question + 1)); std::string part;
    while (std::getline(query, part, '&')) {
        const auto equal = part.find('='); std::string key, value;
        if (!decode(part.substr(0, equal), key) || !decode(equal == std::string::npos ? "" : part.substr(equal + 1), value)) return false;
        if (key == "token") { if (seen || value.size() > 256) return false; seen = true; token = value; }
    }
    return true;
}

struct ControllerAuthentication { bool allowed; uint64_t epoch; };
ControllerAuthentication authenticateController(const std::map<std::string, std::string>& headers, const std::string& path)
{
    std::string required; uint64_t epoch;
    { std::lock_guard<std::mutex> lock(g_state.mutex); required = g_state.controllerSecret; epoch = g_state.controllerAuthEpoch.load(); }
    if (required.empty()) return {true, epoch};
    auto header = [&](const char* name) { const auto it = headers.find(name); return it == headers.end() ? std::string{} : it->second; };
    std::istringstream upgrades(header("upgrade")); std::string value; bool websocket = false;
    while (std::getline(upgrades, value, ',')) if (lower(trim(value)) == "websocket") websocket = true;
    if (websocket) {
        std::string token;
        if (!controllerAuthTokenQuery(path, token)) return {false, epoch};
        if (!token.empty()) return {controllerSecretEqual(token, required), epoch};
    }
    const std::string authorization = header("authorization");
    if (authorization.size() < 7 || lower(authorization.substr(0, 7)) != "bearer ") return {false, epoch};
    return {controllerSecretEqual(authorization.substr(7), required), epoch};
}
