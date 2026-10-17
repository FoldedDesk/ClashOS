std::string inboundStringsJson(const std::vector<std::string>& values)
{
    std::string json = "[";
    for (const auto& value : values) { if (json.size() > 1) json += ","; json += "\"" + jsonEscape(value) + "\""; }
    return json + "]";
}

std::string inboundFieldsJson(const InboundConfig& config)
{
    return std::string("\"allow-lan\":") + (config.allowLan ? "true" : "false") + ",\"bind-address\":\"" + jsonEscape(config.bindAddress) +
        "\",\"skip-auth-prefixes\":" + inboundStringsJson(config.skipAuth) + ",\"lan-allowed-ips\":" + inboundStringsJson(config.allowed) +
        ",\"lan-disallowed-ips\":" + inboundStringsJson(config.denied);
}

bool inboundJsonConfig(ControllerConfigJson& json, InboundConfig& config, std::string& error)
{
    std::vector<std::string> accounts;
    for (const auto& user : config.users) accounts.push_back(user.first + ":" + user.second);
    if (!json.boolean("allow-lan", config.allowLan, error) || !json.string("bind-address", config.bindAddress, error) ||
        !json.strings("skip-auth-prefixes", config.skipAuth, error) || !json.strings("lan-allowed-ips", config.allowed, error) ||
        !json.strings("lan-disallowed-ips", config.denied, error) || !json.strings("authentication", accounts, error)) return false;
    config.users.clear();
    for (const auto& account : accounts) {
        const auto colon = account.find(':');
        if (colon == std::string::npos) { error = "authentication entries require username:password"; return false; }
        config.users.emplace_back(account.substr(0, colon), account.substr(colon + 1));
    }
    return normalizeInboundConfig(config, error);
}

std::string inboundSettingsPath(const std::string& profile)
{
    const auto slash = profile.find_last_of('/');
    return slash == std::string::npos ? std::string{} : profile.substr(0, slash + 1) + ".clashos-inbound";
}

bool readInboundSettings(const std::string& profile, InboundConfig& config, bool& overridden, std::string& error)
{
    const auto path = inboundSettingsPath(profile); overridden = false;
    if (path.empty()) return true;
    struct stat status{};
    if (lstat(path.c_str(), &status) != 0) {
        if (errno == ENOENT) return true;
        error = "Cannot inspect saved inbound settings"; return false;
    }
    std::string text; ControllerConfigJson json;
    if (!readControllerFile(path, 128 * 1024, text, error) || !json.parse(text, error) ||
        !json.keys({"allow-lan", "bind-address", "authentication", "skip-auth-prefixes", "lan-allowed-ips", "lan-disallowed-ips"}, error) ||
        !inboundJsonConfig(json, config, error)) { error = "Saved inbound settings are invalid"; return false; }
    overridden = true; return true;
}

bool stageInboundSettings(const std::string& path, const InboundConfig& config, std::string& temporary, std::string& error)
{
    std::vector<std::string> accounts;
    for (const auto& user : config.users) accounts.push_back(user.first + ":" + user.second);
    const auto bytes = "{" + inboundFieldsJson(config) + ",\"authentication\":" + inboundStringsJson(accounts) + "}";
    static std::atomic<uint64_t> serial{0};
    temporary = path + ".tmp-" + std::to_string(getpid()) + "-" + std::to_string(++serial);
    const int fd = open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) { error = "Cannot save inbound settings"; return false; }
    size_t offset = 0;
    while (offset < bytes.size()) {
        const auto n = write(fd, bytes.data() + offset, bytes.size() - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        offset += static_cast<size_t>(n);
    }
    const bool written = offset == bytes.size() && fsync(fd) == 0; close(fd);
    if (!written) { unlink(temporary.c_str()); error = "Cannot save inbound settings"; }
    return written;
}

std::string inboundStatusLocked()
{
    std::vector<std::string> users;
    for (const auto& user : g_state.inbound.users) users.push_back(user.first);
    std::string endpoints = "[";
    for (const auto& listener : g_state.listeners) {
        if (endpoints.size() > 1) endpoints += ",";
        endpoints += "{\"address\":\"" + jsonEscape(listener->host) + "\",\"port\":" + std::to_string(listener->port) + "}";
    }
    return "{" + inboundFieldsJson(g_state.inbound) + ",\"users\":" + inboundStringsJson(users) + ",\"localAddress\":\"" +
        jsonEscape(inboundLocalAddress(g_state.inbound)) + "\",\"listeners\":" + endpoints + "],\"overridden\":" +
        (g_state.inboundOverridden ? "true" : "false") + ",\"profile\":\"" + jsonEscape(g_state.configPath) +
        "\",\"revision\":" + std::to_string(g_state.configRevision) + "}";
}

bool inboundJsonUsers(ControllerConfigJson& json, InboundConfig& config, std::string& error)
{
    JSContext* ctx = json.context; JSValue users = JS_GetPropertyStr(ctx, json.root, "users");
    if (JS_IsUndefined(users)) { JS_FreeValue(ctx, users); return true; }
    bool valid = JS_IsArray(ctx, users) == 1; uint32_t count = 0;
    JSValue length = JS_GetPropertyStr(ctx, users, "length");
    valid = valid && JS_ToUint32(ctx, &count, length) == 0 && count <= 128; JS_FreeValue(ctx, length);
    std::vector<std::pair<std::string, std::string>> result;
    for (uint32_t i = 0; valid && i < count; ++i) {
        JSValue item = JS_GetPropertyUint32(ctx, users, i);
        valid = JS_IsObject(item) && JS_IsArray(ctx, item) == 0;
        JSPropertyEnum* keys = nullptr; uint32_t keyCount = 0;
        if (valid) valid = JS_GetOwnPropertyNames(ctx, &keys, &keyCount, item, JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0;
        for (uint32_t k = 0; k < keyCount; ++k) {
            const char* key = JS_AtomToCString(ctx, keys[k].atom);
            valid = valid && key && (std::strcmp(key, "username") == 0 || std::strcmp(key, "password") == 0);
            if (key) JS_FreeCString(ctx, key); JS_FreeAtom(ctx, keys[k].atom);
        }
        if (keys) js_free(ctx, keys);
        JSValue name = JS_GetPropertyStr(ctx, item, "username"), secret = JS_GetPropertyStr(ctx, item, "password");
        std::string username, password;
        auto string = [&](JSValue value, std::string& output) {
            if (!JS_IsString(value)) return false;
            size_t size = 0; const char* text = JS_ToCStringLen(ctx, &size, value);
            if (!text) return false;
            output.assign(text, size); JS_FreeCString(ctx, text); return true;
        };
        valid = valid && string(name, username);
        if (JS_IsUndefined(secret)) {
            const auto existing = std::find_if(config.users.begin(), config.users.end(), [&](const auto& user) { return user.first == username; });
            if (existing == config.users.end()) valid = false; else password = existing->second;
        } else valid = valid && string(secret, password);
        if (valid) result.emplace_back(username, password);
        JS_FreeValue(ctx, name); JS_FreeValue(ctx, secret); JS_FreeValue(ctx, item);
    }
    JS_FreeValue(ctx, users);
    if (!valid) { error = "Accounts require username and password; only existing usernames may keep their saved password"; return false; }
    config.users = std::move(result); return true;
}

// Private NAPI-only bridge for the in-process VPN engine. Never return these
// credentials through the controller, runtime status, Want or state files.
std::string localSocksOptions()
{
    std::lock_guard<std::mutex> lock(g_state.mutex);
    const auto& config = g_state.inbound; const auto address = inboundLocalAddress(config);
    if (!g_state.running.load() || g_state.socksPort <= 0) return "{\"error\":\"Local SOCKS ingress is not running\"}";
    if (!inboundClientAllowed(config, address)) return "{\"error\":\"Local SOCKS ingress is excluded by the LAN access rules\"}";
    const bool auth = inboundRequiresAuth(config, address);
    return "{\"address\":\"" + jsonEscape(address) + "\",\"port\":" + std::to_string(g_state.socksPort) +
        ",\"username\":\"" + jsonEscape(auth ? config.users.front().first : "") +
        "\",\"password\":\"" + jsonEscape(auth ? config.users.front().second : "") + "\"}";
}
