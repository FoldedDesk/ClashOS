// Private NAPI backup bridge. Controller responses never expose these accounts.
struct NetworkBackupSettings {
    bool hasPorts = false, hasInbound = false;
    ProxyPortSettings ports;
    InboundConfig inbound;
};

std::string networkPortsJson(const ProxyPortSettings& p)
{
    return "{\"http\":" + std::to_string(p.http) + ",\"socks\":" + std::to_string(p.socks) + ",\"mixed\":" + std::to_string(p.mixed) + "}";
}
std::string networkInboundJson(const InboundConfig& inbound)
{
    std::vector<std::string> accounts;
    for (const auto& user : inbound.users) accounts.push_back(user.first + ":" + user.second);
    return "{" + inboundFieldsJson(inbound) + ",\"authentication\":" + inboundStringsJson(accounts) + "}";
}
std::string networkBackupJson(const NetworkBackupSettings& settings)
{
    return "{\"version\":1,\"ports\":" + (settings.hasPorts ? networkPortsJson(settings.ports) : "null") +
        ",\"inbound\":" + (settings.hasInbound ? networkInboundJson(settings.inbound) : "null") + "}";
}
bool networkRequiredFields(ControllerConfigJson& json, const std::map<std::string, int>& fields, std::string& error)
{
    for (const auto& field : fields) {
        JSValue value = JS_GetPropertyStr(json.context, json.root, field.first.c_str());
        const bool okay = field.second == 0 ? JS_IsBool(value) : field.second == 1 ? JS_IsString(value) :
            field.second == 2 ? JS_IsArray(json.context, value) == 1 : JS_IsNumber(value);
        JS_FreeValue(json.context, value);
        if (!okay) { error = "Network backup has a missing or invalid field"; return false; }
    }
    return true;
}
bool parseNetworkPorts(const std::string& text, ProxyPortSettings& ports, std::string& error)
{
    ControllerConfigJson json;
    if (!json.parse(text, error) || !json.keys({"http", "socks", "mixed"}, error) ||
        !networkRequiredFields(json, {{"http", 3}, {"socks", 3}, {"mixed", 3}}, error) ||
        !json.port("http", ports.http, error) || !json.port("socks", ports.socks, error) || !json.port("mixed", ports.mixed, error)) return false;
    ports.overridden = true; return true;
}
bool parseNetworkInbound(const std::string& text, InboundConfig& inbound, std::string& error)
{
    ControllerConfigJson json;
    return json.parse(text, error) && json.keys({"allow-lan", "bind-address", "authentication", "skip-auth-prefixes", "lan-allowed-ips", "lan-disallowed-ips"}, error) &&
        networkRequiredFields(json, {{"allow-lan", 0}, {"bind-address", 1}, {"authentication", 2}, {"skip-auth-prefixes", 2}, {"lan-allowed-ips", 2}, {"lan-disallowed-ips", 2}}, error) && inboundJsonConfig(json, inbound, error);
}
bool parseNetworkBackup(const std::string& text, NetworkBackupSettings& settings, std::string& error)
{
    if (text.size() > 128 * 1024) { error = "Network backup exceeds its size limit"; return false; }
    ControllerConfigJson json; int version = 0;
    if (!json.parse(text, error) || !json.keys({"version", "ports", "inbound"}, error) ||
        !networkRequiredFields(json, {{"version", 3}}, error) || !json.port("version", version, error) || version != 1) return false;
    auto member = [&](const char* name, bool& present, std::string& output) {
        JSValue value = JS_GetPropertyStr(json.context, json.root, name);
        if (JS_IsNull(value)) { present = false; JS_FreeValue(json.context, value); return true; }
        bool valid = JS_IsObject(value) && JS_IsArray(json.context, value) == 0;
        JSValue encoded = valid ? JS_JSONStringify(json.context, value, JS_UNDEFINED, JS_UNDEFINED) : JS_UNDEFINED;
        size_t size = 0; const char* bytes = JS_IsString(encoded) ? JS_ToCStringLen(json.context, &size, encoded) : nullptr;
        valid = valid && bytes;
        if (valid) { present = true; output.assign(bytes, size); }
        if (bytes) JS_FreeCString(json.context, bytes); JS_FreeValue(json.context, encoded); JS_FreeValue(json.context, value); return valid;
    };
    std::string ports, inbound;
    return member("ports", settings.hasPorts, ports) && member("inbound", settings.hasInbound, inbound) &&
        (!settings.hasPorts || parseNetworkPorts(ports, settings.ports, error)) && (!settings.hasInbound || parseNetworkInbound(inbound, settings.inbound, error));
}
std::string networkBackupRevision(const std::string& text)
{
    std::array<unsigned char, 32> digest{};
    if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), reinterpret_cast<const unsigned char*>(text.data()), text.size(), digest.data()) != 0) return {};
    static const char hex[] = "0123456789abcdef"; std::string result;
    for (auto value : digest) { result += hex[value >> 4]; result += hex[value & 15]; } return result;
}
bool networkBackupDirectory(const std::string& directory, std::string& resolved, std::string& error)
{
    std::array<char, PATH_MAX> real{}; struct stat status{};
    const auto slash = g_state.runtimeDirectory.find_last_of('/');
    if (g_state.runtimeDirectory.empty() || directory.find('\0') != std::string::npos || lstat(directory.c_str(), &status) != 0 ||
        !S_ISDIR(status.st_mode) || status.st_uid != getuid() || !realpath(directory.c_str(), real.data()) ||
        std::string(real.data()) != g_state.runtimeDirectory.substr(0, slash) + "/profiles") {
        error = "Network backup directory is unavailable"; return false;
    }
    resolved = real.data(); return true;
}
bool readNetworkBackupFile(const std::string& path, size_t limit, std::string& bytes, bool& present, std::string& error)
{
    struct stat status{}; present = lstat(path.c_str(), &status) == 0;
    if (!present) { if (errno == ENOENT) return true; error = "Cannot inspect network preferences"; return false; }
    if (!S_ISREG(status.st_mode) || status.st_uid != getuid() || !readControllerFile(path, limit, bytes, error)) { error = "Saved network preferences are invalid"; return false; }
    return true;
}
bool readNetworkBackup(const std::string& directory, NetworkBackupSettings& settings, std::array<std::string, 2>& bytes, std::string& error)
{
    if (!readNetworkBackupFile(directory + "/.clashos-ports", 128, bytes[0], settings.hasPorts, error) ||
        !readNetworkBackupFile(directory + "/.clashos-inbound", 128 * 1024, bytes[1], settings.hasInbound, error)) return false;
    if (settings.hasPorts) {
        std::istringstream input(bytes[0]); std::string version, extra;
        if (!(input >> version >> settings.ports.http >> settings.ports.socks >> settings.ports.mixed) || version != "ClashOS-ports-v1" || (input >> extra) || !validProxyPorts(settings.ports)) {
            error = "Saved network preferences are invalid"; return false;
        }
        settings.ports.overridden = true;
    }
    return !settings.hasInbound || parseNetworkInbound(bytes[1], settings.inbound, error);
}
std::string validateNetworkBackup(const std::string& text)
{
    NetworkBackupSettings settings; std::string error;
    if (!parseNetworkBackup(text, settings, error)) return "{\"error\":\"Network backup is invalid\"}";
    return networkBackupJson(settings);
}
std::string networkBackupSnapshot(const std::string& directory)
{
    std::lock_guard<std::mutex> lock(g_state.mutex);
    NetworkBackupSettings settings; std::array<std::string, 2> bytes; std::string resolved, error;
    if (!networkBackupDirectory(directory, resolved, error) || !readNetworkBackup(resolved, settings, bytes, error)) return "{\"error\":\"Cannot read saved network preferences\"}";
    const auto text = networkBackupJson(settings), revision = networkBackupRevision(text);
    if (revision.empty()) return "{\"error\":\"Cannot identify network preferences\"}";
    return "{\"settings\":" + text + ",\"revision\":\"" + revision + "\"}";
}
struct NetworkBackupFile {
    std::string path, previous, next;
    bool hadPrevious = false, hasNext = false, changed = false, retainPrevious = false;
    ~NetworkBackupFile() { if (!previous.empty() && !retainPrevious) unlink(previous.c_str()); if (!next.empty()) unlink(next.c_str()); }
};
bool stageNetworkBackupFile(const std::string& path, const std::string& bytes, std::string& temporary)
{
    static std::atomic<uint64_t> serial{0};
    temporary = path + ".network-" + std::to_string(getpid()) + "-" + std::to_string(++serial);
    int fd = open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600); if (fd < 0) return false;
    size_t offset = 0;
    while (offset < bytes.size()) { const auto size = write(fd, bytes.data() + offset, bytes.size() - offset); if (size < 0 && errno == EINTR) continue; if (size <= 0) break; offset += static_cast<size_t>(size); }
    const bool okay = offset == bytes.size() && fsync(fd) == 0; close(fd); return okay;
}
std::string restoreNetworkBackup(const std::string& directory, const std::string& text, const std::string& expected, const std::string& profile)
{
    std::lock_guard<std::mutex> lock(g_state.mutex);
    auto fail = [](const std::string& error) { return "{\"error\":\"" + jsonEscape(error) + "\"}"; };
    std::string resolved, error; NetworkBackupSettings previous, next; std::array<std::string, 2> bytes;
    if (!parseNetworkBackup(text, next, error)) return fail("Network backup is invalid");
    if (!networkBackupDirectory(directory, resolved, error) || !readNetworkBackup(resolved, previous, bytes, error)) return fail("Cannot read saved network preferences");
    if (expected.empty() || networkBackupRevision(networkBackupJson(previous)) != expected) return fail("Network preferences changed; preview the backup again");
    const bool running = g_state.running.load();
    const auto slash = profile.find_last_of('/'); std::array<char, PATH_MAX> profileDirectory{};
    if (running && (g_state.temporaryConfig || g_state.configPath != profile || slash == std::string::npos ||
        !realpath(profile.substr(0, slash).c_str(), profileDirectory.data()) || std::string(profileDirectory.data()) != resolved)) return fail("Active configuration changed; select a saved local profile");
    const auto ports = next.hasPorts ? next.ports : g_state.profilePorts;
    const auto inbound = next.hasInbound ? next.inbound : g_state.profileInbound;
    const auto revision = networkBackupRevision(networkBackupJson(next));
    if (revision.empty()) return fail("Cannot identify network preferences");
    std::array<NetworkBackupFile, 2> files;
    files[0].path = resolved + "/.clashos-ports"; files[1].path = resolved + "/.clashos-inbound";
    files[0].hadPrevious = previous.hasPorts; files[1].hadPrevious = previous.hasInbound;
    files[0].hasNext = next.hasPorts; files[1].hasNext = next.hasInbound;
    const std::array<std::string, 2> contents{{"ClashOS-ports-v1 " + std::to_string(next.ports.http) + " " + std::to_string(next.ports.socks) + " " + std::to_string(next.ports.mixed) + "\n", networkInboundJson(next.inbound)}};
    for (size_t i = 0; i < files.size(); ++i) {
        if ((files[i].hadPrevious && !stageNetworkBackupFile(files[i].path, bytes[i], files[i].previous)) ||
            (files[i].hasNext && !stageNetworkBackupFile(files[i].path, contents[i], files[i].next))) return fail("Cannot stage network preferences; previous settings are preserved");
    }
    const auto commit = [&]() {
        for (auto& file : files) {
            const bool okay = file.hasNext ? rename(file.next.c_str(), file.path.c_str()) == 0 : (unlink(file.path.c_str()) == 0 || errno == ENOENT);
            if (okay) { file.changed = true; continue; }
            bool restored = true;
            for (auto it = files.rbegin(); it != files.rend(); ++it) if (it->changed) {
                if (it->hadPrevious) { if (rename(it->previous.c_str(), it->path.c_str()) != 0) { restored = false; it->retainPrevious = true; } }
                else if (unlink(it->path.c_str()) != 0 && errno != ENOENT) restored = false;
            }
            error = restored ? "Cannot commit network preferences; previous settings are preserved" : "Network preference rollback failed; reload and inspect the saved settings";
            return false;
        }
        return true;
    };
    const bool applied = running ? configureProxyListenersLocked(ports.effectiveHttp(), ports.effectiveSocks(), error, commit, &inbound) : commit();
    if (!applied) return fail(error);
    if (running) {
        g_state.portSettings = ports; g_state.httpPort = ports.effectiveHttp(); g_state.socksPort = ports.effectiveSocks();
        g_state.inbound = inbound; g_state.inboundOverridden = next.hasInbound; ++g_state.configRevision;
    }
    coreLog("info", "Network backup preferences restored");
    return "{\"revision\":\"" + revision + "\",\"applied\":" + (running ? "true" : "false") + "}";
}
