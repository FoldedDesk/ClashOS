// Application-level ingress preferences. Keep subscription YAML byte-for-byte intact.
std::string proxyPortSettingsPath(const std::string& profile)
{
    const auto slash = profile.find_last_of('/');
    return slash == std::string::npos ? std::string{} : profile.substr(0, slash + 1) + ".clashos-ports";
}

bool validProxyPorts(const ProxyPortSettings& ports)
{
    return ports.http >= 0 && ports.http <= 65535 && ports.socks >= 0 && ports.socks <= 65535 &&
        ports.mixed >= 0 && ports.mixed <= 65535;
}

bool readProxyPortSettings(const std::string& profile, ProxyPortSettings& ports, std::string& error)
{
    const std::string path = proxyPortSettingsPath(profile);
    if (path.empty()) return true;
    const int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT) return true;
        error = "Cannot read saved proxy port settings"; return false;
    }
    std::array<char, 129> bytes{}; ssize_t size;
    do { size = read(fd, bytes.data(), bytes.size()); } while (size < 0 && errno == EINTR);
    close(fd);
    if (size < 1 || size > 128) { error = "Saved proxy port settings are invalid"; return false; }
    std::istringstream input(std::string(bytes.data(), static_cast<size_t>(size)));
    std::string version, extra; ProxyPortSettings saved;
    if (!(input >> version >> saved.http >> saved.socks >> saved.mixed) || version != "ClashOS-ports-v1" ||
        (input >> extra) || !validProxyPorts(saved)) {
        error = "Saved proxy port settings are invalid"; return false;
    }
    saved.overridden = true; ports = saved; return true;
}

std::string proxyPortsJsonLocked()
{
    const auto& p = g_state.portSettings;
    return "{\"http\":" + std::to_string(p.http) + ",\"socks\":" + std::to_string(p.socks) +
        ",\"mixed\":" + std::to_string(p.mixed) + ",\"overridden\":" + (p.overridden ? "true" : "false") + "}";
}

bool parseProxyPortsRequest(const std::string& body, ProxyPortSettings& ports, std::string& error)
{
    if (body.empty() || body.size() > 1024) { error = "Invalid port settings request"; return false; }
    yaml_parser_t parser; yaml_document_t doc;
    if (!yaml_parser_initialize(&parser)) { error = "Cannot allocate port parser"; return false; }
    yaml_parser_set_input_string(&parser, reinterpret_cast<const unsigned char*>(body.data()), body.size());
    if (!yaml_parser_load(&parser, &doc)) { yaml_parser_delete(&parser); error = "Invalid port settings request"; return false; }
    yaml_node_t* root = yaml_document_get_root_node(&doc);
    bool valid = root && root->type == YAML_MAPPING_NODE;
    std::set<std::string> keys;
    if (valid) for (auto pair = root->data.mapping.pairs.start; pair < root->data.mapping.pairs.top; ++pair) {
        const auto key = yamlText(yaml_document_get_node(&doc, pair->key));
        const auto value = yamlText(yaml_document_get_node(&doc, pair->value));
        if (!keys.insert(key).second || (key != "http" && key != "socks" && key != "mixed") || value.empty() ||
            value.size() > 5 || value.find_first_not_of("0123456789") != std::string::npos) { valid = false; break; }
        const int port = std::atoi(value.c_str());
        if (key == "http") ports.http = port;
        else if (key == "socks") ports.socks = port;
        else ports.mixed = port;
    }
    valid = valid && keys.size() == 3 && validProxyPorts(ports);
    yaml_document_delete(&doc);
    yaml_document_t extra;
    if (!yaml_parser_load(&parser, &extra)) valid = false;
    else { if (yaml_document_get_root_node(&extra) != nullptr) valid = false; yaml_document_delete(&extra); }
    yaml_parser_delete(&parser);
    if (!valid) error = "HTTP, SOCKS5 and mixed ports must be integers between 0 and 65535";
    return valid;
}

std::string proxyPortsControlLocked(const std::string& method, const std::string& path, const std::string& body)
{
    if (method == "GET") return proxyPortsJsonLocked();
    auto failure = [](const std::string& error) { return "{\"error\":\"" + jsonEscape(error) + "\"}"; };
    if (method != "PATCH" && method != "DELETE") return failure("Unsupported proxy port operation");
    if (queryValue(path, "profile") != g_state.configPath || g_state.configPath.empty())
        return failure("Active profile changed; reopen port settings");
    if (g_state.temporaryConfig) return failure("Select a saved profile before saving application port preferences");
    const std::string destination = proxyPortSettingsPath(g_state.configPath);
    if (destination.empty()) return failure("Import a configuration before saving proxy ports");
    ProxyPortSettings ports = g_state.profilePorts;
    std::string error, temporary;
    if (method == "PATCH") {
        if (!parseProxyPortsRequest(body, ports, error)) return failure(error);
        ports.overridden = true;
        static std::atomic<uint64_t> serial{0};
        temporary = destination + ".tmp-" + std::to_string(getpid()) + "-" + std::to_string(++serial);
        const int fd = open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (fd < 0) return failure("Cannot save proxy port settings");
        const std::string text = "ClashOS-ports-v1 " + std::to_string(ports.http) + " " +
            std::to_string(ports.socks) + " " + std::to_string(ports.mixed) + "\n";
        size_t offset = 0;
        while (offset < text.size()) {
            const auto count = write(fd, text.data() + offset, text.size() - offset);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) break;
            offset += static_cast<size_t>(count);
        }
        const bool written = offset == text.size() && fsync(fd) == 0;
        close(fd);
        if (!written) { unlink(temporary.c_str()); return failure("Cannot save proxy port settings"); }
    }
    const auto commit = [&]() {
        const bool saved = method == "PATCH" ? rename(temporary.c_str(), destination.c_str()) == 0 :
            (unlink(destination.c_str()) == 0 || errno == ENOENT);
        if (!saved) error = "Cannot commit proxy port settings; previous listeners have been preserved";
        return saved;
    };
    const bool changed = configureProxyListenersLocked(ports.effectiveHttp(), ports.effectiveSocks(), error, commit);
    if (!temporary.empty()) unlink(temporary.c_str());
    if (!changed) return failure(error);
    g_state.portSettings = ports;
    g_state.httpPort = ports.effectiveHttp(); g_state.socksPort = ports.effectiveSocks();
    coreLog("info", method == "PATCH" ? "Proxy port preferences saved" : "Proxy ports restored from configuration");
    return "{}";
}
