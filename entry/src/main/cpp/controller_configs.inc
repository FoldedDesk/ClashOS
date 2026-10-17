std::string controllerConfigsLocked(const std::string& method, const std::string& path, const std::string& body)
{
    auto failure = [](const std::string& error) { return "{\"error\":\"" + jsonEscape(error) + "\"}"; };
    const char* levels[] = {"debug", "info", "warning", "error", "silent"};
    if (method == "GET") {
        return "{\"mode\":\"" + jsonEscape(g_state.mode) + "\",\"port\":" + std::to_string(g_state.portSettings.http) +
            ",\"socks-port\":" + std::to_string(g_state.portSettings.socks) + ",\"mixed-port\":" + std::to_string(g_state.portSettings.mixed) +
            ",\"allow-lan\":false,\"bind-address\":\"127.0.0.1\",\"log-level\":\"" + levels[g_state.logLevel.load()] +
            "\",\"ipv6\":" + (g_state.ipv6.load() ? "true" : "false") + ",\"path\":\"" + jsonEscape(g_state.configPath) +
            "\",\"temporary\":" + (g_state.temporaryConfig ? "true" : "false") + ",\"origin\":\"" + jsonEscape(g_state.configOrigin) +
            "\",\"revision\":" + std::to_string(g_state.configRevision) + "}";
    }
    if (method != "PATCH" && method != "PUT") return failure("Unsupported configuration operation");
    std::map<std::string, std::string> query;
    if (!controllerStreamQuery(path, query)) return failure("Invalid or duplicate configuration query parameter");
    if (query.count("profile") && query["profile"] != g_state.configPath)
        return failure("Active configuration changed; reopen runtime settings");
    if (query.count("revision") && query["revision"] != std::to_string(g_state.configRevision))
        return failure("Runtime configuration changed; reopen runtime settings");
    ControllerConfigJson json; std::string error;
    if (!json.parse(body, error)) return failure(error);
    if (method == "PATCH") {
        if (!json.keys({"mode", "port", "socks-port", "mixed-port", "log-level", "ipv6", "allow-lan", "bind-address"}, error)) return failure(error);
        std::string mode = g_state.mode, log = levels[g_state.logLevel.load()], bind = "127.0.0.1";
        bool ipv6 = g_state.ipv6.load(), lan = false; ProxyPortSettings ports = g_state.portSettings;
        if (!json.string("mode", mode, error) || !json.string("log-level", log, error) || !json.string("bind-address", bind, error) ||
            !json.boolean("ipv6", ipv6, error) || !json.boolean("allow-lan", lan, error) || !json.port("port", ports.http, error) ||
            !json.port("socks-port", ports.socks, error) || !json.port("mixed-port", ports.mixed, error)) return failure(error);
        mode = lower(mode); log = lower(log);
        if (mode != "rule" && mode != "global" && mode != "direct") return failure("Invalid proxy mode");
        const int level = controllerLogLevel(log);
        if (level < 0) return failure("Invalid log-level");
        if (lan || bind != "127.0.0.1") return failure("This core currently supports loopback listeners only");
        if (g_state.running.load() && !configureProxyListenersLocked(ports.effectiveHttp(), ports.effectiveSocks(), error)) return failure(error);
        // Nothing is written to subscription YAML or application port preferences.
        g_state.portSettings = ports; g_state.httpPort = ports.effectiveHttp(); g_state.socksPort = ports.effectiveSocks();
        g_state.mode = mode == "rule" ? "Rule" : mode == "global" ? "Global" : "Direct";
        g_state.logLevel.store(level); g_state.ipv6.store(ipv6); ++g_state.configRevision;
        return "{}";
    }
    if (!json.keys({"path", "payload", "force"}, error)) return failure(error);
    std::string configPath, payload; bool force = false;
    if (!json.string("path", configPath, error) || !json.string("payload", payload, error) || !json.boolean("force", force, error)) return failure(error);
    if (query.count("force")) {
        if (query["force"] != "true" && query["force"] != "false") return failure("force must be true or false");
        force = query["force"] == "true";
    }
    if (!payload.empty()) {
        if (g_state.runtimeDirectory.empty()) return failure("Temporary configuration storage is not initialized");
        const std::string origin = g_state.temporaryConfig ? g_state.configOrigin : g_state.configPath;
        if (!loadConfigLocked(runtimeConfigPathLocked(), error, force, &payload, origin)) return failure(error);
    } else {
        if (configPath.empty()) configPath = g_state.temporaryConfig ? g_state.configOrigin : g_state.configPath;
        if (configPath.empty()) return failure("No saved configuration is available to reload");
        if (configPath.front() != '/' || configPath.find('\0') != std::string::npos) return failure("Configuration path must be absolute");
        if (!loadConfigLocked(configPath, error, force)) return failure(error);
    }
    return "{}";
}
