std::string controllerConfigsLocked(const std::string& method, const std::string& path, const std::string& body)
{
    auto failure = [](const std::string& error) { return "{\"error\":\"" + jsonEscape(error) + "\"}"; };
    const char* levels[] = {"debug", "info", "warning", "error", "silent"};
    if (method == "GET") {
        return "{\"sniffing\":" + std::string(g_state.sniffer->enabled ? "true" : "false") + ",\"sniffer\":" + snifferConfigJson(*g_state.sniffer) + "," + inboundFieldsJson(g_state.inbound) + ",\"mode\":\"" + jsonEscape(g_state.mode) + "\",\"port\":" + std::to_string(g_state.portSettings.http) +
            ",\"socks-port\":" + std::to_string(g_state.portSettings.socks) + ",\"mixed-port\":" + std::to_string(g_state.portSettings.mixed) +
            ",\"log-level\":\"" + levels[g_state.logLevel.load()] +
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
        if (!json.keys({"mode", "port", "socks-port", "mixed-port", "log-level", "ipv6", "allow-lan", "bind-address",
            "authentication", "skip-auth-prefixes", "lan-allowed-ips", "lan-disallowed-ips", "sniffing", "sniffer"}, error)) return failure(error);
        std::string mode = g_state.mode, log = levels[g_state.logLevel.load()];
        bool ipv6 = g_state.ipv6.load(); ProxyPortSettings ports = g_state.portSettings; InboundConfig inbound = g_state.inbound;
        SnifferConfig sniffer = *g_state.sniffer;
        if (!json.string("mode", mode, error) || !json.string("log-level", log, error) || !json.string("bind-address", inbound.bindAddress, error) ||
            !json.boolean("ipv6", ipv6, error) || !json.boolean("allow-lan", inbound.allowLan, error) || !json.port("port", ports.http, error) ||
            !json.port("socks-port", ports.socks, error) || !json.port("mixed-port", ports.mixed, error)) return failure(error);
        mode = lower(mode); log = lower(log);
        if (mode != "rule" && mode != "global" && mode != "direct") return failure("Invalid proxy mode");
        const int level = controllerLogLevel(log);
        if (level < 0) return failure("Invalid log-level");
        if (!inboundJsonConfig(json, inbound, error) || !snifferJsonPatch(json, sniffer, error)) return failure(error);
        if (g_state.running.load() && !configureProxyListenersLocked(ports.effectiveHttp(), ports.effectiveSocks(), error, {}, &inbound)) return failure(error);
        // Nothing is written to subscription YAML or application port preferences.
        g_state.portSettings = ports; g_state.httpPort = ports.effectiveHttp(); g_state.socksPort = ports.effectiveSocks();
        g_state.inbound = std::move(inbound);
        g_state.sniffer = std::make_shared<SnifferConfig>(std::move(sniffer));
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

std::string inboundControlLocked(const std::string& method, const std::string& path, const std::string& body)
{
    if (method == "GET") return inboundStatusLocked();
    auto failure = [](const std::string& error) { return "{\"error\":\"" + jsonEscape(error) + "\"}"; };
    if (method != "PATCH" && method != "DELETE") return failure("Unsupported inbound operation");
    std::map<std::string, std::string> query;
    if (!controllerStreamQuery(path, query) || query["profile"] != g_state.configPath ||
        query["revision"] != std::to_string(g_state.configRevision) || g_state.configPath.empty()) return failure("Active configuration changed; reopen sharing settings");
    if (!g_state.running.load() || g_state.temporaryConfig) return failure("Select a saved profile before saving inbound preferences");
    InboundConfig config = method == "DELETE" ? g_state.profileInbound : g_state.inbound;
    std::string error, temporary; const auto destination = inboundSettingsPath(g_state.configPath);
    if (destination.empty()) return failure("Import a configuration before saving inbound preferences");
    if (method == "PATCH") {
        ControllerConfigJson json;
        if (!json.parse(body, error) || !json.keys({"allow-lan", "bind-address", "users", "skip-auth-prefixes", "lan-allowed-ips", "lan-disallowed-ips"}, error) ||
            !inboundJsonConfig(json, config, error) || !inboundJsonUsers(json, config, error) || !normalizeInboundConfig(config, error) ||
            !stageInboundSettings(destination, config, temporary, error)) return failure(error);
    }
    const auto commit = [&]() {
        const bool saved = method == "PATCH" ? rename(temporary.c_str(), destination.c_str()) == 0 :
            (unlink(destination.c_str()) == 0 || errno == ENOENT);
        if (!saved) error = "Cannot commit inbound settings; previous settings have been preserved";
        return saved;
    };
    const bool changed = configureProxyListenersLocked(g_state.httpPort, g_state.socksPort, error, commit, &config);
    if (!temporary.empty()) unlink(temporary.c_str());
    if (!changed) return failure(error);
    g_state.inbound = std::move(config); g_state.inboundOverridden = method == "PATCH"; ++g_state.configRevision;
    coreLog("info", method == "PATCH" ? "Inbound preferences saved" : "Inbound preferences restored from configuration");
    return "{}";
}
