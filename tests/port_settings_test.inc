void proxyPortTests(const std::string& directory)
{
    stopCore(); g_testConnector = nullptr;
    const int controller = dnsTestPort(), baseHttp = dnsTestPort(), baseSocks = dnsTestPort();
    const std::string profile = directory + "/ports-first.yaml";
    const std::string source = "# 中文配置，端口设置不应重写注释\nport: " + std::to_string(baseHttp) +
        "\nsocks-port: " + std::to_string(baseSocks) + "\nrules: ['MATCH,REJECT']\n";
    { std::ofstream out(profile); out << source; }
    const std::string preferences = proxyPortSettingsPath(profile), api = "/clashos/ports?profile=" + urlEncode(profile);
    auto body = [](int http, int socks, int mixed = 0) {
        return "{\"http\":" + std::to_string(http) + ",\"socks\":" + std::to_string(socks) + ",\"mixed\":" + std::to_string(mixed) + "}";
    };
    auto alive = [&](int port, bool socks = false) {
        const int fd = dnsTestConnect(SOCK_STREAM, port);
        require(fd >= 0, "Saved proxy listener is not reachable");
        if (socks) {
            require(sendAll(fd, std::string("\5\1\0", 3)) && receiveN(fd, 2) == std::string("\5\0", 2), "Custom SOCKS5 port must negotiate a real client");
        } else {
            require(sendAll(fd, "GET http://ports.fixture.test/ HTTP/1.1\r\nHost: ports.fixture.test\r\n\r\n"), "Custom HTTP port request failed");
            require(readUntilHeaders(fd).find("403") != std::string::npos, "Custom HTTP port must apply the configured REJECT route");
        }
        close(fd); workersIdle();
    };
    auto closed = [](int port) {
        const int fd = dnsTestConnect(SOCK_STREAM, port); if (fd >= 0) close(fd);
        require(fd < 0, "Retired or disabled ingress must release its port");
    };
    require(startCore(profile, controller), "Proxy port preference fixture must start");
    require(responseFor("GET", api, "").find("\"overridden\":false") != std::string::npos, "Initial ports must come from the profile");
    for (const std::string& invalid : {body(-1, 1), body(65536, 1), body(1, 2, 70000),
        std::string("{\"http\":12.5,\"socks\":0,\"mixed\":0}"),
        std::string("{\"http\":12,\"http\":13,\"socks\":0,\"mixed\":0}"),
        std::string("{\"http\":12,\"socks\":0}"), body(1, 2) + "\n---\n{}"}) {
        require(responseFor("PATCH", api, invalid).find("error") != std::string::npos, "Malformed or out-of-range port settings must be rejected");
        require(g_state.httpPort == baseHttp && access(preferences.c_str(), F_OK) != 0, "Invalid edits must not modify listeners or preferences");
    }
    const int http = dnsTestPort(), socks = dnsTestPort();
    const auto revision = g_state.configRevision;
    require(responseFor("PATCH", api, body(http, socks)) == "{}", "Port preferences must save and apply");
    require(g_state.httpPort == http && g_state.socksPort == socks && g_state.configRevision == revision,
        "Port edits must not reload rules, selections, or the active profile");
    struct stat mode{}; require(stat(preferences.c_str(), &mode) == 0 && (mode.st_mode & 0777) == 0600, "Persisted ingress preferences must be owner-only");
    require(readTestFile(profile) == source, "Port preferences must preserve the original subscription bytes and comments");
    alive(http); alive(socks, true); closed(baseHttp); closed(baseSocks);
    const std::string saved = readTestFile(preferences);
    require(responseFor("PATCH", "/clashos/ports?profile=stale", body(0, 0)).find("error") != std::string::npos &&
        readTestFile(preferences) == saved, "Stale dialogs must not change another profile's preferences");
    int occupied = 0; const int busy = dnsTestBind(SOCK_STREAM, 0, occupied), staged = dnsTestPort();
    require(busy >= 0, "Busy-port fixture must bind");
    require(responseFor("PATCH", api, body(staged, occupied)).find("error") != std::string::npos &&
        g_state.httpPort == http && g_state.socksPort == socks && readTestFile(preferences) == saved,
        "A busy port must preserve both active listeners and saved preferences");
    alive(http); alive(socks, true); closed(staged); close(busy);
    require(responseFor("PATCH", api, body(controller, socks)).find("error") != std::string::npos &&
        g_state.httpPort == http && readTestFile(preferences) == saved, "The controller port cannot be reused by an ingress");
    unlink(preferences.c_str()); require(mkdir(preferences.c_str(), 0700) == 0, "Commit failure fixture must be created");
    require(responseFor("PATCH", api, body(staged, socks)).find("error") != std::string::npos && g_state.httpPort == http,
        "A preference rename failure must retain original listener sockets");
    closed(staged); alive(http); rmdir(preferences.c_str());
    { const int fd = open(preferences.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600); require(fd >= 0 && write(fd, saved.data(), saved.size()) == static_cast<ssize_t>(saved.size()), "Restore private commit fixture"); close(fd); }
    stopCore(); require(startCore(profile, controller), "Saved port preferences must survive restart"); alive(http); alive(socks, true);
    const std::string other = directory + "/ports-next.yaml";
    { std::ofstream out(other); out << "port: 0\nsocks-port: 0\nmixed-port: 0\nrules: ['MATCH,REJECT']\n"; }
    require(responseFor("PUT", "/configs", "{\"path\":\"" + jsonEscape(other) + "\"}") == "{}" && g_state.httpPort == http,
        "Application port preferences must survive profile or subscription reloads");
    const std::string nextApi = "/clashos/ports?profile=" + urlEncode(other);
    require(responseFor("DELETE", nextApi, "") == "{}" && g_state.httpPort == 0 && g_state.socksPort == 0 && g_state.listeners.empty(),
        "Restoring a profile with disabled ports must not bind ephemeral port zero");
    closed(http); closed(socks);
    const int mixed = dnsTestPort();
    require(responseFor("PATCH", nextApi, body(0, 0, mixed)) == "{}" && g_state.listeners.size() == 1,
        "A mixed ingress must bind exactly one shared listener");
    alive(mixed); alive(mixed, true);
    require(responseFor("GET", "/configs", "").find("\"mixed-port\":" + std::to_string(mixed)) != std::string::npos,
        "Standard config status must report the actual mixed preference");
    require(responseFor("PATCH", nextApi, body(0, 0)) == "{}" && g_state.httpProxyFd < 0 && g_state.socksProxyFd < 0 && g_state.listeners.empty(),
        "Both ingress protocols can be disabled while the controller stays available");
    closed(mixed);
    require(responseFor("DELETE", nextApi, "") == "{}" && access(preferences.c_str(), F_OK) != 0,
        "Restoring configuration ports must remove the application override");
    stopCore();
}
