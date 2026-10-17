// Real controller workers, file store, DNS hosts and listener sockets.
void controllerConfigTests(const std::string& directory)
{
    stopCore(); workersIdle(); setControllerSecret(""); g_testConnector = nullptr;
    require(configureRuntimeDirectory(directory), "Initialize a private controller payload store");
    const std::string profile = directory + "/runtime-source.yaml", runtime = runtimeConfigPathLocked();
    const int controller = dnsTestPort(), http = dnsTestPort(), socks = dnsTestPort();
    auto source = [&](int port, const std::string& mode = "rule") {
        return "# Original subscription must remain byte-identical\nport: " + std::to_string(port) + "\nsocks-port: " + std::to_string(socks) +
            "\nmode: " + mode + "\nlog-level: debug\nipv6: true\ndns: {enable: true, ipv6: true, nameserver: [192.0.2.53]}\n"
            "hosts: {runtime.fixture.test: ['192.0.2.10', '2001:db8::10']}\nproxies: []\nrules: ['MATCH,DIRECT']\n";
    };
    const std::string original = source(http);
    { std::ofstream out(profile); out << original; }
    require(startCore(profile, controller), "Start public runtime configuration fixture");
    auto request = [&](const std::string& method, const std::string& body, const std::string& query = "") {
        return apiHttp(method + " /configs" + query + " HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body);
    };
    auto snapshot = [&]() { return responseFor("GET", "/configs?read=true", ""); };
    auto success = [&](const std::string& method, const std::string& body, const std::string& query = "") {
        const auto response = request(method, body, query);
        require(response.rfind("HTTP/1.1 204", 0) == 0 && response.substr(response.find("\r\n\r\n") + 4).empty(), "Configuration mutations return standard empty HTTP 204");
    };
    auto sock = [&](int port) {
        const int fd = dnsTestConnect(SOCK_STREAM, port); require(fd >= 0, "Live ingress must accept a client");
        require(sendAll(fd, std::string("\5\1\0", 3)) && receiveN(fd, 2) == std::string("\5\0", 2), "Runtime ingress must actually negotiate SOCKS5");
        close(fd); workersIdle();
    };
    auto closed = [&](int port) { const int fd = dnsTestConnect(SOCK_STREAM, port); if (fd >= 0) close(fd); require(fd < 0, "Retired listener must release its port"); };
    require(snapshot().find("\"log-level\":\"debug\"") != std::string::npos && snapshot().find("\"ipv6\":true") != std::string::npos,
        "General status reflects loaded YAML settings");
    for (const std::string& invalid : {std::string(""), std::string("[]"), std::string("null"), std::string("mode: Direct"), std::string("{\"mode\":\"Direct\"}junk"),
        std::string("{\"mode\":1}"), std::string("{\"ipv6\":\"false\"}"), std::string("{\"port\":12.5}"), std::string("{\"port\":65536}"),
        std::string("{\"port\":-1}"), std::string("{\"log-level\":\"invalid\"}"), std::string("{\"mode\":\"Direct\",\"allow-lan\":true}"), std::string("{\"mode\":\"Direct\",\"sniffing\":true}")}) {
        const auto before = snapshot();
        require(request("PATCH", invalid).rfind("HTTP/1.1 400", 0) == 0 && snapshot() == before, "Malformed or unsupported PATCH must preserve every runtime field");
    }
    success("PATCH", R"({"mode":"direct","log-level":"warning","ipv6":false})");
    require(g_state.mode == "Direct" && g_state.logLevel.load() == 2 && !g_state.ipv6.load(), "PATCH must apply case-insensitive mode, log level and boolean settings together");
    const auto beforeLog = g_state.nextLogId; coreLog("debug", "hidden"); coreLog("info", "hidden"); coreLog("warning", "visible");
    require(g_state.nextLogId == beforeLog + 1 && g_state.logs.back().payload == "visible", "Log level must suppress actual new events before buffering or streaming");
    auto answer = queryDns("runtime.fixture.test", 28, DnsPurpose::General, HealthClock::now() + std::chrono::seconds(1));
    require(answer.error.empty() && answer.records.empty(), "Global IPv6 disabled suppresses AAAA even when DNS allows it");
    success("PATCH", R"({"ipv6":true,"mode":null,"log-level":null})");
    answer = queryDns("runtime.fixture.test", 28, DnsPurpose::General, HealthClock::now() + std::chrono::seconds(1));
    require(dnsAnswerAddresses(answer) == std::vector<std::string>{"2001:db8::10"} && g_state.mode == "Direct", "Enabling IPv6 must restore actual AAAA hosts results and null fields preserve values");
    const auto stable = snapshot();
    require(request("PATCH", "{}", "?profile=stale").rfind("HTTP/1.1 400", 0) == 0 &&
        request("PATCH", "{}", "?revision=99999999").rfind("HTTP/1.1 400", 0) == 0 && snapshot() == stable, "Stale runtime dialogs cannot mutate a replacement configuration");
    const int mixed = dnsTestPort();
    int upstream[2]; pairFor(upstream);
    g_testConnector = [&](const std::string&, int, int) { const int fd = upstream[0]; upstream[0] = -1; return fd; };
    const int connected = dnsTestConnect(SOCK_STREAM, http);
    require(connected >= 0 && sendAll(connected, "CONNECT runtime.fixture.test:443 HTTP/1.1\r\nHost: runtime.fixture.test\r\n\r\n") &&
        readUntilHeaders(connected).find("200 Connection Established") != std::string::npos, "Prepare an actual proxied TCP session before listener replacement");
    success("PATCH", "{\"mixed-port\":" + std::to_string(mixed) + "}");
    require(sendAll(connected, "still-connected") && receiveN(upstream[1], 15) == "still-connected" && sendAll(upstream[1], "reply") && receiveN(connected, 5) == "reply",
        "Changing ingress ports must preserve traffic in established TCP sessions");
    close(connected); close(upstream[1]); g_testConnector = nullptr; workersIdle();
    require(g_state.listeners.size() == 1 && g_state.httpPort == mixed && g_state.socksPort == mixed, "PATCH mixed port must replace the actual listeners");
    sock(mixed); closed(http); closed(socks);
    int occupied = 0; const int busy = dnsTestBind(SOCK_STREAM, 0, occupied), staged = dnsTestPort();
    require(busy >= 0, "Bind independent busy-port fixture");
    const auto stablePorts = snapshot();
    require(request("PATCH", "{\"mixed-port\":0,\"port\":" + std::to_string(staged) + ",\"socks-port\":" + std::to_string(occupied) + ",\"mode\":\"Global\",\"ipv6\":false}").rfind("HTTP/1.1 400", 0) == 0 && snapshot() == stablePorts,
        "Listener bind failure rolls back all PATCH settings, not only ports");
    sock(mixed); closed(staged);
    require(readTestFile(profile) == original && access(proxyPortSettingsPath(profile).c_str(), F_OK) != 0, "Runtime PATCH never rewrites source YAML or persistent app port preferences");
    // An empty PUT really reparses the saved source; force=false retains current ingress settings.
    { std::ofstream out(profile); out << source(http, "global"); }
    success("PUT", "{}");
    require(g_state.mode == "Global" && g_state.httpPort == mixed && g_state.ipv6.load() && g_state.logLevel.load() == 0,
        "Default PUT must reload current source and general settings while retaining ingress unless forced");
    success("PUT", "{}", "?force=true"); sock(http); sock(socks); closed(mixed);
    require(g_state.httpPort == http && !g_state.temporaryConfig, "force=true must restore source ingress settings");
    for (const std::string& invalid : {std::string("[]"), std::string("{\"path\":3}"), std::string("{\"path\":\"relative.yaml\"}"),
        std::string("{\"path\":\"/missing-public-fixture.yaml\"}"), std::string("{\"payload\":42}"), std::string("{\"payload\":\"proxies: [\"}"), std::string("{\"force\":\"true\"}")}) {
        const auto before = snapshot(); require(request("PUT", invalid).rfind("HTTP/1.1 400", 0) == 0 && snapshot() == before, "Failed reloads preserve working rules, settings and listeners");
    }
    const std::string payload = "port: 0\nsocks-port: 0\nmode: direct\nlog-level: error\nipv6: false\nproxies: []\nrules: ['DOMAIN,payload.fixture.test,REJECT','MATCH,DIRECT']\n";
    { std::ofstream out(profile + ".merge.yaml"); out << "log-level: silent\n"; }
    success("PUT", "{\"payload\":\"" + jsonEscape(payload) + "\"}");
    require(g_state.temporaryConfig && g_state.configOrigin == profile && g_state.configPath == runtime && g_state.httpPort == http && g_state.logLevel.load() == 3 &&
        responseFor("GET", "/rules", "").find("payload.fixture.test") != std::string::npos, "Payload loads actual isolated rules without losing the saved recovery path");
    struct stat status{};
    require(stat(runtime.c_str(), &status) == 0 && (status.st_mode & 0777) == 0600, "Payload envelope must be owner-only");
    require(stat(g_state.runtimeDirectory.c_str(), &status) == 0 && (status.st_mode & 0777) == 0700, "Payload store directory must be owner-only");
    const auto envelope = readTestFile(runtime), beforeBadPayload = snapshot();
    require(request("PUT", "{\"payload\":\"port: " + std::to_string(occupied) + "\\nsocks-port: 0\\nrules: ['MATCH,REJECT']\"}", "?force=true").rfind("HTTP/1.1 400", 0) == 0 &&
        snapshot() == beforeBadPayload && readTestFile(runtime) == envelope, "Failed payload listener preparation must preserve both active runtime and prior on-disk envelope");
    const std::string savedEnvelope = runtime + ".saved";
    require(rename(runtime.c_str(), savedEnvelope.c_str()) == 0 && mkdir(runtime.c_str(), 0700) == 0, "Prepare an actual destination rename failure");
    const std::string replacement = "port: " + std::to_string(staged) + "\nsocks-port: 0\nrules: ['MATCH,REJECT']\n";
    require(request("PUT", "{\"payload\":\"" + jsonEscape(replacement) + "\"}", "?force=true").rfind("HTTP/1.1 400", 0) == 0 &&
        snapshot() == beforeBadPayload && readTestFile(savedEnvelope) == envelope, "A payload file commit failure must preserve runtime settings and the previous envelope bytes");
    closed(staged); sock(http);
    require(rmdir(runtime.c_str()) == 0 && rename(savedEnvelope.c_str(), runtime.c_str()) == 0, "Restore the unchanged private envelope after failed commit fixture");
    sock(http); close(busy);
    stopCore(); require(startCore(runtime, controller), "Temporary config must survive a native/UI-to-VPN handoff using its actual path");
    require(g_state.temporaryConfig && g_state.configOrigin == profile && g_state.mode == "Direct", "Handoff must unwrap the payload without applying saved-profile extensions");
    unlink((profile + ".merge.yaml").c_str());
    success("PUT", "{}", "?force=true");
    require(!g_state.temporaryConfig && g_state.configPath == profile && g_state.mode == "Global" && readTestFile(profile) == source(http, "global"), "Empty PUT after a temporary payload returns to the saved profile without source changes");
    require(access(runtime.c_str(), F_OK) != 0, "Selecting a saved profile must remove the inactive private temporary payload");
    // The HTTP worker must not act on incomplete, ambiguous or wrongly framed bodies.
    const std::string framingState = snapshot(), patch = R"({"mode":"Direct"})";
    for (const std::string& header : {"Content-Length: -1", "Content-Length: 12x", "Content-Length: 1,1", "Content-Length: 1\r\nContent-Length: 1", "Content-Length: 999999999999999999999999", "Transfer-Encoding: chunked"})
        require(apiHttp("PATCH /configs HTTP/1.1\r\nHost: localhost\r\n" + header + "\r\n\r\n" + patch).rfind("HTTP/1.1 400", 0) == 0 && snapshot() == framingState, "Ambiguous framing must fail before any mutation");
    int pair[2]; pairFor(pair); dispatchWorker(pair[0], 3);
    require(sendAll(pair[1], "PATCH /configs HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + std::to_string(patch.size() + 1) + "\r\n\r\n" + patch), "Write deliberately truncated request");
    shutdown(pair[1], SHUT_WR); require(apiHeaders(pair[1]).rfind("HTTP/1.1 400", 0) == 0 && snapshot() == framingState, "Truncated JSON must not apply even if its prefix is a complete valid object"); close(pair[1]); workersIdle();
    require(request("PATCH", patch + "ignored-trailing-data").rfind("HTTP/1.1 400", 0) == 0 && snapshot() == framingState,
        "JSON garbage inside declared body must fail without mutation");
    require(apiHttp("PATCH /configs HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + std::to_string(patch.size()) + "\r\n\r\n" + patch + "ignored-trailing-data").rfind("HTTP/1.1 204", 0) == 0 && g_state.mode == "Direct",
        "Only the first declared body is consumed before closing the controller connection");
    stopCore();
}
