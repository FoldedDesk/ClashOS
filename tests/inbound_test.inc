// Public accounts only. Real listeners exercise HTTP Basic and RFC1929 before
// routing, plus address transitions, source ACLs and persistent preferences.
void inboundTests(const std::string& directory)
{
    stopCore(); workersIdle(); setControllerSecret(""); g_testConnector = nullptr;
    const std::string profile = directory + "/inbound.yaml", settings = inboundSettingsPath(profile);
    unlink(settings.c_str());
    const int port = dnsTestPort(), controller = dnsTestPort();
    const std::string yaml = "mixed-port: " + std::to_string(port) + "\nallow-lan: false\nauthentication: ['alice:public:secret']\nrules: ['MATCH,REJECT']\n";
    { std::ofstream out(profile); out << yaml; }
    std::string error; ParsedConfig parsed;
    require(parseConfigText(yaml, parsed, error) && parsed.inbound.users[0].second == "public:secret", "YAML inbound accounts preserve colons in passwords");
    for (const std::string& invalid : {"allow-lan: yes", "allow-lan: []", "bind-address: example.com", "authentication: user:pass",
        "authentication: ['user:']", "authentication: ['same:one','same:two']", "authentication: ['no-colon']", "skip-auth-prefixes: [bad]",
        "lan-allowed-ips: ['192.0.2.1/99']", "lan-disallowed-ips: {}"})
        require(!parseConfigText(invalid, parsed, error), "Invalid inbound source settings must be rejected");
    InboundConfig acl; acl.allowLan = true; acl.allowed = {"192.0.2.0/24", "2001:db8::/32"}; acl.denied = {"192.0.2.3/32", "2001:db8::dead/128"};
    acl.users = {{"alice", "public:secret"}}; acl.skipAuth = {"127.0.0.0/8", "::1/128"};
    require(normalizeInboundConfig(acl, error), "Compile IPv4/IPv6 inbound ACLs");
    require(inboundClientAllowed(acl, "192.0.2.4") && !inboundClientAllowed(acl, "192.0.2.3") && !inboundClientAllowed(acl, "198.51.100.1") &&
        inboundClientAllowed(acl, "2001:db8::1") && !inboundClientAllowed(acl, "2001:db8::dead"), "Deny prefixes take priority over allowed IPv4 and IPv6 ranges");
    require(!inboundRequiresAuth(acl, "127.0.0.2") && !inboundRequiresAuth(acl, "::1") && inboundRequiresAuth(acl, "192.0.2.4"), "Authentication bypass applies only to matching CIDRs");
    require(startCore(profile, controller), "Start authenticated proxy fixture");
    require(localSocksOptions().find("public:secret") != std::string::npos, "Private in-process TUN bridge obtains configured SOCKS credentials");
    auto patch = [&](const std::string& body) { return responseFor("PATCH", "/configs", body); };
    auto preferences = [&](const std::string& method, const std::string& body = "", bool stale = false) {
        return responseFor(method, "/clashos/inbound?profile=" + urlEncode(profile) + "&revision=" + std::to_string(g_state.configRevision + (stale ? 1 : 0)), body);
    };
    auto http = [&](const std::string& headers) {
        const int fd = dnsTestConnect(SOCK_STREAM, port); require(fd >= 0, "Connect live mixed proxy for HTTP authentication");
        sendAll(fd, "CONNECT public.fixture.test:443 HTTP/1.1\r\nHost: public.fixture.test\r\n" + headers + "\r\n");
        const auto response = readUntilHeaders(fd); close(fd); workersIdle(); return response;
    };
    require(http("").find("407 Proxy Authentication Required") != std::string::npos, "Missing HTTP credentials receive an actual 407 challenge");
    require(inboundLoopback("127.0.0.2") && inboundLoopback("::1") && inboundLoopback("::ffff:127.0.0.1") && !inboundLoopback("192.0.2.1"), "Loopback detection handles mapped IPv4 and IPv6 correctly");
    InboundConfig specific; specific.bindAddress = "[::1]";
    require(normalizeInboundConfig(specific, error) && specific.bindAddress == "::1", "Normalize bracketed IPv6 listener addresses");
    specific.bindAddress = "127.0.0.1";
    require(normalizeInboundConfig(specific, error) && specific.bindAddress == "127.0.0.1", "Normalize IPv4 listener addresses using mapped rule storage");
    for (const auto& auth : {"Basic YWxpY2U6d3Jvbmc=", "Bearer anything", "Basic @@@@", "Basic YWxpY2U6cHVibGljOnNlY3JldA===", "Basic =AAA"})
        require(http(std::string("Proxy-Authorization: ") + auth + "\r\n").find("407") != std::string::npos, "Wrong or malformed HTTP credentials cannot reach routing");
    const std::string basic = "pRoXy-AuThOrIzAtIoN: bAsIc YWxpY2U6cHVibGljOnNlY3JldA==\r\n";
    require(http(basic).find("403 Forbidden") != std::string::npos, "Valid case-insensitive Basic authentication reaches REJECT routing");
    require(http(basic + basic).find("407") != std::string::npos, "Duplicate proxy authorization is rejected");
    auto socks = [&](bool good, bool offerPassword = true) {
        const int fd = dnsTestConnect(SOCK_STREAM, port); require(fd >= 0, "Connect live SOCKS ingress");
        const std::string methods = offerPassword ? std::string("\5\2\0\2", 4) : std::string("\5\1\0", 3);
        require(sendAll(fd, methods), "Send real SOCKS methods");
        require(receiveN(fd, 2) == (offerPassword ? std::string("\5\2", 2) : std::string("\5\xff", 2)), "Required accounts select RFC1929 and refuse anonymous fallback");
        if (offerPassword) {
            const std::string password = good ? "public:secret" : "wrong";
            require(sendAll(fd, std::string("\1\5alice", 7) + static_cast<char>(password.size()) + password), "Send username/password subnegotiation");
            require(receiveN(fd, 2) == (good ? std::string("\1\0", 2) : std::string("\1\1", 2)), "SOCKS authentication status matches credentials");
        }
        return fd;
    };
    for (const auto flags : {std::pair<bool,bool>{false,false}, {false,true}}) { const int fd = socks(flags.first, flags.second); close(fd); workersIdle(); }
    int fd = socks(true);
    require(sendAll(fd, std::string("\5\1\0\1\x7f\0\0\1\0\x50", 10)) && receiveN(fd, 10)[1] == 2, "Authenticated SOCKS CONNECT reaches the configured reject rule");
    close(fd); workersIdle();
    fd = socks(true);
    require(sendAll(fd, std::string("\5\3\0\1\0\0\0\0\0\0", 10)), "Send authenticated UDP ASSOCIATE");
    const auto udpReply = receiveN(fd, 10);
    require(udpReply.size() == 10 && udpReply[1] == 0, "Authenticated SOCKS UDP association opens an actual relay socket");
    close(fd); workersIdle();
    require(patch(R"({"skip-auth-prefixes":["127.0.0.0/8"]})") == "{}" && http("").find("403") != std::string::npos,
        "Explicit loopback bypass restores anonymous local applications");
    require(localSocksOptions().find("public:secret") == std::string::npos, "Local TUN uses anonymous access when an explicit bypass applies");
    // Verify stripping using a real upstream relay, not a parser-only assertion.
    require(patch(R"({"mode":"direct","skip-auth-prefixes":[]})") == "{}", "Prepare actual authenticated HTTP forwarding");
    int upstream[2]; pairFor(upstream);
    g_testConnector = [&](const std::string&, int, int) { const int result = upstream[0]; upstream[0] = -1; return result; };
    fd = dnsTestConnect(SOCK_STREAM, port); require(fd >= 0, "Connect actual authenticated forward request");
    require(sendAll(fd, "GET http://public.fixture.test/path HTTP/1.1\r\nHost: public.fixture.test\r\n" + basic + "\r\n"), "Write authenticated plain HTTP request");
    const auto forwarded = readUntilHeaders(upstream[1]);
    require(forwarded.find("GET /path HTTP/1.1") == 0 && lower(forwarded).find("proxy-authorization") == std::string::npos &&
        forwarded.find("YWxpY2U") == std::string::npos, "Proxy credentials are never forwarded to the destination");
    require(sendAll(upstream[1], "HTTP/1.1 204 No Content\r\n\r\n") && readUntilHeaders(fd).find("204") != std::string::npos, "Authenticated HTTP relay transfers the real upstream response");
    require(patch(R"({"allow-lan":true,"bind-address":"*"})") == "{}" && sendAll(fd, "live-session") && receiveN(upstream[1], 12) == "live-session",
        "Changing loopback to wildcard listeners preserves an established authenticated stream");
    require(patch(R"({"allow-lan":false})") == "{}" && sendAll(upstream[1], "back") && receiveN(fd, 4) == "back",
        "Closing LAN listeners preserves established return traffic");
    close(fd); close(upstream[1]); workersIdle(); g_testConnector = nullptr;
    require(patch(R"({"mode":"rule","allow-lan":true,"bind-address":"*","skip-auth-prefixes":["127.0.0.0/8"]})") == "{}", "Enable dual-stack wildcard listeners on the same active port");
    require(g_state.listeners.size() >= 1 && g_state.listeners[0]->host == "0.0.0.0", "LAN mode must bind wildcard sockets, not report an unused setting");
    require(http("").find("403") != std::string::npos, "Wildcard listener still serves local clients after replacement");
    require(patch(R"({"lan-disallowed-ips":["127.0.0.1/32"]})") == "{}", "Apply source deny list");
    require(http("").empty(), "Source ACL rejects a live TCP peer before HTTP routing");
    require(localSocksOptions().find("excluded") != std::string::npos, "Local tunnel cannot silently bypass an explicit LAN deny rule");
    require(patch(R"({"allow-lan":false})") == "{}" && g_state.listeners.size() == 1 && g_state.listeners[0]->host == "127.0.0.1" &&
        http("").find("403") != std::string::npos, "Turning off sharing retires wildcard listeners and restores loopback access");
    const auto before = responseFor("GET", "/configs", "");
    for (const auto& invalid : {R"({"allow-lan":true,"bind-address":"192.0.2.250"})", R"({"authentication":["duplicate:a","duplicate:b"]})",
        R"({"skip-auth-prefixes":[1]})", R"({"lan-allowed-ips":{}})", R"({"allow-lan":"true"})"})
        require(patch(invalid).find("error") != std::string::npos && responseFor("GET", "/configs", "") == before, "Invalid LAN patch rolls back all fields and keeps live listeners");
    require(http("").find("403") != std::string::npos, "Invalid address bind preserves working old ingress");
    const int ipv6Socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (ipv6Socket >= 0) {
        sockaddr_in6 address{}; address.sin6_family = AF_INET6; address.sin6_port = htons(port); inet_pton(AF_INET6, "::1", &address.sin6_addr);
        require(patch(R"({"allow-lan":true,"bind-address":"[::1]","skip-auth-prefixes":["::1/128"]})") == "{}", "Apply an explicit IPv6-only listener");
        socketTimeout(ipv6Socket, 1800);
        require(connect(ipv6Socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 &&
            sendAll(ipv6Socket, "CONNECT public.fixture.test:443 HTTP/1.1\r\n\r\n") && readUntilHeaders(ipv6Socket).find("403") != std::string::npos,
            "Actual IPv6 peer authenticates through its matching bypass and reaches routing");
        close(ipv6Socket); workersIdle();
        require(patch(R"({"allow-lan":false,"bind-address":"*","skip-auth-prefixes":["127.0.0.0/8"]})") == "{}", "Restore IPv4 loopback after IPv6-only mode");
    }
    const std::string save = R"({"allow-lan":false,"bind-address":"*","users":[{"username":"alice"},{"username":"bob","password":"another-public"}],"skip-auth-prefixes":["127.0.0.0/8"],"lan-allowed-ips":["0.0.0.0/0","::/0"],"lan-disallowed-ips":[]})";
    require(preferences("PATCH", save, true).find("error") != std::string::npos && access(settings.c_str(), F_OK) != 0, "Stale sharing dialogs cannot write saved preferences");
    require(preferences("PATCH", save) == "{}" && g_state.inbound.users.size() == 2 && g_state.inbound.users[0].second == "public:secret", "Save accounts while keeping an existing password without disclosing it");
    struct stat status{};
    require(stat(settings.c_str(), &status) == 0 && (status.st_mode & 0777) == 0600, "Stored inbound credentials are owner-only");
    const auto metadata = responseFor("GET", "/clashos/inbound", "") + responseFor("GET", "/configs", "") + runtimeInfo();
    require(metadata.find("public:secret") == std::string::npos && metadata.find("another-public") == std::string::npos && metadata.find("alice") != std::string::npos,
        "Controller and runtime metadata expose account names without passwords");
    const auto saved = readTestFile(settings);
    require(preferences("PATCH", R"({"users":[{"username":"new"}]})").find("error") != std::string::npos && readTestFile(settings) == saved,
        "A new account cannot inherit someone else's password");
    stopCore(); require(startCore(profile, controller) && g_state.inboundOverridden && g_state.inbound.users.size() == 2 && http("").find("403") != std::string::npos,
        "Shared application inbound preferences and credentials survive a real core restart");
    // Exercise cancellation of prepared listener threads repeatedly; no missed wakeups.
    for (int i = 0; i < 24; ++i) {
        std::lock_guard<std::mutex> lock(g_state.mutex); InboundConfig other = g_state.inbound; other.allowLan = true;
        require(!configureProxyListenersLocked(port, port, error, [] { return false; }, &other), "Failed settings commit cancels all prepared listener threads");
    }
    require(http("").find("403") != std::string::npos, "Repeated listener rollback preserves the original listener");
    require(rename(settings.c_str(), (settings + ".saved").c_str()) == 0 && mkdir(settings.c_str(), 0700) == 0, "Prepare a settings commit failure");
    require(preferences("PATCH", R"({"allow-lan":true})").find("error") != std::string::npos && !g_state.inbound.allowLan && http("").find("403") != std::string::npos,
        "File commit failure restores old binding and old access policy together");
    require(rmdir(settings.c_str()) == 0 && rename((settings + ".saved").c_str(), settings.c_str()) == 0, "Restore original preference fixture");
    require(preferences("DELETE") == "{}" && !g_state.inboundOverridden && g_state.inbound.users.size() == 1 && http("").find("407") != std::string::npos,
        "Reset preferences restores source accounts and local authentication semantics");
    require(readTestFile(profile) == yaml && access(settings.c_str(), F_OK) != 0, "Inbound preferences never modify the source subscription");
    stopCore();
}
