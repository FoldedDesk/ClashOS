void shareLinkTests()
{
    auto encode = [](const std::string& text) {
        size_t length = 0; std::vector<unsigned char> bytes((text.size() + 2) / 3 * 4 + 1);
        require(mbedtls_base64_encode(bytes.data(), bytes.size(), &length, reinterpret_cast<const unsigned char*>(text.data()), text.size()) == 0, "Public link fixture must encode");
        return std::string(reinterpret_cast<char*>(bytes.data()), length);
    };
    auto parse = [](const std::string& input, const std::string& occupied = "[]") {
        const std::string response = shareLinksJson(input, occupied); EditorYaml data; std::string error;
        require(data.parse(response, 8 * 1024 * 1024, error), "Share-link result must be JSON/YAML readable");
        auto* root = yaml_document_get_root_node(&data.document);
        const std::string failure = yamlText(yamlValue(data.document, root, "error"));
        require(failure.empty(), ("Public share-link fixture failed: " + failure).c_str());
        const std::string content = yamlText(yamlValue(data.document, root, "content")); ParsedConfig config;
        require(parseConfigText(content, config, error), "Generated standalone configuration must pass production native parsing");
        return config;
    };
    const std::string user = encode("aes-128-gcm:中文:p@ss+/%value"), ss = "ss://" + user + "@127.0.0.1:8443#%E7%A4%BA%E4%BE%8B+%E8%8A%82%E7%82%B9";
    auto config = parse(ss);
    require(config.nodes.size() == 1 && config.nodes[0].name == "示例+节点" && config.nodes[0].password == "中文:p@ss+/%value", "SIP002 must preserve Unicode, embedded colons, literal plus and all password bytes");
    require(config.groups.size() == 1 && config.groups[0].proxies == std::vector<std::string>{"示例+节点"} && config.rules.size() == 1, "Standalone import must create a selectable route through the imported node");
    config = parse("ss://aes-256-gcm:p%40ss%3Aword%2B%25@[2001:db8::1]:443/#IPv6");
    require(config.nodes[0].server == "2001:db8::1" && config.nodes[0].password == "p@ss:word+%" && config.nodes[0].port == 443, "Plain SIP002 userinfo and bracketed IPv6 must decode correctly");
    config = parse("ss://" + encode("chacha20-ietf-poly1305:test/!@#:%25@192.168.100.1:8888") + "#legacy");
    require(config.nodes[0].password == "test/!@#:%25", "Legacy full-URI Base64 passwords must not be percent decoded");
    std::string url64 = user; while (!url64.empty() && url64.back() == '=') url64.pop_back(); std::replace(url64.begin(), url64.end(), '+', '-'); std::replace(url64.begin(), url64.end(), '/', '_');
    config = parse("ss://" + url64 + "@fixture.test:443"); require(config.nodes[0].password == "中文:p@ss+/%value", "Unpadded Base64URL auth must work");
    config = parse("trojan://p%3Ass%2Bword%40@[::1]:443?type=ws&security=tls&sni=fixture.test&host=ws.test&path=%2Fsocket%3Fed%3D1024&allowInsecure=1&alpn=http%2F1.1#Trojan");
    require(config.nodes[0].password == "p:ss+word@" && config.nodes[0].network == "ws" && config.nodes[0].tls && config.nodes[0].skipCertVerify && config.nodes[0].serverName == "fixture.test" && config.nodes[0].wsPath == "/socket?ed=1024" && config.nodes[0].wsHeaders.at("Host") == "ws.test", "Trojan query options must reach the actual TLS/WebSocket node model");
    config = parse("trojan://public-password@fixture.test:443"); require(config.nodes[0].tls && !config.nodes[0].skipCertVerify, "Plain Trojan links must keep TLS certificate checks on");
    const std::string vmess = R"({"v":"2","ps":"VMess 中文","add":"fixture.test","port":"443","id":"01234567-89ab-cdef-0123-456789abcdef","aid":"0","scy":"auto","net":"ws","type":"none","host":"ws.test","path":"/ws","tls":"tls","sni":"tls.test","alpn":"h2,http/1.1","insecure":"0"})";
    config = parse("vmess://" + encode(vmess));
    require(config.nodes[0].name == "VMess 中文" && config.nodes[0].uuid == "01234567-89ab-cdef-0123-456789abcdef" && config.nodes[0].tls && !config.nodes[0].skipCertVerify && config.nodes[0].wsPath == "/ws" && config.nodes[0].serverName == "tls.test" && config.nodes[0].alpn.size() == 2, "v2rayN VMess v2 fields must preserve authentication, transport and TLS settings");
    const std::string legacyTls = R"({"v":"2","add":"192.0.2.1","port":443,"id":"01234567-89ab-cdef-0123-456789abcdef","aid":64,"net":"tcp","host":"tls.test,second.test","tls":"tls"})";
    config = parse("vmess://" + encode(legacyTls));
    require(config.nodes[0].serverName == "tls.test" && config.nodes[0].alterId == 64 && config.nodes[0].network == "tcp", "Legacy VMess TLS links must derive SNI from the first host when explicit SNI is absent");
    config = parse("trojan://public@192.0.2.1:443?type=ws&host=ws.test");
    require(config.nodes[0].serverName == "ws.test" && config.nodes[0].wsHeaders.at("Host") == "ws.test", "Trojan TLS/WS links must keep Host as the fallback SNI");
    config = parse(ss + "\n\n# public fixture\n" + ss, "[\"示例+节点\",\"节点选择\"]");
    require(config.nodes[0].name == "示例+节点 (2)" && config.nodes[1].name == "示例+节点 (3)" && config.groups[0].name == "节点选择 (2)", "Duplicate and existing names must be allocated deterministically without losing nodes");
    config = parse(encode(ss + "\r\n" + "trojan://public@fixture.test:443#public")); require(config.nodes.size() == 2, "Base64-encoded subscription node lists must import locally");
    config = parse("\xef\xbb\xbf" + ss); require(config.nodes.size() == 1, "UTF-8 BOM must not break pasted node lists");
    const std::vector<std::string> bad = {
        "", "not a link", "vless://public-secret@fixture.test:443#unsupported", "ss://bad@fixture.test:443", "ss://a:public-secret@fixture.test:0",
        "ss://aes-128-gcm:public-secret@fixture.test:65536", "ss://aes-128-gcm:public-secret@fixture.test:80.0", "ss://aes-128-gcm:public-secret@::1:443",
        "ss://aes-128-gcm:public-secret@fixture.test:443#bad%xx", "ss://aes-128-gcm:public-secret@fixture.test:443#bad%00",
        "ss://aes-128-gcm:public-secret@fixture.test:443?plugin=obfs-local", "ss://aes-128-gcm:public-secret@fixture.test:443?plugin=&plugin=",
        "ss://aes-128-cfb:public-secret@fixture.test:443", "trojan://public-secret@fixture.test:443?security=none",
        "trojan://public-secret@fixture.test:443?type=grpc", "trojan://public-secret@fixture.test:443?allowInsecure=maybe",
        "trojan://public-secret@fixture.test:443?sni=one&peer=two", "trojan://public-secret@fixture.test:443?type=ws&alpn=h2",
        "trojan://public-secret@fixture.test:443?fp=chrome", "trojan://public-secret@fixture.test:443?path=%2Fws",
        "vmess://" + encode("   "), "vmess://" + encode("[]"), "vmess://" + encode("{\"port\":443,\"port\":444}"),
        "vmess://" + encode(vmess.substr(0, vmess.size() - 1) + ",\"fp\":\"chrome\"}"),
        "vmess://" + encode(vmess.substr(0, vmess.size() - 1) + ",\"unknown\":{}}"),
        ss + "\nvless://public-secret@fixture.test:443", std::string(2 * 1024 * 1024 + 1, 'x')
    };
    for (const auto& item : bad) {
        const std::string result = shareLinksJson(item);
        require(result.find("\"error\":\"\"") == std::string::npos && result.find("\"nodes\"") == std::string::npos && result.find("public-secret") == std::string::npos, "Malformed or unsupported imports must fail as a whole, omit partial nodes and never echo credentials");
    }
    require(shareLinksJson("\n" + ss + "\ninvalid").find("第 3 行") != std::string::npos, "Failure must identify the original physical line");
    require(shareLinksJson(ss, "{}").find("已有节点") != std::string::npos, "Malformed collision context must fail without a crash");
    std::string many; for (int i = 0; i < 501; ++i) many += ss + '\n';
    require(shareLinksJson(many).find("最多导入 500") != std::string::npos, "Large batches must be bounded before configuration creation");
}
