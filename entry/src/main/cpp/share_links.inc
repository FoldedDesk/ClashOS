// Share links are decoded locally. Never include a source URI or credential in errors.
struct ShareLinkNode {
    std::string name, type, server;
    int port = 0;
    std::map<std::string, std::string> fields; // Values are already JSON encoded.
};

std::string shareQuoted(const std::string& value) { return "\"" + jsonEscape(value) + "\""; }

bool shareUtf8(const std::string& text)
{
    for (size_t i = 0; i < text.size();) {
        const unsigned char first = text[i++];
        if (!first) return false;
        if (first < 0x80) continue;
        int extra = first >= 0xc2 && first <= 0xdf ? 1 : first >= 0xe0 && first <= 0xef ? 2 : first >= 0xf0 && first <= 0xf4 ? 3 : -1;
        if (extra < 0 || i + extra > text.size()) return false;
        unsigned int value = first & (extra == 1 ? 31 : extra == 2 ? 15 : 7);
        for (int j = 0; j < extra; ++j) { const unsigned char ch = text[i++]; if ((ch & 0xc0) != 0x80) return false; value = (value << 6) | (ch & 63); }
        if ((extra == 1 && value < 0x80) || (extra == 2 && value < 0x800) || (extra == 3 && value < 0x10000) ||
            value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return false;
    }
    return true;
}

bool sharePercent(const std::string& input, std::string& output)
{
    auto hex = [](unsigned char ch) -> int { if (ch >= '0' && ch <= '9') return ch - '0'; if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10; if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10; return -1; };
    output.clear();
    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] != '%') output += input[i]; // '+' is literal in userinfo and fragments.
        else { if (i + 2 >= input.size()) return false; const int high = hex(input[i + 1]), low = hex(input[i + 2]); if (high < 0 || low < 0) return false; output += static_cast<char>((high << 4) | low); i += 2; }
    }
    return shareUtf8(output);
}

bool shareBase64(std::string encoded, std::string& decoded)
{
    if (encoded.empty() || encoded.size() > 2 * 1024 * 1024) return false;
    for (char& ch : encoded) { if (ch == '-') ch = '+'; else if (ch == '_') ch = '/'; }
    const size_t equal = encoded.find('='), plain = equal == std::string::npos ? encoded.size() : equal;
    if (plain % 4 == 1 || encoded.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 0) < plain) return false;
    const size_t padding = (4 - plain % 4) % 4;
    if (equal != std::string::npos && (encoded.size() - plain != padding || encoded.find_first_not_of('=', plain) != std::string::npos)) return false;
    encoded.resize(plain); encoded.append(padding, '=');
    std::vector<unsigned char> bytes(encoded.size() / 4 * 3 + 1); size_t count = 0;
    if (mbedtls_base64_decode(bytes.data(), bytes.size(), &count, reinterpret_cast<const unsigned char*>(encoded.data()), encoded.size()) != 0) return false;
    decoded.assign(reinterpret_cast<const char*>(bytes.data()), count);
    return !decoded.empty() && shareUtf8(decoded);
}

bool sharePort(const std::string& text, int& port)
{
    if (text.empty() || text.size() > 5 || text.find_first_not_of("0123456789") != std::string::npos) return false;
    port = std::atoi(text.c_str()); return port > 0 && port <= 65535;
}

bool shareEndpoint(const std::string& text, ShareLinkNode& node)
{
    std::string host, port;
    if (!text.empty() && text.front() == '[') {
        const size_t end = text.find(']');
        if (end == std::string::npos || text.substr(end, 2) != "]:") return false;
        host = text.substr(1, end - 1); port = text.substr(end + 2);
        in6_addr address{}; if (inet_pton(AF_INET6, host.c_str(), &address) != 1) return false;
    } else {
        const size_t colon = text.rfind(':');
        if (colon == std::string::npos || text.find(':') != colon) return false;
        host = text.substr(0, colon); port = text.substr(colon + 1);
        if (host.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._") != std::string::npos) return false;
    }
    if (host.empty() || host.size() > 253 || !sharePort(port, node.port)) return false;
    node.server = host; return true;
}

bool shareParams(const std::string& text, const std::set<std::string>& accepted, std::map<std::string, std::string>& params)
{
    if (text.empty()) return true;
    std::istringstream stream(text); std::string part;
    while (std::getline(stream, part, '&')) {
        const size_t equal = part.find('='); std::string key, value;
        if (part.empty() || equal == std::string::npos || !sharePercent(part.substr(0, equal), key) ||
            !sharePercent(part.substr(equal + 1), value) || !accepted.count(key) || !params.emplace(key, value).second) return false;
    }
    return true;
}

bool shareBoolean(const std::string& text, bool& value)
{
    if (text.empty() || text == "0" || text == "false") { value = false; return true; }
    if (text == "1" || text == "true") { value = true; return true; }
    return false;
}

bool shareAlpn(const std::string& text, const std::string& network, std::string& output)
{
    if (text.empty()) return true;
    std::vector<std::string> values; std::istringstream stream(text); std::string item;
    while (std::getline(stream, item, ',')) {
        if (item.empty() || item.size() > 255 || values.size() >= 16 || item.find_first_of("\r\n ") != std::string::npos) return false;
        values.push_back(item);
    }
    if (network == "ws" && std::find(values.begin(), values.end(), "http/1.1") == values.end()) return false;
    output = ruleStringsJson(values); return true;
}

bool shareSs(std::string body, ShareLinkNode& node, std::string& error)
{
    node.type = "ss";
    const size_t query = body.find('?'); std::map<std::string, std::string> params;
    if (query != std::string::npos) {
        if (!shareParams(body.substr(query + 1), {"plugin"}, params)) { error = "不支持此 SS 链接的附加参数"; return false; }
        body.resize(query);
    }
    if (!params["plugin"].empty()) { error = "内置内核尚不支持 Shadowsocks 插件"; return false; }
    bool legacy = false;
    if (body.find('@') == std::string::npos) { std::string decoded; if (!shareBase64(body, decoded)) { error = "SS Base64 编码无效"; return false; } body = decoded; legacy = true; }
    const size_t at = body.rfind('@');
    if (at == std::string::npos) { error = "SS 链接缺少服务器地址"; return false; }
    std::string auth = body.substr(0, at), endpoint = body.substr(at + 1);
    if (!endpoint.empty() && endpoint.back() == '/') endpoint.pop_back();
    if (!legacy) {
        std::string decoded; if (!sharePercent(auth, decoded)) { error = "SS 认证转义无效"; return false; } auth = decoded;
        if (auth.find(':') == std::string::npos) { if (!shareBase64(auth, decoded)) { error = "SS 认证编码无效"; return false; } auth = decoded; }
    }
    const size_t colon = auth.find(':');
    if (colon == std::string::npos || colon + 1 == auth.size() || !shareEndpoint(endpoint, node)) { error = "SS 认证、服务器或端口无效"; return false; }
    node.fields["cipher"] = shareQuoted(lower(auth.substr(0, colon))); node.fields["password"] = shareQuoted(auth.substr(colon + 1)); return true;
}

bool shareTrojan(std::string body, ShareLinkNode& node, std::string& error)
{
    node.type = "trojan";
    const size_t query = body.find('?'); std::map<std::string, std::string> params;
    if (query != std::string::npos) {
        if (!shareParams(body.substr(query + 1), {"sni", "peer", "allowInsecure", "insecure", "type", "security", "host", "path", "alpn"}, params)) { error = "Trojan 链接含有重复或尚不支持的参数"; return false; }
        body.resize(query);
    }
    const size_t at = body.rfind('@'); std::string password, endpoint;
    if (at != std::string::npos) endpoint = body.substr(at + 1);
    if (!endpoint.empty() && endpoint.back() == '/') endpoint.pop_back();
    if (at == std::string::npos || !sharePercent(body.substr(0, at), password) || password.empty() || !shareEndpoint(endpoint, node)) { error = "Trojan 密码、服务器或端口无效"; return false; }
    const std::string network = params["type"].empty() ? "tcp" : params["type"];
    if ((network != "tcp" && network != "ws") || (!params["security"].empty() && params["security"] != "tls")) { error = "Trojan 仅支持 TLS 或 WebSocket + TLS"; return false; }
    if ((!params["sni"].empty() && !params["peer"].empty() && params["sni"] != params["peer"]) ||
        (params.count("insecure") && params.count("allowInsecure") && params["insecure"] != params["allowInsecure"])) { error = "Trojan 链接参数互相冲突"; return false; }
    bool insecure = false;
    if (!shareBoolean(params.count("allowInsecure") ? params["allowInsecure"] : params["insecure"], insecure)) { error = "Trojan 证书校验参数无效"; return false; }
    if (network != "ws" && !params["path"].empty()) { error = "WebSocket 路径需要 type=ws"; return false; }
    node.fields["password"] = shareQuoted(password); node.fields["network"] = shareQuoted(network); node.fields["tls"] = "true";
    std::string sni = params["sni"].empty() ? params["peer"] : params["sni"];
    if (sni.empty()) sni = trim(params["host"].substr(0, params["host"].find(',')));
    node.fields["sni"] = shareQuoted(sni); node.fields["skip-cert-verify"] = insecure ? "true" : "false";
    if (network == "ws") node.fields["ws-opts"] = "{\"path\":" + shareQuoted(params["path"].empty() ? "/" : params["path"]) + ",\"headers\":" + (params["host"].empty() ? "{}" : "{\"Host\":" + shareQuoted(params["host"]) + "}") + "}";
    std::string alpn;
    if (!shareAlpn(params["alpn"], network, alpn)) { error = "TLS ALPN 无效，WebSocket 需要 http/1.1"; return false; }
    if (!alpn.empty()) node.fields["alpn"] = alpn;
    return true;
}

bool shareVmess(const std::string& body, ShareLinkNode& node, std::string& error)
{
    node.type = "vmess"; std::string decoded;
    if (!shareBase64(body, decoded) || decoded.size() > 64 * 1024 || trim(decoded).empty() || trim(decoded).front() != '{') { error = "VMess 链接需要 Base64 编码的 JSON 对象"; return false; }
    EditorYaml data; if (!data.parse(decoded, 64 * 1024, error)) { error = "VMess JSON 格式无效"; return false; }
    auto* root = yaml_document_get_root_node(&data.document); std::string normalized;
    if (!root || root->type != YAML_MAPPING_NODE || !editorNodeText(data.document, 1, normalized, error)) { error = "VMess JSON 不能包含重复字段或复杂引用"; return false; }
    const std::set<std::string> accepted = {"v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni", "alpn", "insecure", "fp", "vcn", "pcs"};
    for (auto* pair = root->data.mapping.pairs.start; pair < root->data.mapping.pairs.top; ++pair) {
        const auto* value = yaml_document_get_node(&data.document, pair->value);
        if (!accepted.count(yamlText(yaml_document_get_node(&data.document, pair->key))) || !value || value->type != YAML_SCALAR_NODE) { error = "VMess 链接含有尚不支持的字段"; return false; }
    }
    auto get = [&](const char* key) { return yamlText(yamlValue(data.document, root, key)); };
    if ((!get("v").empty() && get("v") != "2") || (!get("type").empty() && get("type") != "none") ||
        !get("fp").empty() || !get("vcn").empty() || !get("pcs").empty()) { error = "内置内核不支持此 VMess 版本、伪装或证书指纹选项"; return false; }
    const std::string host = get("add"), endpoint = host.find(':') == std::string::npos ? host + ":" + get("port") : "[" + host + "]:" + get("port");
    if (!shareEndpoint(endpoint, node)) { error = "VMess 服务器或端口无效"; return false; }
    node.name = get("ps"); const std::string network = get("net").empty() ? "tcp" : get("net");
    if ((network != "tcp" && network != "ws") || (!get("tls").empty() && get("tls") != "tls" && get("tls") != "none")) { error = "VMess 仅支持 TCP、TLS、WebSocket 与 WebSocket + TLS"; return false; }
    bool insecure = false; if (!shareBoolean(get("insecure"), insecure)) { error = "VMess 证书校验参数无效"; return false; }
    const std::string aid = get("aid").empty() ? "0" : get("aid");
    if (aid.size() > 5 || aid.find_first_not_of("0123456789") != std::string::npos || std::atoi(aid.c_str()) > 65535) { error = "VMess alterId 应为 0 至 65535 的整数"; return false; }
    if (network != "ws" && ((!get("host").empty() && get("tls") != "tls") || (!get("path").empty() && get("path") != "/"))) { error = "此 VMess TCP 伪装参数尚不支持"; return false; }
    node.fields["uuid"] = shareQuoted(get("id")); node.fields["alterId"] = std::to_string(std::atoi(aid.c_str()));
    node.fields["cipher"] = shareQuoted(get("scy").empty() ? "auto" : lower(get("scy"))); node.fields["network"] = shareQuoted(network);
    std::string sni = get("sni"); if (sni.empty() && get("tls") == "tls") sni = trim(get("host").substr(0, get("host").find(',')));
    node.fields["tls"] = get("tls") == "tls" ? "true" : "false"; node.fields["servername"] = shareQuoted(sni); node.fields["skip-cert-verify"] = insecure ? "true" : "false";
    if (network == "ws") node.fields["ws-opts"] = "{\"path\":" + shareQuoted(get("path").empty() ? "/" : get("path")) + ",\"headers\":" + (get("host").empty() ? "{}" : "{\"Host\":" + shareQuoted(get("host")) + "}") + "}";
    std::string alpn;
    if (!shareAlpn(get("alpn"), network, alpn)) { error = "TLS ALPN 无效，WebSocket 需要 http/1.1"; return false; }
    if (!alpn.empty()) node.fields["alpn"] = alpn;
    return true;
}

std::string shareLinksJson(std::string text, const std::string& occupiedJson = "[]")
{
    auto fail = [](const std::string& error) { return "{\"error\":" + shareQuoted(error) + "}"; };
    if (text.empty() || text.size() > 2 * 1024 * 1024 || !shareUtf8(text)) return fail("请输入有效 UTF-8 节点链接，总大小不得超过 2 MB");
    std::set<std::string> names = {"DIRECT", "REJECT"};
    EditorYaml occupied; std::string error;
    if (!occupied.parse(occupiedJson, 2 * 1024 * 1024, error)) return fail("无法读取已有节点名称");
    auto* existing = yaml_document_get_root_node(&occupied.document);
    if (!existing || existing->type != YAML_SEQUENCE_NODE || existing->data.sequence.items.top - existing->data.sequence.items.start > 10000) return fail("已有节点名称列表无效");
    for (auto* id = existing->data.sequence.items.start; id < existing->data.sequence.items.top; ++id) {
        const std::string name = yamlText(yaml_document_get_node(&occupied.document, *id)); if (!editorName(name)) return fail("已有节点名称无效"); names.insert(name);
    }
    if (text.compare(0, 3, "\xef\xbb\xbf") == 0) text.erase(0, 3);
    if (text.find("://") == std::string::npos) {
        std::string compact, decoded; for (unsigned char ch : text) if (!std::isspace(ch)) compact += ch;
        if (!shareBase64(compact, decoded)) return fail("请输入 ss://、vmess:// 或 trojan:// 节点链接，也可粘贴 Base64 节点列表"); text = decoded;
    }
    std::istringstream lines(text); std::string line, nodes = "[", views = "["; std::vector<std::string> members; size_t number = 0;
    while (std::getline(lines, line)) {
        ++number; line = trim(line); if (line.empty() || line.front() == '#') continue;
        if (members.size() >= 500 || line.size() > 64 * 1024) return fail("每次最多导入 500 个节点，单条链接不得超过 64 KB");
        ShareLinkNode node; std::string fragment, body; const size_t scheme = line.find("://"), hash = line.find('#');
        bool ok = scheme != std::string::npos;
        if (ok) {
            body = line.substr(scheme + 3, (hash == std::string::npos ? line.size() : hash) - scheme - 3);
            if (hash != std::string::npos) ok = sharePercent(line.substr(hash + 1), fragment);
            if (body.find_first_of(" \t\r\n") != std::string::npos) ok = false;
        }
        error.clear();
        if (ok) {
            const std::string protocol = lower(line.substr(0, scheme));
            if (protocol == "ss") ok = shareSs(body, node, error);
            else if (protocol == "trojan") ok = shareTrojan(body, node, error);
            else if (protocol == "vmess") ok = shareVmess(body, node, error);
            else { error = "内置内核支持导入 SS、VMess 和 Trojan 链接；此协议尚不支持"; ok = false; }
        }
        if (!ok) return fail("第 " + std::to_string(number) + " 行：" + (error.empty() ? "链接格式或百分号转义无效" : error));
        if (!fragment.empty()) node.name = fragment;
        if (node.name.empty()) node.name = node.type + "-" + node.server + ":" + std::to_string(node.port);
        if (!editorName(node.name) || node.name.size() > 900) return fail("第 " + std::to_string(number) + " 行：节点名称无效或过长");
        const std::string base = node.name; size_t suffix = 2;
        while (names.count(node.name)) node.name = base + " (" + std::to_string(suffix++) + ")";
        names.insert(node.name); node.fields["name"] = shareQuoted(node.name); node.fields["type"] = shareQuoted(node.type); node.fields["server"] = shareQuoted(node.server); node.fields["port"] = std::to_string(node.port); node.fields["udp"] = "true";
        std::string content = "{";
        for (const auto& field : node.fields) { if (content.size() > 1) content += ','; content += shareQuoted(field.first) + ':' + field.second; } content += '}';
        if (!editorObjectValid({node.name, content}, false, error)) return fail("第 " + std::to_string(number) + " 行：节点参数无效或内核不支持：" + error);
        if (!members.empty()) { nodes += ','; views += ','; }
        nodes += content; views += "{\"name\":" + shareQuoted(node.name) + ",\"type\":" + shareQuoted(node.type) + ",\"server\":" + shareQuoted(node.server) + ",\"port\":" + shareQuoted(std::to_string(node.port)) + ",\"content\":" + shareQuoted(content) + "}";
        members.push_back(node.name);
    }
    if (members.empty()) return fail("没有找到可导入的节点链接");
    std::string group = "节点选择"; size_t suffix = 2; while (names.count(group)) group = "节点选择 (" + std::to_string(suffix++) + ")";
    const std::string content = "{\"port\":7890,\"socks-port\":7891,\"mode\":\"rule\",\"proxies\":" + nodes + "],\"proxy-groups\":[{\"name\":" + shareQuoted(group) + ",\"type\":\"select\",\"proxies\":" + ruleStringsJson(members) + "}],\"rules\":[" + shareQuoted("MATCH," + group) + "]}";
    ParsedConfig parsed; if (!parseConfigText(content, parsed, error)) return fail("节点无法组成有效配置：" + error);
    return "{\"error\":\"\",\"nodes\":" + views + "],\"content\":" + shareQuoted(content) + "}";
}
