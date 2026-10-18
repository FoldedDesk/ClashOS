std::string testObjectEditsJson(const ObjectEdits& edits)
{
    auto section = [](const ObjectSequenceEdits& section) {
        auto items = [](const std::vector<ObjectEditItem>& items) {
            std::string result = "[";
            for (const auto& item : items) { if (result.size() > 1) result += ','; result += "{\"name\":" + editorQuoted(item.name) + ",\"content\":" + editorQuoted(item.content) + "}"; }
            return result + "]";
        };
        return "{\"prepend\":" + items(section.prepend) + ",\"append\":" + items(section.append) + ",\"remove\":" + ruleStringsJson(section.remove) + "}";
    };
    return "{\"version\":1,\"proxies\":" + section(edits.proxies) + ",\"groups\":" + section(edits.groups) + "}";
}

void objectEditsTests(const std::string& directory)
{
    const std::string source = "port: 0\nsocks-port: 0\nproxies: [&node {name: base, type: direct, opaque: {keep: true}}]\n"
        "proxy-groups: [{name: Policy, type: select, proxies: [base]}]\nrules: ['MATCH,Policy']\nuntouched-alias: *node\n";
    ObjectEdits edits;
    edits.proxies.prepend = {{"Extra", "{name: Extra, type: direct}"}, {"base", "{name: base, type: reject, opaque: {custom: true}}"}};
    edits.proxies.remove = {"base"};
    edits.groups.append = {{"新分组", "{name: 新分组, type: select, proxies: [Extra]}"}};
    const std::string settings = testObjectEditsJson(edits); std::string error; ObjectEdits decoded;
    require(parseObjectEdits(settings, decoded, error), "Versioned proxy/group edits must parse");
    ParsedConfig parsed;
    const bool composed = parseConfigText(source, parsed, error, nullptr, &decoded);
    require(composed && parsed.nodes.size() == 2 && parsed.groups.size() == 2, ("Edited node/group collections must compose with source configuration: " + error + " (nodes=" + std::to_string(parsed.nodes.size()) + ", groups=" + std::to_string(parsed.groups.size()) + ")").c_str());
    require(parsed.nodes[0].name == "Extra" && parsed.nodes[1].name == "base" && parsed.nodes[1].type == "reject", "Prepend order and same-name source override must be preserved");
    require(parsed.groups.back().name == "新分组" && parsed.groups.back().proxies.front() == "Extra", "New groups must reference newly added nodes");
    const std::string snapshot = objectEditorJson(source, settings, "");
    require(snapshot.find("\"error\":\"\"") != std::string::npos && snapshot.find("\"choices\":[\"DIRECT\",\"REJECT\",\"Extra\",\"base\",\"Policy\",\"新分组\"]") != std::string::npos, "Editor choices must combine actual effective nodes/groups and built-ins");
    std::string exportText;
    require(renderEditedRules(source, parsed.effectiveRules, exportText, &decoded), "Export must include edited nodes, groups and rules");
    ParsedConfig exported;
    require(parseConfigText(exportText, exported, error) && exported.nodes[1].type == "reject" && exported.groups.back().name == "新分组", "Exported YAML must work without either sidecar");
    EditorYaml exportDocument; require(exportDocument.parse(exportText, 8 * 1024 * 1024, error), "Independent exported document must parse");
    auto* exportedRoot = yaml_document_get_root_node(&exportDocument.document);
    auto* alias = yamlValue(exportDocument.document, exportedRoot, "untouched-alias");
    require(yamlText(yamlValue(exportDocument.document, alias, "type")) == "direct", "Editing the collection must preserve unrelated source aliases");
    const std::string rules = "{version: 1, prepend: [\"DOMAIN,custom.test,新分组\"], append: [], remove: []}";
    require(ruleEditorJson(source, rules, false, settings).find("\"error\":\"\"") != std::string::npos, "Rule editor validation must recognize custom groups");
    require(objectEditorJson(source, settings, rules).find("\"error\":\"\"") != std::string::npos, "Object editor validation must resolve custom rule policies");
    ObjectEdits bad = edits; bad.proxies.remove.clear();
    require(objectEditorJson(source, testObjectEditsJson(bad), "").find("\"error\":\"\"") == std::string::npos, "Duplicate source/custom node names must be rejected");
    bad = edits; bad.proxies.prepend.clear();
    require(objectEditorJson(source, testObjectEditsJson(bad), "").find("Unknown proxy or group") != std::string::npos, "Removing referenced nodes must be rejected");
    bad = edits; bad.groups.append = {{"A", "{name: A, type: select, proxies: [B]}"}, {"B", "{name: B, type: select, proxies: [A]}"}};
    require(objectEditorJson(source, testObjectEditsJson(bad), "").find("circular") != std::string::npos, "Circular custom group references must be rejected");
    bad.groups.append = {{"Empty", "{name: Empty, type: select, proxies: []}"}};
    require(objectEditorJson(source, testObjectEditsJson(bad), "").find("requires members") != std::string::npos, "New groups without candidates or providers must be rejected");
    bad.groups.append = {{"New", "{name: New, type: select, use: [missing]}"}};
    require(objectEditorJson(source, testObjectEditsJson(bad), "").find("Unknown provider") != std::string::npos, "Custom groups must reference actual providers");
    bad.groups.append = {{"New", "{name: New, type: url-test, proxies: [Extra], interval: -1}"}};
    require(objectEditorJson(source, testObjectEditsJson(bad), "").find("health check") != std::string::npos, "Custom health-check parameters must use native validation");
    bad.groups.append.clear();
    for (int index = 0; index < 18; ++index) bad.groups.append.push_back({"chain" + std::to_string(index), "{name: chain" + std::to_string(index) + ", type: select, proxies: [" + (index == 17 ? std::string("Extra") : "chain" + std::to_string(index + 1)) + "]}"});
    require(objectEditorJson(source, testObjectEditsJson(bad), "").find("16 levels") != std::string::npos, "Overlong group chains must fail without unbounded recursion");
    const std::vector<std::string> invalidSettings = {"{}", "null", "[]", "{version: 1, proxies: {}, groups: {}}", settings + "\n---\n{}", settings + "\n---\n[", std::string(2 * 1024 * 1024 + 1, ' ')};
    for (const auto& invalid : invalidSettings) { ObjectEdits rejected; error.clear(); require(!parseObjectEdits(invalid, rejected, error), "Malformed/big/multiple edit documents must be rejected"); }
    const std::vector<ObjectEditItem> invalidItems = {
        {"DIRECT", "{name: DIRECT, type: direct}"}, {"REJECT", "{name: REJECT, type: reject}"}, {"", "{name: '', type: direct}"},
        {"name", "{name: other, type: direct}"}, {"name", "{name: name, type: direct, type: reject}"},
        {"name", "{name: name, type: vless, server: fixture.test, port: 443}"},
        {"name", "{name: name, type: ss, server: fixture.test, port: 123x, cipher: aes-128-gcm}"},
        {"name", "{name: name, type: ss, server: fixture.test, port: 443, cipher: aes-128-cfb}"},
        {"name", "{name: name, type: ss, server: fixture.test, port: 443, cipher: aes-128-gcm, plugin: simple-obfs}"},
        {"name", "{name: name, type: vmess, server: fixture.test, port: 443, uuid: invalid}"},
        {"name", "{name: name, type: trojan, server: fixture.test, port: 443, password: fixture, network: grpc}"},
        {"name", "{name: name, type: direct, opaque: &cycle {self: *cycle}}"},
        {"name", "[name, direct]"}, {"name", std::string(64 * 1024 + 1, ' ')}
    };
    for (const auto& item : invalidItems) { error.clear(); require(!editorObjectValid(item, false, error) && !error.empty(), "Invalid, unsupported or ambiguous node edits must fail with an error"); }
    require(objectEditorJson(source, settings, "", false).find("\"error\":\"\"") != std::string::npos, "Draft collection inspection must remain available before cross-reference validation");
    const std::string vmess = "name: Fixture\ntype: vmess\nserver: fixture.test\nport: 443\nuuid: 01234567-89ab-cdef-0123-456789abcdef\nnetwork: ws\n"
        "ws-opts:\n  path: /old\n  headers: &headers {host: old.test, X-Test: fixture}\nopaque: {headers: *headers, keep: true}\n";
    const std::string draft = objectDraftJson("proxies", vmess, "{\"port\":8443,\"udp\":false,\"ws-opts\":{\"path\":\"/new\",\"headers\":{\"Host\":\"new.test\"}}}");
    EditorYaml result; require(result.parse(draft, 256 * 1024, error), "Draft NAPI result must be valid JSON");
    auto* item = yamlValue(result.document, yaml_document_get_root_node(&result.document), "item");
    const std::string content = yamlText(yamlValue(result.document, item, "content")); EditorYaml patched;
    require(patched.parse(content, 64 * 1024, error), "Patched node content must parse");
    auto* root = yaml_document_get_root_node(&patched.document); auto* ws = yamlValue(patched.document, root, "ws-opts");
    auto* headers = yamlValue(patched.document, ws, "headers"); auto* opaque = yamlValue(patched.document, root, "opaque");
    require(yamlText(yamlValue(patched.document, root, "port")) == "8443" && yamlText(yamlValue(patched.document, root, "udp")) == "false", "Form patches must retain typed numeric and boolean values");
    require(yamlText(yamlValue(patched.document, ws, "path")) == "/new" && yamlText(yamlValue(patched.document, headers, "Host")) == "new.test" && !yamlValue(patched.document, headers, "host"), "WebSocket form edits must normalize Host without duplicate headers");
    require(yamlText(yamlValue(patched.document, headers, "X-Test")) == "fixture", "Editing a known header must preserve other headers");
    require(yamlText(yamlValue(patched.document, yamlValue(patched.document, opaque, "headers"), "host")) == "old.test" && yamlText(yamlValue(patched.document, opaque, "keep")) == "true", "Form edits must detach aliases and preserve unrelated fields");
    require(objectDraftJson("proxies", vmess, "{\"port\":null}").find("\"error\":\"\"") == std::string::npos, "Removing required fields must fail final draft validation");
    require(objectDraftJson("proxies", vmess, "{\"port\":null}", false).find("\"error\":\"\"") != std::string::npos, "Advanced mode may inspect an incomplete draft without saving it");
    require(objectDraftJson("unknown", "{}", "").find("Unknown editor") != std::string::npos, "Draft API must reject unknown collection types");
    for(const std::string protocol:{"vmess","vless"}) {
        const std::string encoded="{name: public-xudp, type: "+protocol+", server: public.invalid, port: 443, uuid: 11111111-2222-4333-8444-555555555555, xudp: true}";
        const auto decoded=objectDraftJson("proxies",encoded,"");
        require(decoded.find("\"error\":\"\"")!=std::string::npos&&decoded.find("\"packetEncoding\":\"xudp\"")!=std::string::npos,"Visual node forms reflect the effective legacy XUDP alias");
        const auto legacy=objectDraftJson("proxies",encoded,R"({"packet-encoding":null,"xudp":null})");
        require(legacy.find("\"error\":\"\"")!=std::string::npos&&legacy.find("\"packetEncoding\":\"\"")!=std::string::npos,"Selecting original UDP encoding clears its legacy alias rather than reactivating XUDP");
        const auto saved=objectDraftJson("proxies",encoded,R"({"packet-encoding":"xudp","xudp":null})");
        require(saved.find("\"error\":\"\"")!=std::string::npos&&saved.find("\"packetEncoding\":\"xudp\"")!=std::string::npos,"Canonical XUDP form edits remain loadable after raw-mode normalization");
    }
    const std::string ss = "{name: Public, type: ss, server: fixture.test, port: 443, cipher: aes-128-gcm, password: fixture}";
    const std::string password = objectDraftJson("proxies", ss, "{\"password\":\"null\"}");
    require(password.find("\"error\":\"\"") != std::string::npos && password.find("\\\"null\\\"") != std::string::npos, "Literal null passwords must remain strings rather than erase instructions");
    const std::string groupDraft = objectDraftJson("groups", "{name: G, type: select, proxies: [DIRECT], icon: 'https://icons.fixture.test/g.svg', hidden: true, opaque: {keep: true}}", "{\"type\":\"url-test\",\"url\":\"https://fixture.test/\",\"interval\":60}");
    require(groupDraft.find("\"error\":\"\"") != std::string::npos && groupDraft.find("\"interval\":\"60\"") != std::string::npos, "Group form metadata must reflect typed patch values and defaults");
    require(groupDraft.find("\"hidden\":true") != std::string::npos && groupDraft.find("\"icon\":\"https://icons.fixture.test/g.svg\"") != std::string::npos,
        "Visual group editing preserves source icons and hidden flags while changing health fields");
    const std::string profile = directory + "/object-edits.yaml";
    { std::ofstream out(profile); out << source; }
    { std::ofstream out(profile + ".objects.json"); out << settings; }
    error.clear(); require(loadConfigLocked(profile, error) && activeProxyNode("fixture.test", 80).type == "reject", "Saved node overrides must affect the actual route");
    { std::ofstream out(profile); out << source + "\nnew-source-field: subscription-update\n"; }
    require(loadConfigLocked(profile, error) && activeProxyNode("fixture.test", 80).type == "reject", "Subscription source replacement must preserve object overrides");
    { std::ofstream out(profile + ".objects.json"); out << "{}"; }
    error.clear(); require(!loadConfigLocked(profile, error) && activeProxyNode("fixture.test", 80).type == "reject", "Corrupt object sidecars must retain working route state");
    { std::ofstream out(profile + ".objects.json"); }
    error.clear(); require(!loadConfigLocked(profile, error), "Empty existing object sidecars must not silently disable overrides");
    std::remove((profile + ".objects.json").c_str()); error.clear();
    require(loadConfigLocked(profile, error) && activeProxyNode("fixture.test", 80).type == "direct", "Removing object edits must restore original nodes/groups");
    std::remove(profile.c_str());
}
