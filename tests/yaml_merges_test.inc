void yamlMergeTests(const std::string& directory)
{
    std::string error;
    const std::string fixture = readTestFile(std::string(CLAHSOS_TEST_ROOT) + "/fixtures/yaml/device-templates.yaml");
    ParsedConfig config; require(parseConfigText(fixture, config, error), "Template fixture must load with native configuration parsing");
    require(config.nodes.size() == 6 && config.groups.size() == 1 && config.groups[0].proxies.size() == 6 && config.rules[0].target == "YAML-Templates", "Aliases and merges must populate real nodes, groups and rules");
    for (size_t i = 0; i < config.nodes.size(); ++i) {
        const auto& node = config.nodes[i]; const bool tls = i == 1 || i == 3, anonymous = i >= 4;
        require(node.server == "127.0.0.1" && node.port == (tls ? 18098 : 18097), "Earlier merge sources must win port conflicts");
        require(node.tls == tls && (!tls || (node.skipCertVerify && node.serverName == "vmess.test")), "Inherited TLS options must retain verification settings");
        require(node.username == (anonymous ? "" : "fixture") && node.password == (anonymous ? "" : "p@ss:word"), "Explicit empty credentials must override inherited values");
        require(node.type == (i == 2 || i == 3 || i == 5 ? "socks5" : "http"), "Explicit protocol and nested template inheritance must agree");
    }
    auto json = [&](const std::string& source) {
        std::string output; error.clear(); require(backupYamlText(source, output, error), "Template JSON conversion failed"); return output;
    };
    const auto expanded = json(R"(center: &center {x: 1, y: 2}
big: &big {r: 10, x: 9}
small: &small {r: 1}
result: {<<: [*big, *center, *small], x: 1, label: center/big}
before: {x: 1, <<: [*big, *center, *small]}
after: {<<: {x: 2, nested: {keep: true, old: true}}, nested: {keep: false}}
empty: {<<: [], present: true}
)");
    require(expanded.find("\"result\":{\"x\":1,\"label\":\"center/big\",\"r\":10,\"y\":2}") != std::string::npos, "YAML specification sequence precedence and explicit overrides must agree");
    require(expanded.find("\"before\":{\"x\":1,\"r\":10,\"y\":2}") != std::string::npos, "Explicit keys before a merge must also take priority");
    require(expanded.find("\"after\":{\"nested\":{\"keep\":false},\"x\":2}") != std::string::npos, "YAML merges must replace supplied nested maps rather than deep-merge them");
    require(expanded.find("\"empty\":{\"present\":true}") != std::string::npos && expanded.find("\"<<\"") == std::string::npos, "Empty merge sequences are no-ops and effective mappings contain no merge directives");
    for (const std::string source : {
        "base: &b {field: inherited}\nvalue: {!!merge '<<': *b}\n",
        "%TAG !m! tag:yaml.org,2002:\n---\nbase: &b {field: inherited}\nvalue: {!m!merge '<<': *b}\n",
        "key: &key <<\nbase: &b {field: inherited}\nvalue: {*key: *b}\n"})
        require(json(source).find("\"value\":{\"field\":\"inherited\"}") != std::string::npos, "Explicit merge tags and aliased merge keys must resolve");
    for (const std::string key : {"'<<'", "\"<<\"", "!!str <<", "!!str '<<'"}) {
        const std::string source = "value: {" + key + ": literal}\nrules: ['MATCH,DIRECT']\n";
        require(json(source).find("\"<<\":\"literal\"") != std::string::npos, "Quoted and explicitly string-tagged merge tokens are literal keys");
        ParsedConfig parsed; require(parseConfigText(source, parsed, error), "Literal merge-token configuration must load");
        std::string output; require(renderEditedRules(source, parsed.effectiveRules, output) && json(output).find("\"<<\":\"literal\"") != std::string::npos, "Standalone export must preserve explicitly string-tagged merge tokens");
    }
    require(json("{\"value\":{\"<<\":\"literal\"}}").find("\"<<\":\"literal\"") != std::string::npos, "JSON keys must never inherit YAML merge semantics");
    for (const std::string source : {
        "value: {<<: text}", "value: {<<: [1]}", "value: {<<: [null]}", "value: {<<: [[{}]]}",
        "value: {<<: {}, <<: {x: 1}}", "value: {<<: {x: 1, x: 2}}", "value: {<<: {}, x: 1, x: 2}",
        "value: {<<: {[complex, key]: 1}}", "value: &x {<<: *x}", "value: &x [*x]", "value: {<<: *missing}",
        "value: {!!merge invalid: {x: 1}}"}) {
        ParsedConfig rejected; error.clear(); require(!parseConfigText(source, rejected, error) && !error.empty(), "Invalid merge shapes, duplicate fields and cyclic/undefined aliases must fail");
        EditorYaml editor; error.clear(); require(!editor.parse(source, 8192, error), "Visual editors must reject the same invalid template documents");
    }
    ParsedConfig rejected; error.clear();
    require(!parseConfigText("# 模板\r\nvalue:\r\n  <<: public-secret\r\n", rejected, error) && error.find("YAML line 3, column") != std::string::npos && error.find("public-secret") == std::string::npos,
        "Merge errors need source locations without echoing configuration values");
    std::string bomb = "a0: &a0 [public]\n";
    for (int i = 1; i < 9; ++i) { bomb += "a" + std::to_string(i) + ": &a" + std::to_string(i) + " ["; for (int j = 0; j < 10; ++j) { if (j) bomb += ','; bomb += "*a" + std::to_string(i - 1); } bomb += "]\n"; }
    const auto began = HealthClock::now(); error.clear();
    require(!parseConfigText(bomb, rejected, error) && error.find("limit") != std::string::npos && HealthClock::now() - began < std::chrono::seconds(2), "Exponential aliases must fail before materializing their expansion");
    std::string deep = "value: "; for (int i = 0; i < 70; ++i) deep += "["; deep += "public"; for (int i = 0; i < 70; ++i) deep += "]";
    error.clear(); require(!parseConfigText(deep, rejected, error) && error.find("64 levels") != std::string::npos, "Deep YAML must fail before recursive downstream readers");

    ConfigMerges merges;
    merges.global = "extra: &e {flag: true, number: 7890, text: !!str 123}\ncustom: {<<: *e}\n";
    merges.profileScript = "function main(c){if(c.custom.flag!==true||c.custom.number!==7890||c.custom.text!=='123'||c.proxies[1].tls!==true||c.proxies[4].username!==''||'<<' in c.proxies[0])throw new Error('template types or order lost');c.custom.number=9000;return c;}";
    ParsedConfig scripted; error.clear(); require(parseConfigText(fixture, scripted, error, nullptr, nullptr, &merges) && scripted.nodes.size() == 6, "Scripts must receive resolved and correctly typed templates");
    ParsedConfig standalone; require(!scripted.enhancedSource.empty() && parseConfigText(scripted.enhancedSource, standalone, error) && standalone.nodes[1].tls, "Enhanced exports must load independently of original anchors and script settings");

    const std::string snapshot = objectEditorJson(fixture, "", ""); EditorYaml view;
    require(view.parse(snapshot, 512 * 1024, error), "Visual node snapshot must return valid JSON");
    auto* root = yaml_document_get_root_node(&view.document); auto* proxies = yamlValue(view.document, root, "proxies"); auto* originals = yamlValue(view.document, proxies, "original");
    require(originals && originals->type == YAML_SEQUENCE_NODE && originals->data.sequence.items.top - originals->data.sequence.items.start == 6, "Visual editor must show all inherited nodes");
    auto* item = yaml_document_get_node(&view.document, originals->data.sequence.items.start[1]);
    const std::string nodeText = yamlText(yamlValue(view.document, item, "content"));
    const auto changed = objectDraftJson("proxies", nodeText, "{\"username\":\"changed-fixture\"}"); EditorYaml draft;
    require(draft.parse(changed, 256 * 1024, error), "Inherited node edit must return valid JSON");
    auto* changedItem = yamlValue(draft.document, yaml_document_get_root_node(&draft.document), "item");
    const auto changedContent = yamlText(yamlValue(draft.document, changedItem, "content"));
    ObjectEdits edits; edits.proxies.remove = {"Template-HTTPS"}; edits.proxies.prepend = {{"Template-HTTPS", changedContent}};
    ParsedConfig edited; require(parseConfigText(fixture, edited, error, nullptr, &edits) && edited.nodes[0].username == "changed-fixture" && edited.nodes[1].username == "fixture", "Inherited field edits must detach the node and preserve other template users");
    std::string exported; require(renderEditedRules(fixture, edited.effectiveRules, exported, &edits), "Edited template profiles must export standalone YAML");
    ParsedConfig exportedConfig; require(parseConfigText(exported, exportedConfig, error) && exportedConfig.nodes[0].username == "changed-fixture" && exportedConfig.nodes[1].username == "fixture", "Standalone edited exports must retain detached credentials");

    ProxyProvider provider; provider.name = "Template-provider"; provider.type = "file";
    std::vector<ProxyNode> providerNodes; require(parseProviderContent(provider, fixture, providerNodes, error) && providerNodes.size() == 6 && providerNodes[3].tls && providerNodes[4].username.empty(), "Downloaded and file providers must resolve protocol templates");
    RuleProvider ruleProvider; ruleProvider.name = "Template-rules"; ruleProvider.behavior = "domain"; ruleProvider.format = "yaml";
    std::shared_ptr<const RuleData> rules;
    require(parseRuleContent(ruleProvider, "base: &b {payload: [fixture.test, '+.other.test']}\n<<: *b\n", rules, error) && rules && rules->count == 2 && rules->domains.matches("fixture.test") && rules->domains.matches("www.other.test"), "Rule-provider root merges must populate actual matching payloads");

    const std::string path = directory + "/templates.yaml";
    stopCore(); { std::ofstream out(path); out << fixture; }
    require(loadConfigLocked(path, error) && activeProxyNode("forward.device.test", 80).name == "Template-HTTP", "Saved template profiles must activate actual selected nodes");
    require(readTestFile(path) == fixture, "Activating and inspecting templates must preserve original source bytes");
    { std::ofstream out(path); out << "value: &bad {<<: *bad}\nrules: ['MATCH,DIRECT']\n"; }
    require(!loadConfigLocked(path, error) && activeProxyNode("forward.device.test", 80).name == "Template-HTTP", "Invalid template reload must retain the working route");
    { std::ofstream out(path); out << fixture; }

    const std::string resource = directory + "/template-provider.yaml", providerPath = directory + "/template-provider-profile.yaml";
    { std::ofstream out(resource); out << fixture; }
    const std::string providerProfile = "proxy-providers: {disk: {type: file, path: template-provider.yaml}}\nproxy-groups: [{name: From-disk, type: select, use: [disk]}]\nrules: ['MATCH,From-disk']\n";
    { std::ofstream out(providerPath); out << providerProfile; }
    require(loadConfigLocked(providerPath, error) && g_state.groups[0].proxies.size() == 6 && activeProxyNode("target.test", 80).username == "fixture", "File-provider template hydration must populate live routes");
    g_state.running.store(true);
    const std::string fileApi = "/clahsos/providers/disk/file?profile=" + urlEncode(providerPath);
    std::string replacement = fixture; replacement.replace(replacement.find("username: fixture"), std::strlen("username: fixture"), "username: replacement");
    require(responseFor("PUT", fileApi, replacement) == "{}" && activeProxyNode("target.test", 80).username == "replacement", "Changing only an anchored credential must rebuild actual provider nodes");
    const std::string cachePath = providerCachePath(providerPath, g_state.providers[0]), retained = readTestFile(cachePath);
    require(responseFor("PUT", fileApi, "template: &cycle {<<: *cycle}\nproxies: []\n").find("error") != std::string::npos && activeProxyNode("target.test", 80).username == "replacement" && readTestFile(cachePath) == retained, "Rejected template provider imports must preserve active routes and cache bytes");
    stopCore(); require(loadConfigLocked(providerPath, error) && activeProxyNode("target.test", 80).username == "replacement", "Provider template caches must survive reopening without modifying the source file");
    require(readTestFile(resource) == fixture && readTestFile(providerPath) == providerProfile, "Provider imports must preserve both original YAML files");

    // Independently inspect actual bytes: metadata alone cannot prove inherited
    // authentication, headers, TLS and destinations are used for connections.
    const auto roots = readTestFile(std::string(CLAHSOS_TEST_ROOT) + "/fixtures/vmess/ca.pem");
    g_testVmessTrust = roots.c_str(); g_state.running.store(true);
    VmBytes payload(50000); for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<unsigned char>(i * 19 + 7);
    VmBytes expected = vmBytes("forward-response:"); expected.insert(expected.end(), payload.rbegin(), payload.rend());
    for (const std::string kind : {"http-tcp", "http-tls", "socks5-tcp", "socks5-tls"}) {
        const bool http = kind.rfind("http", 0) == 0, tls = kind.find("tls") != std::string::npos;
        const std::string source = "base: &base {server: forward.invalid, port: 443, username: fixture用户, password: 'p@ss:word测试'}\n"
            "transport: &transport {tls: " + std::string(tls ? "true" : "false") + ", sni: vmess.test}\nproxies: [{name: Wire-template, <<: [*base, *transport], type: " + (http ? "http, headers: {X-Test: native-peer}" : "socks5") + "}]\nrules: ['MATCH,Wire-template']\n";
        ParsedConfig wire; require(parseConfigText(source, wire, error) && wire.nodes.size() == 1, "Wire template must parse");
        VmessReferencePeer peer(0, kind, "", "forward_reference_peer.py");
        g_testConnector = [&](const std::string& host, int port, int) { require(host == "forward.invalid" && port == 443, "Inherited endpoint must be the actual outbound endpoint"); return peer.take(); };
        { ProxyStream stream; require(openProxyStream(wire.nodes[0], "target.test", 443, stream, error, 5000), "Inherited credentials/TLS must complete independent proxy handshake");
          require(streamWrite(stream, reinterpret_cast<const char*>(payload.data()), payload.size()) && stream.forward->finish(), "Inherited proxy must accept request data and half-close");
          VmBytes response, part; while (streamRead(stream, part)) vmAppend(response, part);
          require(response == expected && errno == 0, "Inherited proxy must preserve independently generated responses"); }
        g_testConnector = nullptr; peer.finish();
    }
    g_testVmessTrust = nullptr; stopCore();
}
