void configMergeTests(const std::string& directory)
{
    const std::string source = R"(port: 7890
socks-port: 7891
mode: rule
shared: &shared {first: 1, retained: source}
untouched: *shared
custom: *shared
hosts: {old.test: 192.0.2.1}
dns:
  enable: true
  nameserver: [1.1.1.1]
  nameserver-policy: {old.test: 8.8.8.8}
  fallback-filter: {domain: [old.test], ipcidr: [192.0.2.0/24]}
proxies: [{name: base, type: direct}]
proxy-groups: [{name: Policy, type: select, proxies: [base]}]
rules: ['MATCH,Policy']
)";
    const std::string global = "custom: {first: 2, added: global}\nhosts: {global.test: 192.0.2.2}\ndns: {nameserver: [8.8.8.8], nameserver-policy: {global.test: 1.1.1.1}}\n";
    const std::string local = "custom: {added: local}\nhosts: {local.test: 192.0.2.3}\ndns: {nameserver-policy: {local.test: 9.9.9.9}, fallback-filter: {domain: [local.test]}}\n";
    auto settings = [](const std::string& global, const std::string& local) { return "{\"version\":1,\"global\":\"" + jsonEscape(global) + "\",\"profile\":\"" + jsonEscape(local) + "\"}"; };
    ConfigMerges merges; std::string error; require(parseConfigMerges(settings(global, local), merges, error), "Global and profile extension text must parse");
    ParsedConfig parsed; require(parseConfigText(source, parsed, error, nullptr, nullptr, &merges), "Extensions must feed production configuration parsing");
    std::string output; require(renderEditedRules(source, parsed.effectiveRules, output, nullptr, &merges), "Export must include both extension levels");
    EditorYaml data; require(data.parse(output, 8 * 1024 * 1024, error), "Merged export must be a standalone YAML document");
    auto* root = yaml_document_get_root_node(&data.document); auto at = [&](yaml_node_t* map, const char* key) { return yamlValue(data.document, map, key); };
    auto text = [&](yaml_node_t* map, const char* key) { return yamlText(at(map, key)); };
    auto* custom = at(root, "custom"); auto* untouched = at(root, "untouched");
    require(text(custom, "first") == "2" && text(custom, "retained") == "source" && text(custom, "added") == "local", "Generic nested mappings merge global then local while keeping unspecified fields");
    require(text(untouched, "first") == "1" && !at(untouched, "added"), "Merging an aliased branch must leave unrelated aliases unchanged");
    auto* hosts = at(root, "hosts"); require(text(hosts, "local.test") == "192.0.2.3" && !at(hosts, "old.test") && !at(hosts, "global.test"), "hosts is an entire-map replacement boundary at both levels");
    auto* dns = at(root, "dns"); auto* policy = at(dns, "nameserver-policy"); auto* filter = at(dns, "fallback-filter");
    require(text(dns, "enable") == "true" && text(policy, "local.test") == "9.9.9.9" && !at(policy, "old.test") && !at(policy, "global.test"), "dns keeps unspecified direct fields and replaces each written child map");
    require(!at(filter, "ipcidr"), "dns fallback-filter must be replaced as a whole rather than recursively merged");
    auto* servers = at(dns, "nameserver"); require(servers && servers->data.sequence.items.top - servers->data.sequence.items.start == 1 && yamlText(yaml_document_get_node(&data.document, *servers->data.sequence.items.start)) == "8.8.8.8", "List overrides replace source entries");
    ConfigMerges reject{ "rules: ['MATCH,REJECT']\n", "" };
    parsed = ParsedConfig{};
    require(parseConfigText(source, parsed, error, nullptr, nullptr, &reject) && parsed.rules.size() == 1 && parsed.rules[0].target == "REJECT", "Extension rules must change the actual route model");
    RuleEdits rules; rules.prepend = {"DOMAIN,fixture.test,DIRECT"};
    parsed = ParsedConfig{};
    require(parseConfigText(source, parsed, error, &rules, nullptr, &reject) && parsed.rules.front().target == "DIRECT", "Visual rule edits apply to the merged base configuration");
    const std::string nodeMerge = "proxies: [{name: merged, type: direct}]\nproxy-groups: [{name: MergedPolicy, type: select, proxies: [merged]}]\nrules: ['MATCH,MergedPolicy']\n";
    const std::string snapshot = objectEditorJson(source, "", "", true, settings("", nodeMerge));
    require(snapshot.find("MergedPolicy") != std::string::npos && snapshot.find("\"name\":\"base\"") == std::string::npos, "Object editor choices must use merged nodes and groups");
    require(ruleEditorJson(source, "", true, "", settings("", nodeMerge)).find("MergedPolicy") != std::string::npos, "Rule editor policies and exports must include merged groups");
    for (const auto& invalid : {"[]", "null", "{port: 1, port: 2}", "{dns: {enable: true, enable: false}}", "{x: &x [*x]}", "---\n{}\n---\n{}", "port: 70000"}) {
        const std::string result = ruleEditorJson(source, "", false, "", settings("", invalid));
        require(result.find("\"error\":\"\"") == std::string::npos, "Invalid, ambiguous and unsupported composed configurations must fail preview");
    }
    require(ruleEditorJson(source, "", false, "", settings("", "dns: [")).find("line 2") != std::string::npos, "Invalid YAML extension syntax reports a useful location");
    require(ruleEditorJson(source, "", false, "", settings("", "proxy-groups: [{name: Policy, type: select, proxies: [Policy]}]")).find("circular") != std::string::npos, "Merged groups must not introduce dependency cycles");
    for (const auto& invalid : {"{}", "{version: 2, global: '', profile: ''}", "{version: 1, global: [], profile: ''}", "{version: 1, global: '', profile: '', extra: 1}"}) {
        ConfigMerges rejected; error.clear(); require(!parseConfigMerges(invalid, rejected, error), "Extension settings require the exact supported schema");
    }
    ConfigMerges comments{"# A public comment\n", " \n"}; require(parseConfigText(source, parsed, error, nullptr, nullptr, &comments), "Comments-only and whitespace-only editor content must be no-ops");
    ConfigMerges tooBig{std::string(256 * 1024 + 1, '#'), ""}; require(!parseConfigText(source, parsed, error, nullptr, nullptr, &tooBig), "Each YAML extension must obey its byte cap");
    const std::string profile = directory + "/merge-device.yaml", globalFile = directory + "/.global-merge.yaml";
    unlink(globalFile.c_str()); { std::ofstream out(profile); out << source; }
    { std::ofstream out(globalFile); out << reject.global; }
    stopCore(); require(loadConfigLocked(profile, error) && activeProxyNode("fixture.test", 443).type == "reject", "Runtime reload must read application-global extensions");
    { std::ofstream out(profile + ".merge.yaml"); out << "rules: ['MATCH,DIRECT']\n"; }
    require(loadConfigLocked(profile, error) && activeProxyNode("fixture.test", 443).type == "direct", "Profile extension has priority over global configuration");
    { std::ofstream out(profile + ".merge.yaml"); out << "[]"; }
    require(!loadConfigLocked(profile, error) && activeProxyNode("fixture.test", 443).type == "direct", "A broken extension must retain the running route");
    unlink((profile + ".merge.yaml").c_str()); unlink(globalFile.c_str());
    require(loadConfigLocked(profile, error), "Removing extensions must restore source configuration");
    require(readTestFile(profile) == source, "Loading, composing and removing extensions must preserve source bytes");
}
