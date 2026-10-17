void ruleEditsTests(const std::string& directory)
{
    const std::string source = "port: 0\nsocks-port: 0\nmode: rule\nopaque: &opaque {value: \"保留 # : \\\"\"}\ncopy: *opaque\n"
        "proxy-groups: [{name: '选择节点', type: select, proxies: [DIRECT]}]\nrules: &rules [\"DOMAIN,original.test,REJECT\", \"MATCH,REJECT\"]\noriginal-copy: *rules\n";
    const std::string text = "{\"version\":1,\"prepend\":[\"DOMAIN,priority.test,REJECT\"],\"append\":[\"MATCH,选择节点\"],\"remove\":[\"MATCH,REJECT\"]}";
    std::string error; RuleEdits edits;
    require(parseRuleEdits(text, edits, error), "Valid versioned custom rules must parse");
    ParsedConfig parsed;
    require(parseConfigText(source, parsed, error, &edits) && parsed.rules.size() == 3, "Prepend, source exclusion and append must compose with full native validation");
    require(parsed.rules[0].value == "priority.test" && parsed.rules[1].value == "original.test" && parsed.rules[2].target == "选择节点", "Effective rules must preserve exact priority and Unicode policies");
    require(parsed.sourceRules.size() == 2 && parsed.sourceRules.back() == "MATCH,REJECT", "Editing must retain the original source list for preview");
    std::string rendered;
    require(renderEditedRules(source, parsed.effectiveRules, rendered), "Export must render effective rules as independent YAML");
    ParsedConfig exported;
    require(parseConfigText(rendered, exported, error) && exported.effectiveRules == parsed.effectiveRules, "Exported rules must work without any sidecar");
    require(rendered.find("opaque:") != std::string::npos && rendered.find("original-copy:") != std::string::npos && rendered.find("保留") != std::string::npos, "Export must preserve unrelated data and alias references");
    require(ruleEditorJson(source, text).find("\"policies\":[\"DIRECT\",\"REJECT\",\"选择节点\"]") != std::string::npos, "Editor policy choices must come from the actual profile");
    require(ruleEditorJson(source, text, true).find("\"content\":") != std::string::npos, "NAPI export must return rendered source");
    const std::vector<std::string> invalid = {
        "{}", "[]", "null", "{version: 2, prepend: [], append: [], remove: []}",
        "{version: 1, prepend: [], append: [], remove: [], extra: []}",
        "{version: 1, version: 1, prepend: [], append: [], remove: []}",
        "{version: 1, prepend: x, append: [], remove: []}",
        "{version: 1, prepend: [\"\"], append: [], remove: []}",
        "{version: 1, prepend: [\"DOMAIN,x,DIRECT\\nMATCH,REJECT\"], append: [], remove: []}",
        "{version: 1, prepend: [\"PROCESS-NAME,app,DIRECT\"], append: [], remove: []}",
        "{version: 1, prepend: [], append: [], remove: []}\n---\n{}",
        "{version: 1, prepend: [], append: [], remove: []}\n---\n["
    };
    for (const auto& bad : invalid) { RuleEdits rejected; error.clear(); require(!parseRuleEdits(bad, rejected, error) && !error.empty(), "Malformed or unsupported custom rules must be rejected"); }
    require(ruleEditorJson(source, "{version: 1, prepend: [\"DOMAIN,x,missing\"], append: [], remove: []}").find("unknown target") != std::string::npos, "Custom targets must exist in the current profile");
    require(ruleEditorJson(source, "{version: 1, prepend: [\"RULE-SET,missing,DIRECT\"], append: [], remove: []}").find("Unknown rule provider") != std::string::npos, "Custom rule providers must exist in the current profile");
    require(ruleEditorJson(source, "{version: 1, prepend: [\"IP-CIDR,999.0.0.1/32,DIRECT\"], append: [], remove: []}").find("\"error\":\"\"") == std::string::npos, "Invalid CIDR additions must be refused before saving");
    const std::string empty = "{version: 1, prepend: [], append: [], remove: []}";
    ParsedConfig untouched; RuleEdits noEdits; error.clear();
    require(parseRuleEdits(empty, noEdits, error) && parseConfigText(source, untouched, error, &noEdits) && untouched.effectiveRules == untouched.sourceRules, "Clearing edits must restore the original list");
    std::string missingRules;
    require(renderEditedRules("mode: rule\n", {"MATCH,DIRECT"}, missingRules) && parseConfigText(missingRules, exported = ParsedConfig{}, error), "Export must support configurations with no original rules key");
    std::string jsonRules;
    require(renderEditedRules("{\"rules\":[\"MATCH,DIRECT\"],\"port\":0}", {"MATCH,REJECT"}, jsonRules) && parseConfigText(jsonRules, exported = ParsedConfig{}, error), "JSON profiles must export usable YAML with effective rules");
    RuleEdits duplicate; duplicate.remove = {"MATCH,REJECT"};
    require(applyRuleEdits({"MATCH,REJECT", "MATCH,REJECT"}, &duplicate).empty(), "Exclusions must remove every exact duplicate original rule");
    duplicate.remove = {"match,reject"};
    require(applyRuleEdits({"MATCH,REJECT"}, &duplicate).size() == 1, "Exclusions must use exact original text, not fuzzy matching");
    RuleEdits oversized; error.clear(); require(!parseRuleEdits(std::string(256 * 1024 + 1, ' '), oversized, error), "Sidecar size must be bounded");
    std::string huge = "{version: 1, prepend: [";
    for (int i = 0; i < 1001; ++i) { if (i) huge += ','; huge += "\"MATCH,DIRECT\""; }
    huge += "], append: [], remove: []}"; error.clear();
    require(!parseRuleEdits(huge, oversized = RuleEdits{}, error), "Custom rule count must be bounded");
    const std::string profile = directory + "/rule-edits.yaml";
    { std::ofstream out(profile); out << source; }
    { std::ofstream out(profile + ".rules.json"); out << text; }
    error.clear(); require(loadConfigLocked(profile, error), "Real profile loading must read the saved sidecar");
    require(activeProxyNode("priority.test", 80).name == "REJECT" && activeProxyNode("elsewhere.test", 80).name == "DIRECT", "Saved edits must affect real route selection");
    { std::ofstream out(profile); out << "port: 0\nsocks-port: 0\nproxy-groups: [{name: '选择节点', type: select, proxies: [DIRECT]}]\nrules: [\"DOMAIN,new-subscription.test,REJECT\", \"MATCH,REJECT\"]\n"; }
    require(loadConfigLocked(profile, error) && activeProxyNode("priority.test", 80).name == "REJECT" && activeProxyNode("new-subscription.test", 80).name == "REJECT" && activeProxyNode("elsewhere.test", 80).name == "DIRECT", "Subscription source replacement must preserve edits while using newly downloaded rules");
    { std::ofstream out(profile + ".rules.json"); out << "{}"; }
    error.clear(); require(!loadConfigLocked(profile, error) && activeProxyNode("priority.test", 80).name == "REJECT", "Corrupt sidecars must preserve the previous running routing state");
    { std::ofstream out(profile + ".rules.json"); }
    error.clear(); require(!loadConfigLocked(profile, error), "Existing empty sidecars must not silently remove routing overrides");
    std::remove((profile + ".rules.json").c_str()); error.clear();
    require(loadConfigLocked(profile, error) && activeProxyNode("elsewhere.test", 80).name == "REJECT", "Removing the sidecar must restore subscription routing");
    std::remove(profile.c_str());
}
