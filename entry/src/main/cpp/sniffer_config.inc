bool snifferPorts(const std::vector<std::string>& input, std::vector<std::pair<int, int>>& output, std::string& error)
{
    output.clear();
    if (input.size() > 128) { error = "sniffer ports has too many ranges"; return false; }
    for (const auto& text : input) {
        const auto dash = text.find('-'); const auto left = text.substr(0, dash), right = dash == std::string::npos ? left : text.substr(dash + 1);
        const auto number = [](const std::string& value) {
            return !value.empty() && value.size() <= 5 && value.find_first_not_of("0123456789") == std::string::npos && std::atoi(value.c_str()) > 0 && std::atoi(value.c_str()) <= 65535;
        };
        if (!number(left) || !number(right) || std::atoi(left.c_str()) > std::atoi(right.c_str())) { error = "sniffer ports requires integers or ascending ranges between 1 and 65535"; return false; }
        output.emplace_back(std::atoi(left.c_str()), std::atoi(right.c_str()));
    }
    return true;
}

bool normalizeSnifferConfig(SnifferConfig& config, std::string& error)
{
    for (const auto& entry : config.protocols) {
        if (entry.first != "HTTP" && entry.first != "TLS" && entry.first != "QUIC") { error = "sniffer supports HTTP, TLS and QUIC"; return false; }
        if (entry.second.ports.size() > 128) { error = "sniffer ports has too many ranges"; return false; }
        for (const auto& port : entry.second.ports) if (port.first < 1 || port.second > 65535 || port.first > port.second) { error = "Invalid sniffer port range"; return false; }
    }
    const auto domains = [&](const std::vector<std::string>& input, RuleDomainIndex& index, std::vector<std::string>& literals) {
        if (input.size() > 256) { error = "sniffer domain list has too many entries"; return false; }
        std::vector<std::string> patterns; literals.clear();
        for (const auto& text : input) {
            if (text.empty() || text.size() > 1024 || !shareUtf8(text) || std::any_of(text.begin(), text.end(), [](unsigned char c) { return c < 32 || c == 127; })) {
                error = "Invalid sniffer domain pattern"; return false;
            }
            // Some imported configurations exclude literal SNI labels such as
            // 'Mijia Cloud'. Keep literal matching without relaxing host validation.
            if (text.find(' ') != std::string::npos) literals.push_back(lower(text)); else patterns.push_back(text);
        }
        if (!buildRuleDomains(patterns, index, error)) { error = "Invalid sniffer domain pattern"; return false; }
        return true;
    };
    const auto ranges = [&](const std::vector<std::string>& input, std::vector<RuleIpRange>& output) {
        if (input.size() > 256) { error = "sniffer IP list has too many entries"; return false; }
        output.clear();
        for (const auto& text : input) { RuleIpRange range; if (!parseRuleCidr(text, range)) { error = "sniffer address exclusions require IPv4/IPv6 CIDR"; return false; } output.push_back(range); }
        return true;
    };
    return domains(config.forceDomain, config.forceIndex, config.forceLiterals) && domains(config.skipDomain, config.skipIndex, config.skipLiterals) &&
        ranges(config.skipSource, config.sourceRanges) && ranges(config.skipDestination, config.destinationRanges);
}

bool parseSnifferConfig(yaml_document_t& document, yaml_node_t* root, SnifferConfig& config, std::string& error)
{
    config = SnifferConfig{};
    if (!root) return normalizeSnifferConfig(config, error);
    if (root->type != YAML_MAPPING_NODE) { error = "sniffer must be a mapping"; return false; }
    const auto keys = [&](yaml_node_t* node, const std::set<std::string>& allowed) {
        std::set<std::string> seen;
        for (auto* pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; ++pair) {
            auto* key = yaml_document_get_node(&document, pair->key); const auto text = yamlText(key);
            if (!key || key->type != YAML_SCALAR_NODE || !allowed.count(text) || !seen.insert(text).second) { error = "Unknown or duplicate sniffer field"; return false; }
        }
        return true;
    };
    const auto boolean = [&](yaml_node_t* node, const char* name, bool& value) {
        auto* found = yamlValue(document, node, name); if (!found) return true;
        const auto text = lower(yamlText(found));
        if (found->type != YAML_SCALAR_NODE || (text != "true" && text != "false")) { error = std::string("sniffer.") + name + " must be true or false"; return false; }
        value = text == "true"; return true;
    };
    const auto strings = [&](yaml_node_t* node, const char* name, std::vector<std::string>& output) {
        auto* list = yamlValue(document, node, name); if (!list) return true;
        if (list->type != YAML_SEQUENCE_NODE) { error = std::string("sniffer.") + name + " must be a list"; return false; }
        output.clear();
        for (auto* item = list->data.sequence.items.start; item < list->data.sequence.items.top; ++item) {
            auto* value = yaml_document_get_node(&document, *item);
            if (!value || value->type != YAML_SCALAR_NODE || output.size() >= 256) { error = "Invalid sniffer list"; return false; }
            output.push_back(yamlText(value));
        }
        return true;
    };
    if (!keys(root, {"enable", "force-dns-mapping", "parse-pure-ip", "override-destination", "sniff", "force-domain", "skip-domain", "skip-src-address", "skip-dst-address", "sniffing", "port-whitelist"}) ||
        !boolean(root, "enable", config.enabled) || !boolean(root, "force-dns-mapping", config.forceDnsMapping) || !boolean(root, "parse-pure-ip", config.parsePureIp) ||
        !boolean(root, "override-destination", config.overrideDestination) || !strings(root, "force-domain", config.forceDomain) || !strings(root, "skip-domain", config.skipDomain) ||
        !strings(root, "skip-src-address", config.skipSource) || !strings(root, "skip-dst-address", config.skipDestination)) return false;
    config.protocols.clear();
    auto* sniff = yamlValue(document, root, "sniff");
    if (sniff && sniff->type != YAML_MAPPING_NODE) { error = "sniffer.sniff must be a mapping"; return false; }
    if (sniff) {
        for (auto* pair = sniff->data.mapping.pairs.start; pair < sniff->data.mapping.pairs.top; ++pair) {
            auto* value = yaml_document_get_node(&document, pair->value); auto name = lower(yamlText(yaml_document_get_node(&document, pair->key)));
            name = name == "http" ? "HTTP" : name == "tls" ? "TLS" : name == "quic" ? "QUIC" : name;
            if (config.protocols.count(name) || !value || value->type != YAML_MAPPING_NODE || !keys(value, {"ports", "override-destination"})) { error = "Invalid or duplicate sniffer protocol"; return false; }
            SnifferProtocol protocol; protocol.overrideDestination = config.overrideDestination; std::vector<std::string> ports;
            if (!strings(value, "ports", ports) || !snifferPorts(ports, protocol.ports, error) || !boolean(value, "override-destination", protocol.overrideDestination)) return false;
            config.protocols[name] = std::move(protocol);
        }
    }
    if (config.protocols.empty()) {
        std::vector<std::string> names, ports;
        if (!strings(root, "sniffing", names) || !strings(root, "port-whitelist", ports)) return false;
        for (auto name : names) {
            name = lower(name); name = name == "http" ? "HTTP" : name == "tls" ? "TLS" : name == "quic" ? "QUIC" : name;
            SnifferProtocol protocol; protocol.overrideDestination = config.overrideDestination;
            if (config.protocols.count(name) || !snifferPorts(ports, protocol.ports, error)) { error = "Invalid legacy sniffer protocols or ports"; return false; }
            config.protocols[name] = std::move(protocol);
        }
    }
    return normalizeSnifferConfig(config, error);
}
