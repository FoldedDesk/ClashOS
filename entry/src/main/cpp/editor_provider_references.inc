// Read-only editor assistance. Never download or publish connection parameters.
std::string editorProviderReferences(const std::string& filesRoot, const std::string& profile,
    const std::string& expectedSource, const std::string& query)
{
    const std::string empty = "{\"providers\":[]}";
    if (query.empty() || query.size() > 256 * 1024 || expectedSource.size() > 8 * 1024 * 1024 ||
        profile.empty() || profile.size() >= PATH_MAX || profile.find('\0') != std::string::npos) return empty;
    if (!ownedProviderProfile(filesRoot, profile)) return empty;
    std::string current, error;
    if (!readControllerFile(profile, 8 * 1024 * 1024, current, error) || current != expectedSource) return empty;
    ControllerConfigJson json;
    if (!json.parse(query, error) || !json.keys({"proxy-providers"}, error)) return empty;
    yaml_parser_t parser; yaml_document_t document;
    if (!yaml_parser_initialize(&parser)) return empty;
    yaml_parser_set_input_string(&parser, reinterpret_cast<const unsigned char*>(query.data()), query.size());
    if (!yaml_parser_load(&parser, &document)) { yaml_parser_delete(&parser); return empty; }
    std::vector<ProxyProvider> providers;
    const bool valid = parseProviderDefinitions(document, yaml_document_get_root_node(&document), providers, error);
    yaml_document_delete(&document); yaml_parser_delete(&parser);
    if (!valid || providers.size() > 256) return empty;
    const auto deadline = HealthClock::now() + std::chrono::seconds(2);
    ProviderCacheContext context; context.profile = profile;
    std::string output = "{\"providers\":["; size_t totalBytes = 0, totalNodes = 0; bool first = true;
    for (const auto& provider : providers) {
        if (HealthClock::now() > deadline) return empty;
        if (provider.type != "http" && provider.type != "file") continue;
        std::vector<ProxyNode> nodes; size_t bytes = 0;
        const bool loaded = providerCacheNodes(context, provider, nodes, bytes);
        totalBytes += bytes; if (totalBytes > 32 * 1024 * 1024) return empty;
        if (!loaded) continue;
        totalNodes += nodes.size(); if (totalNodes > 16384 || HealthClock::now() > deadline) return empty;
        if (!first) output += ","; first = false;
        output += "{\"name\":\"" + jsonEscape(provider.name) + "\",\"nodes\":[";
        bool firstNode = true;
        for (const auto& node : nodes) {
            if (!firstNode) output += ","; firstNode = false;
            output += "{\"name\":\"" + jsonEscape(node.name) + "\",\"type\":\"" + jsonEscape(node.type) +
                "\",\"dialer\":\"" + jsonEscape(node.dialerProxy) + "\"}";
            if (output.size() > 2 * 1024 * 1024) return empty;
        }
        output += "]}";
    }
    return output + "]}";
}
