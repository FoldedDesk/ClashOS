// Provider references are validated against this profile's owned caches, or an
// explicit archive bundle. Context is internal; it is never a YAML extension.
struct ProviderCacheContext {
    std::string profile;
    std::map<std::string, std::string> resources;
};

bool ownedProviderProfile(const std::string& filesRoot, const std::string& profile)
{
    std::array<char, PATH_MAX> owned{}, directory{}; struct stat status{};
    const auto slash = profile.find_last_of('/');
    return !profile.empty() && profile.size() < PATH_MAX && profile.find('\0') == std::string::npos && slash != std::string::npos &&
        realpath(filesRoot.c_str(), owned.data()) && realpath(profile.substr(0, slash).c_str(), directory.data()) &&
        std::string(directory.data()) == std::string(owned.data()) + "/profiles" && lstat(profile.c_str(), &status) == 0 && S_ISREG(status.st_mode) && status.st_uid == getuid();
}
bool parseProviderCacheContext(const std::string& text, ProviderCacheContext& context, std::string& error)
{
    context = {};
    if (text.empty()) return true;
    auto fail = [&] { error = "Invalid provider-cache validation context"; return false; };
    EditorYaml data;
    if (!data.parse(text, 48 * 1024 * 1024, error)) return fail();
    auto* root = yaml_document_get_root_node(&data.document);
    if (!editorKeys(data.document, root, {"version", "profile", "resources"}) || yamlText(yamlValue(data.document, root, "version")) != "1") return fail();
    auto* profile = yamlValue(data.document, root, "profile"); auto* resources = yamlValue(data.document, root, "resources");
    if (!profile || profile->type != YAML_SCALAR_NODE || !resources || resources->type != YAML_SEQUENCE_NODE) return fail();
    context.profile = yamlText(profile); if (context.profile.size() >= PATH_MAX || context.profile.find('\0') != std::string::npos) return fail();
    size_t total = 0, count = 0;
    for (auto* item = resources->data.sequence.items.start; item < resources->data.sequence.items.top; ++item) {
        auto* value = yaml_document_get_node(&data.document, *item);
        if (++count > 256 || !editorKeys(data.document, value, {"suffix", "data"})) return fail();
        auto* suffix = yamlValue(data.document, value, "suffix"); auto* encoded = yamlValue(data.document, value, "data");
        if (!suffix || suffix->type != YAML_SCALAR_NODE || !encoded || encoded->type != YAML_SCALAR_NODE) return fail();
        const auto name = yamlText(suffix), bytes = yamlText(encoded);
        if (name.size() != 32 || name.rfind(".provider-", 0) != 0 || name.substr(26) != ".cache" ||
            name.substr(10, 16).find_first_not_of("0123456789abcdef") != std::string::npos || context.resources.count(name) || bytes.size() > 12 * 1024 * 1024) return fail();
        size_t size = 0; const int measured = mbedtls_base64_decode(nullptr, 0, &size, reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
        if ((measured != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL && measured != 0) || !size || size > 8 * 1024 * 1024 + 256 || (total += size) > 32 * 1024 * 1024) return fail();
        std::string decoded(size, '\0');
        if (mbedtls_base64_decode(reinterpret_cast<unsigned char*>(decoded.data()), decoded.size(), &size, reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()) != 0) return fail();
        decoded.resize(size); context.resources.emplace(name, std::move(decoded));
    }
    return context.profile.empty() || context.resources.empty() ? true : fail();
}
bool providerCacheNodes(const ProviderCacheContext& context, const ProxyProvider& provider, std::vector<ProxyNode>& nodes, size_t& size)
{
    std::string body, error;
    const std::string suffix = ".provider-" + providerHash(provider.name).substr(0, 16) + ".cache";
    const auto archived = context.resources.find(suffix);
    if (archived != context.resources.end()) body = archived->second;
    else {
        if (context.profile.empty()) return false;
        const auto path = providerCachePath(context.profile, provider); struct stat status{};
        if (lstat(path.c_str(), &status) != 0 || !S_ISREG(status.st_mode) || status.st_uid != getuid() ||
            !readControllerFile(path, provider.sizeLimit + 256, body, error)) return false;
    }
    size = body.size(); if (size > provider.sizeLimit + 256) return false;
    const auto identity = providerIdentity(provider); if (identity.empty()) return false;
    const std::string prefix = "# ClahsOS provider source: " + identity + "\n";
    return body.rfind(prefix, 0) == 0 && parseProviderContent(provider, body.substr(prefix.size()), nodes, error);
}
bool hydrateParsedProviderCaches(ParsedConfig& config, const ProviderCacheContext& context, std::string& error)
{
    size_t totalBytes = 0, totalNodes = 0;
    if (config.providers.size() > 256) { error = "Provider cache validation exceeds 256 providers"; return false; }
    for (size_t index = 0; index < config.providers.size(); ++index) {
        auto& provider = config.providers[index]; if (provider.type == "inline") continue;
        std::vector<ProxyNode> nodes; size_t bytes = 0;
        const bool loaded = providerCacheNodes(context, provider, nodes, bytes);
        totalBytes += bytes; totalNodes += nodes.size();
        if (totalBytes > 32 * 1024 * 1024 || totalNodes > 16384) { error = "Provider cache validation exceeds its resource limit"; return false; }
        if (!loaded) continue;
        // Match the runtime cache loader's namespace and dialer rejection policy.
        std::set<std::string> names{"DIRECT", "REJECT"};
        for (const auto& node : config.nodes) names.insert(node.name);
        for (const auto& group : config.groups) names.insert(group.name);
        for (size_t i = 0; i < config.providers.size(); ++i) if (i != index) for (const auto& node : config.providers[i].nodes) names.insert(node.name);
        bool valid = true; for (const auto& node : nodes) if (!names.insert(node.name).second) { valid = false; break; }
        if (!valid) continue;
        auto candidates = config.providers; candidates[index].nodes = nodes; std::string error;
        if (validateDialerGraph(config.nodes, candidates, config.groups, error, true)) provider.nodes = std::move(nodes);
    }
    error.clear(); return true;
}
