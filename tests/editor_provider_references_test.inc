std::string editorProviderTestRequest(const std::string& text)
{
    ControllerConfigJson json; std::string error, files, profile, source, query;
    if (!json.parse(text, error) || !json.string("files", files, error) || !json.string("profile", profile, error) ||
        !json.string("source", source, error) || !json.string("query", query, error)) throw std::runtime_error("Invalid public provider-reference test request");
    return editorProviderReferences(files, profile, source, query);
}

// Bridge the production ArkTS store to the real native parser in host tests.
std::string profileCacheTestRequest(const std::string& text)
{
    ControllerConfigJson json; std::string error, files, source, contextText, kind, rules, objects, merges, profile;
    if (!json.parse(text, error) || !json.string("files", files, error) || !json.string("source", source, error) ||
        !json.string("context", contextText, error) || !json.string("kind", kind, error) || !json.string("rules", rules, error) ||
        !json.string("objects", objects, error) || !json.string("merges", merges, error) || !json.string("profile", profile, error)) throw std::runtime_error("Invalid public cache-context test request");
    ProviderCacheContext context;
    if (!parseProviderCacheContext(contextText, context, error)) return editorError(error);
    if (!context.profile.empty() && !ownedProviderProfile(files, context.profile)) return editorError("Provider cache context is not an owned saved profile");
    if (kind == "rules") return ruleEditorJson(source, rules, true, objects, merges, &context);
    if (kind == "objects") return objectEditorJson(source, objects, rules, true, merges, &context);
    if (kind == "load") {
        if (!ownedProviderProfile(files, profile)) return editorError("Test profile is not owned");
        if (!loadConfigLocked(profile, error)) return editorError(error);
        return "{\"error\":\"\",\"nodes\":" + std::to_string(g_state.nodes.size()) + ",\"groups\":" + std::to_string(g_state.groups.size()) + "}";
    }
    ParsedConfig parsed;
    return parseConfigText(source, parsed, error, nullptr, nullptr, nullptr, nullptr, &context) ? "{\"error\":\"\"}" : editorError(error);
}

void providerCacheValidationTests(const std::string& directory)
{
    const auto root = directory + "/validation-cache", profiles = root + "/profiles", profile = profiles + "/public.yaml";
    mkdir(root.c_str(), 0700); mkdir(profiles.c_str(), 0700);
    const std::string declaration = "proxy-providers: {P: {type: file, path: absent.yaml, filter: Public, override: {additional-prefix: '[P] ', additional-suffix: ' 😀'}}}\n";
    const std::string node = "[P] Public 日本 #1 😀";
    const std::string source = declaration + "proxy-groups: [{name: Main, type: select, proxies: ['" + node + "'], default-selected: '" + node + "'}]\nrules: ['MATCH," + node + "']\n";
    { std::ofstream file(profile); file << source; }
    ProxyProvider provider; provider.name = "P"; provider.type = "file"; provider.path = "absent.yaml";
    const std::string body = "proxies: [{name: 'Public 日本 #1', type: http, server: 127.0.0.1, port: 18097}, {name: Drop, type: direct}]\n";
    ProviderUpdateJob job{provider, {}, profile, 0, 1}; std::string error;
    require(writeProviderCache(job, body, error), "Write an imported file-provider cache using the production writer");
    ProviderCacheContext context; context.profile = profile;
    auto valid = [&](const std::string& text, const ProviderCacheContext* cache) { ParsedConfig config; error.clear(); return parseConfigText(text, config, error, nullptr, nullptr, nullptr, nullptr, cache); };
    require(!valid(source, nullptr), "Regression witness: literal cached members cannot validate before caches are hydrated");
    require(valid(source, &context), "Saved-profile cache resolves exact filtered and affixed group members and routing policies");
    require(ruleEditorJson(source, "", true, "", "", &context).find("\"error\":\"\"") != std::string::npos, "Rule rendering and export retain valid literal cache references");
    require(objectEditorJson(source, "", "", true, "", &context).find("\"error\":\"\"") != std::string::npos, "Structured node/group editing validates with the same cache context");
    const auto route = source + "rule-providers: {R: {type: inline, behavior: domain, payload: [public.invalid], proxy: '" + node + "'}}\n";
    require(valid(route, &context) && !valid(route, nullptr), "Rule-provider download routes resolve from matching saved caches only");
    const auto typo = source + "proxies: [{name: Local, type: http, server: 127.0.0.1, port: 18097, dialer-proxy: Missing}]\n";
    require(valid(typo, &context), "Remote-provider dialer dependencies may still wait for their provider update as before");
    auto replace = [](std::string text, const std::string& from, const std::string& to) { const auto at = text.find(from); text.replace(at, from.size(), to); return text; };
    require(!valid(replace(source, "path: absent.yaml", "path: different.yaml"), &context), "Changed file-provider source cannot validate using an old cache");
    require(!valid(replace(source, "filter: Public", "filter: Drop"), &context), "Changed filters cannot keep references to now-excluded cached nodes");
    require(!valid(replace(source, "'[P] '", "'[Other] '"), &context), "Changed name overrides invalidate references to former cache names");
    ParsedConfig collision;
    require(parseConfigText(source + "proxies: [{name: '" + node + "', type: direct}]\n", collision, error, nullptr, nullptr, nullptr, nullptr, &context) && collision.providers.front().nodes.empty(), "Conflicting cache nodes are rejected without replacing an explicitly declared local node");
    const auto cyclic = replace(source, "proxies: ['" + node + "']", "proxies: [Back]") + "proxies: [{name: Back, type: http, server: 127.0.0.1, port: 18097, dialer-proxy: Main}]\n";
    require(!valid(cyclic, &context), "Cached reference hydration preserves outbound cycle rejection");
    require(ownedProviderProfile(root, profile) && !ownedProviderProfile(directory, profile), "Private validation contexts accept only owned saved profile paths");
    ConfigMerges merges; require(readConfigMerges(profile, merges, error) && merges.cacheProfile == profile, "Runtime loading retains an internal provider-cache profile context");
    ParsedConfig parsed; require(parseConfigText(source, parsed, error, nullptr, nullptr, &merges), "Runtime parsing validates cache references before installing route state");
    require(loadConfigLocked(profile, error) && g_state.nodes.size() == 1 && g_state.groups.front().now == node, "Cold profile loading installs its exact filtered cached node and default selection without network access");
    require(loadConfigLocked(profile, error) && g_state.nodes.size() == 1, "Repeated cold loading never doubles name affixes or cached nodes");
    std::string bytes; require(readControllerFile(providerCachePath(profile, provider), 8 * 1024 * 1024, bytes, error), "Read the real serialized cache for archive validation");
    std::vector<unsigned char> encoded((bytes.size() + 2) / 3 * 4 + 1); size_t size = 0;
    require(mbedtls_base64_encode(encoded.data(), encoded.size(), &size, reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()) == 0, "Encode the actual private cache resource for a portable archive context");
    const auto suffix = providerCachePath("", provider);
    const std::string archive = "{\"version\":1,\"profile\":\"\",\"resources\":[{\"suffix\":\"" + suffix + "\",\"data\":\"" + std::string(encoded.begin(), encoded.begin() + size) + "\"}]}";
    ProviderCacheContext archived; require(parseProviderCacheContext(archive, archived, error), "Decode an explicit bounded archive resource context");
    unlink(providerCachePath(profile, provider).c_str());
    require(!valid(source, &context) && valid(source, &archived), "Archive validation is independent of live cache files and remains usable on a fresh device");
    require(!valid(replace(source, "path: absent.yaml", "path: foreign.yaml"), &archived), "Archived resources are still bound to their original provider source identity");
    for (const auto& malformed : {std::string("[]"), std::string("{\"version\":2,\"profile\":\"\",\"resources\":[]}"), replace(archive, suffix, "../../outside"), replace(archive, "\"data\":\"", "\"data\":\"!"), replace(archive, "\"profile\":\"\"", "\"profile\":\"/untrusted\"")}) {
        ProviderCacheContext invalid; require(!parseProviderCacheContext(malformed, invalid, error), "Malformed, mixed-path and traversing archive contexts fail closed");
    }
    require(!valid(replace(source, node, "Typo missing member"), &archived), "Matching cache context does not defer an unknown explicit group member");
}

void editorProviderReferenceTests(const std::string& directory)
{
    const auto root = directory + "/editor-cache", profiles = root + "/profiles", profile = profiles + "/public.yaml";
    mkdir(root.c_str(), 0700); mkdir(profiles.c_str(), 0700);
    const std::string source = "# PUBLIC original source\nmode: rule\nproxies: []\n";
    { std::ofstream file(profile); file << source; require(file.good(), "Create a public saved editor profile"); }
    const std::string body = "proxies:\n  - {name: 'Japan 日本 #1', type: ss, server: PRIVATE-SERVER.invalid, port: 12345, cipher: aes-128-gcm, password: PRIVATE-NODE-PASSWORD, dialer-proxy: Gateway}\n  - {name: US_2, type: direct}\n  - {name: Other, type: direct}\n";
    const std::string definition = "{\"type\":\"http\",\"url\":\"https://PRIVATE-FEED.invalid/nodes\",\"path\":\"remote.yaml\",\"header\":{\"Authorization\":[\"PRIVATE-HEADER\",\"NEXT\"]}}";
    auto queryFor = [&](const std::string& definition, const std::string& name = "P") { return "{\"proxy-providers\":{\"" + name + "\":" + definition + "}}"; };
    const std::string query = queryFor(definition), empty = "{\"providers\":[]}";
    auto snapshot = [&](const std::string& query) { return editorProviderReferences(root, profile, source, query); };
    require(snapshot(query) == empty, "A provider without an owned cache supplies no invented node names");
    ProxyProvider provider; provider.name = "P"; provider.type = "http"; provider.url = "https://PRIVATE-FEED.invalid/nodes"; provider.path = "remote.yaml"; provider.headers["Authorization"] = "PRIVATE-HEADER, NEXT";
    auto cache = [&](const std::string& path, const ProxyProvider& provider, const std::string& bytes) {
        std::string error; ProviderUpdateJob job{provider, {}, path, 0, 1};
        require(writeProviderCache(job, bytes, error), "Write a source-bound cache with the production cache writer");
    };
    cache(profile, provider, body);
    const auto beforeRevision = g_state.configRevision;
    const auto first = snapshot(query);
    require(first.find("Japan 日本 #1") != std::string::npos && first.find("\"dialer\":\"Gateway\"") != std::string::npos && first.find("\"type\":\"ss\"") != std::string::npos, "Cache metadata includes exact names, protocols and dialer dependencies");
    for (const auto& secret : {"PRIVATE-SERVER", "12345", "PRIVATE-NODE-PASSWORD", "PRIVATE-FEED", "PRIVATE-HEADER"}) require(first.find(secret) == std::string::npos, "Cache assistance never exports servers, ports, passwords, URLs or headers");
    require(g_state.configRevision == beforeRevision, "Reading editor references does not mutate the live configuration");
    auto replace = [](std::string value, const std::string& old, const std::string& next) { const auto at = value.find(old); if (at != std::string::npos) value.replace(at, old.size(), next); return value; };
    for (const auto& changed : {replace(query, "PRIVATE-FEED", "DIFFERENT-FEED"), replace(query, "remote.yaml", "different.yaml"), replace(query, "PRIVATE-HEADER", "DIFFERENT-HEADER")}) require(snapshot(changed) == empty, "Changed URL, path or HTTP headers cannot borrow the old provider cache");
    const auto customized = definition.substr(0, definition.size() - 1) + ",\"filter\":\"Japan```US\",\"override\":{\"additional-prefix\":\"[P] \",\"additional-suffix\":\" #2\",\"dialer-proxy\":\"Transit\"}}";
    const auto transformed = snapshot(queryFor(customized));
    require(transformed.find("[P] Japan 日本 #1 #2") != std::string::npos && transformed.find("[P] US_2 #2") != std::string::npos && transformed.find("Other") == std::string::npos, "Native RE2 filters and name affixes are applied to the cached source exactly once");
    require(transformed.find("\"dialer\":\"Transit\"") != std::string::npos && transformed.find("Gateway") == std::string::npos, "Draft dialer overrides replace cached per-node dialers before graph assistance");
    const auto excluded = definition.substr(0, definition.size() - 1) + ",\"exclude-type\":\"ss\",\"exclude-filter\":\"Other\"}";
    const auto selection = snapshot(queryFor(excluded));
    require(selection.find("US_2") != std::string::npos && selection.find("Japan") == std::string::npos && selection.find("Other") == std::string::npos, "Native type and name exclusions constrain cached suggestions");
    require(snapshot(queryFor(definition.substr(0, definition.size() - 1) + ",\"filter\":\"[\"}")) == empty, "Invalid filters return no speculative cached names");
    require(editorProviderReferences(root, profile, source + "# unsaved source identity\n", query) == empty, "A stale saved-source identity cannot read cache metadata");
    require(editorProviderReferences(directory, profile, source, query) == empty, "Profiles outside the configured application directory are rejected");
    const auto secondProfile = profiles + "/second.yaml";
    { std::ofstream file(secondProfile); file << source; }
    require(editorProviderReferences(root, secondProfile, source, query) == empty, "A different profile cannot borrow the first profile's cache even with identical source text");
    cache(secondProfile, provider, "proxies: [{name: Second profile only, type: direct}]\n");
    const auto second = editorProviderReferences(root, secondProfile, source, query);
    require(second.find("Second profile only") != std::string::npos && second.find("Japan") == std::string::npos && snapshot(query).find("Second profile only") == std::string::npos, "Each saved profile uses only its own managed provider file");
    const auto path = providerCachePath(profile, provider), saved = path + ".original";
    require(rename(path.c_str(), saved.c_str()) == 0 && symlink(saved.c_str(), path.c_str()) == 0, "Create an owned symlink cache rejection control");
    require(snapshot(query) == empty, "Provider assistance does not follow cache symlinks"); unlink(path.c_str());
    require(mkfifo(path.c_str(), 0600) == 0, "Create a nonblocking rejection control for special files");
    require(snapshot(query) == empty, "Provider assistance never opens FIFO cache files"); unlink(path.c_str());
    require(rename(saved.c_str(), path.c_str()) == 0, "Restore the public regular cache file");
    cache(profile, provider, "proxies: invalid\n"); require(snapshot(query) == empty, "Invalid cache payloads return no metadata");
    cache(profile, provider, body);
    auto otherProvider = provider; otherProvider.name = "Q"; cache(profile, otherProvider, body);
    require(snapshot(queryFor(definition, "Q")).find("\"name\":\"Q\"") != std::string::npos, "Provider names select separate managed-cache files");
    for (const auto& value : {std::string("[]"), std::string("not JSON"), query + "\n{}", std::string(256 * 1024 + 1, 'x')}) require(snapshot(value) == empty, "Malformed, trailing and oversized editor queries fail closed");
    ProxyProvider fileProvider; fileProvider.name = "File"; fileProvider.type = "file"; fileProvider.path = "not-on-disk.yaml";
    cache(profile, fileProvider, body);
    const auto fileQuery = queryFor("{\"type\":\"file\",\"path\":\"not-on-disk.yaml\"}", "File");
    require(snapshot(fileQuery).find("Japan 日本 #1") != std::string::npos, "Imported file-provider caches work without opening their configured source path");
    unlink(providerCachePath(profile, fileProvider).c_str()); require(snapshot(fileQuery) == empty, "Missing imported file caches are not replaced by arbitrary source-file reads");
    const auto originalProfile = profile + ".original"; require(rename(profile.c_str(), originalProfile.c_str()) == 0 && symlink(originalProfile.c_str(), profile.c_str()) == 0, "Create an owned profile symlink rejection control");
    require(snapshot(query) == empty, "Provider assistance rejects a symlinked saved profile"); unlink(profile.c_str()); rename(originalProfile.c_str(), profile.c_str());
    providerCacheValidationTests(directory);
}
