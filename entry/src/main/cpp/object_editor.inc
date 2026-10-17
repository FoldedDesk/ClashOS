std::string editorQuoted(const std::string& value) { return '"' + jsonEscape(value) + '"'; }
std::string editorError(const std::string& value) { return "{\"error\":" + editorQuoted(value.empty() ? "Node/group editor failed" : value) + "}"; }

std::vector<std::string> editorStringList(yaml_document_t& document, yaml_node_t* map, const char* field)
{
    std::vector<std::string> result; auto* list = yamlValue(document, map, field);
    if (list && list->type == YAML_SEQUENCE_NODE) for (auto* item = list->data.sequence.items.start; item < list->data.sequence.items.top; ++item)
        result.push_back(yamlText(yaml_document_get_node(&document, *item)));
    return result;
}

std::string editorObjectView(yaml_document_t& document, int id, std::string& error)
{
    auto* map = yaml_document_get_node(&document, id);
    if (!map || map->type != YAML_MAPPING_NODE) { error = "Node/group collection requires mappings"; return ""; }
    const std::string name = yamlText(yamlValue(document, map, "name"));
    const std::string type = yamlText(yamlValue(document, map, "type"));
    const std::string server = yamlText(yamlValue(document, map, "server"));
    const std::string port = yamlText(yamlValue(document, map, "port"));
    std::string content; if (!editorNodeText(document, id, content, error)) return "";
    return "{\"name\":" + editorQuoted(name) + ",\"type\":" + editorQuoted(type) + ",\"server\":" + editorQuoted(server) +
        ",\"port\":" + editorQuoted(port) + ",\"content\":" + editorQuoted(content) + "}";
}

std::string objectEditorJson(const std::string& source, const std::string& settings, const std::string& ruleSettings, bool validate = true, const std::string& mergeSettings = "")
{
    ObjectEdits edits; RuleEdits rules; ConfigMerges merges; std::string error;
    if (!parseObjectEdits(settings, edits, error) || !parseRuleEdits(ruleSettings, rules, error) || !parseConfigMerges(mergeSettings, merges, error)) return editorError(error);
    std::string enhanced;
    if (validate) {
        ParsedConfig config;
        if (!parseConfigText(source, config, error, &rules, &edits, &merges)) return editorError(error);
        enhanced = config.enhancedSource;
    }
    EditorYaml original; if (!original.parse(enhanced.empty() ? source : enhanced, 8 * 1024 * 1024, error)) return editorError(error);
    if (enhanced.empty() && !applyConfigMerges(original.document, &merges, error, source)) return editorError(error);
    auto* root = yaml_document_get_root_node(&original.document);
    if (!root || root->type != YAML_MAPPING_NODE) return editorError("Configuration root must be a mapping");
    std::vector<std::string> choices = {"DIRECT", "REJECT"}, providers;
    auto section = [&](const char* field, const ObjectSequenceEdits& edits) {
        std::string sourceJson = "[";
        const std::set<std::string> removed(edits.remove.begin(), edits.remove.end());
        auto* list = yamlValue(original.document, root, field);
        if (list && list->type != YAML_SEQUENCE_NODE) { error = "Proxy/group collection must be a list"; return std::string(); }
        if (list) for (auto* item = list->data.sequence.items.start; item < list->data.sequence.items.top; ++item) {
            const std::string json = editorObjectView(original.document, *item, error); if (json.empty()) return std::string();
            if (sourceJson.size() > 1) sourceJson += ','; sourceJson += json;
            const std::string name = yamlText(yamlValue(original.document, yaml_document_get_node(&original.document, *item), "name"));
            if (!removed.count(name)) choices.push_back(name);
        }
        auto additions = [&](const std::vector<ObjectEditItem>& items) {
            std::string result = "[";
            for (const auto& item : items) {
                EditorYaml data; if (!data.parse(item.content, 64 * 1024, error)) return std::string();
                const std::string json = editorObjectView(data.document, 1, error); if (json.empty()) return std::string();
                if (result.size() > 1) result += ','; result += json; choices.push_back(item.name);
            }
            return result + "]";
        };
        const std::string prepend = additions(edits.prepend), append = additions(edits.append);
        if (prepend.empty() || append.empty()) return std::string();
        return "{\"original\":" + sourceJson + "],\"prepend\":" + prepend + ",\"append\":" + append + "}";
    };
    const std::string proxies = section("proxies", edits.proxies), groups = section("proxy-groups", edits.groups);
    if (proxies.empty() || groups.empty()) return editorError(error);
    auto* map = yamlValue(original.document, root, "proxy-providers");
    if (map && map->type == YAML_MAPPING_NODE) for (auto* pair = map->data.mapping.pairs.start; pair < map->data.mapping.pairs.top; ++pair)
        providers.push_back(yamlText(yaml_document_get_node(&original.document, pair->key)));
    std::vector<std::string> unique; std::set<std::string> seen;
    for (const auto& name : choices) if (!name.empty() && seen.insert(name).second) unique.push_back(name);
    return "{\"error\":\"\",\"proxies\":" + proxies + ",\"groups\":" + groups + ",\"choices\":" + ruleStringsJson(unique) + ",\"providers\":" + ruleStringsJson(providers) + "}";
}

void editorEraseKey(yaml_document_t& document, int id, const std::string& key, bool insensitive = false)
{
    auto* map = yaml_document_get_node(&document, id); if (!map || map->type != YAML_MAPPING_NODE) return;
    auto* output = map->data.mapping.pairs.start;
    for (auto* pair = map->data.mapping.pairs.start; pair < map->data.mapping.pairs.top; ++pair) {
        const std::string name = yamlText(yaml_document_get_node(&document, pair->key));
        if ((insensitive ? lower(name) : name) != (insensitive ? lower(key) : key)) *output++ = *pair;
    }
    map->data.mapping.pairs.top = output;
}

bool editorMergePatch(yaml_document_t& target, int id, yaml_document_t& patch, int patchId, std::string& error, int depth = 0, const std::string& path = "")
{
    auto* source = yaml_document_get_node(&patch, patchId);
    if (depth > 32 || !source || source->type != YAML_MAPPING_NODE) { error = "Editor form patch must be a bounded mapping"; return false; }
    std::set<std::string> keys;
    for (auto* pair = source->data.mapping.pairs.start; pair < source->data.mapping.pairs.top; ++pair) {
        auto* name = yaml_document_get_node(&patch, pair->key);
        const std::string key = yamlText(name);
        if (!name || name->type != YAML_SCALAR_NODE || !keys.insert(key).second) { error = "Form patch requires unique scalar keys"; return false; }
        auto* value = yaml_document_get_node(&patch, pair->value); if (!value) return false;
        const bool hostHeader = path == "/ws-opts/headers" && lower(key) == "host";
        if (hostHeader) editorEraseKey(target, id, key, true);
        if (value->type == YAML_SCALAR_NODE && value->data.scalar.style == YAML_PLAIN_SCALAR_STYLE && yamlText(value) == "null") {
            editorEraseKey(target, id, key); continue;
        }
        auto* current = yamlValue(target, yaml_document_get_node(&target, id), key);
        if (current && current->type == YAML_MAPPING_NODE && value->type == YAML_MAPPING_NODE) {
            const int currentId = static_cast<int>(current - target.nodes.start) + 1;
            // Detach the edited branch so a YAML alias in another field keeps its original value.
            std::string detachedText; EditorYaml detached;
            if (!editorNodeText(target, currentId, detachedText, error) || !detached.parse(detachedText, 128 * 1024, error)) return false;
            std::map<int, int> copied; std::set<int> active;
            const int detachedId = editorCloneNode(detached.document, 1, target, copied, active, error);
            if (!detachedId || !editorSetValue(target, id, key, detachedId) || !editorMergePatch(target, detachedId, patch, pair->value, error, depth + 1, path + "/" + key)) return false;
        } else {
            std::map<int, int> copied; std::set<int> active;
            const int replacement = editorCloneNode(patch, pair->value, target, copied, active, error);
            if (!replacement || !editorSetValue(target, id, key, replacement)) return false;
        }
    }
    return true;
}

std::string editorFormJson(yaml_document_t& document, yaml_node_t* root, bool group)
{
    auto text = [&](yaml_node_t* map, const char* key) { return yamlText(yamlValue(document, map, key)); };
    auto flag = [&](const char* key, bool fallback = false) {
        const std::string value = lower(text(root, key)); return value.empty() ? fallback : value == "true";
    };
    auto boolean = [](bool value) -> std::string { return value ? "true" : "false"; };
    std::string result = "{\"name\":" + editorQuoted(text(root, "name")) + ",\"type\":" + editorQuoted(text(root, "type"));
    if (!group) {
        const std::string type = lower(text(root, "type")); ProxyNode defaults;
        for (const char* field : {"server", "port", "password", "uuid", "cipher", "alterId"}) result += ",\"" + std::string(field) + "\":" + editorQuoted(text(root, field));
        std::string sni = text(root, "servername"); if (sni.empty()) sni = text(root, "sni");
        std::string network = text(root, "network"); if (network.empty()) network = defaults.network;
        auto* ws = yamlValue(document, root, "ws-opts"); std::string path = text(ws, "path"); if (path.empty()) path = defaults.wsPath;
        std::string host; auto* headers = yamlValue(document, ws, "headers");
        if (headers && headers->type == YAML_MAPPING_NODE) for (auto* pair = headers->data.mapping.pairs.start; pair < headers->data.mapping.pairs.top; ++pair)
            if (lower(yamlText(yaml_document_get_node(&document, pair->key))) == "host") host = yamlText(yaml_document_get_node(&document, pair->value));
        result += ",\"tls\":" + boolean(type == "trojan" || flag("tls")) + ",\"udp\":" + boolean(flag("udp", true)) +
            ",\"skipCertVerify\":" + boolean(flag("skip-cert-verify")) + ",\"serverName\":" + editorQuoted(sni) +
            ",\"network\":" + editorQuoted(network) + ",\"wsPath\":" + editorQuoted(path) + ",\"wsHost\":" + editorQuoted(host);
    } else {
        ProxyGroup defaults;
        for (const char* field : {"url", "interval", "timeout", "tolerance", "expected-status", "strategy", "filter", "exclude-filter", "default-selected"}) {
            std::string value = text(root, field);
            if (value.empty()) {
                if (std::string(field) == "url") value = defaults.url;
                else if (std::string(field) == "interval") value = std::to_string(defaults.interval);
                else if (std::string(field) == "timeout") value = std::to_string(defaults.timeout);
                else if (std::string(field) == "tolerance") value = std::to_string(defaults.tolerance);
                else if (std::string(field) == "expected-status") value = defaults.expectedStatus;
                else if (std::string(field) == "strategy") value = defaults.strategy;
            }
            std::string property = field;
            if (property == "expected-status") property = "expectedStatus";
            else if (property == "exclude-filter") property = "excludeFilter";
            else if (property == "default-selected") property = "defaultSelected";
            result += ",\"" + property + "\":" + editorQuoted(value);
        }
        result += ",\"members\":" + ruleStringsJson(editorStringList(document, root, "proxies")) + ",\"providers\":" + ruleStringsJson(editorStringList(document, root, "use")) +
            ",\"lazy\":" + boolean(flag("lazy", true)) + ",\"disableUdp\":" + boolean(flag("disable-udp")) +
            ",\"includeAllProxies\":" + boolean(flag("include-all-proxies") || flag("include-all")) + ",\"includeAllProviders\":" + boolean(flag("include-all-providers") || flag("include-all"));
    }
    return result + "}";
}

std::string objectDraftJson(const std::string& kind, const std::string& content, const std::string& patchText, bool validate = true)
{
    if (kind != "proxies" && kind != "groups") return editorError("Unknown editor collection");
    EditorYaml data; std::string error;
    if (!data.parse(content.empty() ? "{}" : content, 64 * 1024, error)) return editorError(error);
    if (!yaml_document_get_root_node(&data.document) || yaml_document_get_root_node(&data.document)->type != YAML_MAPPING_NODE) return editorError("Node/group must be a mapping");
    if (!patchText.empty()) {
        EditorYaml patch;
        if (!patch.parse(patchText, 64 * 1024, error) || !editorMergePatch(data.document, 1, patch.document, 1, error)) return editorError(error);
    }
    const std::string view = editorObjectView(data.document, 1, error); if (view.empty()) return editorError(error);
    auto* root = yaml_document_get_root_node(&data.document);
    if (validate) {
        std::string normalized; if (!editorNodeText(data.document, 1, normalized, error) || !editorObjectValid({yamlText(yamlValue(data.document, root, "name")), normalized}, kind == "groups", error)) return editorError(error);
    }
    return "{\"error\":\"\",\"item\":" + view + ",\"form\":" + editorFormJson(data.document, root, kind == "groups") + "}";
}
