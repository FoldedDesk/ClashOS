struct ObjectEditItem { std::string name, content; };
struct ObjectSequenceEdits { std::vector<ObjectEditItem> prepend, append; std::vector<std::string> remove; };
struct ObjectEdits { ObjectSequenceEdits proxies, groups; };

class EditorYaml {
public:
    yaml_document_t document{};
    bool loaded = false;
    EditorYaml() = default;
    EditorYaml(const EditorYaml&) = delete;
    EditorYaml& operator=(const EditorYaml&) = delete;
    ~EditorYaml() { if (loaded) yaml_document_delete(&document); }
    bool parse(const std::string& text, size_t maximum, std::string& error) {
        if (text.empty() || text.size() > maximum) { error = "Editor document is empty or exceeds its size limit"; return false; }
        yaml_parser_t parser;
        if (!yaml_parser_initialize(&parser)) { error = "Cannot allocate editor YAML parser"; return false; }
        yaml_parser_set_input_string(&parser, reinterpret_cast<const unsigned char*>(text.data()), text.size());
        loaded = yaml_parser_load(&parser, &document);
        bool valid = loaded && yaml_document_get_root_node(&document);
        if (valid) {
            yaml_document_t extra;
            if (!yaml_parser_load(&parser, &extra)) valid = false;
            else { valid = yaml_document_get_root_node(&extra) == nullptr; yaml_document_delete(&extra); }
        }
        yaml_parser_delete(&parser);
        if (!valid) error = "Expected one valid YAML or JSON document";
        return valid;
    }
    bool initialize() { loaded = yaml_document_initialize(&document, nullptr, nullptr, nullptr, 1, 1); return loaded; }
};

bool editorName(const std::string& name)
{
    return !name.empty() && name.size() <= 1024 && std::none_of(name.begin(), name.end(), [](unsigned char ch) { return ch < 32 || ch == 127; });
}

int editorCloneNode(yaml_document_t& source, int id, yaml_document_t& target,
    std::map<int, int>& copied, std::set<int>& active, std::string& error, int depth = 0)
{
    if (depth > 32 || active.count(id) || copied.size() > 10000) { error = "Editor YAML is too deep, cyclic or complex"; return 0; }
    auto previous = copied.find(id); if (previous != copied.end()) return previous->second;
    yaml_node_t* node = yaml_document_get_node(&source, id);
    if (!node) { error = "Invalid editor YAML node"; return 0; }
    active.insert(id); int result = 0;
    if (node->type == YAML_SCALAR_NODE) {
        result = yaml_document_add_scalar(&target, node->tag, node->data.scalar.value,
            static_cast<int>(node->data.scalar.length), node->data.scalar.style);
        copied[id] = result;
    } else if (node->type == YAML_SEQUENCE_NODE) {
        result = yaml_document_add_sequence(&target, node->tag, node->data.sequence.style); copied[id] = result;
        for (auto* item = node->data.sequence.items.start; result && item < node->data.sequence.items.top; ++item) {
            const int child = editorCloneNode(source, *item, target, copied, active, error, depth + 1);
            if (!child || !yaml_document_append_sequence_item(&target, result, child)) result = 0;
        }
    } else if (node->type == YAML_MAPPING_NODE) {
        result = yaml_document_add_mapping(&target, node->tag, node->data.mapping.style); copied[id] = result;
        std::set<std::string> keys;
        for (auto* pair = node->data.mapping.pairs.start; result && pair < node->data.mapping.pairs.top; ++pair) {
            const yaml_node_t* key = yaml_document_get_node(&source, pair->key);
            if (!key || key->type != YAML_SCALAR_NODE || !keys.insert(yamlText(const_cast<yaml_node_t*>(key))).second) {
                error = "Editor mappings require unique scalar keys"; result = 0; break;
            }
            const int keyId = editorCloneNode(source, pair->key, target, copied, active, error, depth + 1);
            const int valueId = editorCloneNode(source, pair->value, target, copied, active, error, depth + 1);
            if (!keyId || !valueId || !yaml_document_append_mapping_pair(&target, result, keyId, valueId)) result = 0;
        }
    }
    active.erase(id);
    if (!result && error.empty()) error = "Cannot allocate editor YAML node";
    return result;
}

bool editorEmit(EditorYaml& source, std::string& output, size_t maximum = 8 * 1024 * 1024)
{
    yaml_emitter_t emitter;
    if (!yaml_emitter_initialize(&emitter)) return false;
    struct Sink { std::string* text; size_t maximum; } sink{&output, maximum};
    yaml_emitter_set_unicode(&emitter, 1);
    yaml_emitter_set_output(&emitter, [](void* context, unsigned char* data, size_t length) -> int {
        auto& sink = *static_cast<Sink*>(context);
        if (sink.text->size() + length > sink.maximum) return 0;
        sink.text->append(reinterpret_cast<char*>(data), length); return 1;
    }, &sink);
    const bool emitted = yaml_emitter_dump(&emitter, &source.document);
    source.loaded = false; // yaml_emitter_dump takes ownership even on failure.
    const bool valid = emitted && yaml_emitter_close(&emitter);
    yaml_emitter_delete(&emitter); return valid;
}

bool editorNodeText(yaml_document_t& source, int id, std::string& output, std::string& error)
{
    EditorYaml copy; if (!copy.initialize()) { error = "Cannot allocate editor document"; return false; }
    std::map<int, int> copied; std::set<int> active;
    const bool valid = editorCloneNode(source, id, copy.document, copied, active, error) && editorEmit(copy, output, 128 * 1024);
    if (!valid && error.empty()) error = "Cannot serialize node/group YAML";
    return valid;
}

bool editorObjectValid(const ObjectEditItem& item, bool group, std::string& error)
{
    EditorYaml data;
    if (!editorName(item.name) || item.name == "DIRECT" || item.name == "REJECT" || !data.parse(item.content, 64 * 1024, error)) { if (error.empty()) error = "Invalid or reserved node/group name"; return false; }
    auto* root = yaml_document_get_root_node(&data.document);
    if (!root || root->type != YAML_MAPPING_NODE || yamlText(yamlValue(data.document, root, "name")) != item.name) {
        error = "Node/group content must be a mapping with the matching name"; return false;
    }
    // Cloning also bounds nesting and rejects ambiguous duplicate keys.
    std::string normalized;
    if (!editorNodeText(data.document, 1, normalized, error)) return false;
    const std::string type = lower(yamlText(yamlValue(data.document, root, "type")));
    if (group) {
        if (type != "select" && type != "url-test" && type != "fallback" && type != "load-balance") {
            error = "This group type is not implemented by the built-in core"; return false;
        }
        for (const char* field : {"proxies", "use"}) {
            auto* sequence = yamlValue(data.document, root, field);
            if (!sequence) continue;
            if (sequence->type != YAML_SEQUENCE_NODE) { error = "Group members/providers must be lists"; return false; }
            for (auto* item = sequence->data.sequence.items.start; item < sequence->data.sequence.items.top; ++item)
                if (!editorName(yamlText(yaml_document_get_node(&data.document, *item)))) { error = "Group members/providers require valid names"; return false; }
        }
        return true; // Full configuration validation resolves references and health-check options.
    }
    ProxyNode node;
    if (!parseProxyNode(data.document, root, node, error)) return false;
    if (type != "ss" && type != "vmess" && type != "trojan" && type != "vless" && type != "direct" && type != "reject") {
        error = "This proxy protocol is not implemented by the built-in core"; return false;
    }
    if (type != "direct" && type != "reject") {
        const std::string port = yamlText(yamlValue(data.document, root, "port")); char* end = nullptr;
        const long number = std::strtol(port.c_str(), &end, 10);
        if (end == port.c_str() || *end || number < 1 || number > 65535) { error = "Proxy port must be an integer from 1 to 65535"; return false; }
    }
    if ((type == "vmess" || type == "trojan" || type == "vless") && (node.network != "tcp" && node.network != "ws")) {
        error = "This proxy transport is not implemented by the built-in core"; return false;
    }
    if (!node.transportError.empty()) { error = node.transportError; return false; }
    if (type == "vless" && node.network == "ws" && !node.alpn.empty() && std::find(node.alpn.begin(), node.alpn.end(), "http/1.1") == node.alpn.end()) {
        error = "VLESS WebSocket requires HTTP/1.1 ALPN"; return false;
    }
    if (type == "ss" && (!yamlText(yamlValue(data.document, root, "plugin")).empty() || node.tls ||
        lower(yamlText(yamlValue(data.document, root, "udp-over-tcp"))) == "true")) {
        error = "Shadowsocks plugins, TLS and UDP-over-TCP are not implemented"; return false;
    }
    const std::set<std::string> ss = {"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "chacha20-poly1305", "aead_aes_128_gcm", "aead_aes_256_gcm", "aead_chacha20_poly1305"};
    const std::set<std::string> vmess = {"", "auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"};
    if ((type == "ss" && !ss.count(node.cipher)) || (type == "vmess" && !vmess.count(node.cipher))) {
        error = "This proxy cipher is not implemented by the built-in core"; return false;
    }
    return true;
}

bool editorKeys(yaml_document_t& document, yaml_node_t* map, const std::set<std::string>& expected)
{
    if (!map || map->type != YAML_MAPPING_NODE) return false;
    std::set<std::string> found;
    for (auto* pair = map->data.mapping.pairs.start; pair < map->data.mapping.pairs.top; ++pair) {
        const std::string key = yamlText(yaml_document_get_node(&document, pair->key));
        if (!expected.count(key) || !found.insert(key).second) return false;
    }
    return found == expected;
}

bool parseObjectEdits(const std::string& text, ObjectEdits& edits, std::string& error)
{
    if (text.empty()) return true;
    EditorYaml data; if (!data.parse(text, 2 * 1024 * 1024, error)) return false;
    auto* root = yaml_document_get_root_node(&data.document);
    bool valid = editorKeys(data.document, root, {"version", "proxies", "groups"}) && yamlText(yamlValue(data.document, root, "version")) == "1";
    auto section = [&](const char* key, ObjectSequenceEdits& output, bool group) {
        auto* map = yamlValue(data.document, root, key);
        if (!editorKeys(data.document, map, {"prepend", "append", "remove"})) return false;
        auto additions = [&](const char* field, std::vector<ObjectEditItem>& output) {
            auto* list = yamlValue(data.document, map, field);
            if (!list || list->type != YAML_SEQUENCE_NODE) return false;
            for (auto* child = list->data.sequence.items.start; child < list->data.sequence.items.top; ++child) {
                auto* item = yaml_document_get_node(&data.document, *child);
                if (output.size() >= 1000 || !editorKeys(data.document, item, {"name", "content"})) return false;
                ObjectEditItem entry{yamlText(yamlValue(data.document, item, "name")), yamlText(yamlValue(data.document, item, "content"))};
                if (!editorObjectValid(entry, group, error)) return false;
                output.push_back(std::move(entry));
            }
            return true;
        };
        auto* removed = yamlValue(data.document, map, "remove");
        if (!removed || removed->type != YAML_SEQUENCE_NODE) return false;
        for (auto* child = removed->data.sequence.items.start; child < removed->data.sequence.items.top; ++child) {
            const std::string name = yamlText(yaml_document_get_node(&data.document, *child));
            if (!editorName(name) || output.remove.size() >= 2000) return false;
            output.remove.push_back(name);
        }
        return additions("prepend", output.prepend) && additions("append", output.append) && output.prepend.size() + output.append.size() <= 1000;
    };
    valid = valid && section("proxies", edits.proxies, false) && section("groups", edits.groups, true);
    if (!valid && error.empty()) error = "Invalid version 1 node/group edits or collection size";
    return valid;
}

bool readObjectEdits(const std::string& profile, ObjectEdits& edits, std::string& error)
{
    const std::string path = profile + ".objects.json"; struct stat info{};
    if (::stat(path.c_str(), &info) != 0) { if (errno == ENOENT) return true; error = "Cannot inspect node/group edits"; return false; }
    if (!S_ISREG(info.st_mode) || info.st_size <= 0 || info.st_size > 2 * 1024 * 1024) { error = "Invalid node/group edit file"; return false; }
    std::ifstream input(path, std::ios::binary); if (!input.good()) { error = "Cannot read node/group edits"; return false; }
    std::string text; char buffer[8192];
    while (input.read(buffer, sizeof(buffer)) || input.gcount()) {
        text.append(buffer, static_cast<size_t>(input.gcount()));
        if (text.size() > 2 * 1024 * 1024) { error = "Node/group edits exceed 2 MB"; return false; }
    }
    if (input.bad() || text.empty()) { error = "Cannot read node/group edits"; return false; }
    return parseObjectEdits(text, edits, error);
}

bool editorSetValue(yaml_document_t& document, int mapId, const std::string& key, int value)
{
    auto* map = yaml_document_get_node(&document, mapId);
    if (!map || map->type != YAML_MAPPING_NODE || !value) return false;
    bool replaced = false;
    for (auto* pair = map->data.mapping.pairs.start; pair < map->data.mapping.pairs.top; ++pair)
        if (yamlText(yaml_document_get_node(&document, pair->key)) == key) { pair->value = value; replaced = true; }
    if (replaced) return true;
    const int name = yaml_document_add_scalar(&document, reinterpret_cast<const yaml_char_t*>(YAML_STR_TAG),
        reinterpret_cast<const yaml_char_t*>(key.data()), static_cast<int>(key.size()), YAML_PLAIN_SCALAR_STYLE);
    return name && yaml_document_append_mapping_pair(&document, mapId, name, value);
}

bool applyObjectEdits(yaml_document_t& document, const ObjectEdits* edits, std::string& error)
{
    if (!edits) return true;
    auto section = [&](const char* key, const ObjectSequenceEdits& edits) {
        if (edits.prepend.empty() && edits.append.empty() && edits.remove.empty()) return true;
        auto* original = yamlValue(document, yaml_document_get_root_node(&document), key);
        std::vector<int> retained; const std::set<std::string> removed(edits.remove.begin(), edits.remove.end());
        if (original) {
            if (original->type != YAML_SEQUENCE_NODE) { error = "Original proxy/group collection must be a list"; return false; }
            for (auto* item = original->data.sequence.items.start; item < original->data.sequence.items.top; ++item) {
                const std::string name = yamlText(yamlValue(document, yaml_document_get_node(&document, *item), "name"));
                if (!removed.count(name)) retained.push_back(*item);
            }
        }
        const int sequence = yaml_document_add_sequence(&document, reinterpret_cast<const yaml_char_t*>(YAML_SEQ_TAG), YAML_BLOCK_SEQUENCE_STYLE);
        if (!sequence) return false;
        auto append = [&](const std::vector<ObjectEditItem>& items) {
            for (const auto& item : items) {
                EditorYaml data; if (!data.parse(item.content, 64 * 1024, error)) return false;
                std::map<int, int> copied; std::set<int> active;
                const int node = editorCloneNode(data.document, 1, document, copied, active, error);
                if (!node || !yaml_document_append_sequence_item(&document, sequence, node)) return false;
            }
            return true;
        };
        if (!append(edits.prepend)) return false;
        for (int id : retained) if (!yaml_document_append_sequence_item(&document, sequence, id)) return false;
        return append(edits.append) && editorSetValue(document, 1, key, sequence);
    };
    const bool valid = section("proxies", edits->proxies) && section("proxy-groups", edits->groups);
    if (!valid && error.empty()) error = "Cannot compose node/group edits";
    return valid;
}
