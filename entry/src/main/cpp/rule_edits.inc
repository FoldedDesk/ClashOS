// Per-profile rule edits are applied to each freshly downloaded source configuration.
// They never rewrite subscription YAML, its anchors, comments or credentials.
struct RuleEdits {
    std::vector<std::string> prepend, append, remove;
};

bool parseRuleEdits(const std::string& text, RuleEdits& edits, std::string& error)
{
    if (text.empty()) return true;
    if (text.size() > 256 * 1024) { error = "Custom rules exceed 256 KB"; return false; }
    yaml_parser_t parser;
    if (!yaml_parser_initialize(&parser)) { error = "Cannot allocate custom rule parser"; return false; }
    yaml_parser_set_input_string(&parser, reinterpret_cast<const unsigned char*>(text.data()), text.size());
    yaml_document_t document;
    if (!yaml_parser_load(&parser, &document)) {
        yaml_parser_delete(&parser); error = "Invalid custom rule document"; return false;
    }
    yaml_node_t* root = yaml_document_get_root_node(&document);
    bool valid = root && root->type == YAML_MAPPING_NODE;
    std::set<std::string> keys;
    if (valid) for (auto* pair = root->data.mapping.pairs.start; pair < root->data.mapping.pairs.top; ++pair) {
        const std::string key = yamlText(yaml_document_get_node(&document, pair->key));
        if ((key != "version" && key != "prepend" && key != "append" && key != "remove") || !keys.insert(key).second) valid = false;
    }
    valid = valid && keys.size() == 4 && yamlText(yamlValue(document, root, "version")) == "1";
    auto list = [&](const char* key, std::vector<std::string>& destination, size_t maximum) {
        yaml_node_t* sequence = yamlValue(document, root, key);
        if (!sequence || sequence->type != YAML_SEQUENCE_NODE) return false;
        for (auto* item = sequence->data.sequence.items.start; item < sequence->data.sequence.items.top; ++item) {
            yaml_node_t* node = yaml_document_get_node(&document, *item);
            const std::string rule = yamlText(node);
            if (!node || node->type != YAML_SCALAR_NODE || rule.empty() || rule.size() > 4096 ||
                rule.find_first_of("\r\n\0", 0, 3) != std::string::npos || destination.size() >= maximum) return false;
            destination.push_back(rule);
        }
        return true;
    };
    if (valid) valid = list("prepend", edits.prepend, 1000) && list("append", edits.append, 1000) &&
        list("remove", edits.remove, 2000) && edits.prepend.size() + edits.append.size() <= 1000;
    if (valid) for (const auto* additions : {&edits.prepend, &edits.append}) for (const auto& raw : *additions) {
        ProxyRule rule;
        if (!parseRuleExpression(raw, rule, false, error)) valid = false;
    }
    yaml_document_delete(&document);
    if (valid) {
        yaml_document_t extra;
        if (!yaml_parser_load(&parser, &extra)) valid = false;
        else { valid = yaml_document_get_root_node(&extra) == nullptr; yaml_document_delete(&extra); }
    }
    yaml_parser_delete(&parser);
    if (!valid && error.empty()) error = "Invalid custom rules: expected version 1 and bounded prepend/append/remove lists";
    return valid;
}

bool readRuleEdits(const std::string& profile, RuleEdits& edits, std::string& error)
{
    const std::string path = profile + ".rules.json";
    struct stat info{};
    if (::stat(path.c_str(), &info) != 0) {
        if (errno == ENOENT) return true;
        error = "Cannot inspect custom rules"; return false;
    }
    if (!S_ISREG(info.st_mode) || info.st_size < 0 || info.st_size > 256 * 1024) { error = "Invalid custom rule file"; return false; }
    std::ifstream input(path, std::ios::binary);
    if (!input.good()) { error = "Cannot read custom rules"; return false; }
    std::string text;
    char chunk[8192];
    while (input.read(chunk, sizeof(chunk)) || input.gcount()) {
        text.append(chunk, static_cast<size_t>(input.gcount()));
        if (text.size() > 256 * 1024) { error = "Custom rules exceed 256 KB"; return false; }
    }
    if (input.bad()) { error = "Cannot read custom rules"; return false; }
    // An existing, empty sidecar is corrupt; absence alone means no overrides.
    if (text.empty()) { error = "Empty custom rule file"; return false; }
    return parseRuleEdits(text, edits, error);
}

std::vector<std::string> applyRuleEdits(const std::vector<std::string>& source, const RuleEdits* edits)
{
    if (!edits) return source;
    std::vector<std::string> result = edits->prepend;
    const std::set<std::string> removed(edits->remove.begin(), edits->remove.end());
    for (const auto& rule : source) if (removed.count(rule) == 0) result.push_back(rule);
    result.insert(result.end(), edits->append.begin(), edits->append.end());
    return result;
}

std::string ruleStringsJson(const std::vector<std::string>& values)
{
    std::string json = "[";
    for (const auto& value : values) { if (json.size() > 1) json += ','; json += '"' + jsonEscape(value) + '"'; }
    return json + "]";
}

bool renderEditedRules(const std::string& source, const std::vector<std::string>& rules, std::string& output, const ObjectEdits* objects = nullptr, const ConfigMerges* merges = nullptr)
{
    yaml_parser_t parser;
    if (!yaml_parser_initialize(&parser)) return false;
    yaml_parser_set_input_string(&parser, reinterpret_cast<const unsigned char*>(source.data()), source.size());
    yaml_document_t document;
    const bool loaded = yaml_parser_load(&parser, &document);
    yaml_parser_delete(&parser);
    if (!loaded) return false;
    std::string error;
    if (!applyConfigMerges(document, merges, error, source) || !applyObjectEdits(document, objects, error)) { yaml_document_delete(&document); return false; }
    const int sequence = yaml_document_add_sequence(&document, reinterpret_cast<const yaml_char_t*>(YAML_SEQ_TAG), YAML_BLOCK_SEQUENCE_STYLE);
    bool valid = sequence != 0;
    for (const auto& rule : rules) {
        const int node = yaml_document_add_scalar(&document, reinterpret_cast<const yaml_char_t*>(YAML_STR_TAG),
            reinterpret_cast<const yaml_char_t*>(rule.data()), static_cast<int>(rule.size()), YAML_DOUBLE_QUOTED_SCALAR_STYLE);
        if (!node || !yaml_document_append_sequence_item(&document, sequence, node)) { valid = false; break; }
    }
    bool replaced = false;
    yaml_node_t* root = yaml_document_get_root_node(&document);
    if (valid && root && root->type == YAML_MAPPING_NODE) {
        for (auto* pair = root->data.mapping.pairs.start; pair < root->data.mapping.pairs.top; ++pair)
            if (yamlText(yaml_document_get_node(&document, pair->key)) == "rules") { pair->value = sequence; replaced = true; }
        if (!replaced) {
            const int key = yaml_document_add_scalar(&document, reinterpret_cast<const yaml_char_t*>(YAML_STR_TAG),
                reinterpret_cast<const yaml_char_t*>("rules"), 5, YAML_PLAIN_SCALAR_STYLE);
            valid = key != 0 && yaml_document_append_mapping_pair(&document, 1, key, sequence);
        }
    } else valid = false;
    if (!valid) { yaml_document_delete(&document); return false; }
    yaml_emitter_t emitter;
    if (!yaml_emitter_initialize(&emitter)) { yaml_document_delete(&document); return false; }
    yaml_emitter_set_unicode(&emitter, 1);
    yaml_emitter_set_output(&emitter, [](void* context, unsigned char* buffer, size_t size) -> int {
        auto& text = *static_cast<std::string*>(context);
        if (text.size() + size > 8 * 1024 * 1024) return 0;
        text.append(reinterpret_cast<char*>(buffer), size); return 1;
    }, &output);
    // dump owns the document even when emission fails.
    valid = yaml_emitter_dump(&emitter, &document) && yaml_emitter_close(&emitter);
    yaml_emitter_delete(&emitter);
    return valid;
}
