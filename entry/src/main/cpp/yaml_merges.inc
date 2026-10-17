// Resolve YAML merge keys on the composed graph, before configuration readers,
// scripts or editors inspect it. Never rewrite the imported source document.
bool resolveYamlMerges(yaml_document_t& document, const std::string& source, std::string& error)
{
    constexpr size_t nodeLimit = 1000000, workLimit = 2000000, byteLimit = 64 * 1024 * 1024;
    const size_t count = document.nodes.top - document.nodes.start;
    if (!count) return true;
    auto fail = [&](const yaml_node_t* node, const char* reason) {
        error = "YAML line " + std::to_string(node ? node->start_mark.line + 1 : 1) +
            ", column " + std::to_string(node ? node->start_mark.column + 1 : 1) + ": " + reason;
        return false;
    };
    if (count > nodeLimit) return fail(nullptr, "document exceeds the YAML node limit");

    // libyaml's composed scalar tags do not distinguish plain << from !!str <<.
    // Read the original event properties; aliases retain the same node IDs.
    std::vector<bool> mergeKeys(count + 1, false);
    yaml_parser_t parser;
    if (!yaml_parser_initialize(&parser)) return fail(nullptr, "cannot allocate YAML merge reader");
    yaml_parser_set_input_string(&parser, reinterpret_cast<const unsigned char*>(source.data()), source.size());
    size_t next = 1; bool valid = true, done = false;
    while (valid && !done) {
        yaml_event_t event;
        if (!yaml_parser_parse(&parser, &event)) { valid = fail(nullptr, "invalid YAML merge input"); break; }
        if (event.type == YAML_MAPPING_START_EVENT || event.type == YAML_SEQUENCE_START_EVENT) ++next;
        if (event.type == YAML_SCALAR_EVENT) {
            auto* node = yaml_document_get_node(&document, static_cast<int>(next));
            if (!node || node->type != YAML_SCALAR_NODE || node->data.scalar.length != event.data.scalar.length ||
                std::memcmp(node->data.scalar.value, event.data.scalar.value, event.data.scalar.length) != 0) {
                valid = fail(node, "YAML merge input does not match its document");
            } else {
                const bool explicitMerge = event.data.scalar.tag &&
                    std::strcmp(reinterpret_cast<const char*>(event.data.scalar.tag), "tag:yaml.org,2002:merge") == 0;
                const bool token = event.data.scalar.length == 2 && event.data.scalar.value[0] == '<' && event.data.scalar.value[1] == '<';
                if (explicitMerge && !token) valid = fail(node, "invalid explicit YAML merge key");
                mergeKeys[next] = token && (explicitMerge ||
                    (event.data.scalar.plain_implicit && event.data.scalar.style == YAML_PLAIN_SCALAR_STYLE));
                // Keep !!str << literal when libyaml emits a standalone copy.
                if (token && !mergeKeys[next]) node->data.scalar.style = YAML_DOUBLE_QUOTED_SCALAR_STYLE;
            }
            ++next;
        }
        done = event.type == YAML_DOCUMENT_END_EVENT || event.type == YAML_STREAM_END_EVENT;
        yaml_event_delete(&event);
    }
    yaml_parser_delete(&parser);
    if (!valid) return false;
    if (next != count + 1) return fail(nullptr, "YAML merge input does not match its document");

    struct Size { size_t nodes = 1, bytes = 0, height = 1; };
    std::vector<unsigned char> color(count + 1, 0);
    std::vector<Size> sizes(count + 1);
    size_t work = 0;
    std::function<bool(int, size_t)> visit = [&](int id, size_t depth) {
        auto* node = yaml_document_get_node(&document, id);
        if (!node || id < 1 || static_cast<size_t>(id) > count) return fail(node, "invalid YAML reference");
        if (depth > 64) return fail(node, "YAML nesting exceeds 64 levels");
        if (color[id] == 1) return fail(node, "cyclic YAML aliases are not supported in configurations");
        if (color[id] == 2) return depth + sizes[id].height <= 65 || fail(node, "YAML nesting exceeds 64 levels");
        color[id] = 1;
        if (node->type == YAML_SCALAR_NODE) sizes[id].bytes = node->data.scalar.length;
        else if (node->type == YAML_SEQUENCE_NODE) {
            for (auto* item = node->data.sequence.items.start; item < node->data.sequence.items.top; ++item) {
                if (++work > workLimit) return fail(node, "YAML expansion exceeds its work limit");
                if (!visit(*item, depth + 1)) return false;
            }
        } else if (node->type == YAML_MAPPING_NODE) {
            std::vector<std::pair<int, int>> own, inherited; std::set<std::string> keys;
            int merge = 0;
            for (auto* pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; ++pair) {
                if (++work > workLimit) return fail(node, "YAML expansion exceeds its work limit");
                if (!visit(pair->key, depth + 1) || !visit(pair->value, depth + 1)) return false;
                if (mergeKeys[pair->key]) {
                    if (merge) return fail(yaml_document_get_node(&document, pair->key), "duplicate merge key; use a sequence of mappings");
                    merge = pair->value;
                } else own.emplace_back(pair->key, pair->value);
            }
            if (merge) {
                for (const auto& pair : own) {
                    auto* key = yaml_document_get_node(&document, pair.first);
                    if (key->type != YAML_SCALAR_NODE || !keys.insert(yamlText(key)).second)
                        return fail(key, "merged mappings require unique scalar keys");
                }
                auto add = [&](int sourceId) {
                    auto* map = yaml_document_get_node(&document, sourceId);
                    if (!map || map->type != YAML_MAPPING_NODE) return fail(map, "merge sources must be mappings");
                    std::set<std::string> sourceKeys;
                    for (auto* pair = map->data.mapping.pairs.start; pair < map->data.mapping.pairs.top; ++pair) {
                        if (++work > workLimit) return fail(node, "YAML expansion exceeds its work limit");
                        auto* key = yaml_document_get_node(&document, pair->key);
                        if (key->type != YAML_SCALAR_NODE || !sourceKeys.insert(yamlText(key)).second)
                            return fail(key, "merge sources require unique scalar keys");
                        if (keys.insert(yamlText(key)).second) inherited.emplace_back(pair->key, pair->value);
                    }
                    return true;
                };
                auto* value = yaml_document_get_node(&document, merge);
                if (value->type == YAML_SEQUENCE_NODE) {
                    for (auto* item = value->data.sequence.items.start; item < value->data.sequence.items.top; ++item)
                        if (!add(*item)) return false;
                } else if (!add(merge)) return false;
                // Explicit fields win regardless of position; earlier merge
                // sources win over later ones. YAML merges are shallow.
                node->data.mapping.pairs.top = node->data.mapping.pairs.start;
                own.insert(own.end(), inherited.begin(), inherited.end());
                for (const auto& pair : own)
                    if (!yaml_document_append_mapping_pair(&document, id, pair.first, pair.second)) return fail(node, "cannot allocate merged YAML mapping");
            }
        } else return fail(node, "invalid YAML node");

        auto sum = [&](int child) {
            const auto& size = sizes[child]; auto& total = sizes[id];
            if (size.nodes > workLimit - total.nodes || size.bytes > byteLimit - total.bytes)
                return fail(node, "YAML alias expansion exceeds its size limit");
            total.nodes += size.nodes; total.bytes += size.bytes;
            total.height = std::max(total.height, size.height + 1);
            return true;
        };
        if (node->type == YAML_SEQUENCE_NODE) {
            for (auto* item = node->data.sequence.items.start; item < node->data.sequence.items.top; ++item) if (!sum(*item)) return false;
        } else if (node->type == YAML_MAPPING_NODE) {
            for (auto* pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; ++pair)
                if (!sum(pair->key) || !sum(pair->value)) return false;
        }
        if (depth + sizes[id].height > 65) return fail(node, "YAML nesting exceeds 64 levels");
        color[id] = 2; return true;
    };
    return visit(1, 0);
}
