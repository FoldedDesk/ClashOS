// YAML extensions preserve source bytes. Each extension is applied to a fresh AST.
struct ConfigMerges { std::string global, profile, globalScript, profileScript, profileName, sequence; };

bool mergeDocument(const std::string& text, EditorYaml& document, std::string& error)
{
    if (text.empty()) return true;
    if (text.size() > 256 * 1024) { error = "YAML extension exceeds 256 KB"; return false; }
    bool content = false; std::istringstream lines(text); std::string line;
    while (std::getline(lines, line)) { line = trim(line); if (!line.empty() && line.front() != '#') { content = true; break; } }
    if (!content) return true;
    if (!document.parse(text, 256 * 1024, error)) {
        yaml_parser_t parser;
        if (yaml_parser_initialize(&parser)) {
            yaml_parser_set_input_string(&parser, reinterpret_cast<const unsigned char*>(text.data()), text.size()); yaml_document_t detail;
            if (!yaml_parser_load(&parser, &detail)) error = "YAML extension line " + std::to_string(parser.problem_mark.line + 1) + ", column " + std::to_string(parser.problem_mark.column + 1) + ": " + (parser.problem ? parser.problem : "invalid syntax");
            else yaml_document_delete(&detail);
            yaml_parser_delete(&parser);
        }
        error = "Invalid YAML extension: " + error; return false;
    }
    auto* root = yaml_document_get_root_node(&document.document);
    if (!root) return true; // A comments-only extension is a no-op.
    if (root->type != YAML_MAPPING_NODE) { error = "YAML extension must be a mapping"; return false; }
    std::string normalized;
    return editorNodeText(document.document, 1, normalized, error);
}

bool parseConfigMerges(const std::string& text, ConfigMerges& merges, std::string& error)
{
    if (text.empty()) return true;
    EditorYaml data;
    if (!data.parse(text, 4 * 1024 * 1024, error)) return false;
    auto* root = yaml_document_get_root_node(&data.document);
    const std::string version = yamlText(yamlValue(data.document, root, "version"));
    const bool scripts = version == "2" || version == "3";
    if ((!scripts && (version != "1" || !editorKeys(data.document, root, {"version", "global", "profile"}))) ||
        (scripts && !editorKeys(data.document, root, version == "3" ? std::set<std::string>{"version", "global", "profile", "globalScript", "profileScript", "profileName", "sequence"} : std::set<std::string>{"version", "global", "profile", "globalScript", "profileScript", "profileName"}))) {
        error = "Invalid YAML extension settings"; return false;
    }
    if (version == "3") {
        auto* value = yamlValue(data.document, root, "sequence");
        if (!value || value->type != YAML_SCALAR_NODE || (merges.sequence = yamlText(value)).size() > 256 * 1024) { error = "Invalid migrated sequence settings"; return false; }
    }
    for (const char* key : {"global", "profile"}) {
        auto* value = yamlValue(data.document, root, key);
        if (!value || value->type != YAML_SCALAR_NODE) { error = "YAML extension content must be text"; return false; }
    }
    merges.global = yamlText(yamlValue(data.document, root, "global")); merges.profile = yamlText(yamlValue(data.document, root, "profile"));
    if (scripts) {
        for (const char* key : {"globalScript", "profileScript", "profileName"}) {
            auto* value = yamlValue(data.document, root, key);
            if (!value || value->type != YAML_SCALAR_NODE) { error = "Script extension settings must contain text"; return false; }
        }
        merges.globalScript = yamlText(yamlValue(data.document, root, "globalScript")); merges.profileScript = yamlText(yamlValue(data.document, root, "profileScript"));
        merges.profileName = yamlText(yamlValue(data.document, root, "profileName"));
        if (merges.globalScript.size() > 256 * 1024 || merges.profileScript.size() > 256 * 1024 || merges.profileName.size() > 1024) { error = "Script settings exceed size limits"; return false; }
    }
    EditorYaml global, profile;
    return mergeDocument(merges.global, global, error) && mergeDocument(merges.profile, profile, error);
}

bool readMergeFile(const std::string& path, std::string& text, std::string& error)
{
    struct stat info{};
    if (stat(path.c_str(), &info) != 0) { if (errno == ENOENT) return true; error = "Cannot inspect YAML extension"; return false; }
    if (!S_ISREG(info.st_mode) || info.st_size <= 0 || info.st_size > 256 * 1024) { error = "YAML extension file is empty or exceeds 256 KB"; return false; }
    std::ifstream input(path, std::ios::binary); if (!input.good()) { error = "Cannot read YAML extension"; return false; }
    char buffer[8192];
    while (input.read(buffer, sizeof(buffer)) || input.gcount()) {
        text.append(buffer, static_cast<size_t>(input.gcount())); if (text.size() > 256 * 1024) { error = "YAML extension exceeds 256 KB"; return false; }
    }
    if (input.bad()) { error = "Cannot read YAML extension"; return false; }
    EditorYaml data; return mergeDocument(text, data, error);
}

bool readConfigMerges(const std::string& profile, ConfigMerges& merges, std::string& error)
{
    const size_t slash = profile.rfind('/');
    if (!readMergeFile((slash == std::string::npos ? "." : profile.substr(0, slash)) + "/.global-merge.yaml", merges.global, error) || !readMergeFile(profile + ".merge.yaml", merges.profile, error)) return false;
    auto readScript = [&](const std::string& path, std::string& destination) {
        struct stat info{}; if (stat(path.c_str(), &info) != 0) { if (errno == ENOENT) return true; error = "Cannot inspect script file"; return false; }
        if (!S_ISREG(info.st_mode) || info.st_size <= 0 || info.st_size > 256 * 1024) { error = "Script file is empty or exceeds 256 KB"; return false; }
        std::ifstream input(path, std::ios::binary); if (!input.good()) { error = "Cannot read script file"; return false; }
        char chunk[8192]; while (input.read(chunk, sizeof(chunk)) || input.gcount()) { destination.append(chunk, static_cast<size_t>(input.gcount())); if (destination.size() > 256 * 1024) { error = "Script file exceeds 256 KB"; return false; } }
        if (input.bad()) { error = "Cannot read script file"; return false; } return true;
    };
    if (!readScript((slash == std::string::npos ? "." : profile.substr(0, slash)) + "/.global-script.js", merges.globalScript) || !readScript(profile + ".script.js", merges.profileScript) || !readScript(profile + ".verge-seq.json", merges.sequence)) return false;
    if (!merges.globalScript.empty() || !merges.profileScript.empty()) {
        const size_t extension = profile.rfind('.');
        merges.profileName = profile.substr(slash == std::string::npos ? 0 : slash + 1, (extension == std::string::npos ? profile.size() : extension) - (slash == std::string::npos ? 0 : slash + 1));
        const std::string path = (extension == std::string::npos ? profile : profile.substr(0, extension)) + ".meta.json";
        std::ifstream input(path, std::ios::binary);
        if (input.good()) {
            std::string text; char chunk[8192];
            while (input.read(chunk, sizeof(chunk)) || input.gcount()) { text.append(chunk, static_cast<size_t>(input.gcount())); if (text.size() > 65536) { error = "Profile metadata exceeds script name limit"; return false; } }
            EditorYaml metadata; if (!metadata.parse(text, 65536, error)) return false;
            const std::string name = yamlText(yamlValue(metadata.document, yaml_document_get_root_node(&metadata.document), "name")); if (!name.empty()) merges.profileName = name;
        }
    }
    return true;
}

int mergeMapping(yaml_document_t& target, int baseId, yaml_document_t& extension, int extraId,
    std::map<int, int>& copied, std::set<int>& active, std::string& error, const std::string& path = "", int depth = 0)
{
    if (depth > 32) { error = "YAML extension nesting exceeds 32 levels"; return 0; }
    // Snapshot pairs before allocation; libyaml may move its node storage.
    std::vector<std::pair<int, int>> original, extra;
    auto pairs = [&](yaml_document_t& document, int id, std::vector<std::pair<int, int>>& output) {
        auto* map = yaml_document_get_node(&document, id); if (!map || map->type != YAML_MAPPING_NODE) return false;
        std::set<std::string> names;
        for (auto* pair = map->data.mapping.pairs.start; pair < map->data.mapping.pairs.top; ++pair) {
            auto* key = yaml_document_get_node(&document, pair->key);
            if (!key || key->type != YAML_SCALAR_NODE || !names.insert(yamlText(key)).second) { error = "YAML extension cannot merge duplicate or complex keys"; return false; }
            output.emplace_back(pair->key, pair->value);
        }
        return true;
    };
    if (!pairs(target, baseId, original) || !pairs(extension, extraId, extra)) return 0;
    std::map<std::string, int> replacements; std::set<std::string> seen;
    for (const auto& pair : extra) replacements[yamlText(yaml_document_get_node(&extension, pair.first))] = pair.second;
    const int result = yaml_document_add_mapping(&target, reinterpret_cast<const yaml_char_t*>(YAML_MAP_TAG), YAML_BLOCK_MAPPING_STYLE);
    if (!result) { error = "Cannot allocate merged mapping"; return 0; }
    for (const auto& pair : original) {
        const std::string key = yamlText(yaml_document_get_node(&target, pair.first)); int value = pair.second;
        const auto replacement = replacements.find(key);
        if (replacement != replacements.end()) {
            auto* before = yaml_document_get_node(&target, value); auto* after = yaml_document_get_node(&extension, replacement->second);
            // hosts and every direct child of dns are replacement boundaries.
            if (before && after && before->type == YAML_MAPPING_NODE && after->type == YAML_MAPPING_NODE && path != "dns" && !(path.empty() && key == "hosts"))
                value = mergeMapping(target, value, extension, replacement->second, copied, active, error, path.empty() ? key : path + '.' + key, depth + 1);
            else value = editorCloneNode(extension, replacement->second, target, copied, active, error);
            seen.insert(key);
        }
        if (!value || !yaml_document_append_mapping_pair(&target, result, pair.first, value)) return 0;
    }
    for (const auto& pair : extra) {
        const std::string key = yamlText(yaml_document_get_node(&extension, pair.first)); if (seen.count(key)) continue;
        const int keyId = editorCloneNode(extension, pair.first, target, copied, active, error), valueId = editorCloneNode(extension, pair.second, target, copied, active, error);
        if (!keyId || !valueId || !yaml_document_append_mapping_pair(&target, result, keyId, valueId)) return 0;
    }
    return result;
}

bool applyConfigMerges(yaml_document_t& document, const ConfigMerges* merges, std::string& error, const std::string& source = "", std::vector<ScriptLog>* logs = nullptr)
{
    if (!merges) return true;
    const bool scripted = !merges->globalScript.empty() || !merges->profileScript.empty();
    if (!scripted && merges->global.empty() && merges->profile.empty()) return true;
    if (scripted && !scriptTagScalars(document, source, error)) return false;
    const std::string* layers[] = {&merges->global, &merges->profile};
    const std::string* scripts[] = {&merges->globalScript, &merges->profileScript};
    for (int stage = 0; stage < 2; ++stage) {
        const std::string* text = layers[stage];
        EditorYaml extension; if (!mergeDocument(*text, extension, error)) return false;
        if (extension.loaded && yaml_document_get_root_node(&extension.document)) {
        if (scripted && !scriptTagScalars(extension.document, *text, error)) return false;
        std::map<int, int> copied; std::set<int> active;
        const int result = mergeMapping(document, 1, extension.document, 1, copied, active, error);
        if (!result) { if (error.empty()) error = "Cannot merge YAML extension"; return false; }
        std::vector<std::pair<int, int>> pairs;
        auto* map = yaml_document_get_node(&document, result);
        for (auto* pair = map->data.mapping.pairs.start; pair < map->data.mapping.pairs.top; ++pair) pairs.emplace_back(pair->key, pair->value);
        auto* root = yaml_document_get_root_node(&document); root->data.mapping.pairs.top = root->data.mapping.pairs.start;
        for (const auto& pair : pairs) if (!yaml_document_append_mapping_pair(&document, 1, pair.first, pair.second)) { error = "Cannot install merged configuration"; return false; }
        }
        if (!applyConfigScript(document, *scripts[stage], stage == 0 ? "global" : "profile", merges->profileName, logs, error)) return false;
    }
    return true;
}
