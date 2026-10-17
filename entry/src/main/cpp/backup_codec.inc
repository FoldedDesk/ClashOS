constexpr size_t BACKUP_BYTES_LIMIT = 32 * 1024 * 1024;

bool backupYamlText(const std::string& source, std::string& output, std::string& error)
{
    EditorYaml document;
    if (!document.parse(source, 8 * 1024 * 1024, error) || !scriptTagScalars(document.document, source, error)) return false;
    ScriptExecution state{std::chrono::steady_clock::now() + std::chrono::milliseconds(500)};
    ScriptEngine engine(state); if (!engine.context) { error = "Cannot allocate backup YAML reader"; return false; }
    std::set<int> active; size_t visited = 0;
    ScriptValue value(engine.context, scriptYamlValue(engine.context, document.document, 1, active, visited, error));
    if (JS_IsException(value.value)) { if (error.empty()) error = "Cannot decode backup YAML"; return false; }
    ScriptValue json(engine.context, JS_JSONStringify(engine.context, value.value, JS_UNDEFINED, JS_UNDEFINED));
    size_t size = 0; const char* text = JS_ToCStringLen(engine.context, &size, json.value);
    if (!text || size > 16 * 1024 * 1024) { if (text) JS_FreeCString(engine.context, text); error = "Backup YAML is too large or complex"; return false; }
    output.assign(text, size); JS_FreeCString(engine.context, text); return true;
}

bool backupInflate(const unsigned char* source, size_t size, size_t expected, std::vector<unsigned char>& output)
{
    if (size > BACKUP_BYTES_LIMIT || expected > BACKUP_BYTES_LIMIT) return false;
    output.resize(expected + 1); z_stream stream{};
    stream.next_in = const_cast<Bytef*>(source); stream.avail_in = static_cast<uInt>(size);
    stream.next_out = output.data(); stream.avail_out = static_cast<uInt>(output.size());
    if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) return false;
    const int status = inflate(&stream, Z_FINISH);
    const bool valid = status == Z_STREAM_END && stream.total_in == size && stream.total_out == expected;
    inflateEnd(&stream); if (valid) output.resize(expected); else output.clear(); return valid;
}

// The upstream sequence operations run before global and profile extensions.
// Keep their declaration separate from native visual edits so subscription
// updates retain this order and do not bake one old download into the profile.
bool applyBackupSequence(yaml_document_t& document, const std::string& sequence, std::string& error)
{
    if (sequence.empty()) return true;
    std::string data; if (sequence.size() > 256 * 1024 || !backupYamlText(sequence, data, error)) return false;
    const std::string program = "const sequence = JSON.parse(\"" + jsonEscape(data) + R"JS(");
function main(config) {
  for (const [kind, field] of [['rules', 'rules'], ['proxies', 'proxies'], ['groups', 'proxy-groups']]) {
    const section = sequence[kind];
    if (!section || !Array.isArray(section.prepend) || !Array.isArray(section.append) || !Array.isArray(section.delete))
      throw new Error('Invalid migrated sequence');
    const removed = new Set(section.delete);
    const current = config[field] || [];
    if (!Array.isArray(current)) throw new Error('Migrated collection must be a list');
    config[field] = section.prepend.concat(current.filter(x => !removed.has(typeof x === 'string' ? x : x.name)), section.append);
    if (kind !== 'proxies' || !Array.isArray(config['proxy-groups'])) continue;
    const added = [...new Set(section.prepend.concat(section.append).map(x => typeof x === 'string' ? x : x.name))];
    let first = true;
    for (const group of config['proxy-groups']) {
      if (!group || typeof group !== 'object') continue;
      if (Array.isArray(group.proxies)) group.proxies = group.proxies.filter(x => !removed.has(x));
      if (first && added.length && ['select', 'selector'].includes(String(group.type).toLowerCase())) {
        group.proxies = [...new Set(added.concat(Array.isArray(group.proxies) ? group.proxies : []))]; first = false;
      }
    }
  }
  return config;
}
)JS";
    return applyConfigScript(document, program, "migration", "", nullptr, error);
}
