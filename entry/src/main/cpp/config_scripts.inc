struct ScriptLog { std::string scope, level, text; };

std::string scriptTextPrefix(const char* text, size_t size, size_t maximum)
{
    size_t end = std::min(size, maximum); if (end < size) while (end && (static_cast<unsigned char>(text[end]) & 0xc0) == 0x80) --end;
    return std::string(text, end);
}

bool scriptDocumentText(yaml_document_t& source, std::string& output, std::string& error)
{
    const size_t count = source.nodes.top - source.nodes.start;
    if (count > 200000) { error = "Script configuration snapshot is too complex"; return false; }
    EditorYaml copy; if (!copy.initialize()) { error = "Cannot allocate script configuration snapshot"; return false; }
    for (auto* node = source.nodes.start; node < source.nodes.top; ++node) {
        int id = 0;
        if (node->type == YAML_SCALAR_NODE) {
            // Format a presentation copy only. JSON strings retain their quotes;
            // numbers, booleans and null remain plain YAML without explicit tags.
            const std::string tag(reinterpret_cast<const char*>(node->tag));
            const bool typed = tag == YAML_INT_TAG || tag == YAML_FLOAT_TAG || tag == YAML_BOOL_TAG || tag == YAML_NULL_TAG;
            id = yaml_document_add_scalar(&copy.document, typed ? reinterpret_cast<const yaml_char_t*>(YAML_STR_TAG) : node->tag,
                node->data.scalar.value, static_cast<int>(node->data.scalar.length), typed ? YAML_PLAIN_SCALAR_STYLE : node->data.scalar.style);
        }
        else if (node->type == YAML_SEQUENCE_NODE) id = yaml_document_add_sequence(&copy.document, node->tag, YAML_BLOCK_SEQUENCE_STYLE);
        else if (node->type == YAML_MAPPING_NODE) id = yaml_document_add_mapping(&copy.document, node->tag, YAML_BLOCK_MAPPING_STYLE);
        if (!id) { error = "Cannot clone script configuration snapshot"; return false; }
    }
    int id = 0;
    for (auto* node = source.nodes.start; node < source.nodes.top; ++node) {
        ++id;
        if (node->type == YAML_SEQUENCE_NODE) for (auto* item = node->data.sequence.items.start; item < node->data.sequence.items.top; ++item)
            if (!yaml_document_append_sequence_item(&copy.document, id, *item)) return false;
        if (node->type == YAML_MAPPING_NODE) for (auto* pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; ++pair)
            if (!yaml_document_append_mapping_pair(&copy.document, id, pair->key, pair->value)) return false;
    }
    if (!editorEmit(copy, output, 8 * 1024 * 1024)) { error = "Cannot emit script configuration snapshot"; return false; } return true;
}

// libyaml leaves implicit scalars as strings. Resolve only the YAML core scalar
// types for the JSON/JavaScript boundary, while retaining explicit !!str tags.
bool scriptTagScalars(yaml_document_t& document, const std::string& source, std::string& error)
{
    yaml_parser_t parser; if (!yaml_parser_initialize(&parser)) { error = "Cannot allocate script YAML reader"; return false; }
    yaml_parser_set_input_string(&parser, reinterpret_cast<const unsigned char*>(source.data()), source.size());
    int next = 1, documents = 0; bool done = false, valid = true;
    while (valid && !done) {
        yaml_event_t event;
        if (!yaml_parser_parse(&parser, &event)) { error = "Invalid YAML at script boundary"; valid = false; break; }
        if (event.type == YAML_DOCUMENT_START_EVENT && ++documents > 1) valid = false;
        if (event.type == YAML_MAPPING_START_EVENT || event.type == YAML_SEQUENCE_START_EVENT) ++next;
        if (event.type == YAML_SCALAR_EVENT) {
            auto* node = yaml_document_get_node(&document, next++);
            if (!node || node->type != YAML_SCALAR_NODE || node->data.scalar.length != event.data.scalar.length ||
                std::memcmp(node->data.scalar.value, event.data.scalar.value, event.data.scalar.length) != 0) valid = false;
            else if (event.data.scalar.plain_implicit && event.data.scalar.style == YAML_PLAIN_SCALAR_STYLE) {
                const std::string value(reinterpret_cast<char*>(event.data.scalar.value), event.data.scalar.length), lowered = lower(value);
                const char* tag = nullptr;
                if (value.empty() || value == "~" || lowered == "null") tag = YAML_NULL_TAG;
                else if (lowered == "true" || lowered == "false") tag = YAML_BOOL_TAG;
                else {
                    std::string number = value; if (!number.empty() && (number.front() == '+' || number.front() == '-')) number.erase(0, 1);
                    if (!number.empty() && number.find_first_not_of("0123456789") == std::string::npos) tag = YAML_INT_TAG;
                    else if (number.size() > 2 && number[0] == '0' && ((number[1] == 'x' && number.find_first_not_of("0123456789abcdefABCDEF", 2) == std::string::npos) ||
                        (number[1] == 'o' && number.find_first_not_of("01234567", 2) == std::string::npos))) tag = YAML_INT_TAG;
                    else if (lowered == ".inf" || lowered == "+.inf" || lowered == "-.inf" || lowered == ".nan") tag = YAML_FLOAT_TAG;
                    else if (value.find_first_of(".eE") != std::string::npos && value.find_first_not_of("0123456789.eE+-") == std::string::npos) {
                        char* end = nullptr; std::strtod(value.c_str(), &end); if (end != value.c_str() && *end == '\0') tag = YAML_FLOAT_TAG;
                    }
                }
                if (tag) {
                    auto* replacement = static_cast<yaml_char_t*>(std::malloc(std::strlen(tag) + 1));
                    if (!replacement) { valid = false; error = "Cannot allocate YAML scalar tag"; }
                    else { std::strcpy(reinterpret_cast<char*>(replacement), tag); std::free(node->tag); node->tag = replacement; }
                }
            }
        }
        if (next > 100001) { valid = false; error = "Script configuration exceeds 100000 YAML nodes"; }
        done = event.type == YAML_STREAM_END_EVENT; yaml_event_delete(&event);
    }
    yaml_parser_delete(&parser);
    if (!valid && error.empty()) error = "Script input must be one bounded YAML/JSON document";
    return valid;
}

class ScriptValue {
public:
    JSContext* context; JSValue value;
    ScriptValue(JSContext* context, JSValue value) : context(context), value(value) {}
    ~ScriptValue() { JS_FreeValue(context, value); }
    ScriptValue(const ScriptValue&) = delete;
    JSValue release() { const JSValue result = value; value = JS_UNDEFINED; return result; }
    void reset(JSValue replacement) { JS_FreeValue(context, value); value = replacement; }
};

struct ScriptExecution {
    std::chrono::steady_clock::time_point deadline;
    std::vector<ScriptLog>* logs = nullptr;
    std::string scope;
    size_t logBytes = 0, outputNodes = 0;
    bool timedOut = false, truncated = false;
    bool expired() { if (std::chrono::steady_clock::now() >= deadline) timedOut = true; return timedOut; }
};

JSValue scriptConsole(JSContext* context, JSValueConst, int argc, JSValueConst* argv, int magic)
{
    auto* state = static_cast<ScriptExecution*>(JS_GetContextOpaque(context));
    if (!state || !state->logs || state->truncated) return JS_UNDEFINED;
    if (state->expired()) return JS_ThrowInternalError(context, "script execution timed out");
    std::string line;
    for (int i = 0; i < argc; ++i) {
        size_t length = 0; const char* text = JS_ToCStringLen(context, &length, argv[i]); if (!text) return JS_EXCEPTION;
        if (i) line += ' ';
        const size_t room = state->logBytes + line.size() < 16384 ? 16384 - state->logBytes - line.size() : 0;
        line += scriptTextPrefix(text, length, room); JS_FreeCString(context, text);
        if (length > room) { state->truncated = true; break; }
    }
    if (state->logs->size() >= 100) state->truncated = true;
    else { static const char* levels[] = {"debug", "info", "warning", "error"}; state->logBytes += line.size(); state->logs->push_back({state->scope, levels[std::max(0, std::min(3, magic))], line}); }
    if (state->truncated) state->logs->push_back({state->scope, "warning", "Script console output truncated"});
    return JS_UNDEFINED;
}

JSValue scriptOutputValue(JSContext* context, JSValueConst, int argc, JSValueConst* argv)
{
    auto* state = static_cast<ScriptExecution*>(JS_GetContextOpaque(context));
    if (!state || state->expired() || ++state->outputNodes > 100000) return JS_ThrowRangeError(context, "script output too complex or timed out");
    return argc > 1 ? JS_DupValue(context, argv[1]) : JS_UNDEFINED;
}

class ScriptEngine {
public:
    JSRuntime* runtime = nullptr; JSContext* context = nullptr;
    explicit ScriptEngine(ScriptExecution& state) {
        runtime = JS_NewRuntime(); if (!runtime) return;
        JS_SetMemoryLimit(runtime, 64 * 1024 * 1024); JS_SetMaxStackSize(runtime, 512 * 1024); JS_SetCanBlock(runtime, false);
        JS_SetInterruptHandler(runtime, [](JSRuntime*, void* opaque) -> int { return static_cast<ScriptExecution*>(opaque)->expired(); }, &state);
        context = JS_NewContext(runtime); if (!context) return;
        JS_SetContextOpaque(context, &state);
        ScriptValue global(context, JS_GetGlobalObject(context)), console(context, JS_NewObject(context));
        const std::pair<const char*, int> methods[] = {{"log",1},{"info",1},{"warn",2},{"error",3},{"debug",0}};
        for (const auto& method : methods) JS_SetPropertyStr(context, console.value, method.first,
            JS_NewCFunctionMagic(context, scriptConsole, method.first, 1, JS_CFUNC_generic_magic, method.second));
        JS_SetPropertyStr(context, global.value, "console", console.release());
    }
    ~ScriptEngine() { if (context) JS_FreeContext(context); if (runtime) JS_FreeRuntime(runtime); }
};

JSValue scriptYamlValue(JSContext* context, yaml_document_t& document, int id, std::set<int>& active, size_t& visited, std::string& error, int depth = 0)
{
    if (depth > 64 || ++visited > 100000 || active.count(id)) { error = "Script input is cyclic, too deep or too complex"; return JS_EXCEPTION; }
    auto* node = yaml_document_get_node(&document, id); if (!node) { error = "Invalid script YAML node"; return JS_EXCEPTION; }
    if (node->type == YAML_SCALAR_NODE) {
        const std::string text = yamlText(node), tag = reinterpret_cast<const char*>(node->tag);
        if (tag == YAML_NULL_TAG) { if (!text.empty() && text != "~" && lower(text) != "null") { error = "Invalid explicit YAML null scalar"; return JS_EXCEPTION; } return JS_NULL; }
        if (tag == YAML_BOOL_TAG) { if (lower(text) != "true" && lower(text) != "false") { error = "Invalid explicit YAML boolean scalar"; return JS_EXCEPTION; } return JS_NewBool(context, lower(text) == "true"); }
        if (tag == YAML_INT_TAG) {
            std::string digits = text; bool negative = false;
            if (!digits.empty() && (digits.front() == '-' || digits.front() == '+')) { negative = digits.front() == '-'; digits.erase(0, 1); }
            int base = 10; if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'o')) { base = digits[1] == 'x' ? 16 : 8; digits.erase(0, 2); }
            char* end = nullptr; errno = 0; const unsigned long long value = std::strtoull(digits.c_str(), &end, base);
            if (digits.empty() || end == digits.c_str() || *end || errno == ERANGE || value > 9007199254740991ULL) { error = "Integer outside JavaScript safe range; quote the scalar to keep it as text"; return JS_EXCEPTION; }
            return JS_NewFloat64(context, negative ? -static_cast<double>(value) : static_cast<double>(value));
        }
        if (tag == YAML_FLOAT_TAG) {
            char* end = nullptr; const double value = std::strtod(text.c_str(), &end);
            if (end == text.c_str() || *end || !std::isfinite(value)) { error = "Script configuration requires finite numeric scalars"; return JS_EXCEPTION; }
            return JS_NewFloat64(context, value);
        }
        if (tag != YAML_STR_TAG) { error = "Unsupported YAML scalar tag in script configuration"; return JS_EXCEPTION; }
        return JS_NewStringLen(context, text.data(), text.size());
    }
    active.insert(id);
    ScriptValue output(context, node->type == YAML_SEQUENCE_NODE ? JS_NewArray(context) : JS_NewObject(context));
    if (JS_IsException(output.value)) { active.erase(id); return JS_EXCEPTION; }
    bool valid = true;
    if (node->type == YAML_SEQUENCE_NODE) {
        uint32_t index = 0;
        for (auto* item = node->data.sequence.items.start; item < node->data.sequence.items.top; ++item) {
            const JSValue value = scriptYamlValue(context, document, *item, active, visited, error, depth + 1);
            if (JS_IsException(value)) { valid = false; break; }
            if (JS_SetPropertyUint32(context, output.value, index++, value) < 0) { valid = false; break; }
        }
    } else if (node->type == YAML_MAPPING_NODE) {
        std::set<std::string> keys;
        for (auto* pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; ++pair) {
            auto* key = yaml_document_get_node(&document, pair->key); const std::string name = yamlText(key);
            if (!key || key->type != YAML_SCALAR_NODE || !keys.insert(name).second) { error = "Scripts require unique scalar mapping keys"; valid = false; break; }
            const JSValue value = scriptYamlValue(context, document, pair->value, active, visited, error, depth + 1);
            if (JS_IsException(value)) { valid = false; break; }
            const JSAtom atom = JS_NewAtomLen(context, name.data(), name.size());
            const int result = JS_DefinePropertyValue(context, output.value, atom, value, JS_PROP_C_W_E); JS_FreeAtom(context, atom);
            if (result < 0) { valid = false; break; }
        }
    } else { error = "Invalid script YAML collection"; valid = false; }
    active.erase(id); return valid ? output.release() : JS_EXCEPTION;
}

std::string scriptException(JSContext* context, ScriptExecution& state)
{
    if (state.timedOut) return "Script exceeded its 500 ms execution limit";
    ScriptValue exception(context, JS_GetException(context));
    size_t size = 0; const char* message = JS_ToCStringLen(context, &size, exception.value);
    std::string result = message ? scriptTextPrefix(message, size, 2048) : "Script failed or exceeded its 64 MB memory limit";
    if (message) JS_FreeCString(context, message);
    ScriptValue stack(context, JS_GetPropertyStr(context, exception.value, "stack"));
    if (!JS_IsException(stack.value) && !JS_IsUndefined(stack.value)) {
        const char* trace = JS_ToCStringLen(context, &size, stack.value);
        if (trace) { if (result.size() < 2048) result += '\n' + scriptTextPrefix(trace, size, 2048 - result.size()); JS_FreeCString(context, trace); }
    }
    return result;
}

bool applyConfigScript(yaml_document_t& document, const std::string& source, const std::string& scope, const std::string& profileName,
    std::vector<ScriptLog>* logs, std::string& error)
{
    if (source.empty()) return true;
    if (source.size() > 256 * 1024) { error = "Script source exceeds 256 KB"; return false; }
    ScriptExecution state{std::chrono::steady_clock::now() + std::chrono::milliseconds(500), logs, scope}; ScriptEngine engine(state);
    if (!engine.context) { error = "Cannot allocate script runtime"; return false; }
    JSContext* context = engine.context; std::set<int> active; size_t visited = 0;
    ScriptValue config(context, scriptYamlValue(context, document, 1, active, visited, error)), name(context, JS_NewStringLen(context, profileName.data(), profileName.size()));
    auto failed = [&]() { if (error.empty()) error = scriptException(context, state); error = scope + ": " + error; return false; };
    if (JS_IsException(config.value) || JS_IsException(name.value)) return failed();
    ScriptValue evaluated(context, JS_Eval(context, source.data(), source.size(), (scope + "-script.js").c_str(), JS_EVAL_TYPE_GLOBAL));
    if (JS_IsException(evaluated.value)) return failed();
    const char* lookup = "typeof main === 'function' ? main : undefined";
    ScriptValue entry(context, JS_Eval(context, lookup, std::strlen(lookup), "clashos-script-entry", JS_EVAL_TYPE_GLOBAL));
    if (JS_IsException(entry.value)) return failed();
    if (!JS_IsFunction(context, entry.value)) { error = scope + ": script must define main(config, profileName)"; return false; }
    JSValueConst arguments[] = {config.value, name.value}; ScriptValue result(context, JS_Call(context, entry.value, JS_UNDEFINED, 2, arguments));
    if (JS_IsException(result.value)) return failed();
    size_t jobs = 0;
    while (JS_PromiseState(context, result.value) == JS_PROMISE_PENDING) {
        if (state.expired() || ++jobs > 10000) { error = scope + ": asynchronous script exceeded its execution limit"; return false; }
        JSContext* jobContext = nullptr; const int ran = JS_ExecutePendingJob(engine.runtime, &jobContext);
        if (ran < 0) return failed();
        if (!ran) { error = scope + ": asynchronous script cannot finish without external I/O or timers"; return false; }
    }
    if (JS_PromiseState(context, result.value) == JS_PROMISE_REJECTED) { ScriptValue reason(context, JS_PromiseResult(context, result.value)); JS_Throw(context, reason.release()); return failed(); }
    if (JS_PromiseState(context, result.value) == JS_PROMISE_FULFILLED) result.reset(JS_PromiseResult(context, result.value));
    if (!JS_IsObject(result.value) || JS_IsArray(context, result.value) != 0) { error = scope + ": main must return a configuration object"; return false; }
    ScriptValue replacer(context, JS_NewCFunction(context, scriptOutputValue, "clashosOutput", 2));
    ScriptValue json(context, JS_JSONStringify(context, result.value, replacer.value, JS_UNDEFINED));
    if (JS_IsException(json.value)) return failed();
    size_t size = 0; const char* text = JS_ToCStringLen(context, &size, json.value);
    if (!text) return failed();
    std::string output;
    if (size <= 8 * 1024 * 1024) output.assign(text, size); JS_FreeCString(context, text);
    if (output.empty()) { error = scope + ": generated configuration is empty or exceeds 8 MB"; return false; }
    EditorYaml parsed;
    if (!parsed.parse(output, 8 * 1024 * 1024, error) || !scriptTagScalars(parsed.document, output, error)) return failed();
    auto* root = yaml_document_get_root_node(&parsed.document);
    if (!root || root->type != YAML_MAPPING_NODE) { error = scope + ": main must serialize to a configuration object"; return false; }
    yaml_document_delete(&document); document = parsed.document; parsed.loaded = false; return true;
}

std::string scriptLogsJson(const std::vector<ScriptLog>& logs)
{
    std::string result = "[";
    for (const auto& log : logs) { if (result.size() > 1) result += ','; result += "{\"scope\":\"" + jsonEscape(log.scope) + "\",\"level\":\"" + jsonEscape(log.level) + "\",\"text\":\"" + jsonEscape(log.text) + "\"}"; }
    return result + ']';
}
