// Controller JSON is parsed as data; no JavaScript is evaluated.
class ControllerConfigJson {
    JSRuntime* runtime = nullptr;
public:
    JSContext* context = nullptr;
    JSValue root = JS_UNDEFINED;
    ControllerConfigJson() {
        runtime = JS_NewRuntime();
        if (runtime) {
            JS_SetMemoryLimit(runtime, 64 * 1024 * 1024); JS_SetMaxStackSize(runtime, 128 * 1024);
            context = JS_NewContext(runtime);
        }
    }
    ControllerConfigJson(const ControllerConfigJson&) = delete;
    ~ControllerConfigJson() { if (context) { JS_FreeValue(context, root); JS_FreeContext(context); } if (runtime) JS_FreeRuntime(runtime); }
    bool parse(const std::string& text, std::string& error) {
        if (!context || text.empty() || text.size() > 16 * 1024 * 1024) { error = "Invalid configuration JSON size"; return false; }
        root = JS_ParseJSON(context, text.data(), text.size(), "configs.json");
        if (!JS_IsObject(root) || JS_IsArray(context, root) != 0) { error = "Configuration request must be a JSON object"; return false; }
        return true;
    }
    bool keys(const std::set<std::string>& supported, std::string& error) {
        JSPropertyEnum* properties = nullptr; uint32_t count = 0;
        if (JS_GetOwnPropertyNames(context, &properties, &count, root, JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) < 0) { error = "Cannot read configuration fields"; return false; }
        bool valid = true;
        for (uint32_t i = 0; i < count; ++i) {
            const char* name = JS_AtomToCString(context, properties[i].atom);
            if (!name || !supported.count(name)) { valid = false; error = std::string("Unsupported configuration field: ") + (name ? name : "invalid key"); }
            if (name) JS_FreeCString(context, name);
            JS_FreeAtom(context, properties[i].atom);
        }
        js_free(context, properties); return valid;
    }
    // Omitted and null fields preserve the current value, as in Clash's optional PATCH schema.
    bool string(const char* key, std::string& output, std::string& error) {
        JSValue value = JS_GetPropertyStr(context, root, key);
        bool valid = JS_IsUndefined(value) || JS_IsNull(value);
        if (JS_IsString(value)) {
            size_t length = 0; const char* text = JS_ToCStringLen(context, &length, value);
            if (text) { output.assign(text, length); JS_FreeCString(context, text); valid = true; }
        }
        JS_FreeValue(context, value);
        if (!valid) error = std::string(key) + " must be a string"; return valid;
    }
    bool boolean(const char* key, bool& output, std::string& error) {
        JSValue value = JS_GetPropertyStr(context, root, key);
        const bool valid = JS_IsUndefined(value) || JS_IsNull(value) || JS_IsBool(value);
        if (JS_IsBool(value)) output = JS_ToBool(context, value) != 0;
        JS_FreeValue(context, value);
        if (!valid) error = std::string(key) + " must be a boolean"; return valid;
    }
    bool port(const char* key, int& output, std::string& error) {
        JSValue value = JS_GetPropertyStr(context, root, key);
        bool valid = JS_IsUndefined(value) || JS_IsNull(value);
        if (JS_IsNumber(value)) {
            double number = -1; JS_ToFloat64(context, &number, value);
            valid = std::isfinite(number) && std::floor(number) == number && number >= 0 && number <= 65535;
            if (valid) output = static_cast<int>(number);
        }
        JS_FreeValue(context, value);
        if (!valid) error = std::string(key) + " must be an integer between 0 and 65535"; return valid;
    }
};

bool readControllerFile(const std::string& path, size_t maximum, std::string& text, std::string& error)
{
    if (path.empty() || path.find('\0') != std::string::npos) { error = "Invalid configuration path"; return false; }
    const int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) { error = "Cannot read configuration file"; return false; }
    struct stat status{};
    bool valid = fstat(fd, &status) == 0 && S_ISREG(status.st_mode) && status.st_size > 0 && static_cast<uint64_t>(status.st_size) <= maximum;
    text.clear(); std::array<char, 8192> bytes{};
    while (valid) {
        const auto count = read(fd, bytes.data(), bytes.size());
        if (count < 0 && errno == EINTR) continue;
        if (count == 0) break;
        if (count < 0 || text.size() + static_cast<size_t>(count) > maximum) { valid = false; break; }
        text.append(bytes.data(), static_cast<size_t>(count));
    }
    close(fd);
    if (!valid) error = "Configuration must be a regular file within its size limit";
    return valid;
}

std::string runtimeConfigPathLocked() { return g_state.runtimeDirectory + "/controller.json"; }

bool configureRuntimeDirectory(const std::string& files)
{
    if (files.empty() || files.front() != '/' || files.find('\0') != std::string::npos) return false;
    std::array<char, PATH_MAX> real{};
    if (!realpath(files.c_str(), real.data())) return false;
    const std::string directory = std::string(real.data()) + "/.clashos-runtime";
    std::lock_guard<std::mutex> lock(g_state.mutex);
    if (!g_state.runtimeDirectory.empty() && g_state.running.load() && directory != g_state.runtimeDirectory) return false;
    if (mkdir(directory.c_str(), 0700) != 0 && errno != EEXIST) return false;
    struct stat status{};
    if (lstat(directory.c_str(), &status) != 0 || !S_ISDIR(status.st_mode) || status.st_uid != getuid() || chmod(directory.c_str(), 0700) != 0) return false;
    g_state.runtimeDirectory = directory; return true;
}

bool readRuntimeEnvelope(const std::string& source, std::string& payload, std::string& origin, std::string& error)
{
    ControllerConfigJson json; std::string format;
    if (!json.parse(source, error) || !json.keys({"format", "origin", "payload"}, error) ||
        !json.string("format", format, error) || !json.string("origin", origin, error) || !json.string("payload", payload, error) ||
        format != "ClashOS-runtime-v1" || payload.empty() || (!origin.empty() && origin.front() != '/') || origin.find('\0') != std::string::npos) {
        error = "Invalid temporary configuration envelope"; return false;
    }
    return true;
}

bool stageRuntimeEnvelope(const std::string& path, const std::string& payload, const std::string& origin,
    std::string& temporary, std::string& error)
{
    static std::atomic<uint64_t> serial{0};
    temporary = path + ".tmp-" + std::to_string(getpid()) + "-" + std::to_string(++serial);
    const std::string bytes = "{\"format\":\"ClashOS-runtime-v1\",\"origin\":\"" + jsonEscape(origin) + "\",\"payload\":\"" + jsonEscape(payload) + "\"}";
    const int fd = open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) { error = "Cannot stage temporary configuration"; return false; }
    size_t offset = 0;
    while (offset < bytes.size()) {
        const auto size = write(fd, bytes.data() + offset, bytes.size() - offset);
        if (size < 0 && errno == EINTR) continue;
        if (size <= 0) break;
        offset += static_cast<size_t>(size);
    }
    const bool valid = offset == bytes.size() && fsync(fd) == 0;
    close(fd);
    if (!valid) { unlink(temporary.c_str()); error = "Cannot save temporary configuration"; }
    return valid;
}
