// Real process resident bytes, rather than allocator estimates or fabricated graph data.
// The embedded core shares its host process; RSS therefore includes the host UI/VM.
bool controllerMemoryBytes(uint64_t& bytes)
{
#ifdef __APPLE__
    mach_task_basic_info_data_t info{}; mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, reinterpret_cast<task_info_t>(&info), &count) != KERN_SUCCESS) return false;
    bytes = info.resident_size;
#else
    std::ifstream input("/proc/self/statm"); uint64_t pages = 0, resident = 0;
    const long pageSize = sysconf(_SC_PAGESIZE);
    if (!(input >> pages >> resident) || pageSize <= 0 || resident > UINT64_MAX / static_cast<uint64_t>(pageSize)) return false;
    bytes = resident * static_cast<uint64_t>(pageSize);
#endif
    return bytes > 0;
}

int controllerLogLevel(const std::string& level)
{
    if (level == "debug") return 0;
    if (level == "info") return 1;
    if (level == "warning" || level == "warn") return 2;
    if (level == "error") return 3;
    if (level == "silent") return 4;
    return -1;
}

bool controllerStreamQuery(const std::string& path, std::map<std::string, std::string>& values)
{
    auto decode = [](const std::string& raw, std::string& value) {
        auto hex = [](char c) { return c >= '0' && c <= '9' ? c-'0' : c >= 'a' && c <= 'f' ? c-'a'+10 : c >= 'A' && c <= 'F' ? c-'A'+10 : -1; };
        for (size_t i = 0; i < raw.size(); ++i) {
            unsigned char ch = raw[i];
            if (ch == '%') {
                if (i + 2 >= raw.size() || hex(raw[i+1]) < 0 || hex(raw[i+2]) < 0) return false;
                ch = static_cast<unsigned char>((hex(raw[i+1]) << 4) | hex(raw[i+2])); i += 2;
            } else if (ch == '+') ch = ' ';
            if (ch < 0x20 || ch == 0x7f) return false;
            value += static_cast<char>(ch);
        }
        return true;
    };
    const size_t question = path.find('?'); if (question == std::string::npos) return true;
    std::istringstream query(path.substr(question + 1)); std::string item;
    while (std::getline(query, item, '&')) {
        if (item.empty()) continue;
        const auto equal = item.find('='); std::string key, value;
        if (!decode(item.substr(0, equal), key) || !decode(equal == std::string::npos ? "" : item.substr(equal + 1), value) || values.count(key)) return false;
        values.emplace(std::move(key), std::move(value));
    }
    return true;
}

enum class ControllerStreamKind { Traffic, Memory, Logs, Connections };
struct ControllerStreamOptions {
    ControllerStreamKind kind = ControllerStreamKind::Traffic;
    int interval = 1000, logLevel = 1;
    bool structured = false;
};

bool controllerStreamOptions(const std::string& path, ControllerStreamOptions& options)
{
    const std::string resource = path.substr(0, path.find('?'));
    if (resource == "/memory") options.kind = ControllerStreamKind::Memory;
    else if (resource == "/logs") { options.kind = ControllerStreamKind::Logs; options.interval = 100; }
    else if (resource == "/connections") options.kind = ControllerStreamKind::Connections;
    std::map<std::string, std::string> query;
    if (!controllerStreamQuery(path, query)) return false;
    if (options.kind == ControllerStreamKind::Logs) {
        if (!query["level"].empty()) options.logLevel = controllerLogLevel(query["level"]);
        if (options.logLevel < 0) return false;
        options.structured = query["format"] == "structured";
    }
    if (options.kind == ControllerStreamKind::Connections && !query["interval"].empty()) {
        const std::string& raw = query["interval"];
        if (raw.size() > 8 || raw.find_first_not_of("0123456789") != std::string::npos) return false;
        options.interval = std::stoi(raw);
        if (options.interval < 100 || options.interval > 60000) return false;
    }
    return true;
}

std::vector<std::string> controllerLogSamples(uint64_t& cursor, const ControllerStreamOptions& options)
{
    std::vector<CoreLog> batch;
    {
        std::lock_guard<std::mutex> lock(g_state.sessionsMutex);
        for (const CoreLog& log : g_state.logs) if (log.id > cursor) batch.push_back(log);
    }
    std::vector<std::string> samples;
    for (const auto& log : batch) {
        cursor = log.id;
        const int level = controllerLogLevel(log.type);
        if (level < options.logLevel || level < 0 || level == 4) continue;
        const std::string type = level == 2 ? "warning" : log.type;
        if (options.structured) samples.push_back("{\"time\":\"" + jsonEscape(log.time.substr(11, 8)) +
            "\",\"level\":\"" + (level == 2 ? "warn" : type) + "\",\"message\":\"" + jsonEscape(log.payload) + "\",\"fields\":[]}");
        else samples.push_back("{\"type\":\"" + type + "\",\"payload\":\"" + jsonEscape(log.payload) + "\"}");
    }
    return samples;
}
