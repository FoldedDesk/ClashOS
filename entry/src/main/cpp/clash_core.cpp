#ifndef CLAHSOS_HOST_TEST
#include <napi/native_api.h>
#endif
#include <yaml.h>
#include "third_party/quickjs/quickjs.h"
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/md.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/entropy.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/base64.h>
#include <psa/crypto.h>
extern "C" {
#include "sha3.h"
}

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cmath>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <tuple>
#include <set>
#include <map>
#include <mutex>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <ctime>
#include <poll.h>
#include <regex.h>
#include <zlib.h>
#include <zstd.h>
#include <maxminddb.h>
#include <string_view>
#include <re2/re2.h>
#include <sys/stat.h>
#include <limits.h>
#include <functional>
#ifdef __APPLE__
#include <mach/mach.h>
#endif

namespace {

using HealthClock = std::chrono::steady_clock;
struct GroupHealthSample { int delay=0;std::string resolved; };
struct BalancedSession {
    std::string member;
    HealthClock::time_point expires{},used{};
};
struct RouteContext {
    std::string host,source,network="tcp";
    HealthClock::time_point now=HealthClock::now();
    bool advance=true;
    std::set<std::string> ancestors;
};
enum class SsCipher { Unsupported,Aes128Gcm,Aes256Gcm,ChaCha20Poly1305 };
SsCipher shadowsocksCipher(const std::string& name)
{
    if(name=="aes-128-gcm"||name=="aead_aes_128_gcm")return SsCipher::Aes128Gcm;
    if(name=="aes-256-gcm"||name=="aead_aes_256_gcm")return SsCipher::Aes256Gcm;
    if(name=="chacha20-ietf-poly1305"||name=="chacha20-poly1305"||name=="aead_chacha20_poly1305")return SsCipher::ChaCha20Poly1305;
    return SsCipher::Unsupported;
}
size_t shadowsocksKeySize(SsCipher cipher)
{
    return cipher==SsCipher::Aes128Gcm?16:cipher==SsCipher::Unsupported?0:32;
}
bool validProbeUrl(const std::string& url);
bool validProbeStatus(const std::string& text);
void wakeHealthChecks();
struct ProxyGroup {
    std::string name;
    std::string type = "Selector";
    std::string now;
    std::vector<std::string> proxies;
    std::vector<std::string> configuredProxies, providers;
    bool includeAllProxies=false, includeAllProviders=false;
    std::string filter, excludeFilter;
    std::string url="https://www.gstatic.com/generate_204";
    std::string expectedStatus="*";
    int interval=300, timeout=5000, tolerance=50;
    bool lazy=true, disableUdp=false, checking=false, forceCheck=false;
    std::string manual,pendingSelection;
    bool pendingManual=false;
    std::map<std::string,GroupHealthSample> health;
    HealthClock::time_point nextCheck{}, lastUsed{};
    uint64_t checkGeneration=0;
    std::string strategy="consistent-hashing",lastSelected;
    uint64_t roundRobin=0,sessionSerial=0;
    std::map<std::string,BalancedSession> sessions;
};

struct ProxyNode {
    std::string name;
    std::string type;
    std::string server;
    int port = 0;
    std::string cipher;
    std::string password;
    std::string uuid;
    int alterId = 0;
    bool tls = false;
    std::string network = "tcp";
    std::string wsPath = "/";
    std::map<std::string, std::string> wsHeaders;
    std::string serverName;
    std::vector<std::string> alpn;
    std::string transportError;
    bool skipCertVerify = false;
    bool udp = false;
    bool udpConfigured = false;
    uint64_t revision = 0;
    std::vector<std::string> chain;
    std::string matchedRule;
    std::string provider;
    bool loadBalanced=false;
};

struct ProxyProvider {
    std::string name,type,url,path,downloadProxy="DIRECT";
    std::string filter,excludeFilter,excludeType,prefix,suffix;
    std::map<std::string,std::string> headers;
    int interval=3600,timeout=10000,overrideUdp=-1,overrideSkipVerify=-1;
    size_t sizeLimit=8*1024*1024;
    bool updating=false,forceUpdate=false,healthEnabled=false;
    std::string updatedAt,lastError;
    HealthClock::time_point nextUpdate{};
    uint64_t updateGeneration=0;
    ProxyGroup health;
    std::vector<ProxyNode> nodes;
};

struct ProviderPattern;
struct RuleDomainIndex;
struct ProxyRule {
    std::string kind;
    std::string value;
    std::string target;
    bool noResolve = false;
    std::vector<ProxyRule> conditions;
    std::shared_ptr<ProviderPattern> pattern;
    std::shared_ptr<RuleDomainIndex> domainPattern;
};

#include "rule_types.inc"
#include "geo_types.inc"
#include "dns_types.inc"

struct ConnectionInfo {
    std::string id;
    std::string host;
    int port = 0;
    int client = -1;
    int upstream = -1;
    int owner = -1;
    std::string network = "tcp";
    bool cancelled = false;
    std::vector<std::string> chains;
    std::string rule;
    std::string start;
    uint64_t upload = 0;
    uint64_t download = 0;
};

struct CoreLog {
    uint64_t id = 0;
    std::string time;
    std::string type;
    std::string payload;
};

struct ProxyListener {
    int fd = -1;
    int port = 0;
    std::string host;
    std::atomic<bool> active{true};
    std::mutex startMutex;
    std::condition_variable startWake;
    bool ready = false;
    std::thread thread;
};

struct ProxyPortSettings {
    int http = 7890, socks = 7891, mixed = 0;
    bool overridden = false;
    int effectiveHttp() const { return mixed > 0 ? mixed : http; }
    int effectiveSocks() const { return mixed > 0 ? mixed : socks; }
};

struct InboundConfig {
    bool allowLan = false;
    std::string bindAddress = "*";
    std::vector<std::pair<std::string, std::string>> users;
    std::vector<std::string> skipAuth, allowed{"0.0.0.0/0", "::/0"}, denied;
    std::vector<RuleIpRange> skipRanges, allowedRanges, deniedRanges;
};

struct SnifferProtocol {
    std::vector<std::pair<int, int>> ports;
    bool overrideDestination = true;
};
struct SnifferConfig {
    bool enabled = false, forceDnsMapping = true, parsePureIp = true, overrideDestination = true;
    std::map<std::string, SnifferProtocol> protocols;
    std::vector<std::string> forceDomain, skipDomain, skipSource, skipDestination;
    RuleDomainIndex forceIndex, skipIndex;
    std::vector<std::string> forceLiterals, skipLiterals;
    std::vector<RuleIpRange> sourceRanges, destinationRanges;
};

struct CoreState {
    std::mutex mutex;
    std::mutex sessionsMutex;
    std::condition_variable workersDone;
    std::set<int> sockets;
    std::map<int, ConnectionInfo> connections;
    std::deque<CoreLog> logs;
    uint64_t nextConnectionId = 1;
    uint64_t nextLogId = 1;
    std::atomic<int> workers{0};
    std::atomic<int> controllerStreams{0};
    std::string controllerSecret;
    std::atomic<uint64_t> controllerAuthEpoch{0};
    std::atomic<uint64_t> uploadTotal{0};
    std::atomic<uint64_t> downloadTotal{0};
    std::string instance;
    std::map<std::string, int> delays;
    std::atomic<bool> running{false};
    std::thread serverThread;
    std::vector<std::shared_ptr<ProxyListener>> listeners;
    uint64_t configRevision = 0;
    int serverFd = -1;
    int httpProxyFd = -1;
    int socksProxyFd = -1;
    int port = 9090;
    int httpPort = 7890;
    int socksPort = 7891;
    ProxyPortSettings portSettings, profilePorts;
    InboundConfig inbound, profileInbound;
    std::shared_ptr<const SnifferConfig> sniffer = std::make_shared<SnifferConfig>();
    bool inboundOverridden = false;
    std::string configPath;
    std::string runtimeDirectory, configOrigin;
    bool temporaryConfig = false;
    std::atomic<int> logLevel{1};
    std::atomic<bool> ipv6{false};
    std::string lastError;
    std::string mode = "Rule";
    std::vector<std::string> proxyNames;
    std::vector<ProxyNode> nodes;
    std::vector<ProxyNode> localNodes;
    std::vector<ProxyProvider> providers;
    uint64_t profileEpoch=0;
    std::vector<ProxyGroup> groups;
    std::vector<ProxyRule> rules;
    std::vector<RuleProvider> ruleProviders;
    GeoConfig geo;
    std::shared_ptr<DnsConfig> dns=std::make_shared<DnsConfig>();
    std::shared_ptr<DnsListener> dnsListener;
    int ruleCount = 0;
};

CoreState g_state;
std::mutex g_lifecycleMutex;
std::mutex g_healthWaitMutex;
std::condition_variable g_healthWake;
std::thread g_healthThread;
std::thread g_providerThread;
std::thread g_ruleProviderThread;
std::thread g_geoThread;
std::string ruleProviderControlLocked(const std::string&,const std::string&,const std::string&);
void initializeProvidersLocked();
void rebuildProviderNodesLocked();
std::string providersJsonLocked(const std::string& name="");
std::string providerNodeJsonLocked(const ProxyNode& node);
std::string importProviderFileLocked(const std::string& name,const std::string& body);
std::string resetProviderFileLocked(const std::string& name);
void wakeHealthChecks() { g_healthWake.notify_all(); }
void markProxyUsedLocked(std::string name)
{
    std::set<std::string> visited;
    while(visited.size()<32 && visited.insert(name).second) {
        auto group=std::find_if(g_state.groups.begin(),g_state.groups.end(),[&](const ProxyGroup& item){return item.name==name;});
        if(group==g_state.groups.end())break;
        group->lastUsed=HealthClock::now();name=group->now;
    }
    wakeHealthChecks();
}
thread_local int g_currentClient = -1;
extern thread_local std::chrono::steady_clock::time_point g_probeDeadline;
bool configureProxyListenersLocked(int httpPort, int socksPort, std::string& error,
    const std::function<bool()>& commit = {}, const InboundConfig* inbound = nullptr);
bool shareUtf8(const std::string& text);
std::string queryValue(const std::string& path, const std::string& key);

bool protectFileDescriptor(int fd)
{
    struct stat info{};
    return fd>=0&&fstat(fd,&info)==0&&S_ISREG(info.st_mode)&&fchmod(fd,S_IRUSR|S_IWUSR)==0;
}

std::string utcNow()
{
    const std::time_t now = std::time(nullptr);
    std::tm time{};
    gmtime_r(&now, &time);
    char buffer[32] = {};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &time);
    return buffer;
}

void socketTimeout(int fd, int milliseconds)
{
    timeval timeout{milliseconds / 1000, (milliseconds % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#ifdef SO_NOSIGPIPE
    int enabled = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
#endif
}

thread_local std::chrono::steady_clock::time_point g_probeDeadline{};
bool prepareSocketIo(int fd)
{
    if (g_probeDeadline == std::chrono::steady_clock::time_point{}) return true;
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(g_probeDeadline - std::chrono::steady_clock::now()).count();
    if (remaining <= 0) { errno = ETIMEDOUT; return false; }
    socketTimeout(fd, static_cast<int>(std::min<int64_t>(remaining, 60000))); return true;
}

void trackSocket(int fd)
{
    if (fd < 0) return;
    socketTimeout(fd, 10000);
    std::lock_guard<std::mutex> guard(g_state.sessionsMutex);
    g_state.sockets.insert(fd);
}

void closeSocket(int fd)
{
    if (fd < 0) return;
    // Keep removal and close atomic with respect to cancellation and descriptor reuse.
    std::lock_guard<std::mutex> guard(g_state.sessionsMutex);
    g_state.connections.erase(fd);
    for (auto& pair : g_state.connections) if (pair.second.upstream == fd) pair.second.upstream = -1;
    g_state.sockets.erase(fd);
    close(fd);
}

void coreLog(const std::string& type, const std::string& payload)
{
    const int level = type == "debug" ? 0 : type == "info" ? 1 : (type == "warning" || type == "warn") ? 2 : 3;
    if (level < g_state.logLevel.load()) return;
    std::lock_guard<std::mutex> guard(g_state.sessionsMutex);
    g_state.logs.push_back({g_state.nextLogId++, utcNow(), type, payload});
    if (g_state.logs.size() > 300) g_state.logs.pop_front();
}

bool beginConnection(int client, const std::string& host, int port, const std::vector<std::string>& chains,
    const std::string& rule, const std::string& network = "tcp", int owner = -1)
{
    std::lock_guard<std::mutex> guard(g_state.sessionsMutex);
    if (network == "udp" && std::count_if(g_state.connections.begin(), g_state.connections.end(),
        [](const auto& pair) { return pair.second.network == "udp"; }) >= 256) return false;
    ConnectionInfo info;
    info.id = std::to_string(g_state.nextConnectionId++);
    info.client = client;
    info.host = host;
    info.port = port;
    info.start = utcNow();
    info.chains = chains;
    info.rule = rule;
    info.network = network;
    info.owner = owner;
    g_state.connections[client] = std::move(info);
    return true;
}

void attachUpstream(int client, int upstream)
{
    std::lock_guard<std::mutex> guard(g_state.sessionsMutex);
    auto found = g_state.connections.find(client);
    if (found != g_state.connections.end()) found->second.upstream = upstream;
}

void recordTransfer(int client, bool upload, size_t bytes)
{
    std::lock_guard<std::mutex> guard(g_state.sessionsMutex);
    auto found = g_state.connections.find(client);
    if (found == g_state.connections.end()) return;
    if (upload) {
        found->second.upload += bytes;
        g_state.uploadTotal.fetch_add(bytes);
    } else {
        found->second.download += bytes;
        g_state.downloadTotal.fetch_add(bytes);
    }
}

bool cancelConnections(const std::string& id = "", const std::string& chain = "")
{
    std::lock_guard<std::mutex> guard(g_state.sessionsMutex);
    bool matched = false;
    for (auto& pair : g_state.connections) {
        ConnectionInfo& item = pair.second;
        if ((!id.empty() && item.id != id) || (!chain.empty() &&
            std::find(item.chains.begin(), item.chains.end(), chain) == item.chains.end())) continue;
        matched = true;
        item.cancelled = true;
        shutdown(item.client, SHUT_RDWR);
        if (item.upstream >= 0) shutdown(item.upstream, SHUT_RDWR);
        if (id.empty() && chain.empty() && item.owner >= 0) shutdown(item.owner, SHUT_RDWR);
    }
    return matched;
}

std::string trim(const std::string& value)
{
    size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
        ++start;
    }
    size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }
    std::string result = value.substr(start, end - start);
    if (result.size() >= 2 && ((result.front() == '\'' && result.back() == '\'') ||
                               (result.front() == '"' && result.back() == '"'))) {
        result = result.substr(1, result.size() - 2);
    }
    return result;
}

std::string jsonEscape(const std::string& value)
{
    std::ostringstream output;
    for (unsigned char ch : value) {
        switch (ch) {
            case '\\': output << "\\\\"; break;
            case '"': output << "\\\""; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (ch < 0x20) {
                    output << ' ';
                } else {
                    output << ch;
                }
        }
    }
    return output.str();
}

std::string lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string valueAfter(const std::string& line, const std::string& key)
{
    size_t position = line.find(key);
    if (position == std::string::npos) {
        return "";
    }
    return trim(line.substr(position + key.size()));
}

std::string yamlScalar(const std::string& value)
{
    std::string result = trim(value);
    if (result.size() >= 2 && ((result.front() == '\'' && result.back() == '\'') ||
                               (result.front() == '"' && result.back() == '"'))) {
        std::string unquoted;
        bool escaped = false;
        for (size_t i = 1; i + 1 < result.size(); ++i) {
            const char ch = result[i];
            if (escaped) {
                unquoted.push_back(ch);
                escaped = false;
            } else if (ch == '\\' && result.front() == '"') {
                escaped = true;
            } else {
                unquoted.push_back(ch);
            }
        }
        return unquoted;
    }
    return result;
}

std::vector<std::string> splitYamlMap(const std::string& value)
{
    std::vector<std::string> parts;
    size_t start = 0;
    char quote = 0;
    bool escaped = false;
    int depth = 0;
    for (size_t i = 0; i < value.size(); ++i) {
        const char ch = value[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (quote != 0) {
            if (ch == '\\' && quote == '"') escaped = true;
            else if (ch == quote) quote = 0;
            continue;
        }
        if (ch == '\'' || ch == '"') {
            quote = ch;
        } else if (ch == '{' || ch == '[') {
            ++depth;
        } else if (ch == '}' || ch == ']') {
            --depth;
        } else if (ch == ',' && depth == 0) {
            parts.push_back(trim(value.substr(start, i - start)));
            start = i + 1;
        }
    }
    if (start < value.size()) parts.push_back(trim(value.substr(start)));
    return parts;
}

ProxyNode parseInlineProxy(const std::string& line)
{
    ProxyNode node;
    const size_t open = line.find('{');
    const size_t close = line.rfind('}');
    if (open == std::string::npos || close <= open) return node;
    for (const std::string& part : splitYamlMap(line.substr(open + 1, close - open - 1))) {
        const size_t colon = part.find(':');
        if (colon == std::string::npos) continue;
        const std::string key = lower(trim(part.substr(0, colon)));
        const std::string value = yamlScalar(part.substr(colon + 1));
        if (key == "name") node.name = value;
        else if (key == "type") node.type = lower(value);
        else if (key == "server" || key == "address") node.server = value;
        else if (key == "port") node.port = std::atoi(value.c_str());
        else if (key == "cipher" || key == "method") node.cipher = lower(value);
        else if (key == "password") node.password = value;
        else if (key == "uuid") node.uuid = value;
        else if (key == "alterid" || key == "alter-id") node.alterId = std::atoi(value.c_str());
        else if (key == "tls") node.tls = lower(value) == "true";
    }
    return node;
}

std::string bodyValue(const std::string& body, const std::string& key)
{
    const std::string marker = "\"" + key + "\"";
    size_t position = body.find(marker);
    if (position == std::string::npos) {
        return "";
    }
    position = body.find(':', position + marker.size());
    if (position == std::string::npos) {
        return "";
    }
    position = body.find('"', position);
    if (position == std::string::npos) {
        return "";
    }
    ++position;
    std::string result;
    bool escaped = false;
    for (; position < body.size(); ++position) {
        char ch = body[position];
        if (escaped) {
            result.push_back(ch);
            escaped = false;
        } else if (ch == '\\') {
            escaped = true;
        } else if (ch == '"') {
            break;
        } else {
            result.push_back(ch);
        }
    }
    return result;
}

std::string urlDecode(const std::string& value)
{
    std::string result;
    for (size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '%' && i + 2 < value.size()) {
            char hex[3] = {value[i + 1], value[i + 2], '\0'};
            result.push_back(static_cast<char>(std::strtol(hex, nullptr, 16)));
            i += 2;
        } else if (value[i] == '+') {
            result.push_back(' ');
        } else {
            result.push_back(value[i]);
        }
    }
    return result;
}

std::string urlEncode(const std::string& value)
{
    static const char hex[] = "0123456789ABCDEF";
    std::ostringstream output;
    for (unsigned char ch : value) {
        if (std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~') {
            output << ch;
        } else {
            output << '%' << hex[ch >> 4] << hex[ch & 0x0F];
        }
    }
    return output.str();
}

std::string groupType(const std::string& type)
{
    const std::string normalized = lower(type);
    if (normalized == "select" || normalized == "selector") {
        return "Selector";
    }
    if (normalized == "url-test" || normalized == "urltest") {
        return "URLTest";
    }
    if (normalized == "load-balance" || normalized == "loadbalance") {
        return "LoadBalance";
    }
    if (normalized == "fallback") {
        return "Fallback";
    }
    if (normalized == "relay") {
        return "Relay";
    }
    return type.empty() ? "Selector" : type;
}

struct ParsedConfig {
    int httpPort = 7890;
    int socksPort = 7891;
    ProxyPortSettings ports;
    std::string mode = "Rule";
    int logLevel = 1;
    bool ipv6 = false;
    InboundConfig inbound;
    SnifferConfig sniffer;
    std::vector<ProxyNode> nodes;
    std::vector<ProxyProvider> providers;
    std::vector<ProxyGroup> groups;
    std::vector<ProxyRule> rules;
    std::vector<std::string> sourceRules, effectiveRules;
    std::string enhancedSource;
    std::vector<RuleProvider> ruleProviders;
    GeoConfig geo;
    std::shared_ptr<DnsConfig> dns=std::make_shared<DnsConfig>();
};

std::string yamlText(yaml_node_t* node)
{
    if (node == nullptr || node->type != YAML_SCALAR_NODE) return "";
    return std::string(reinterpret_cast<char*>(node->data.scalar.value), node->data.scalar.length);
}

yaml_node_t* yamlValue(yaml_document_t& document, yaml_node_t* map, const std::string& key)
{
    if (map == nullptr || map->type != YAML_MAPPING_NODE) return nullptr;
    for (yaml_node_pair_t* pair = map->data.mapping.pairs.start; pair < map->data.mapping.pairs.top; ++pair) {
        if (yamlText(yaml_document_get_node(&document, pair->key)) == key) {
            return yaml_document_get_node(&document, pair->value);
        }
    }
    return nullptr;
}

bool parseProxyNode(yaml_document_t& document,yaml_node_t* source,ProxyNode& node,std::string& error)
{
    auto value=[&](yaml_node_t* map,const char* key){return yamlText(yamlValue(document,map,key));};
    bool valid=true;
    do {
            node.name = value(source, "name");
            node.type = lower(value(source, "type"));
            node.server = value(source, "server");
            node.port = std::atoi(value(source, "port").c_str());
            node.cipher = lower(value(source, "cipher"));
            node.password = value(source, "password");
            node.uuid = value(source, "uuid");
            const std::string alter = value(source, "alterId");
            char* alterEnd = nullptr;
            const long alterValue = alter.empty() ? 0 : std::strtol(alter.c_str(), &alterEnd, 10);
            node.alterId = static_cast<int>(alterValue);
            if (!alter.empty() && (alterEnd == alter.c_str() || *alterEnd != '\0' || alterValue < 0 || alterValue > 65535)) {
                valid = false; error = "VMess alterId must be between 0 and 65535"; break;
            }
            node.tls = node.type == "trojan" || lower(value(source, "tls")) == "true";
            node.udp = lower(value(source, "udp")) == "true";
            node.udpConfigured=yamlValue(document,source,"udp")!=nullptr;
            const std::string network = lower(value(source, "network"));
            if (!network.empty()) node.network = network;
            node.serverName = value(source, "servername");
            if (node.serverName.empty()) node.serverName = value(source, "sni");
            node.skipCertVerify = lower(value(source, "skip-cert-verify")) == "true";
            yaml_node_t* alpn = yamlValue(document, source, "alpn");
            if (alpn != nullptr && (node.type == "trojan" || node.type == "vmess")) {
                if (alpn->type != YAML_SEQUENCE_NODE || alpn->data.sequence.items.top - alpn->data.sequence.items.start > 16) {
                    valid = false; error = "TLS ALPN must be a list of at most 16 protocol names"; break;
                }
                for (yaml_node_item_t* item = alpn->data.sequence.items.start; item < alpn->data.sequence.items.top; ++item) {
                    const std::string protocol = yamlText(yaml_document_get_node(&document, *item));
                    if (protocol.empty() || protocol.size() > 255 || protocol.find('\0') != std::string::npos) {
                        valid = false; error = "Invalid TLS ALPN protocol name"; break;
                    }
                    node.alpn.push_back(protocol);
                }
                if (!valid) break;
            }
            yaml_node_t* ws = yamlValue(document, source, "ws-opts");
            const std::string wsPath = value(ws, "path");
            if (!wsPath.empty()) node.wsPath = wsPath;
            yaml_node_t* headers = yamlValue(document, ws, "headers");
            if (headers != nullptr && headers->type == YAML_MAPPING_NODE) {
                for (yaml_node_pair_t* pair = headers->data.mapping.pairs.start; pair < headers->data.mapping.pairs.top; ++pair) {
                    node.wsHeaders[yamlText(yaml_document_get_node(&document, pair->key))] =
                        yamlText(yaml_document_get_node(&document, pair->value));
                }
            }
            if (node.type == "trojan") {
                if (yamlValue(document, source, "password") == nullptr || node.password.empty()) {
                    valid = false; error = "Trojan requires a non-empty password"; break;
                }
                for (const char* option : {"reality-opts", "shadow-tls-opts", "restls-opts", "jls-opts", "fingerprint", "name-cert-verify", "client-fingerprint", "dialer-proxy"}) {
                    yaml_node_t* configured = yamlValue(document, source, option);
                    if (configured != nullptr && (configured->type == YAML_MAPPING_NODE || !yamlText(configured).empty()))
                        node.transportError = std::string("Unsupported Trojan option: ") + option;
                }
                for (const char* option : {"smux", "ss-opts"}) {
                    if (lower(value(yamlValue(document, source, option), "enabled")) == "true")
                        node.transportError = std::string("Unsupported Trojan option: ") + option;
                }
            }
            if (node.type == "vmess") {
                std::string id;
                for (char ch : node.uuid) { if (ch != '-') id += ch; }
                if (id.size() != 32 || !std::all_of(id.begin(), id.end(), [](unsigned char ch) { return std::isxdigit(ch); })) {
                    valid = false; error = "VMess requires a valid 16-byte UUID"; break;
                }
            }
            if (node.type == "vmess" || node.type == "trojan") {
                if (node.wsPath.empty() || node.wsPath.front() != '/' || node.wsPath.find_first_of("\r\n ") != std::string::npos ||
                    node.serverName.find_first_of("\r\n") != std::string::npos) {
                    valid = false; error = "Invalid proxy transport path or server name"; break;
                }
                for (const auto& header : node.wsHeaders) {
                    if (header.first.empty() || header.first.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`|~") != std::string::npos ||
                        header.second.find_first_of("\r\n") != std::string::npos) {
                        valid = false; error = "Invalid WebSocket header"; break;
                    }
                }
                if (!valid) break;
            }
            if (node.name.empty() || node.type.empty()) {
                valid = false; error = "Proxy names and types are required, and names must be unique"; break;
            }
            if (node.type != "direct" && node.type != "reject" &&
                (node.server.empty() || node.port < 1 || node.port > 65535)) {
                valid = false; error = "Proxy server and port are required"; break;
            }
    } while(false);
    return valid;
}

bool parseProxySequence(yaml_document_t& document,yaml_node_t* sequence,std::vector<ProxyNode>& nodes,std::string& error)
{
    if(sequence==nullptr||sequence->type!=YAML_SEQUENCE_NODE){error="Provider/proxies content must be a list";return false;}
    std::set<std::string> names={"DIRECT","REJECT"};nodes.clear();
    for(yaml_node_item_t* item=sequence->data.sequence.items.start;item<sequence->data.sequence.items.top;++item) {
        ProxyNode node;
        if(!parseProxyNode(document,yaml_document_get_node(&document,*item),node,error))return false;
        if(!names.insert(node.name).second){error="Duplicate or reserved proxy name";return false;}
        nodes.push_back(std::move(node));
    }
    return true;
}

#include "provider_config.inc"
#include "rule_codec.inc"
#include "geo_codec.inc"
#include "rule_config.inc"
#include "dns_codec.inc"
#include "dns_wire.inc"
#include "dns_config.inc"
#include "geo_config.inc"
#include "object_edits.inc"
#include "config_scripts.inc"
#include "backup_codec.inc"
#include "config_merges.inc"
#include "rule_edits.inc"
#include "inbound_policy.inc"
#include "sniffer_config.inc"

bool parseConfigText(const std::string& text, ParsedConfig& config, std::string& error, const RuleEdits* edits = nullptr, const ObjectEdits* objects = nullptr, const ConfigMerges* merges = nullptr, std::vector<ScriptLog>* scriptLogs = nullptr)
{
    if (text.empty() || text.size() > 8 * 1024 * 1024) {
        error = "Configuration must be between 1 byte and 8 MB";
        return false;
    }
    yaml_parser_t parser;
    if (!yaml_parser_initialize(&parser)) { error = "Cannot allocate YAML parser"; return false; }
    yaml_parser_set_input_string(&parser, reinterpret_cast<const unsigned char*>(text.data()), text.size());
    yaml_document_t document;
    if (!yaml_parser_load(&parser, &document)) {
        error = "YAML line " + std::to_string(parser.problem_mark.line + 1) + ": " +
            (parser.problem == nullptr ? "invalid syntax" : parser.problem);
        yaml_parser_delete(&parser);
        return false;
    }
    yaml_node_t* root = yaml_document_get_root_node(&document);
    bool valid = root != nullptr && root->type == YAML_MAPPING_NODE;
    if (!valid) error = "Configuration root must be a mapping";
    if (valid && merges && !merges->sequence.empty()) {
        valid = scriptTagScalars(document, text, error) && applyBackupSequence(document, merges->sequence, error);
        if (valid) valid = scriptDocumentText(document, config.enhancedSource, error);
    }
    if (valid) valid = applyConfigMerges(document, merges, error, config.enhancedSource.empty() ? text : config.enhancedSource, scriptLogs);
    if (valid && merges && (!merges->sequence.empty() || !merges->globalScript.empty() || !merges->profileScript.empty())) valid = scriptDocumentText(document, config.enhancedSource, error);
    if (valid) valid = applyObjectEdits(document, objects, error);
    root = yaml_document_get_root_node(&document);
    if (valid) valid = parseInboundConfig(document, root, config.inbound, error);
    if (valid) valid = parseSnifferConfig(document, yamlValue(document, root, "sniffer"), config.sniffer, error);
    auto value = [&](yaml_node_t* node, const char* key) { return yamlText(yamlValue(document, node, key)); };
    auto portValue = [&](const char* key, int& destination) {
        auto* node = yamlValue(document, root, key);
        if (node && node->type != YAML_SCALAR_NODE) { valid = false; error = std::string(key) + " must be an integer"; return; }
        const std::string raw = value(root, key);
        if (raw.empty()) return;
        char* end = nullptr;
        const long port = std::strtol(raw.c_str(), &end, 10);
        if (end == raw.c_str() || *end != '\0' || port < 0 || port > 65535) {
            valid = false; error = std::string(key) + " must be between 0 and 65535";
        } else destination = static_cast<int>(port);
    };
    if (valid) {
        portValue("port", config.ports.http);
        portValue("socks-port", config.ports.socks);
        portValue("mixed-port", config.ports.mixed);
        config.httpPort = config.ports.effectiveHttp();
        config.socksPort = config.ports.effectiveSocks();
        const std::string mode = lower(value(root, "mode"));
        if (mode == "global") config.mode = "Global";
        else if (mode == "direct") config.mode = "Direct";
        else if (!mode.empty() && mode != "rule") { valid = false; error = "Unsupported proxy mode"; }
        const std::string log = lower(value(root, "log-level"));
        for (const char* key : {"mode", "log-level", "ipv6"}) {
            auto* node = yamlValue(document, root, key);
            if (node && node->type != YAML_SCALAR_NODE) { valid = false; error = std::string(key) + " must be a scalar"; }
        }
        if (log == "debug") config.logLevel = 0;
        else if (log.empty() || log == "info") config.logLevel = 1;
        else if (log == "warning" || log == "warn") config.logLevel = 2;
        else if (log == "error") config.logLevel = 3;
        else if (log == "silent") config.logLevel = 4;
        else { valid = false; error = "Unsupported log-level"; }
        const std::string ipv6 = lower(value(root, "ipv6"));
        if (ipv6 == "true") config.ipv6 = true;
        else if (!ipv6.empty() && ipv6 != "false") { valid = false; error = "ipv6 must be true or false"; }
    }
    std::set<std::string> names = {"DIRECT", "REJECT"};
    yaml_node_t* nodes = yamlValue(document, root, "proxies");
    if (nodes != nullptr && nodes->type != YAML_SEQUENCE_NODE) { valid = false; error = "proxies must be a list"; }
    if(valid&&nodes!=nullptr) {
        valid=parseProxySequence(document,nodes,config.nodes,error);
        for(const ProxyNode& node:config.nodes)if(!names.insert(node.name).second){valid=false;error="Duplicate proxy name";break;}
    }
    if(valid&&!parseProviderDefinitions(document,root,config.providers,error))valid=false;
    if(valid&&!parseRuleDefinitions(document,root,config.ruleProviders,error))valid=false;
    yaml_node_t* groups = yamlValue(document, root, "proxy-groups");
    if (groups != nullptr && groups->type != YAML_SEQUENCE_NODE) { valid = false; error = "proxy-groups must be a list"; }
    if (valid && groups != nullptr) {
        for (yaml_node_item_t* item = groups->data.sequence.items.start; item < groups->data.sequence.items.top; ++item) {
            yaml_node_t* source = yaml_document_get_node(&document, *item);
            ProxyGroup group;
            group.name = value(source, "name");
            group.type = groupType(value(source, "type"));
            const std::string probeUrl=value(source,"url");if(!probeUrl.empty())group.url=probeUrl;
            const std::string expected=value(source,"expected-status");if(!expected.empty())group.expectedStatus=expected;
            auto integer=[&](const char* field,int& output,int minimum,int maximum) {
                const std::string raw=value(source,field);if(raw.empty())return true;
                char* end=nullptr;const long parsed=std::strtol(raw.c_str(),&end,10);
                if(end==raw.c_str()||*end!='\0'||parsed<minimum||parsed>maximum)return false;
                output=static_cast<int>(parsed);return true;
            };
            if(!integer("interval",group.interval,0,604800)||!integer("timeout",group.timeout,100,60000)||!integer("tolerance",group.tolerance,0,60000)) {
                valid=false;error="Invalid proxy-group health check interval, timeout or tolerance";break;
            }
            const std::string lazy=lower(value(source,"lazy"));group.lazy=lazy!="false";
            group.disableUdp=lower(value(source,"disable-udp"))=="true";
            if(group.type=="LoadBalance") {
                const std::string strategy=lower(value(source,"strategy"));
                if(!strategy.empty())group.strategy=strategy;
                if(group.strategy!="round-robin"&&group.strategy!="consistent-hashing"&&group.strategy!="sticky-sessions") {
                    valid=false;error="Unsupported load-balance strategy";break;
                }
                if(!value(source,"hash-key").empty()) {valid=false;error="Load-balance hash-key is not implemented by this core";break;}
                if(!value(source,"default-selected").empty()) {valid=false;error="Load-balance groups cannot pin default-selected";break;}
            }
            if((group.type=="URLTest"||group.type=="Fallback"||group.type=="LoadBalance")&&(!validProbeUrl(group.url)||!validProbeStatus(group.expectedStatus))) {
                valid=false;error="Invalid proxy-group HTTP(S) URL or expected-status";break;
            }
            if (group.name.empty() || !names.insert(group.name).second) {
                valid = false; error = "Proxy group names must be non-empty and unique"; break;
            }
            yaml_node_t* candidates = yamlValue(document, source, "proxies");
            if (candidates != nullptr && candidates->type != YAML_SEQUENCE_NODE) {
                valid = false; error = "Group proxies must be a list"; break;
            }
            if (candidates != nullptr) {
                for (yaml_node_item_t* child = candidates->data.sequence.items.start; child < candidates->data.sequence.items.top; ++child) {
                    const std::string name = yamlText(yaml_document_get_node(&document, *child));
                    if (!name.empty()) group.proxies.push_back(name);
                }
            }
            group.configuredProxies=group.proxies;
            yaml_node_t* uses=yamlValue(document,source,"use");
            if(uses!=nullptr) {
                if(uses->type!=YAML_SEQUENCE_NODE){valid=false;error="Group use must be a list";break;}
                for(yaml_node_item_t* child=uses->data.sequence.items.start;child<uses->data.sequence.items.top;++child) {
                    const std::string provider=yamlText(yaml_document_get_node(&document,*child));
                    if(std::none_of(config.providers.begin(),config.providers.end(),[&](const ProxyProvider& item){return item.name==provider;})) {
                        valid=false;error="Unknown provider in proxy group";break;
                    }
                    group.providers.push_back(provider);
                }
                if(!valid)break;
            }
            group.includeAllProxies=lower(value(source,"include-all-proxies"))=="true"||lower(value(source,"include-all"))=="true";
            group.includeAllProviders=lower(value(source,"include-all-providers"))=="true"||lower(value(source,"include-all"))=="true";
            group.filter=value(source,"filter");group.excludeFilter=value(source,"exclude-filter");
            if(!validProviderPattern(group.filter)||!validProviderPattern(group.excludeFilter)){valid=false;error="Invalid proxy-group filter";break;}
            if (!group.proxies.empty()&&group.type!="LoadBalance") group.now = group.proxies.front();
            const std::string initial=value(source,"default-selected");group.pendingSelection=initial;
            if(std::find(group.proxies.begin(),group.proxies.end(),initial)!=group.proxies.end())group.now=initial;
            config.groups.push_back(std::move(group));
        }
    }
    if(valid)for(const ProxyProvider& provider:config.providers)for(const ProxyNode& node:provider.nodes) {
        if(!names.insert(node.name).second){valid=false;error="Provider proxy name conflicts with another proxy or group";break;}
    }
    if (valid) {
        for (const ProxyGroup& group : config.groups) {
            for (const std::string& name : group.proxies) {
                if (names.count(name) == 0) { valid = false; error = "Unknown proxy or group in " + group.name; break; }
            }
            if (!valid) break;
        }
    }
    if (valid && ((objects && (!objects->groups.prepend.empty() || !objects->groups.append.empty())) || (merges && (!merges->sequence.empty() || !merges->global.empty() || !merges->profile.empty() || !merges->globalScript.empty() || !merges->profileScript.empty())))) {
        std::map<std::string, const ProxyGroup*> groups;
        for (const auto& group : config.groups) groups[group.name] = &group;
        std::map<std::string, int> visited, height;
        std::function<bool(const std::string&, int)> visit = [&](const std::string& name, int depth) {
            if (depth >= 16 || visited[name] == 1) return false;
            if (visited[name] == 2) return depth + height[name] <= 16;
            visited[name] = 1;
            height[name] = 1;
            for (const auto& member : groups[name]->proxies) if (groups.count(member)) {
                if (!visit(member, depth + 1)) return false;
                height[name] = std::max(height[name], 1 + height[member]);
            }
            if (depth + height[name] > 16) return false;
            visited[name] = 2; return true;
        };
        for (const auto& group : groups) if (!visit(group.first, 0)) { valid = false; error = "Proxy groups contain a circular reference or exceed 16 levels"; break; }
        for (const auto& group : config.groups) if (valid && group.proxies.empty() && group.providers.empty() && !group.includeAllProxies && !group.includeAllProviders) {
            valid = false; error = "A proxy group requires members, providers or include-all";
        }
    }
    if(valid)for(const ProxyProvider& provider:config.providers)if(names.count(provider.downloadProxy)==0){valid=false;error="Unknown download proxy for provider";break;}
    if(valid)for(const RuleProvider& provider:config.ruleProviders)if(names.count(provider.downloadProxy)==0){valid=false;error="Unknown download proxy for rule provider";break;}
    yaml_node_t* rules = yamlValue(document, root, "rules");
    if (rules != nullptr && rules->type != YAML_SEQUENCE_NODE) { valid = false; error = "rules must be a list"; }
    if (valid && rules != nullptr) {
        for (yaml_node_item_t* item = rules->data.sequence.items.start; item < rules->data.sequence.items.top; ++item) {
            yaml_node_t* node = yaml_document_get_node(&document, *item);
            if (!node || node->type != YAML_SCALAR_NODE) { valid = false; error = "rules must contain strings"; break; }
            config.sourceRules.push_back(yamlText(node));
        }
    }
    config.effectiveRules = applyRuleEdits(config.sourceRules, edits);
    if (valid) {
        for (const std::string& rawRule : config.effectiveRules) {
            const std::vector<std::string> fields = splitRuleFields(rawRule);
            if (fields.size() < 2) { valid = false; error = "Invalid routing rule"; break; }
            ProxyRule rule;
            rule.kind = lower(trim(fields[0]));
            if(rule.kind=="geoip"||rule.kind=="src-geoip"||rule.kind=="geosite"||rule.kind=="ip-asn"||rule.kind=="src-ip-asn"||rule.kind=="rule-set"||rule.kind=="and"||rule.kind=="or"||rule.kind=="not"||rule.kind=="domain-wildcard"||rule.kind=="domain-regex"||rule.kind=="src-ip-cidr"||rule.kind=="src-ip-cidr6"||
                rule.kind=="domain"||rule.kind=="domain-suffix"||rule.kind=="domain-keyword"||rule.kind=="ip-cidr"||rule.kind=="ip-cidr6"||rule.kind=="dst-port"||rule.kind=="network"||rule.kind=="match"||rule.kind=="final") {
                if(!parseRuleExpression(rawRule,rule,false,error)){valid=false;break;}
            } else {
            if (rule.kind == "final") rule.kind = "match";
            rule.value = rule.kind == "match" ? "" : trim(fields[1]);
            rule.target = trim(fields[rule.kind == "match" ? 1 : std::min<size_t>(2, fields.size() - 1)]);
            rule.noResolve=lower(fields.back())=="no-resolve";
            }
            if (names.count(rule.target) == 0) {
                valid = false;
                error = "Rule " + std::to_string(config.rules.size() + 1) + " refers to unknown target: " + rule.target;
                break;
            }
            config.rules.push_back(std::move(rule));
        }
    }
    if(valid) {
        valid=parseDnsConfig(document,root,*config.dns,error)&&parseGeoConfig(document,root,config.geo,error);
        if(valid)for(const auto* policies:{&config.dns->policies,&config.dns->proxyPolicies})for(const auto& policy:*policies)
            if(policy.expression.rfind("rule-set:",0)==0&&std::none_of(config.ruleProviders.begin(),config.ruleProviders.end(),[&](const auto& provider){return provider.name==policy.expression.substr(9);})) {
                valid=false;error="DNS policy references an unknown rule provider";
            }
    }
    if(valid) {
        std::function<bool(const ProxyRule&)> references=[&](const ProxyRule& rule) {
            if(rule.kind=="rule-set"&&std::none_of(config.ruleProviders.begin(),config.ruleProviders.end(),[&](const auto& provider){return provider.name==rule.value;})){error="Unknown rule provider: "+rule.value;return false;}
            for(const auto& child:rule.conditions)if(!references(child))return false;return true;
        };
        for(const auto& rule:config.rules)if(!references(rule)){valid=false;break;}
    }
    yaml_document_delete(&document);
    if (valid) {
        yaml_document_t extra;
        if (!yaml_parser_load(&parser, &extra)) {
            valid = false; error = "Invalid trailing YAML document";
        } else {
            if (yaml_document_get_root_node(&extra) != nullptr) { valid = false; error = "Only one configuration document is supported"; }
            yaml_document_delete(&extra);
        }
    }
    yaml_parser_delete(&parser);
    return valid;
}

std::string ruleEditorJson(const std::string& source, const std::string& settings, bool render = false, const std::string& objectSettings = "", const std::string& mergeSettings = "")
{
    RuleEdits edits; ObjectEdits objects; ConfigMerges merges; ParsedConfig parsed; std::string error; std::vector<ScriptLog> logs;
    if (!parseRuleEdits(settings, edits, error) || !parseObjectEdits(objectSettings, objects, error) || !parseConfigMerges(mergeSettings, merges, error) || !parseConfigText(source, parsed, error, &edits, &objects, &merges, &logs))
        return "{\"error\":\"" + jsonEscape(error) + "\",\"scriptLogs\":" + scriptLogsJson(logs) + "}";
    // Custom additions use the supported expression parser, including target/provider validation above.
    for (const auto* list : {&edits.prepend, &edits.append}) for (const auto& raw : *list) {
        ProxyRule rule;
        if (!parseRuleExpression(raw, rule, false, error)) return "{\"error\":\"" + jsonEscape(error) + "\"}";
    }
    std::vector<std::string> policies = {"DIRECT", "REJECT"}, providers;
    for (const auto& node : parsed.nodes) policies.push_back(node.name);
    for (const auto& group : parsed.groups) policies.push_back(group.name);
    for (const auto& provider : parsed.providers) for (const auto& node : provider.nodes) policies.push_back(node.name);
    for (const auto& provider : parsed.ruleProviders) providers.push_back(provider.name);
    std::string output = "{\"error\":\"\",\"rules\":" + ruleStringsJson(parsed.sourceRules) +
        ",\"policies\":" + ruleStringsJson(policies) + ",\"providers\":" + ruleStringsJson(providers) +
        ",\"effective\":" + ruleStringsJson(parsed.effectiveRules) + ",\"scriptLogs\":" + scriptLogsJson(logs);
    if (render) {
        std::string text;
        if (!renderEditedRules(parsed.enhancedSource.empty() ? source : parsed.enhancedSource, parsed.effectiveRules, text, &objects, parsed.enhancedSource.empty() ? &merges : nullptr)) return "{\"error\":\"Cannot export custom configuration\"}";
        output += ",\"content\":\"" + jsonEscape(text) + "\"";
    }
    return output + "}";
}

#include "object_editor.inc"
#include "share_links.inc"

#include "port_settings.inc"
#include "controller_config_store.inc"
#include "inbound_settings.inc"
#include "sniffer_control.inc"

void persistSelectionsLocked()
{
    if (g_state.configPath.empty()) return;
    const std::string path = g_state.configPath + ".selections";
    const std::string temporary = path + ".tmp";
    std::ofstream output(temporary, std::ios::trunc);
    if (!output.good()) return;
    for (const ProxyGroup& group : g_state.groups) {
        if(group.type=="LoadBalance")continue;
        const std::string selected=(group.type=="URLTest"||group.type=="Fallback") ? group.manual:group.now;
        if(!selected.empty())output << std::quoted(group.name) << ' ' << std::quoted(selected) << '\n';
    }
    output.close();
    std::rename(temporary.c_str(), path.c_str());
}

bool loadConfigLocked(const std::string& path, std::string& error, bool force = true,
    const std::string* payload = nullptr, const std::string& origin = "")
{
    std::string text, configOrigin = origin, temporary;
    const bool transient = !g_state.runtimeDirectory.empty() && path == runtimeConfigPathLocked();
    if (payload) text = *payload;
    else if (!readControllerFile(path, (transient ? 16 : 8) * 1024 * 1024, text, error)) return false;
    if (transient && !payload && !readRuntimeEnvelope(text, text, configOrigin, error)) return false;
    ParsedConfig parsed;
    RuleEdits edits; ObjectEdits objects; ConfigMerges merges; std::vector<ScriptLog> scriptLogs;
    if (!transient && (!readRuleEdits(path, edits, error) || !readObjectEdits(path, objects, error) || !readConfigMerges(path, merges, error))) return false;
    if (!parseConfigText(text, parsed, error, &edits, &objects, &merges, &scriptLogs)) return false;
    ProxyPortSettings ports = parsed.ports;
    if (!transient && !readProxyPortSettings(path, ports, error)) return false;
    InboundConfig inbound = parsed.inbound;
    bool inboundOverridden = false;
    if (!transient && !readInboundSettings(path, inbound, inboundOverridden, error)) return false;
    if (!force) {
        ports = g_state.portSettings;
        const auto users = inbound.users;
        inbound = g_state.inbound; inbound.users = users;
        inboundOverridden = g_state.inboundOverridden;
    }
    std::shared_ptr<DnsListener> dnsListener;
    if(g_state.running.load()&&!prepareDnsListener(parsed.dns,dnsListener,error))return false;
    if (payload && !stageRuntimeEnvelope(path, text, configOrigin, temporary, error)) return false;
    const auto commit = [&]() {
        if (temporary.empty()) return true;
        if (rename(temporary.c_str(), path.c_str()) == 0) return true;
        error = "Cannot commit temporary configuration; previous configuration has been preserved"; return false;
    };
    const bool applied = g_state.running.load() ? configureProxyListenersLocked(ports.effectiveHttp(), ports.effectiveSocks(), error, commit, &inbound) : commit();
    if (!temporary.empty()) unlink(temporary.c_str());
    if (!applied) return false;
    g_state.configRevision++;
    g_state.profileEpoch++;
    g_state.logLevel.store(parsed.logLevel);
    g_state.ipv6.store(parsed.ipv6);
    for (const auto& log : scriptLogs) coreLog(log.level, "[" + log.scope + " script] " + log.text);
    g_state.delays.clear();
    // Parsing finishes before replacing state, so invalid imports preserve the working configuration.
    g_state.configPath = path;
    g_state.configOrigin = transient ? configOrigin : path;
    g_state.temporaryConfig = transient;
    g_state.proxyNames.clear();
    g_state.localNodes=std::move(parsed.nodes);
    g_state.providers=std::move(parsed.providers);
    g_state.groups = std::move(parsed.groups);
    g_state.rules = std::move(parsed.rules);
    g_state.ruleProviders = std::move(parsed.ruleProviders);
    g_state.geo=std::move(parsed.geo);
    g_state.dns=std::move(parsed.dns);
    if(g_state.running.load())replaceDnsListenerLocked(dnsListener);
    g_state.ruleCount = static_cast<int>(g_state.rules.size());
    g_state.profilePorts = parsed.ports; g_state.portSettings = ports;
    g_state.profileInbound = parsed.inbound; g_state.inbound = std::move(inbound); g_state.inboundOverridden = inboundOverridden;
    g_state.sniffer = std::make_shared<SnifferConfig>(std::move(parsed.sniffer));
    g_state.httpPort = ports.effectiveHttp();
    g_state.socksPort = ports.effectiveSocks();
    g_state.mode = parsed.mode;
    initializeProvidersLocked();
    initializeRuleProvidersLocked();
    initializeGeoLocked();
    rebuildProviderNodesLocked();
    std::ifstream selections(path + ".selections");
    std::string name, selected;
    while (selections >> std::quoted(name) >> std::quoted(selected)) {
        for (ProxyGroup& group : g_state.groups) {
            if(group.name==name&&group.type!="LoadBalance") {
                group.pendingSelection=selected;group.pendingManual=true;
                if(std::find(group.proxies.begin(),group.proxies.end(),selected)!=group.proxies.end()) {
                    group.now=selected;if(group.type=="URLTest"||group.type=="Fallback")group.manual=selected;group.pendingSelection.clear();
                }
            }
        }
    }
    if (!transient && !g_state.runtimeDirectory.empty()) {
        const std::string previous = runtimeConfigPathLocked();
        unlink(previous.c_str()); unlink((previous + ".selections").c_str());
    }
    wakeHealthChecks();
    return true;
}

bool supportsVmess(const ProxyNode& node)
{
    return node.type == "vmess" && (node.network == "tcp" || node.network == "ws") &&
        (node.cipher.empty() || node.cipher == "auto" || node.cipher == "aes-128-gcm" ||
         node.cipher == "chacha20-poly1305" || node.cipher == "none" || node.cipher == "zero");
}
bool supportsTrojan(const ProxyNode& node)
{
    return node.type == "trojan" && (node.network == "tcp" || node.network == "ws") && !node.password.empty() &&
        node.transportError.empty() && (node.network != "ws" || node.alpn.empty() ||
        std::find(node.alpn.begin(), node.alpn.end(), "http/1.1") != node.alpn.end());
}
bool supportsUdp(const ProxyNode& node)
{
    return (node.type == "direct"&&(!node.udpConfigured||node.udp)) || (node.udp && ((node.type == "ss" && shadowsocksCipher(node.cipher)!=SsCipher::Unsupported) || supportsVmess(node) || supportsTrojan(node)));
}

std::string proxyNodeJsonLocked(const ProxyNode& node)
{
    const std::string type = node.type == "ss" ? "Shadowsocks" : node.type == "vmess" ? "VMess" :
        node.type == "trojan" ? "Trojan" : node.type == "direct" ? "DIRECT" : node.type == "reject" ? "REJECT" : node.type;
    std::ostringstream output;
    output << "{\"name\":\"" << jsonEscape(node.name) << "\",\"type\":\"" << jsonEscape(type)
        << "\",\"udp\":" << (supportsUdp(node) ? "true" : "false");
    if (!node.provider.empty()) output << ",\"provider-name\":\"" << jsonEscape(node.provider) << '"';
    const auto delay = g_state.delays.find(node.name);
    if (delay != g_state.delays.end()) output << ",\"alive\":" << (delay->second > 0 ? "true" : "false")
        << ",\"history\":[{\"delay\":" << delay->second << "}]";
    else output << ",\"history\":[]";
    output << '}';
    return output.str();
}

bool proxyUdpLocked(const std::string& name, std::set<std::string> seen = {})
{
    if (name == "DIRECT") return true;
    if (name == "REJECT") return false;
    if (!seen.insert(name).second || seen.size() > 32) return false;
    for (const auto& node : g_state.nodes) if (node.name == name) return supportsUdp(node);
    for (const auto& group : g_state.groups) if (group.name == name && !group.disableUdp) {
        if (group.type != "LoadBalance") return proxyUdpLocked(group.now, seen);
        return !group.proxies.empty() && std::all_of(group.proxies.begin(), group.proxies.end(),
            [&](const std::string& member) { return proxyUdpLocked(member, seen); });
    }
    return false;
}

std::string proxyGroupJsonLocked(const ProxyGroup& group)
{
    std::ostringstream output;
    output << "{\"name\":\"" << jsonEscape(group.name) << "\",\"type\":\"" << jsonEscape(group.type)
        << "\",\"now\":\"" << jsonEscape(group.now) << "\",\"all\":[";
    for (size_t i = 0; i < group.proxies.size(); ++i) {
        if (i) output << ',';
        output << '"' << jsonEscape(group.proxies[i]) << '"';
    }
    output << "],\"udp\":" << (proxyUdpLocked(group.name) ? "true" : "false")
        << ",\"history\":[],\"checking\":" << (group.checking ? "true" : "false") << ",\"manual\":\"" << jsonEscape(group.manual)
        << "\",\"url\":\"" << jsonEscape(group.url) << "\",\"testUrl\":\"" << jsonEscape(group.url) << '"';
    if (group.type == "LoadBalance") output << ",\"strategy\":\"" << group.strategy
        << "\",\"lastSelected\":\"" << jsonEscape(group.lastSelected) << '"';
    output << '}';
    return output.str();
}

bool decodeProxyPath(std::string raw, std::string& name)
{
    if (!raw.empty() && raw.back() == '/') raw.pop_back();
    if (raw.empty() || raw.find('/') != std::string::npos) return false;
    name.clear();
    auto hex = [](unsigned char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        return -1;
    };
    for (size_t i = 0; i < raw.size(); ++i) {
        unsigned char ch = raw[i];
        if (ch == '%') {
            if (i + 2 >= raw.size() || hex(raw[i+1]) < 0 || hex(raw[i+2]) < 0) return false;
            ch = static_cast<unsigned char>((hex(raw[i+1]) << 4) | hex(raw[i+2])); i += 2;
        }
        if (ch < 0x20 || ch == 0x7f) return false;
        name += static_cast<char>(ch); // '+' is literal in a URL path, unlike a query.
    }
    return true;
}

bool proxySelectionName(const std::string& body, std::string& name)
{
    if (body.size() > 65536) return false;
    std::unique_ptr<JSRuntime, decltype(&JS_FreeRuntime)> runtime(JS_NewRuntime(), JS_FreeRuntime);
    if (!runtime) return false;
    JS_SetMemoryLimit(runtime.get(), 4 * 1024 * 1024); JS_SetMaxStackSize(runtime.get(), 128 * 1024);
    std::unique_ptr<JSContext, decltype(&JS_FreeContext)> context(JS_NewContext(runtime.get()), JS_FreeContext);
    if (!context) return false;
    JSValue value = JS_ParseJSON(context.get(), body.data(), body.size(), "controller.json");
    bool valid = false;
    if (JS_IsObject(value) && JS_IsArray(context.get(), value) == 0) {
        JSValue selected = JS_GetPropertyStr(context.get(), value, "name");
        if (JS_IsString(selected)) {
            size_t length = 0; const char* bytes = JS_ToCStringLen(context.get(), &length, selected);
            if (bytes) { name.assign(bytes, length); JS_FreeCString(context.get(), bytes); valid = !name.empty(); }
        }
        JS_FreeValue(context.get(), selected);
    }
    JS_FreeValue(context.get(), value);
    return valid;
}

std::string proxiesJson()
{
    std::ostringstream output;
    output << "{\"proxies\":{";
    bool first = true;
    auto append = [&](const std::string& name, const std::string& value) {
        if (!first) output << ',';
        first = false;
        output << '"' << jsonEscape(name) << "\":" << value;
    };
    for (const char* name : {"DIRECT", "REJECT"}) {
        ProxyNode builtin; builtin.name = name; builtin.type = builtin.name == "DIRECT" ? "direct" : "reject";
        append(name, proxyNodeJsonLocked(builtin));
    }
    for (const ProxyNode& node : g_state.nodes) {
        append(node.name, proxyNodeJsonLocked(node));
    }
    for (const ProxyGroup& group : g_state.groups) {
        append(group.name, proxyGroupJsonLocked(group));
    }
    output << "}}";
    return output.str();
}

std::string rulesJson()
{
    std::ostringstream output;
    output << "{\"rules\":[";
    for (size_t i = 0; i < g_state.rules.size(); ++i) {
        if (i > 0) output << ',';
        const ProxyRule& rule = g_state.rules[i];
        output << "{\"type\":\"" << jsonEscape(rule.kind) << "\",\"payload\":\"" << jsonEscape(rule.value)
            << "\",\"proxy\":\"" << jsonEscape(rule.target) << "\",\"noResolve\":" << (rule.noResolve?"true":"false") << "}";
    }
    output << "]}";
    return output.str();
}

#include "controller_state.inc"

std::string connectionsJson()
{
    uint64_t memory = 0; controllerMemoryBytes(memory);
    std::lock_guard<std::mutex> guard(g_state.sessionsMutex);
    std::ostringstream output;
    output << "{\"downloadTotal\":" << g_state.downloadTotal.load() << ",\"uploadTotal\":" << g_state.uploadTotal.load() << ",\"connections\":[";
    bool first = true;
    for (const auto& pair : g_state.connections) {
        const ConnectionInfo& item = pair.second;
        if (!first) output << ',';
        first = false;
        output << "{\"id\":\"" << item.id << "\",\"metadata\":{\"network\":\"" << item.network << "\",\"host\":\"" << jsonEscape(item.host)
            << "\",\"destinationPort\":\"" << item.port << "\",\"sourceIP\":\"127.0.0.1\"},\"start\":\"" << item.start
            << "\",\"upload\":" << item.upload << ",\"download\":" << item.download << ",\"rule\":\"" << jsonEscape(item.rule) << "\",\"chains\":[";
        for (size_t i = 0; i < item.chains.size(); ++i) {
            if (i > 0) output << ',';
            output << '"' << jsonEscape(item.chains[i]) << '"';
        }
        output << "]}";
    }
    output << "],\"memory\":" << memory << "}";
    return output.str();
}

std::string queryValue(const std::string& path, const std::string& key)
{
    const size_t question = path.find('?');
    if (question == std::string::npos) return "";
    size_t start = question + 1;
    while (start < path.size()) {
        const size_t end = path.find('&', start);
        const std::string part = path.substr(start, end == std::string::npos ? std::string::npos : end - start);
        const size_t equal = part.find('=');
        if (equal != std::string::npos && part.substr(0, equal) == key) return urlDecode(part.substr(equal + 1));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return "";
}

std::string logsJson(uint64_t since)
{
    std::lock_guard<std::mutex> guard(g_state.sessionsMutex);
    std::ostringstream output;
    output << "{\"logs\":[";
    bool first = true;
    for (const CoreLog& log : g_state.logs) {
        if (log.id <= since) continue;
        if (!first) output << ',';
        first = false;
        output << "{\"id\":" << log.id << ",\"time\":\"" << log.time << "\",\"type\":\"" << log.type << "\",\"payload\":\"" << jsonEscape(log.payload) << "\"}";
    }
    output << "]}";
    return output.str();
}

#include "controller_configs.inc"

std::string diagnosticsJson();

std::string responseFor(const std::string& method, const std::string& path, const std::string& body)
{
    if(path.rfind("/clahsos/geodata",0)==0)return geoControl(method,path,body);
    if(method=="GET"&&path.rfind("/dns/query?",0)==0)return dnsQueryResponse(path);
    if(method=="GET"&&path=="/clahsos/dns")return dnsStatusJson();
    if(method=="DELETE"&&path=="/clahsos/dns/cache") {
        std::shared_ptr<DnsConfig> config;{std::lock_guard<std::mutex> lock(g_state.mutex);config=g_state.dns;}
        std::lock_guard<std::mutex> lock(config->cacheMutex);config->cache.clear();++config->cacheGeneration;return "{}";
    }
    std::lock_guard<std::mutex> guard(g_state.mutex);
    if (path.substr(0, path.find('?')) == "/clashos/ports") return proxyPortsControlLocked(method, path, body);
    if (path.substr(0, path.find('?')) == "/clashos/inbound") return inboundControlLocked(method, path, body);
    if (method == "GET" && path == "/version") {
        return "{\"version\":\"ClashOS Core 0.27 native\",\"instance\":\"" + jsonEscape(g_state.instance) +
            "\",\"premium\":false,\"meta\":true,\"features\":[\"direct\",\"shadowsocks-aes-128-gcm\",\"shadowsocks-aes-256-gcm\",\"shadowsocks-chacha20-ietf-poly1305\",\"vmess\",\"trojan\",\"tls\",\"websocket\",\"udp\",\"rules\",\"connections\",\"controller-auth\",\"lan\",\"proxy-auth\",\"inbound-acl\",\"sniffer-http\",\"sniffer-tls\",\"sniffer-quic\",\"proxy-details\",\"traffic-http\",\"traffic-ws\",\"memory-http\",\"memory-ws\",\"logs-http\",\"logs-ws\",\"connections-ws\",\"delay\",\"https-delay\",\"url-test\",\"fallback\",\"proxy-providers\",\"rule-providers\",\"rule-set\",\"mrs\",\"dns\",\"dns-query\",\"dns-listener\",\"dns-proxy-udp\",\"load-balance\",\"geoip\",\"geosite\",\"ip-asn\",\"geodata\",\"re2\"]}";
    }
    if (method == "GET" && path == "/clahsos/diagnostics") return diagnosticsJson();
    const std::string resource=path.substr(0,path.find('?'));
    if((method=="PUT"||method=="DELETE")&&resource.rfind("/clahsos/providers/",0)==0&&resource.size()>24&&resource.substr(resource.size()-5)=="/file") {
        if(queryValue(path,"profile")!=g_state.configPath)return "{\"error\":\"Active profile changed; select the provider again\"}";
        const std::string name=urlDecode(resource.substr(19,resource.size()-24));
        return method=="PUT"?importProviderFileLocked(name,body):resetProviderFileLocked(name);
    }
    if(method=="GET"&&path=="/providers/proxies")return providersJsonLocked();
    if(path.rfind("/providers/proxies/",0)==0) {
        const std::string rest=path.substr(19);const size_t slash=rest.find('/');
        const std::string name=urlDecode(rest.substr(0,slash));
        for(ProxyProvider& provider:g_state.providers)if(provider.name==name) {
            if(method=="GET"&&slash==std::string::npos)return providersJsonLocked(name);
            if(method=="PUT"&&slash==std::string::npos) {
                if(provider.type=="inline")return "{\"error\":\"Edit the configuration to change an inline provider\"}";
                provider.forceUpdate=true;wakeHealthChecks();return "{}";
            }
            if(method=="GET"&&slash!=std::string::npos&&rest.substr(slash+1)=="healthcheck") {
                provider.health.forceCheck=true;provider.health.lastUsed=HealthClock::now();wakeHealthChecks();return "{}";
            }
            if(method=="GET"&&slash!=std::string::npos) {
                const std::string node=urlDecode(rest.substr(slash+1));
                for(const ProxyNode& item:provider.nodes)if(item.name==node)return providerNodeJsonLocked(item);
            }
            return "{\"error\":\"Provider operation or member not found\"}";
        }
        return "{\"error\":\"Proxy provider not found\"}";
    }
    if (method == "GET" && path == "/proxies") {
        return proxiesJson();
    }
    if (method == "GET" && resource.rfind("/proxies/", 0) == 0) {
        std::string name;
        if (!decodeProxyPath(resource.substr(9), name)) return "{\"error\":\"Invalid proxy path\"}";
        if (name == "DIRECT" || name == "REJECT") {
            ProxyNode builtin; builtin.name = name; builtin.type = name == "DIRECT" ? "direct" : "reject";
            return proxyNodeJsonLocked(builtin);
        }
        for (const auto& node : g_state.nodes) if (node.name == name) return proxyNodeJsonLocked(node);
        for (const auto& group : g_state.groups) if (group.name == name) return proxyGroupJsonLocked(group);
        return "{\"error\":\"Proxy not found\"}";
    }
    if(path=="/providers/rules")return ruleProviderControlLocked(method,"/providers/rules/",body);
    if(path.rfind("/providers/rules/",0)==0||path.rfind("/clahsos/rule-providers/",0)==0)return ruleProviderControlLocked(method,path,body);
    if (resource == "/configs" || resource == "/configs/") return controllerConfigsLocked(method, path, body);
    if (method == "GET" && resource == "/connections") {
        return connectionsJson();
    }
    if (method == "DELETE" && (path == "/connections" || path.rfind("/connections/", 0) == 0)) {
        cancelConnections(path == "/connections" ? "" : urlDecode(path.substr(13)));
        return "{}";
    }
    if (method == "GET" && path.rfind("/clahsos/logs", 0) == 0) {
        const std::string since = queryValue(path, "since");
        return logsJson(std::strtoull(since.c_str(), nullptr, 10));
    }
    if (method == "GET" && path == "/rules") {
        return rulesJson();
    }
    if (method == "PUT" && resource.rfind("/proxies/", 0) == 0) {
        std::string groupName, proxy;
        if (!decodeProxyPath(resource.substr(9), groupName)) return "{\"error\":\"Invalid proxy path\"}";
        if (!proxySelectionName(body, proxy)) return "{\"error\":\"Invalid proxy selection JSON\"}";
        for (ProxyGroup& group : g_state.groups) {
            if (group.name == groupName) {
                if(group.type=="LoadBalance")return "{\"error\":\"Load-balance chooses an outbound per connection; select a Selector group instead\"}";
                if (std::find(group.proxies.begin(), group.proxies.end(), proxy) == group.proxies.end()) return "{\"error\":\"Proxy is not in this group\"}";
                group.now = proxy;group.pendingSelection.clear();
                if(group.type=="URLTest"||group.type=="Fallback")group.manual=proxy;
                markProxyUsedLocked(group.name);
                persistSelectionsLocked();
                return "{}";
            }
        }
        return "{\"error\":\"Proxy group not found\"}";
    }
    if(method=="POST"&&path.rfind("/clahsos/groups/",0)==0) {
        const size_t suffix=path.rfind('/');
        const std::string name=urlDecode(path.substr(16,suffix-16)),action=path.substr(suffix+1);
        for(ProxyGroup& group:g_state.groups)if(group.name==name&&(group.type=="URLTest"||group.type=="Fallback"||group.type=="LoadBalance")) {
            if(action=="reset-sessions"&&group.type=="LoadBalance") {group.sessions.clear();return "{}";}
            if(action=="auto"&&group.type!="LoadBalance") {group.manual.clear();persistSelectionsLocked();}
            else if(action!="healthcheck")return "{\"error\":\"Unknown group action\"}";
            group.forceCheck=true;group.lastUsed=HealthClock::now();group.nextCheck={};wakeHealthChecks();return "{}";
        }
        return "{\"error\":\"Automatic proxy group not found\"}";
    }
    return "{\"error\":\"Endpoint is not supported\"}";
}

bool sendAll(int fd, const std::string& data);
std::string delayResponse(const std::string& path);
std::string providerMemberDelayResponse(const std::string& path);
#include "controller_auth.inc"
void handleControllerStreamClient(int client, const std::string& path, const std::string& version,
    const std::map<std::string, std::string>& headers, const std::string& pending, uint64_t authEpoch);

void handleClient(int client)
{
    std::string request;
    char buffer[4096];
    ssize_t received = 0;
    do {
        received = recv(client, buffer, sizeof(buffer), 0);
        if (received > 0) request.append(buffer, static_cast<size_t>(received));
    } while (received > 0 && request.find("\r\n\r\n") == std::string::npos && request.size() < 65536);

    size_t headerEnd = request.find("\r\n\r\n");
    if (headerEnd == std::string::npos) {
        closeSocket(client);
        return;
    }
    const size_t lineEnd = request.find("\r\n");
    std::istringstream requestLine(request.substr(0, lineEnd));
    std::string method;
    std::string path;
    std::string version;
    std::string extra;
    if (!(requestLine >> method >> path >> version) || (version != "HTTP/1.1" && version != "HTTP/1.0") || (requestLine >> extra)) {
        sendAll(client, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        closeSocket(client); return;
    }
    std::istringstream header(request.substr(lineEnd + 2, headerEnd > lineEnd ? headerEnd - lineEnd - 2 : 0));
    std::string body = request.substr(headerEnd + 4);
    size_t contentLength = 0;
    std::map<std::string, std::string> headers;
    std::string headerLine;
    while (std::getline(header, headerLine)) {
        const size_t colon = headerLine.find(':');
        if (colon != std::string::npos) {
            const std::string key = lower(trim(headerLine.substr(0, colon))), value = trim(headerLine.substr(colon + 1));
            if (headers.count(key)) headers[key] += "," + value;
            else headers[key] = value;
        }
    }
    const ControllerAuthentication authentication = authenticateController(headers, path);
    if (!authentication.allowed) {
        const std::string payload = "{\"error\":\"Unauthorized\"}";
        sendAll(client, "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nWWW-Authenticate: Bearer\r\nContent-Length: " +
            std::to_string(payload.size()) + "\r\nConnection: close\r\n\r\n" + payload);
        closeSocket(client); return;
    }
    auto badFraming = [&]() {
        sendAll(client, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        closeSocket(client);
    };
    if (headers.count("transfer-encoding")) { badFraming(); return; }
    if (headers.count("content-length")) {
        const auto& raw = headers["content-length"];
        if (raw.empty() || raw.find_first_not_of("0123456789") != std::string::npos) { badFraming(); return; }
        for (char digit : raw) {
            if (contentLength > (SIZE_MAX - (digit - '0')) / 10) { badFraming(); return; }
            contentLength = contentLength * 10 + digit - '0';
        }
    }
    if(contentLength>8*1024*1024) {
        const std::string payload="{\"error\":\"Controller request exceeds 8 MB\"}";
        sendAll(client,"HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: "+std::to_string(payload.size())+"\r\nConnection: close\r\n\r\n"+payload);
        closeSocket(client);return;
    }
    const std::string resource = path.substr(0, path.find('?'));
    if (method == "GET" && (resource == "/traffic" || resource == "/logs" || resource == "/memory" ||
        (resource == "/connections" && !headers["upgrade"].empty()))) {
        handleControllerStreamClient(client, path, version, headers, body, authentication.epoch);
        closeSocket(client); return;
    }
    while (body.size() < contentLength) {
        received = recv(client, buffer, sizeof(buffer), 0);
        if (received <= 0) break;
        body.append(buffer, static_cast<size_t>(received));
    }

    if (body.size() < contentLength) { badFraming(); return; }
    body.resize(contentLength);

    const bool delay = method == "GET" && path.rfind("/proxies/", 0) == 0 && path.find("/delay?") != std::string::npos;
    const bool providerDelay=method=="GET"&&path.rfind("/providers/proxies/",0)==0&&path.find("/healthcheck?")!=std::string::npos;
    std::string payload = delay ? delayResponse(path) : providerDelay ? providerMemberDelayResponse(path) : responseFor(method, path, body);
    const bool selected = payload == "{}" && ((method == "PUT" && path.rfind("/proxies/", 0) == 0) ||
        (method == "DELETE" && (resource == "/connections" || resource.rfind("/connections/", 0) == 0)) ||
        ((method == "PATCH" || method == "PUT") && (resource == "/configs" || resource == "/configs/")));
    const std::string status = selected ? "204 No Content" : payload == "{\"error\":\"Proxy not found\"}" ? "404 Not Found" :
        payload.rfind("{\"error\":", 0) == 0 ? "400 Bad Request" : "200 OK";
    if (selected) payload.clear();
    const std::string response = "HTTP/1.1 " + status + "\r\nContent-Type: application/json\r\nContent-Length: " +
        std::to_string(payload.size()) + "\r\nConnection: close\r\n\r\n" + payload;
    sendAll(client, response);
    closeSocket(client);
}

int openListener(int port, const std::string& host = "127.0.0.1")
{
    const int family = host.find(':') == std::string::npos ? AF_INET : AF_INET6;
    int listener = socket(family, SOCK_STREAM, 0);
    if (listener < 0) return -1;
    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    // Both generations can bind while changing loopback/wildcard addresses.
    setsockopt(listener, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
    int result = -1;
    if (family == AF_INET6) {
        setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, &reuse, sizeof(reuse));
        sockaddr_in6 address{}; address.sin6_family = AF_INET6; address.sin6_port = htons(static_cast<uint16_t>(port));
        if (inet_pton(AF_INET6, host.c_str(), &address.sin6_addr) == 1) result = bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    } else {
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(static_cast<uint16_t>(port));
        if (inet_pton(AF_INET, host.c_str(), &address.sin_addr) == 1) result = bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    }
    if (result < 0 || listen(listener, 32) < 0) {
        const int failure = errno; closeSocket(listener); errno = failure; return -1;
    }
    return listener;
}

bool sendAll(int fd, const char* data, size_t length)
{
    size_t sent = 0;
    while (sent < length) {
        if (!prepareSocketIo(fd)) return false;
#ifdef MSG_NOSIGNAL
        ssize_t count = send(fd, data + sent, length - sent, MSG_NOSIGNAL);
#else
        ssize_t count = send(fd, data + sent, length - sent, 0);
#endif
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        sent += static_cast<size_t>(count);
    }
    return true;
}

bool sendAll(int fd, const std::string& data)
{
    return sendAll(fd, data.data(), data.size());
}

bool sendAll(int fd, const std::vector<unsigned char>& data)
{
    return sendAll(fd, reinterpret_cast<const char*>(data.data()), data.size());
}

bool readExact(int fd, char* data, size_t length)
{
    errno = 0;
    size_t received = 0;
    while (received < length) {
        if (!prepareSocketIo(fd)) return false;
        ssize_t count = recv(fd, data + received, length - received, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            if (count == 0) errno = received > 0 ? ECONNRESET : 0;
            return false;
        }
        received += static_cast<size_t>(count);
    }
    return true;
}

std::vector<unsigned char> digestBytes(const char* algorithm, const std::vector<unsigned char>& input)
{
    const mbedtls_md_info_t* info = mbedtls_md_info_from_string(algorithm);
    if (info == nullptr) return {};
    std::vector<unsigned char> result(mbedtls_md_get_size(info));
    if (mbedtls_md(info, input.data(), input.size(), result.data()) != 0) return {};
    return result;
}

uint32_t rotateLeft(uint32_t value, uint32_t bits)
{
    return (value << bits) | (value >> (32 - bits));
}

std::vector<unsigned char> sha1(const std::vector<unsigned char>& input)
{
    std::vector<unsigned char> message = input;
    const uint64_t bitLength = static_cast<uint64_t>(message.size()) * 8;
    message.push_back(0x80);
    while ((message.size() % 64) != 56) message.push_back(0);
    for (int i = 7; i >= 0; --i) message.push_back(static_cast<unsigned char>(bitLength >> (i * 8)));

    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;
    for (size_t offset = 0; offset < message.size(); offset += 64) {
        uint32_t words[80] = {};
        for (int i = 0; i < 16; ++i) {
            const size_t at = offset + static_cast<size_t>(i) * 4;
            words[i] = (static_cast<uint32_t>(message[at]) << 24) |
                (static_cast<uint32_t>(message[at + 1]) << 16) |
                (static_cast<uint32_t>(message[at + 2]) << 8) | message[at + 3];
        }
        for (int i = 16; i < 80; ++i) words[i] = rotateLeft(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        for (int i = 0; i < 80; ++i) {
            uint32_t f = 0, k = 0;
            if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            const uint32_t next = rotateLeft(a, 5) + f + e + k + words[i];
            e = d; d = c; c = rotateLeft(b, 30); b = a; a = next;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    }
    std::vector<unsigned char> result(20);
    const uint32_t words[] = {h0, h1, h2, h3, h4};
    for (size_t i = 0; i < 5; ++i) {
        result[i * 4] = static_cast<unsigned char>(words[i] >> 24);
        result[i * 4 + 1] = static_cast<unsigned char>(words[i] >> 16);
        result[i * 4 + 2] = static_cast<unsigned char>(words[i] >> 8);
        result[i * 4 + 3] = static_cast<unsigned char>(words[i]);
    }
    return result;
}

std::vector<unsigned char> hmacSha1(const std::vector<unsigned char>& key, const std::vector<unsigned char>& message)
{
    std::vector<unsigned char> normalized = key;
    if (normalized.size() > 64) normalized = sha1(normalized);
    normalized.resize(64, 0);
    std::vector<unsigned char> inner(64), outer(64);
    for (size_t i = 0; i < 64; ++i) {
        inner[i] = normalized[i] ^ 0x36;
        outer[i] = normalized[i] ^ 0x5c;
    }
    inner.insert(inner.end(), message.begin(), message.end());
    const std::vector<unsigned char> innerDigest = sha1(inner);
    outer.insert(outer.end(), innerDigest.begin(), innerDigest.end());
    return sha1(outer);
}

std::vector<unsigned char> evpBytesToKey(const std::string& password, size_t length)
{
    std::vector<unsigned char> result;
    std::vector<unsigned char> previous;
    const std::vector<unsigned char> pass(password.begin(), password.end());
    while (result.size() < length) {
        std::vector<unsigned char> input = previous;
        input.insert(input.end(), pass.begin(), pass.end());
        previous = digestBytes("MD5", input);
        if (previous.empty()) return {};
        result.insert(result.end(), previous.begin(), previous.end());
    }
    result.resize(length);
    return result;
}

std::vector<unsigned char> hkdfSha1(const std::vector<unsigned char>& salt,
    const std::vector<unsigned char>& ikm, const std::string& info, size_t length)
{
    const std::vector<unsigned char> prk = hmacSha1(salt, ikm);
    std::vector<unsigned char> output;
    std::vector<unsigned char> previous;
    for (unsigned char counter = 1; output.size() < length; ++counter) {
        std::vector<unsigned char> message = previous;
        message.insert(message.end(), info.begin(), info.end());
        message.push_back(counter);
        previous = hmacSha1(prk, message);
        output.insert(output.end(), previous.begin(), previous.end());
    }
    output.resize(length);
    return output;
}

bool randomBytes(std::vector<unsigned char>& output)
{
    int randomFd = open("/dev/urandom", O_RDONLY);
    if (randomFd >= 0) {
        size_t offset = 0;
        while (offset < output.size()) {
            const ssize_t count = read(randomFd, output.data() + offset, output.size() - offset);
            if (count <= 0) break;
            offset += static_cast<size_t>(count);
        }
        close(randomFd);
        if (offset == output.size()) return true;
    }
    return false;
}

bool aesGcm(bool encrypt, const std::vector<unsigned char>& key, const std::vector<unsigned char>& nonce,
    const std::vector<unsigned char>& aad, const std::vector<unsigned char>& input,
    std::vector<unsigned char>& output, std::vector<unsigned char>& tag)
{
    // The shipping Harmony build and host regressions execute the same crypto backend.
    output.clear();
    if ((key.size() != 16&&key.size() != 32) || nonce.size() != 12 || tag.size() != 16) return false;
    output.resize(input.size() + 16);
    mbedtls_gcm_context context; mbedtls_gcm_init(&context);
    int result = mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, key.data(), static_cast<unsigned>(key.size()*8));
    if (result == 0) result = encrypt ?
        mbedtls_gcm_crypt_and_tag(&context, MBEDTLS_GCM_ENCRYPT, input.size(), nonce.data(), nonce.size(), aad.data(), aad.size(),
            input.data(), output.data(), tag.size(), tag.data()) :
        mbedtls_gcm_auth_decrypt(&context, input.size(), nonce.data(), nonce.size(), aad.data(), aad.size(), tag.data(), tag.size(),
            input.data(), output.data());
    mbedtls_gcm_free(&context);
    if (result != 0) { output.clear(); return false; }
    output.resize(input.size()); return true;
}

bool shadowsocksAead(bool encrypt,SsCipher method,const std::vector<unsigned char>& key,const std::vector<unsigned char>& nonce,
    const std::vector<unsigned char>& input,std::vector<unsigned char>& output,std::vector<unsigned char>& tag)
{
    output.clear();
    if(method==SsCipher::Unsupported||key.size()!=shadowsocksKeySize(method)||nonce.size()!=12||tag.size()!=16)return false;
    if(method!=SsCipher::ChaCha20Poly1305)return aesGcm(encrypt,key,nonce,{},input,output,tag);
    output.resize(input.size()+16);
    mbedtls_chachapoly_context context;mbedtls_chachapoly_init(&context);
    int result=mbedtls_chachapoly_setkey(&context,key.data());
    if(result==0)result=encrypt?
        mbedtls_chachapoly_encrypt_and_tag(&context,input.size(),nonce.data(),nullptr,0,input.data(),output.data(),tag.data()):
        mbedtls_chachapoly_auth_decrypt(&context,input.size(),nonce.data(),nullptr,0,tag.data(),input.data(),output.data());
    mbedtls_chachapoly_free(&context);
    if(result!=0){output.clear();return false;}
    output.resize(input.size());return true;
}

bool validShadowsocksNonce(const std::vector<unsigned char>& nonce)
{
    if(nonce.size()!=12)return false;
    // Leave the final pair unused so neither length nor payload can wrap the counting nonce.
    if(nonce[0]>=0xfe&&std::all_of(nonce.begin()+1,nonce.end(),[](unsigned char byte){return byte==0xff;})) {
        errno=EOVERFLOW;return false;
    }
    return true;
}

std::vector<unsigned char> decodeHex(const std::string& value)
{
    std::vector<unsigned char> result;
    for (size_t i = 0; i + 1 < value.size(); i += 2) result.push_back(static_cast<unsigned char>(std::strtoul(value.substr(i, 2).c_str(), nullptr, 16)));
    return result;
}

bool shadowsocksCryptoSelfTest()
{
    const struct Vector {SsCipher method;const char* cipher;const char* tag;} vectors[]={
        {SsCipher::Aes128Gcm,"0388","93dcdd26f79ec1dd9bff57204d9b33f5"},
        {SsCipher::Aes256Gcm,"cea7","957c05e58a61bd271536ef0c15582fe2"},
        {SsCipher::ChaCha20Poly1305,"9f07","58336e20e19c64d766e94705fc31f12e"}
    };
    for(const auto& vector:vectors) {
        const std::vector<unsigned char> key(shadowsocksKeySize(vector.method),0),nonce(12,0),plain{0,0};
        std::vector<unsigned char> cipher,tag(16),decoded;
        if(!shadowsocksAead(true,vector.method,key,nonce,plain,cipher,tag)||cipher!=decodeHex(vector.cipher)||tag!=decodeHex(vector.tag))return false;
        if(!shadowsocksAead(false,vector.method,key,nonce,cipher,decoded,tag)||decoded!=plain)return false;
        tag[0]^=1;
        if(shadowsocksAead(false,vector.method,key,nonce,cipher,decoded,tag)||!decoded.empty())return false;
    }
    return true;
}

bool vmessCryptoSelfTest();
bool vmessTrustStoreSelfTest();
bool trojanCryptoSelfTest();

std::string diagnosticsJson()
{
    // Public known-answer vectors; no configuration credentials are used or returned.
    std::vector<unsigned char> random(32);
    const bool randomOk = randomBytes(random);
    const bool md5Ok = digestBytes("MD5", {'a','b','c'}) == decodeHex("900150983cd24fb0d6963f7d28e17f72");
    std::vector<unsigned char> key(32, 0), nonce(12, 0), tag(16), cipher;
    const bool encryptOk = aesGcm(true, key, nonce, {}, {0,0}, cipher, tag) && cipher == decodeHex("cea7") &&
        tag == decodeHex("957c05e58a61bd271536ef0c15582fe2");
    std::vector<unsigned char> plaintext;
    auto expectedTag = decodeHex("957c05e58a61bd271536ef0c15582fe2");
    const bool decryptOk = aesGcm(false, key, nonce, {}, decodeHex("cea7"), plaintext, expectedTag) && plaintext == std::vector<unsigned char>({0,0});
    expectedTag[0] ^= 1;
    plaintext.clear();
    const bool authenticationOk = decryptOk && !aesGcm(false, key, nonce, {}, decodeHex("cea7"), plaintext, expectedTag);
    const bool vmessOk = vmessCryptoSelfTest();
    const bool shadowsocksOk=shadowsocksCryptoSelfTest();
    const bool trojanOk=trojanCryptoSelfTest();
    const bool rootsOk = vmessTrustStoreSelfTest();
    const bool listenersOk = g_state.httpProxyFd >= 0 && (g_state.httpPort == g_state.socksPort || g_state.socksProxyFd >= 0);
    const auto boolean = [](bool value) { return value ? "true" : "false"; };
    return std::string("{\"passed\":") + boolean(randomOk && md5Ok && encryptOk && decryptOk && authenticationOk && listenersOk && vmessOk && rootsOk&&shadowsocksOk&&trojanOk) +
        ",\"random\":" + boolean(randomOk) + ",\"md5\":" + boolean(md5Ok) + ",\"aesEncrypt\":" + boolean(encryptOk) +
        ",\"aesDecrypt\":" + boolean(decryptOk) + ",\"authentication\":" + boolean(authenticationOk) +
        ",\"shadowsocks\":"+boolean(shadowsocksOk)+",\"vmess\":" + boolean(vmessOk) + ",\"trojan\":" + boolean(trojanOk) + ",\"certificateStore\":" + boolean(rootsOk) +
        ",\"listeners\":" + boolean(listenersOk) + ",\"httpPort\":" + std::to_string(g_state.httpPort) +
        ",\"socksPort\":" + std::to_string(g_state.socksPort) + "}";
}

std::string readUntilHeaders(int fd)
{
    std::string data;
    char buffer[4096];
    while (data.size() < 65536 && data.find("\r\n\r\n") == std::string::npos) {
        ssize_t count = recv(fd, buffer, sizeof(buffer), 0);
        if (count <= 0) break;
        data.append(buffer, static_cast<size_t>(count));
    }
    return data;
}

#ifdef CLAHSOS_HOST_TEST
std::function<int(const std::string&, int, int)> g_testConnector;
std::function<int(const std::string&, int, int)> g_testResolvedConnector;
#endif

int connectUpstream(const std::string& host, int port, int timeoutMs = 6000,DnsPurpose purpose=DnsPurpose::Direct)
{
#ifdef CLAHSOS_HOST_TEST
    if (g_testConnector) {
        const int fd = g_testConnector(host, port, timeoutMs);
        trackSocket(fd);
        if (g_currentClient >= 0) attachUpstream(g_currentClient, fd);
        return fd;
    }
#endif
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    if(g_probeDeadline!=HealthClock::time_point{})deadline=std::min(deadline,g_probeDeadline);
    if(g_geoBootstrapDns||(g_dnsBootstrapConnection&&purpose==DnsPurpose::Direct))purpose=DnsPurpose::Bootstrap;
    const auto addresses=resolveDnsAddresses(host,purpose,deadline);
    if (addresses.empty()) {
        coreLog("error", "DNS resolution failed: " + host);
        return -1;
    }
    int upstream = -1;
    for (const auto& ip:addresses) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) break;
        sockaddr_storage address{};socklen_t addressLength=0;
        if(inet_pton(AF_INET,ip.c_str(),&reinterpret_cast<sockaddr_in*>(&address)->sin_addr)==1){auto* a=reinterpret_cast<sockaddr_in*>(&address);a->sin_family=AF_INET;a->sin_port=htons(port);addressLength=sizeof(*a);}
        else if(inet_pton(AF_INET6,ip.c_str(),&reinterpret_cast<sockaddr_in6*>(&address)->sin6_addr)==1){auto* a=reinterpret_cast<sockaddr_in6*>(&address);a->sin6_family=AF_INET6;a->sin6_port=htons(port);addressLength=sizeof(*a);}
        if(!addressLength)continue;
#ifdef CLAHSOS_HOST_TEST
        if(g_testResolvedConnector){upstream=g_testResolvedConnector(ip,port,static_cast<int>(remaining));trackSocket(upstream);if(g_currentClient>=0)attachUpstream(g_currentClient,upstream);if(upstream>=0)break;continue;}
#endif
        upstream = socket(address.ss_family, SOCK_STREAM, 0);
        if (upstream < 0) continue;
        trackSocket(upstream);
        if (g_currentClient >= 0) attachUpstream(g_currentClient, upstream);
        const int flags = fcntl(upstream, F_GETFL, 0);
        fcntl(upstream, F_SETFL, flags | O_NONBLOCK);
        bool connected = connect(upstream, reinterpret_cast<sockaddr*>(&address), addressLength) == 0;
        if (!connected && errno == EINPROGRESS) {
            pollfd wait{upstream, POLLOUT, 0};
            int ready;
            do { ready = poll(&wait, 1, static_cast<int>(remaining)); } while (ready < 0 && errno == EINTR);
            if (ready > 0) {
                int error = 0;
                socklen_t length = sizeof(error);
                connected = getsockopt(upstream, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0;
            }
        }
        fcntl(upstream, F_SETFL, flags);
        if (connected) break;
        closeSocket(upstream);
        upstream = -1;
    }
    if (upstream < 0) coreLog("error", "TCP connection failed: " + host + ":" + std::to_string(port));
    return upstream;
}

void closePair(int first, int second);

bool findNodeLocked(const std::string& name, ProxyNode& result)
{
    for (const ProxyNode& node : g_state.nodes) {
        if (node.name == name) {
            result = node;
            return true;
        }
    }
    return false;
}

bool findGroupSelectionLocked(const std::string& name, std::string& selection)
{
    for (const ProxyGroup& group : g_state.groups) {
        if (group.name == name) {
            selection = group.now;
            return !selection.empty();
        }
    }
    return false;
}

bool cidrMatches(const std::string& host, const std::string& cidr, int family)
{
    const size_t slash = cidr.find('/');
    if (slash == std::string::npos) return false;
    const std::string address = cidr.substr(0, slash);
    char* end = nullptr;
    const std::string prefix = cidr.substr(slash + 1);
    const int bits = static_cast<int>(std::strtol(prefix.c_str(), &end, 10));
    if (prefix.empty() || *end != '\0') return false;
    const int length = family == AF_INET ? 4 : 16;
    if (bits < 0 || bits > length * 8) return false;
    unsigned char candidate[16] = {}, network[16] = {};
    if (inet_pton(family, host.c_str(), candidate) != 1 || inet_pton(family, address.c_str(), network) != 1) return false;
    for (int i = 0; i < length; ++i) {
        const int remaining = bits - i * 8;
        const unsigned char mask = remaining >= 8 ? 0xff : remaining <= 0 ? 0 : static_cast<unsigned char>(0xff << (8 - remaining));
        if ((candidate[i] & mask) != (network[i] & mask)) return false;
    }
    return true;
}

bool ruleMatches(const ProxyRule& rule, const std::string& host, int port = 0, const std::string& network = "tcp")
{
    std::string normalizedHost = lower(host);
    if (!normalizedHost.empty() && normalizedHost.back() == '.') normalizedHost.pop_back();
    const std::string pattern = lower(trim(rule.value));
    if (rule.kind == "match" || rule.kind == "final") return true;
    if (rule.kind == "domain") return normalizedHost == pattern;
    if (rule.kind == "domain-suffix") {
        return normalizedHost == pattern || (normalizedHost.size() > pattern.size() &&
            normalizedHost.compare(normalizedHost.size() - pattern.size(), pattern.size(), pattern) == 0 &&
            normalizedHost[normalizedHost.size() - pattern.size() - 1] == '.');
    }
    if (rule.kind == "domain-keyword") return normalizedHost.find(pattern) != std::string::npos;
    if (rule.kind == "dst-port") return port > 0 && port == std::atoi(pattern.c_str());
    if (rule.kind == "network") return pattern == lower(network);
    if (rule.kind == "ip-cidr") return cidrMatches(host, pattern, AF_INET);
    if (rule.kind == "ip-cidr6") return cidrMatches(host, pattern, AF_INET6);
    return false;
}

ProxyNode resolveProxyLocked(std::string selection,const RouteContext* context=nullptr);
#include "load_balance.inc"
#include "rule_match.inc"

ProxyNode resolveProxyLocked(std::string selection,const RouteContext* context)
{
    std::set<std::string> visited=context!=nullptr?context->ancestors:std::set<std::string>{};
    std::vector<std::string> chain;
    ProxyNode node;
    bool balanced=false;
    while (!selection.empty() && visited.size() < 32) {
        if (!visited.insert(selection).second) break;
        chain.push_back(selection);
        if (selection == "DIRECT" || selection == "REJECT") {
            node.name = selection;
            node.type = selection == "DIRECT" ? "direct" : "reject";
            node.udp = selection == "DIRECT";
            node.loadBalanced=balanced;
            node.chain.assign(chain.rbegin(), chain.rend());
            return node;
        }
        if (findNodeLocked(selection, node)) {
            node.loadBalanced=balanced;
            node.chain.assign(chain.rbegin(), chain.rend());
            return node;
        }
        auto group=std::find_if(g_state.groups.begin(),g_state.groups.end(),[&](const ProxyGroup& item){return item.name==selection;});
        if(group==g_state.groups.end())break;
        if(context!=nullptr&&context->advance)group->lastUsed=context->now;
        if(group->type=="LoadBalance") {
            balanced=true;
            if(context!=nullptr) {
                RouteContext child=*context;child.ancestors=visited;
                selection=chooseBalancedMemberLocked(*group,child);
            }
            else selection=!group->lastSelected.empty()?group->lastSelected:group->proxies.empty()?"":group->proxies.front();
        } else selection=group->now;
    }
    node.type = "reject";
    node.name = selection.empty()&&!chain.empty()?chain.back():selection;
    node.loadBalanced=balanced;
    node.chain.assign(chain.rbegin(), chain.rend());
    return node;
}

ProxyNode activeProxyNode(const std::string& host, int port = 0, const std::string& network = "tcp",const std::string& source="",const std::vector<std::string>* knownIps=nullptr)
{
    RuleQuery query;query.host=host;query.port=port;query.network=network;query.source=source;
    if(knownIps){query.ips=*knownIps;query.resolved=true;}
    for(int retry=0;retry<3;++retry) {
    if(retry>0&&!knownIps){query.resolved=false;query.ips.clear();}
    std::vector<ProxyRule> rules;RuleSnapshots providers;uint64_t revision;std::string mode;
    {
        std::lock_guard<std::mutex> guard(g_state.mutex);revision=g_state.configRevision;mode=lower(g_state.mode);
        query.geo=geoSnapshotsLocked();
        if(mode!="direct"&&mode!="global") {rules=g_state.rules;for(const auto& provider:g_state.ruleProviders)providers[provider.name]={provider.behavior,provider.data};}
    }
    std::string selection = "DIRECT";
    std::string matchedRule = "MATCH";
    if(mode!="global"&&mode!="direct")for(const auto& rule:rules) {
        const auto result=evaluateRule(rule,query,providers);
        if(result==RuleVerdict::No)continue;
        selection=result==RuleVerdict::Unavailable?"REJECT":rule.target;
        matchedRule=rule.kind+(rule.kind=="rule-set"?":"+rule.value:"")+(result==RuleVerdict::Unavailable?" (unavailable)":"");break;
    }
    std::lock_guard<std::mutex> guard(g_state.mutex);
    if(revision!=g_state.configRevision||mode!=lower(g_state.mode))continue;
    if (mode == "global") {
        matchedRule = "GLOBAL";
        if (std::any_of(g_state.groups.begin(),g_state.groups.end(),[](const ProxyGroup& group){return group.name=="GLOBAL";})) selection = "GLOBAL";
        else if (!g_state.groups.empty()) selection = g_state.groups.front().name;
        else if (!g_state.nodes.empty()) selection = g_state.nodes.front().name;
    } else if(mode=="direct")matchedRule="DIRECT";
    const RouteContext context{host,source,network};
    ProxyNode node = resolveProxyLocked(selection,&context);
    wakeHealthChecks();
    if(network=="udp")for(const std::string& name:node.chain) {
        const auto group=std::find_if(g_state.groups.begin(),g_state.groups.end(),[&](const ProxyGroup& item){return item.name==name;});
        if(group!=g_state.groups.end()&&group->disableUdp){node.type="reject";node.udp=false;break;}
    }
    if(!node.provider.empty())for(ProxyProvider& provider:g_state.providers)if(provider.name==node.provider){provider.health.lastUsed=HealthClock::now();wakeHealthChecks();break;}
    node.matchedRule = matchedRule;
    node.revision = g_state.configRevision;
    return node;
    }
    ProxyNode rejected;rejected.name="REJECT";rejected.type="reject";rejected.matchedRule="Configuration changed during routing";return rejected;
}

void incrementNonce(std::vector<unsigned char>& nonce)
{
    for (size_t i = 0; i < nonce.size(); ++i) {
        if (++nonce[i] != 0) break;
    }
}

std::vector<unsigned char> shadowsocksAddress(const std::string& host, int port)
{
    std::vector<unsigned char> address;
    in_addr ipv4{};
    in6_addr ipv6{};
    if (inet_pton(AF_INET, host.c_str(), &ipv4) == 1) {
        address.push_back(1);
        const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&ipv4);
        address.insert(address.end(), bytes, bytes + 4);
    } else if (inet_pton(AF_INET6, host.c_str(), &ipv6) == 1) {
        address.push_back(4);
        const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&ipv6);
        address.insert(address.end(), bytes, bytes + 16);
    } else {
        if (host.size() > 255) return {};
        address.push_back(3);
        address.push_back(static_cast<unsigned char>(host.size()));
        address.insert(address.end(), host.begin(), host.end());
    }
    address.push_back(static_cast<unsigned char>((port >> 8) & 0xff));
    address.push_back(static_cast<unsigned char>(port & 0xff));
    return address;
}

bool shadowsocksSendChunk(int fd, const std::vector<unsigned char>& key, std::vector<unsigned char>& nonce,
    const std::vector<unsigned char>& plain,SsCipher method=SsCipher::Aes256Gcm)
{
    if (plain.empty() || plain.size() > 0x3fff || !validShadowsocksNonce(nonce)) return false;
    const unsigned short length = static_cast<unsigned short>(plain.size());
    std::vector<unsigned char> lengthBytes = {static_cast<unsigned char>(length >> 8), static_cast<unsigned char>(length)};
    std::vector<unsigned char> lengthCipher;
    std::vector<unsigned char> lengthTag(16);
    if (!shadowsocksAead(true,method,key,nonce,lengthBytes,lengthCipher,lengthTag) || lengthCipher.size() != 2) return false;
    incrementNonce(nonce);
    std::vector<unsigned char> payloadCipher;
    std::vector<unsigned char> payloadTag(16);
    if (!shadowsocksAead(true,method,key,nonce,plain,payloadCipher,payloadTag)) return false;
    incrementNonce(nonce);
    return sendAll(fd, lengthCipher) && sendAll(fd, lengthTag) && sendAll(fd, payloadCipher) && sendAll(fd, payloadTag);
}

bool shadowsocksReadChunk(int fd, const std::vector<unsigned char>& key, std::vector<unsigned char>& nonce,
    std::vector<unsigned char>& plain,SsCipher method=SsCipher::Aes256Gcm)
{
    plain.clear();
    if(!validShadowsocksNonce(nonce)||method==SsCipher::Unsupported||key.size()!=shadowsocksKeySize(method))return false;
    unsigned char lengthPacket[18] = {};
    if (!readExact(fd, reinterpret_cast<char*>(lengthPacket), sizeof(lengthPacket))) return false;
    std::vector<unsigned char> encryptedLength(lengthPacket, lengthPacket + 2);
    std::vector<unsigned char> lengthTag(lengthPacket + 2, lengthPacket + 18);
    std::vector<unsigned char> lengthPlain;
    if (!shadowsocksAead(false,method,key,nonce,encryptedLength,lengthPlain,lengthTag) || lengthPlain.size() != 2) { errno = EBADMSG; return false; }
    incrementNonce(nonce);
    const size_t length = (static_cast<size_t>(lengthPlain[0]) << 8) | lengthPlain[1];
    if (length == 0 || length > 0x3fff) { errno = EPROTO; return false; }
    std::vector<unsigned char> packet(length + 16);
    if (!readExact(fd, reinterpret_cast<char*>(packet.data()), packet.size())) return false;
    std::vector<unsigned char> encrypted(packet.begin(), packet.begin() + length);
    std::vector<unsigned char> tag(packet.begin() + length, packet.end());
    if (!shadowsocksAead(false,method,key,nonce,encrypted,plain,tag) || plain.size() != length) { errno = EBADMSG; return false; }
    incrementNonce(nonce);
    return true;
}

bool shadowsocksReceive(int fd, const std::vector<unsigned char>& masterKey, bool& receivedSalt,
    std::vector<unsigned char>& receiveKey, std::vector<unsigned char>& nonce, std::vector<unsigned char>& plain,SsCipher method=SsCipher::Aes256Gcm)
{
    plain.clear();const size_t keySize=shadowsocksKeySize(method);
    if(keySize==0||masterKey.size()!=keySize)return false;
    if (!receivedSalt) {
        std::vector<unsigned char> salt(keySize);
        if (!readExact(fd, reinterpret_cast<char*>(salt.data()), salt.size())) return false;
        receiveKey = hkdfSha1(salt, masterKey, "ss-subkey", keySize);
        receivedSalt = true;
    }
    return shadowsocksReadChunk(fd, receiveKey, nonce, plain,method);
}

bool connectShadowsocks(const ProxyNode& node, const std::string& host, int port, int& upstream,
    std::vector<unsigned char>& key, std::vector<unsigned char>& nonce, int timeoutMs = 6000)
{
    const SsCipher method=shadowsocksCipher(node.cipher);const size_t keySize=shadowsocksKeySize(method);
    if (node.type != "ss" || keySize==0 || node.server.empty() || node.port <= 0) return false;
    const std::vector<unsigned char> masterKey = evpBytesToKey(node.password, keySize);
    if (masterKey.size() != keySize) return false;
    std::vector<unsigned char> salt(keySize);
    if (!randomBytes(salt)) return false;
    upstream = connectUpstream(node.server, node.port, timeoutMs,DnsPurpose::Proxy);
    if (upstream < 0 || !sendAll(upstream, salt)) {
        if (upstream >= 0) closeSocket(upstream);
        upstream = -1;
        return false;
    }
    key = hkdfSha1(salt, masterKey, "ss-subkey", keySize);
    nonce.assign(12, 0);
    const std::vector<unsigned char> address = shadowsocksAddress(host, port);
    if (address.empty() || !shadowsocksSendChunk(upstream, key, nonce, address,method)) {
        closeSocket(upstream);
        upstream = -1;
        return false;
    }
    return true;
}

#include "vmess_transport.inc"
#include "vmess_protocol.inc"
#include "trojan_protocol.inc"

struct ProxyStream {
    int fd = -1;
    std::unique_ptr<VmessSession> vmess;
    std::unique_ptr<TrojanSession> trojan;
    bool encrypted = false;
    SsCipher ssCipher=SsCipher::Aes256Gcm;
    bool receivedSalt = false;
    std::vector<unsigned char> masterKey;
    std::vector<unsigned char> sendKey;
    std::vector<unsigned char> sendNonce;
    std::vector<unsigned char> receiveKey;
    std::vector<unsigned char> receiveNonce = std::vector<unsigned char>(12, 0);
    ProxyStream() = default;
    ProxyStream(const ProxyStream&) = delete;
    ProxyStream& operator=(const ProxyStream&) = delete;
    ~ProxyStream() { if (fd >= 0) closeSocket(fd); }
};

bool openProxyStream(const ProxyNode& node, const std::string& host, int port, ProxyStream& stream,
    std::string& error, int timeoutMs = 6000)
{
    if (node.type == "direct") {
        stream.fd = connectUpstream(host, port, timeoutMs);
    } else if (node.type == "ss" && shadowsocksCipher(node.cipher)!=SsCipher::Unsupported) {
        stream.encrypted = true;
        stream.ssCipher=shadowsocksCipher(node.cipher);
        stream.masterKey = evpBytesToKey(node.password, shadowsocksKeySize(stream.ssCipher));
        if (!connectShadowsocks(node, host, port, stream.fd, stream.sendKey, stream.sendNonce, timeoutMs)) {
            error = "Shadowsocks connection or handshake failed";
            return false;
        }
    } else if (node.type == "trojan") {
        if (!TrojanSession::validate(node, error)) return false;
        stream.fd = connectUpstream(node.server, node.port, timeoutMs,DnsPurpose::Proxy);
        if (stream.fd < 0) { error = "Cannot connect to Trojan server"; return false; }
        socketTimeout(stream.fd, timeoutMs);
        stream.trojan = std::make_unique<TrojanSession>(stream.fd);
        if (!stream.trojan->start(node, host, port, false, error)) return false;
    } else if (node.type == "vmess") {
        stream.fd = connectUpstream(node.server, node.port, timeoutMs,DnsPurpose::Proxy);
        if (stream.fd < 0) { error = "Cannot connect to VMess server"; return false; }
        socketTimeout(stream.fd, timeoutMs);
        stream.vmess = std::make_unique<VmessSession>(stream.fd);
        if (!stream.vmess->start(node, host, port, false, error)) return false;
    } else {
        error = node.type == "reject" ? "Connection rejected by routing policy" : "Unsupported outbound: " + node.type + " " + node.cipher;
        return false;
    }
    if (stream.fd < 0) { error = "Cannot connect to outbound server"; return false; }
    socketTimeout(stream.fd, timeoutMs);
    return true;
}

bool streamWrite(ProxyStream& stream, const char* data, size_t size)
{
    if (stream.vmess) return stream.vmess->write(reinterpret_cast<const unsigned char*>(data), size);
    if (stream.trojan) return stream.trojan->write(reinterpret_cast<const unsigned char*>(data), size);
    if (!stream.encrypted) return sendAll(stream.fd, data, size);
    for (size_t offset = 0; offset < size;) {
        const size_t length = std::min<size_t>(0x3fff, size - offset);
        std::vector<unsigned char> chunk(data + offset, data + offset + length);
        if (!shadowsocksSendChunk(stream.fd, stream.sendKey, stream.sendNonce, chunk,stream.ssCipher)) return false;
        offset += length;
    }
    return true;
}

bool streamRead(ProxyStream& stream, std::vector<unsigned char>& output, bool nonblocking = false)
{
    output.clear();
    if (stream.vmess) return stream.vmess->read(output);
    if (stream.trojan) return stream.trojan->read(output, nonblocking);
    if (stream.encrypted) return shadowsocksReceive(stream.fd, stream.masterKey, stream.receivedSalt,
        stream.receiveKey, stream.receiveNonce, output,stream.ssCipher);
    if (!prepareSocketIo(stream.fd)) return false;
    output.resize(16384);
    ssize_t count;
    errno = 0;
    do { count = recv(stream.fd, output.data(), output.size(), 0); } while (count < 0 && errno == EINTR);
    if (count <= 0) { if (count == 0) errno = 0; output.clear(); return false; }
    output.resize(static_cast<size_t>(count));
    return true;
}

bool sendPayload(int client, ProxyStream& stream, const std::string& data)
{
    if (data.empty()) return true;
    if (!streamWrite(stream, data.data(), data.size())) return false;
    recordTransfer(client, true, data.size());
    return true;
}

void relayStream(int client, ProxyStream& stream)
{
    bool clientOpen = true, remoteOpen = true;
    std::vector<unsigned char> buffer(16384);
    while (clientOpen || remoteOpen) {
        pollfd reads[2] = {{clientOpen ? client : -1, POLLIN, 0}, {remoteOpen ? stream.fd : -1, POLLIN, 0}};
        const bool buffered = remoteOpen && ((stream.vmess && stream.vmess->pending()) || (stream.trojan && stream.trojan->pending()));
        const int ready = poll(reads, 2, buffered ? 0 : 300000);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || (ready == 0 && !buffered)) break;
        if (buffered) reads[1].revents |= POLLIN;
        if (clientOpen && reads[0].revents != 0) {
            const ssize_t count = recv(client, buffer.data(), buffer.size(), 0);
            if (count == 0) {
                clientOpen = false;
                if (stream.vmess) { if (!stream.vmess->finish()) break; }
                else if (stream.trojan) { if (!stream.trojan->finish()) break; }
                else shutdown(stream.fd, SHUT_WR);
            } else if (count < 0) {
                if (errno == EINTR) continue;
                break;
            } else {
                if (!streamWrite(stream, reinterpret_cast<const char*>(buffer.data()), static_cast<size_t>(count))) break;
                recordTransfer(client, true, static_cast<size_t>(count));
            }
        }
        if (remoteOpen && reads[1].revents != 0) {
            std::vector<unsigned char> plain;
            if (!streamRead(stream, plain, true)) {
                if (stream.trojan && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
                if (errno != 0) {
                    if (stream.vmess) coreLog("warning", errno == EBADMSG ? "VMess response authentication failed" :
                        errno == EOVERFLOW ? "VMess connection reached its nonce limit" : "VMess transport interrupted or timed out");
                    else if (stream.trojan) coreLog("warning", "Trojan TLS or WebSocket transport interrupted or timed out");
                    else if (stream.encrypted) coreLog("warning", errno == EBADMSG ? "Shadowsocks authentication failed" : "Encrypted connection interrupted or timed out");
                    break;
                }
                remoteOpen = false;
                shutdown(client, SHUT_WR);
            } else {
                if (!sendAll(client, plain)) break;
                recordTransfer(client, false, plain.size());
            }
        }
    }
}

#include "latency_probe.inc"
#include "provider_http.inc"
#include "provider_runtime.inc"
#include "rule_runtime.inc"
#include "geo_runtime.inc"
#include "group_health.inc"

bool splitHostPort(const std::string& authority, std::string& host, int& port, int defaultPort = 443)
{
    const std::string value = trim(authority);
    if (value.empty() || value.find_first_of("\r\n /?@#") != std::string::npos) return false;
    std::string portText;
    port = defaultPort;
    if (value.front() == '[') {
        const size_t closing = value.find(']');
        if (closing == std::string::npos) return false;
        host = value.substr(1, closing - 1);
        in6_addr ip{};
        if (inet_pton(AF_INET6, host.c_str(), &ip) != 1) return false;
        if (closing + 1 < value.size()) {
            if (value[closing + 1] != ':') return false;
            portText = value.substr(closing + 2);
            if (portText.empty()) return false;
        }
    } else {
        const size_t colon = value.rfind(':');
        host = value.substr(0, colon);
        if (colon != std::string::npos) {
            portText = value.substr(colon + 1);
            if (portText.empty() || host.find(':') != std::string::npos) return false;
        }
    }
    if (!portText.empty()) {
        char* end = nullptr;
        const long parsed = std::strtol(portText.c_str(), &end, 10);
        if (*end != '\0' || parsed < 1 || parsed > 65535) return false;
        port = static_cast<int>(parsed);
    }
    return !host.empty() && port > 0 && port < 65536;
}

void closePair(int first, int second)
{
    shutdown(first, SHUT_RDWR);
    shutdown(second, SHUT_RDWR);
    closeSocket(first);
    closeSocket(second);
}

#include "inbound_auth.inc"
#include "sniffer_wire.inc"
#include "sniffer_runtime.inc"

void handleHttpProxyClient(int client)
{
    InboundConfig policy; std::string source;
    if (!inboundHandshakePolicy(client, policy, source)) { closeSocket(client); return; }
    const std::string request = readUntilHeaders(client);
    const size_t headerEnd = request.find("\r\n\r\n");
    const size_t lineEnd = request.find("\r\n");
    if (headerEnd == std::string::npos || lineEnd == std::string::npos) { closeSocket(client); return; }
    if (!inboundHttpAuthenticated(policy, source, request)) {
        sendAll(client, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"ClashOS\", charset=\"UTF-8\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        closeSocket(client); return;
    }
    std::istringstream firstLine(request.substr(0, lineEnd));
    std::string method, target, version;
    firstLine >> method >> target >> version;
    const bool tunnel = lower(method) == "connect";
    std::string host;
    int port = tunnel ? 443 : 80;
    std::string forwardedHeaders;
    std::istringstream headers(request.substr(lineEnd + 2, headerEnd - lineEnd - 2));
    std::string header;
    while (std::getline(headers, header)) {
        if (!header.empty() && header.back() == '\r') header.pop_back();
        const size_t colon = header.find(':');
        if (colon == std::string::npos) continue;
        const std::string key = lower(trim(header.substr(0, colon)));
        if (key == "host" && !tunnel) splitHostPort(trim(header.substr(colon + 1)), host, port, 80);
        if (key != "proxy-connection" && key != "proxy-authorization" && key != "connection") forwardedHeaders += header + "\r\n";
    }
    bool valid = version == "HTTP/1.1" || version == "HTTP/1.0";
    if (tunnel) {
        valid = valid && splitHostPort(target, host, port, 443);
    } else if (target.rfind("http://", 0) == 0) {
        TestTarget absolute;
        valid = valid && parseTestUrl(target, absolute);
        if (valid) { host = absolute.host; port = absolute.port; target = absolute.path; }
    } else valid = valid && !host.empty() && !target.empty() && (target.front() == '/' || target == "*");
    if (!valid || host.empty()) {
        sendAll(client, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
        closeSocket(client);
        return;
    }
    auto plan = sniffPlan(host, port, clientSourceAddress(client));
    bool acknowledged = false;
    std::string prefix = request.substr(headerEnd + 4);
    if (tunnel && plan.eligible) {
        if (!sendAll(client, "HTTP/1.1 200 Connection Established\r\n\r\n")) { closeSocket(client); return; }
        acknowledged = true; sniffTcp(client, plan, prefix);
    } else if (!tunnel && plan.eligible && sniffProtocolPort(*plan.config, "HTTP", port)) sniffApply(plan, "HTTP", sniffHttp(request));
    const ProxyNode node = activeProxyNode(plan.route, port, "tcp", plan.source, plan.originalIps.empty() ? nullptr : &plan.originalIps);
    beginConnection(client, plan.route, port, node.chain, node.matchedRule);
    ProxyStream stream;
    std::string error;
    if (!openProxyStream(node, plan.destination, port, stream, error)) {
        coreLog("error", host + ":" + std::to_string(port) + " via " + node.name + ": " + error);
        const std::string status = node.type == "reject" ? "403 Forbidden" : node.type != "ss" && node.type != "direct" && node.type != "vmess" && node.type != "trojan" ? "501 Not Implemented" : "502 Bad Gateway";
        if (!acknowledged) sendAll(client, "HTTP/1.1 " + status + "\r\nConnection: close\r\n\r\n");
        closeSocket(client);
        return;
    }
    attachUpstream(client, stream.fd);
    coreLog("info", host + ":" + std::to_string(port) + " via " + node.name);
    bool ready = true;
    if (tunnel) {
        ready = (acknowledged || sendAll(client, "HTTP/1.1 200 Connection Established\r\n\r\n")) && sendPayload(client, stream, prefix);
    } else {
        const std::string forwarded = method + " " + target + " " + version + "\r\n" + forwardedHeaders +
            "Connection: close\r\n\r\n" + request.substr(headerEnd + 4);
        ready = sendPayload(client, stream, forwarded);
    }
    if (ready) relayStream(client, stream);
    closePair(client, stream.fd);
    stream.fd = -1;
}

void socksReply(int client, unsigned char status)
{
    const unsigned char reply[] = {5, status, 0, 1, 0, 0, 0, 0, 0, 0};
    sendAll(client, reinterpret_cast<const char*>(reply), sizeof(reply));
}

#include "udp_proxy.inc"
#include "dns_runtime.inc"
#include "dns_listener.inc"
#include "controller_stream.inc"

void handleSocksClient(int client)
{
    InboundConfig policy; std::string source;
    if (!inboundHandshakePolicy(client, policy, source) || !inboundSocksAuthenticate(client, policy, source)) { closeSocket(client); return; }
    unsigned char request[4];
    if (!readExact(client, reinterpret_cast<char*>(request), 4) || request[0] != 5 || request[2] != 0) { closeSocket(client); return; }
    if (request[1] != 1 && request[1] != 3) { socksReply(client, 7); closeSocket(client); return; }
    std::string host;
    if (request[3] == 1 || request[3] == 4) {
        unsigned char address[16] = {};
        const size_t length = request[3] == 1 ? 4 : 16;
        if (!readExact(client, reinterpret_cast<char*>(address), length)) { closeSocket(client); return; }
        char text[INET6_ADDRSTRLEN] = {};
        inet_ntop(request[3] == 1 ? AF_INET : AF_INET6, address, text, sizeof(text));
        host = text;
    } else if (request[3] == 3) {
        unsigned char length = 0;
        if (!readExact(client, reinterpret_cast<char*>(&length), 1) || length == 0) { closeSocket(client); return; }
        host.resize(length);
        if (!readExact(client, host.data(), length) || host.find('\0') != std::string::npos) { closeSocket(client); return; }
    } else { socksReply(client, 8); closeSocket(client); return; }
    unsigned char portBytes[2];
    if (!readExact(client, reinterpret_cast<char*>(portBytes), 2)) { closeSocket(client); return; }
    const int port = (static_cast<int>(portBytes[0]) << 8) | portBytes[1];
    if (request[1] == 3) {
        handleUdpAssociate(client, host, port);
        closeSocket(client);
        return;
    }
    if (port == 0) { socksReply(client, 1); closeSocket(client); return; }
    auto plan = sniffPlan(host, port, clientSourceAddress(client));
    std::string prefix; const bool acknowledged = plan.eligible;
    if (acknowledged) { socksReply(client, 0); sniffTcp(client, plan, prefix); }
    const ProxyNode node = activeProxyNode(plan.route, port, "tcp", plan.source, plan.originalIps.empty() ? nullptr : &plan.originalIps);
    beginConnection(client, plan.route, port, node.chain, node.matchedRule);
    ProxyStream stream;
    std::string error;
    if (!openProxyStream(node, plan.destination, port, stream, error)) {
        coreLog("error", host + ":" + std::to_string(port) + " via " + node.name + ": " + error);
        if (!acknowledged) socksReply(client, node.type == "reject" ? 2 : node.type != "ss" && node.type != "direct" && node.type != "vmess" && node.type != "trojan" ? 7 : 5);
        closeSocket(client);
        return;
    }
    attachUpstream(client, stream.fd);
    if (!acknowledged) socksReply(client, 0);
    coreLog("info", host + ":" + std::to_string(port) + " via " + node.name);
    if (sendPayload(client, stream, prefix)) relayStream(client, stream);
    closePair(client, stream.fd);
    stream.fd = -1;
}

void handleMixedProxyClient(int client)
{
    InboundConfig policy; std::string source;
    if (!inboundHandshakePolicy(client, policy, source)) { closeSocket(client); return; }
    unsigned char first = 0;
    const ssize_t count = recv(client, reinterpret_cast<char*>(&first), 1, MSG_PEEK);
    if (count == 1 && first == 5) handleSocksClient(client);
    else handleHttpProxyClient(client);
}

void dispatchWorker(int client, int mode)
{
    if (!g_state.running.load() || g_state.workers.load() >= (mode == 3 ? 288 : 256)) { closeSocket(client); return; }
    trackSocket(client);
    g_state.workers.fetch_add(1);
    try {
        std::thread([client, mode]() {
            g_currentClient = mode == 3 ? -1 : client;
            try {
                if (mode == 3) handleClient(client);
                else if (mode == 1) handleSocksClient(client);
                else if (mode == 2) handleMixedProxyClient(client);
                else handleHttpProxyClient(client);
            } catch (const std::exception&) {
                coreLog("error", "Connection worker failed");
                closeSocket(client);
            }
            g_currentClient = -1;
            {
                std::lock_guard<std::mutex> guard(g_state.sessionsMutex);
                g_state.workers.fetch_sub(1);
            }
            g_state.workersDone.notify_all();
        }).detach();
    } catch (const std::exception&) {
        closeSocket(client);
        g_state.workers.fetch_sub(1);
        g_state.workersDone.notify_all();
    }
}

void proxyLoop(int listener, int mode, std::shared_ptr<ProxyListener> context = nullptr)
{
    if (context) {
        std::unique_lock<std::mutex> lock(context->startMutex);
        context->startWake.wait(lock, [&]() { return context->ready || !context->active.load(); });
    }
    while (g_state.running.load() && (context == nullptr || context->active.load())) {
        sockaddr_storage address{};
        socklen_t length = sizeof(address);
        const int client = accept(listener, reinterpret_cast<sockaddr*>(&address), &length);
        if (client < 0) {
            if (!g_state.running.load() || (context != nullptr && !context->active.load())) break;
            if (errno == EBADF || errno == EINVAL) break;
            continue;
        }
        if (context != nullptr && !context->active.load()) { closeSocket(client); break; }
        dispatchWorker(client, mode);
    }
}

bool configureProxyListenersLocked(int httpPort, int socksPort, std::string& error,
    const std::function<bool()>& commit, const InboundConfig* policy)
{
    if (httpPort < 0 || httpPort > 65535 || socksPort < 0 || socksPort > 65535) {
        error = "Proxy ports must be between 0 and 65535"; return false;
    }
    const auto& inbound = policy ? *policy : g_state.inbound;
    const auto hosts = inboundBindAddresses(inbound);
    std::set<int> ports{httpPort, socksPort}; ports.erase(0);
    using Endpoint = std::pair<std::string, int>;
    std::set<Endpoint> wanted;
    std::vector<std::shared_ptr<ProxyListener>> next, opened;
    const auto discard = [&]() {
        for (const auto& listener : opened) {
            { std::lock_guard<std::mutex> lock(listener->startMutex); listener->active.store(false); }
            listener->startWake.notify_all();
            shutdown(listener->fd, SHUT_RDWR); closeSocket(listener->fd);
            if (listener->thread.joinable()) listener->thread.join();
        }
    };
    for (int port : ports) for (const auto& host : hosts) {
        std::shared_ptr<ProxyListener> current;
        for (const auto& listener : g_state.listeners) if (listener->port == port && listener->host == host) current = listener;
        if (current == nullptr) {
            const int fd = openListener(port, host);
            if (fd < 0) {
                if (inbound.bindAddress == "*" && host == "::" && (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT || errno == EADDRNOTAVAIL)) continue;
                discard(); error = "Cannot bind proxy port " + std::to_string(port) + "; current listeners have been preserved"; return false;
            }
            current = std::make_shared<ProxyListener>();
            current->fd = fd; current->port = port; current->host = host; opened.push_back(current);
        }
        wanted.emplace(host, port); next.push_back(current);
    }
    try {
        for (const auto& listener : opened) listener->thread = std::thread(proxyLoop, listener->fd, 2, listener);
    } catch (const std::exception&) {
        discard(); error = "Cannot start proxy listeners; previous listeners have been preserved"; return false;
    }
    if (commit && !commit()) { discard(); return false; }
    for (const auto& listener : g_state.listeners) {
        if (wanted.count({listener->host, listener->port})) continue;
        { std::lock_guard<std::mutex> lock(listener->startMutex); listener->active.store(false); }
        listener->startWake.notify_all();
        shutdown(listener->fd, SHUT_RDWR); closeSocket(listener->fd);
        if (listener->thread.joinable()) listener->thread.join();
    }
    g_state.listeners = std::move(next);
    g_state.httpProxyFd = g_state.socksProxyFd = -1;
    for (const auto& listener : g_state.listeners) {
        if (listener->port == httpPort) g_state.httpProxyFd = listener->fd;
        if (listener->port == socksPort && httpPort != socksPort) g_state.socksProxyFd = listener->fd;
    }
    for (const auto& listener : opened) {
        { std::lock_guard<std::mutex> lock(listener->startMutex); listener->ready = true; }
        listener->startWake.notify_all();
    }
    return true;
}

bool startFailure(const std::string& error)
{
    std::lock_guard<std::mutex> guard(g_state.mutex);g_state.lastError=error;coreLog("error",error);return false;
}

bool startCore(const std::string& configPath, int port)
{
    std::lock_guard<std::mutex> lifecycle(g_lifecycleMutex);
    if (port < 1 || port > 65535) return startFailure("Controller port must be between 1 and 65535");
    if (g_state.running.load()) return true;
    if (g_state.workers.load() != 0) return startFailure("Previous core connections are still stopping");
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) return startFailure(std::string("Cannot create controller socket: ")+std::strerror(errno));
    int reuse = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0 || listen(server, 16) < 0) {
        const std::string error=std::string("Cannot listen on controller port ")+std::to_string(port)+": "+std::strerror(errno);
        closeSocket(server);
        return startFailure(error);
    }
    {
        std::lock_guard<std::mutex> guard(g_state.mutex);
        g_state.lastError.clear();
        g_state.serverFd = server;
        g_state.port = port;
        g_state.httpProxyFd = -1;
        g_state.socksProxyFd = -1;
        g_state.httpPort = 7890;
        g_state.socksPort = 7891;
        g_state.portSettings = ProxyPortSettings{}; g_state.profilePorts = ProxyPortSettings{};
        g_state.mode = "Rule";
        g_state.inbound = InboundConfig{}; g_state.profileInbound = InboundConfig{}; g_state.inboundOverridden = false;
        g_state.sniffer = std::make_shared<SnifferConfig>();
        g_state.logLevel.store(1); g_state.ipv6.store(false);
        g_state.temporaryConfig = false; g_state.configOrigin.clear();
        g_state.configPath.clear();
        g_state.nodes.clear();g_state.localNodes.clear();g_state.providers.clear();g_state.ruleProviders.clear();++g_state.profileEpoch;
        g_state.dns=std::make_shared<DnsConfig>();
        g_state.geo=GeoConfig{};
        g_state.proxyNames.clear(); g_state.groups.clear(); g_state.rules.clear();
        g_state.ruleCount = 0;
        g_state.delays.clear();
        {
            std::lock_guard<std::mutex> sessions(g_state.sessionsMutex);
            g_state.logs.clear();
            g_state.nextLogId = 1;
        }
        if (!configPath.empty()) {
            std::string error;
            if (!loadConfigLocked(configPath, error)) {g_state.lastError=error;coreLog("error",error);closeSocket(server);g_state.serverFd=-1;return false;}
        }
        g_state.running.store(true);
        std::string error;
        std::shared_ptr<DnsListener> dnsListener;
        if(!prepareDnsListener(g_state.dns,dnsListener,error)) {g_state.running.store(false);closeSocket(server);g_state.serverFd=-1;g_state.lastError=error;coreLog("error",error);return false;}
        if (!configureProxyListenersLocked(g_state.httpPort, g_state.socksPort, error)) {
            g_state.running.store(false);
            closeSocket(server);
            g_state.serverFd = -1;
            coreLog("error", error);
            g_state.lastError=error;
            return false;
        }
        replaceDnsListenerLocked(dnsListener);
        g_state.instance = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        g_state.uploadTotal.store(0);
        g_state.downloadTotal.store(0);
    }
    g_state.running.store(true);
    coreLog("info", "ClashOS core started");
    g_state.serverThread = std::thread(proxyLoop, server, 3, nullptr);
    g_healthThread = std::thread(healthLoop);
    g_providerThread = std::thread(providerLoop);
    g_ruleProviderThread = std::thread(ruleProviderLoop);
    g_geoThread = std::thread(geoLoop);
    return true;
}

void stopCore()
{
    std::lock_guard<std::mutex> lifecycle(g_lifecycleMutex);
    if (!g_state.running.exchange(false)) return;
    int server = -1;
    std::vector<std::shared_ptr<ProxyListener>> listeners;
    std::shared_ptr<DnsListener> dnsListener;
    {
        std::lock_guard<std::mutex> guard(g_state.mutex);
        server = g_state.serverFd;
        listeners.swap(g_state.listeners);
        dnsListener=std::move(g_state.dnsListener);
        g_state.serverFd = g_state.httpProxyFd = g_state.socksProxyFd = -1;
    }
    if(dnsListener)dnsListener->stop();
    if (server >= 0) { shutdown(server, SHUT_RDWR); closeSocket(server); }
    for (const auto& listener : listeners) {
        { std::lock_guard<std::mutex> lock(listener->startMutex); listener->active.store(false); }
        listener->startWake.notify_all();
        shutdown(listener->fd, SHUT_RDWR);
        closeSocket(listener->fd);
    }
    if (g_state.serverThread.joinable()) g_state.serverThread.join();
    for (const auto& listener : listeners) if (listener->thread.joinable()) listener->thread.join();
    {
        std::lock_guard<std::mutex> lock(g_state.sessionsMutex);
        for(int fd:g_state.sockets)shutdown(fd,SHUT_RDWR);
    }
    wakeHealthChecks();
    if(g_healthThread.joinable())g_healthThread.join();
    if(g_providerThread.joinable())g_providerThread.join();
    if(g_ruleProviderThread.joinable())g_ruleProviderThread.join();
    if(g_geoThread.joinable())g_geoThread.join();
    std::unique_lock<std::mutex> lock(g_state.sessionsMutex);
    g_state.workersDone.wait_for(lock, std::chrono::seconds(15), [] { return g_state.workers.load() == 0; });
}

std::string runtimeInfo()
{
    std::lock_guard<std::mutex> guard(g_state.mutex);
    return std::string("{\"running\":") + (g_state.running.load() ? "true" : "false") +
        ",\"instance\":\"" + jsonEscape(g_state.instance) + "\",\"configPath\":\"" + jsonEscape(g_state.configPath) +
        "\",\"temporaryConfig\":" + (g_state.temporaryConfig ? "true" : "false") + ",\"origin\":\"" + jsonEscape(g_state.configOrigin) +
        "\",\"mode\":\"" + jsonEscape(g_state.mode) + "\",\"controllerPort\":" + std::to_string(g_state.port) +
        ",\"httpPort\":" + std::to_string(g_state.httpPort) + ",\"socksPort\":" + std::to_string(g_state.socksPort) +
        ",\"proxyHost\":\"" + jsonEscape(inboundLocalAddress(g_state.inbound)) + "\",\"allowLan\":" + (g_state.inbound.allowLan ? "true" : "false") +
        ",\"error\":\""+jsonEscape(g_state.lastError)+"\"}";
}

bool setRuntimeMode(const std::string& mode)
{
    if (mode != "Rule" && mode != "Global" && mode != "Direct") return false;
    std::lock_guard<std::mutex> guard(g_state.mutex);
    g_state.mode = mode;
    ++g_state.configRevision;
    return true;
}

#ifndef CLAHSOS_HOST_TEST
std::string napiText(napi_env env, napi_value value)
{
    size_t length = 0;
    if (value == nullptr || napi_get_value_string_utf8(env, value, nullptr, 0, &length) != napi_ok) return "";
    std::string text(length + 1, '\0');
    napi_get_value_string_utf8(env, value, text.data(), text.size(), &length);
    text.resize(length);
    return text;
}

struct LifecycleOperation {
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    std::string path;
    int port = 9090;
    bool start = false;
    bool result = false;
};

napi_value ScheduleLifecycle(napi_env env, napi_callback_info info, bool start)
{
    size_t argc = 2;
    napi_value args[2] = {nullptr, nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    auto* operation = new LifecycleOperation();
    operation->start = start;
    if (start) {
        operation->path = argc > 0 ? napiText(env, args[0]) : "";
        if (argc > 1) napi_get_value_int32(env, args[1], &operation->port);
    }
    napi_value promise, name;
    napi_create_promise(env, &operation->deferred, &promise);
    napi_create_string_utf8(env, "ClashOS core lifecycle", NAPI_AUTO_LENGTH, &name);
    const napi_status created = napi_create_async_work(env, nullptr, name,
        [](napi_env, void* data) {
            auto* op = static_cast<LifecycleOperation*>(data);
            try {
                if (op->start) op->result = startCore(op->path, op->port);
                else { stopCore(); op->result = true; }
            } catch (...) { op->result = false; }
        },
        [](napi_env env, napi_status status, void* data) {
            auto* op = static_cast<LifecycleOperation*>(data);
            napi_value result;
            napi_get_boolean(env, status == napi_ok && op->result, &result);
            napi_resolve_deferred(env, op->deferred, result);
            napi_delete_async_work(env, op->work);
            delete op;
        }, operation, &operation->work);
    if (created != napi_ok || napi_queue_async_work(env, operation->work) != napi_ok) {
        napi_value error;
        napi_create_string_utf8(env, "Cannot schedule core lifecycle operation", NAPI_AUTO_LENGTH, &error);
        napi_reject_deferred(env, operation->deferred, error);
        if (operation->work != nullptr) napi_delete_async_work(env, operation->work);
        delete operation;
    }
    return promise;
}
napi_value StartAsync(napi_env env, napi_callback_info info) { return ScheduleLifecycle(env, info, true); }
napi_value StopAsync(napi_env env, napi_callback_info info) { return ScheduleLifecycle(env, info, false); }
napi_value SetControllerSecret(napi_env env, napi_callback_info info)
{
    size_t argc = 1, length = 0; napi_value argument = nullptr, result; napi_valuetype type = napi_undefined;
    napi_get_cb_info(env, info, &argc, &argument, nullptr, nullptr);
    const bool valid = argc == 1 && napi_typeof(env, argument, &type) == napi_ok && type == napi_string &&
        napi_get_value_string_utf8(env, argument, nullptr, 0, &length) == napi_ok && length <= 256;
    napi_get_boolean(env, valid && setControllerSecret(napiText(env, argument)), &result); return result;
}
napi_value ControllerSecret(napi_env env, napi_callback_info)
{
    const std::string secret = controllerSecret(); napi_value result;
    napi_create_string_utf8(env, secret.data(), secret.size(), &result); return result;
}
napi_value RuntimeInfo(napi_env env, napi_callback_info)
{
    const std::string text = runtimeInfo();
    napi_value result;
    napi_create_string_utf8(env, text.c_str(), text.size(), &result);
    return result;
}
napi_value LocalSocksOptions(napi_env env, napi_callback_info)
{
    const auto text = localSocksOptions(); napi_value result;
    napi_create_string_utf8(env, text.data(), text.size(), &result); return result;
}
napi_value ConfigureRuntimeDirectory(napi_env env, napi_callback_info info)
{
    size_t argc = 1; napi_value argument = nullptr, result;
    napi_get_cb_info(env, info, &argc, &argument, nullptr, nullptr);
    napi_get_boolean(env, configureRuntimeDirectory(napiText(env, argument)), &result); return result;
}
napi_value SetRuntimeMode(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argument = nullptr, result;
    napi_get_cb_info(env, info, &argc, &argument, nullptr, nullptr);
    napi_get_boolean(env, setRuntimeMode(napiText(env, argument)), &result);
    return result;
}

napi_value Start(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[2] = {nullptr, nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    std::string path;
    if (argc > 0 && argv[0] != nullptr) {
        size_t length = 0;
        napi_get_value_string_utf8(env, argv[0], nullptr, 0, &length);
        path.resize(length + 1);
        napi_get_value_string_utf8(env, argv[0], path.data(), length + 1, &length);
        path.resize(length);
    }
    int32_t port = 9090;
    if (argc > 1 && argv[1] != nullptr) napi_get_value_int32(env, argv[1], &port);
    napi_value result;
    napi_get_boolean(env, startCore(path, port), &result);
    return result;
}

napi_value Validate(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    std::string error;
    std::string content;
    if (argc > 0) {
        size_t length = 0;
        napi_get_value_string_utf8(env, argv[0], nullptr, 0, &length);
        content.resize(length + 1);
        napi_get_value_string_utf8(env, argv[0], content.data(), length + 1, &length);
        content.resize(length);
    }
    ParsedConfig parsed;
    parseConfigText(content, parsed, error);
    napi_value result;
    napi_create_string_utf8(env, error.c_str(), error.size(), &result);
    return result;
}

napi_value ProtectFile(napi_env env,napi_callback_info info)
{
    size_t argc=1;napi_value argument=nullptr,result;int32_t fd=-1;
    const bool valid=napi_get_cb_info(env,info,&argc,&argument,nullptr,nullptr)==napi_ok&&argc==1&&
        argument!=nullptr&&napi_get_value_int32(env,argument,&fd)==napi_ok;
    napi_get_boolean(env,valid&&protectFileDescriptor(fd),&result);return result;
}

napi_value ValidateSniffer(napi_env env, napi_callback_info info)
{
    size_t argc = 1; napi_value argument = nullptr, result;
    napi_get_cb_info(env, info, &argc, &argument, nullptr, nullptr);
    const auto error = snifferDraftError(argc ? napiText(env, argument) : "");
    napi_create_string_utf8(env, error.data(), error.size(), &result); return result;
}

napi_value RuleEditor(napi_env env, napi_callback_info info)
{
    size_t argc = 5; napi_value args[5] = {nullptr, nullptr, nullptr, nullptr, nullptr}, result; bool render = false;
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc > 2) napi_get_value_bool(env, args[2], &render);
    const std::string json = ruleEditorJson(argc > 0 ? napiText(env, args[0]) : "", argc > 1 ? napiText(env, args[1]) : "", render, argc > 3 ? napiText(env, args[3]) : "", argc > 4 ? napiText(env, args[4]) : "");
    napi_create_string_utf8(env, json.data(), json.size(), &result); return result;
}

napi_value ObjectEditor(napi_env env, napi_callback_info info)
{
    size_t argc = 5; napi_value args[5] = {nullptr, nullptr, nullptr, nullptr, nullptr}, result; bool validate = true;
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc > 3) napi_get_value_bool(env, args[3], &validate);
    const std::string json = objectEditorJson(argc > 0 ? napiText(env, args[0]) : "", argc > 1 ? napiText(env, args[1]) : "", argc > 2 ? napiText(env, args[2]) : "", validate, argc > 4 ? napiText(env, args[4]) : "");
    napi_create_string_utf8(env, json.data(), json.size(), &result); return result;
}

napi_value ObjectDraft(napi_env env, napi_callback_info info)
{
    size_t argc = 4; napi_value args[4] = {nullptr, nullptr, nullptr, nullptr}, result; bool validate = true;
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc > 3) napi_get_value_bool(env, args[3], &validate);
    const std::string json = objectDraftJson(argc > 0 ? napiText(env, args[0]) : "", argc > 1 ? napiText(env, args[1]) : "", argc > 2 ? napiText(env, args[2]) : "", validate);
    napi_create_string_utf8(env, json.data(), json.size(), &result); return result;
}

napi_value ShareLinks(napi_env env, napi_callback_info info)
{
    size_t argc = 2; napi_value args[2] = {nullptr, nullptr}, result;
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    const std::string json = shareLinksJson(argc > 0 ? napiText(env, args[0]) : "", argc > 1 ? napiText(env, args[1]) : "[]");
    napi_create_string_utf8(env, json.data(), json.size(), &result); return result;
}

napi_value BackupYaml(napi_env env, napi_callback_info info)
{
    size_t argc = 1; napi_value argument = nullptr, result;
    napi_get_cb_info(env, info, &argc, &argument, nullptr, nullptr);
    std::string output, error;
    if (argc != 1 || !backupYamlText(napiText(env, argument), output, error)) {
        napi_throw_error(env, nullptr, error.empty() ? "Invalid backup YAML" : error.c_str()); return nullptr;
    }
    napi_create_string_utf8(env, output.data(), output.size(), &result); return result;
}

napi_value BackupInflate(napi_env env, napi_callback_info info)
{
    size_t argc = 2, size = 0, offset = 0; napi_value args[2] = {nullptr, nullptr}, buffer = nullptr, result; void* data = nullptr;
    napi_typedarray_type type; uint32_t expected = 0;
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    std::vector<unsigned char> output;
    if (argc != 2 || napi_get_typedarray_info(env, args[0], &type, &size, &data, &buffer, &offset) != napi_ok || type != napi_uint8_array ||
        napi_get_value_uint32(env, args[1], &expected) != napi_ok || !backupInflate(static_cast<const unsigned char*>(data), size, expected, output)) {
        napi_throw_error(env, nullptr, "ZIP compressed data or size is invalid"); return nullptr;
    }
    void* destination = nullptr;
    if (napi_create_arraybuffer(env, output.size(), &destination, &buffer) != napi_ok) { napi_throw_error(env, nullptr, "Cannot allocate ZIP output"); return nullptr; }
    if (!output.empty()) std::memcpy(destination, output.data(), output.size());
    if (napi_create_typedarray(env, napi_uint8_array, output.size(), buffer, 0, &result) != napi_ok) { napi_throw_error(env, nullptr, "Cannot allocate ZIP result"); return nullptr; } return result;
}

napi_value Stop(napi_env env, napi_callback_info info)
{
    stopCore();
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

napi_value IsRunning(napi_env env, napi_callback_info info)
{
    napi_value result;
    napi_get_boolean(env, g_state.running.load(), &result);
    return result;
}

napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        {"startAsync", nullptr, StartAsync, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"stopAsync", nullptr, StopAsync, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"info", nullptr, RuntimeInfo, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"localSocksOptions", nullptr, LocalSocksOptions, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"configureRuntimeDirectory", nullptr, ConfigureRuntimeDirectory, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"setControllerSecret", nullptr, SetControllerSecret, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"controllerSecret", nullptr, ControllerSecret, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"setMode", nullptr, SetRuntimeMode, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"start", nullptr, Start, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"validate", nullptr, Validate, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"validateSniffer", nullptr, ValidateSniffer, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"ruleEditor", nullptr, RuleEditor, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"objectEditor", nullptr, ObjectEditor, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"objectDraft", nullptr, ObjectDraft, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"shareLinks", nullptr, ShareLinks, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"backupYaml", nullptr, BackupYaml, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"backupInflate", nullptr, BackupInflate, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"protectFile", nullptr, ProtectFile, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"stop", nullptr, Stop, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"isRunning", nullptr, IsRunning, nullptr, nullptr, nullptr, napi_default, nullptr}
    };
    napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties);
    return exports;
}

#endif // CLAHSOS_HOST_TEST
} // namespace

#ifndef CLAHSOS_HOST_TEST
NAPI_MODULE(clash_core, Init)
#endif
