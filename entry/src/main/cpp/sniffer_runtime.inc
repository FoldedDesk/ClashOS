struct SniffPlan {
    std::shared_ptr<const SnifferConfig> config;
    std::string original, route, destination, source, protocol;
    int port = 0;
    bool eligible = false;
    std::vector<std::string> originalIps;
};

bool sniffDomainMatches(const RuleDomainIndex& index, const std::vector<std::string>& literals, const std::string& domain)
{
    return index.matches(domain) || std::find(literals.begin(), literals.end(), lower(domain)) != literals.end();
}

bool sniffProtocolPort(const SnifferConfig& config, const std::string& name, int port)
{
    const auto found = config.protocols.find(name);
    if (found == config.protocols.end()) return false;
    return found->second.ports.empty() || std::any_of(found->second.ports.begin(), found->second.ports.end(), [&](const auto& range) { return port >= range.first && port <= range.second; });
}

SniffPlan sniffPlan(const std::string& host, int port, const std::string& source, bool udp = false)
{
    SniffPlan plan; plan.original = plan.route = plan.destination = host; plan.source = source; plan.port = port;
    std::shared_ptr<DnsConfig> dns;
    { std::lock_guard<std::mutex> lock(g_state.mutex); plan.config = g_state.sniffer; dns = g_state.dns; }
    int family = 0; std::array<unsigned char, 16> ip{};
    const bool address = ruleIpAddress(host, family, ip);
    if (address) plan.originalIps.push_back(host);
    const auto& config = *plan.config;
    if (!config.enabled || (udp ? !sniffProtocolPort(config, "QUIC", port) :
        !sniffProtocolPort(config, "HTTP", port) && !sniffProtocolPort(config, "TLS", port)) ||
        ruleRangesMatch(config.sourceRanges, source) || ruleRangesMatch(config.destinationRanges, host) ||
        sniffDomainMatches(config.skipIndex, config.skipLiterals, host)) return plan;
    const bool force = sniffDomainMatches(config.forceIndex, config.forceLiterals, host);
    bool mapped = false;
    if (address && !config.parsePureIp && config.forceDnsMapping && dns && dns->enabled && dns->enhancedMode == "redir-host") {
        // Only live answers learned by our resolver qualify as DNS mappings.
        // The original destination remains available when sniffing fails.
        std::lock_guard<std::mutex> lock(dns->cacheMutex);
        for (const auto& entry : dns->cache) if (entry.second.expires > HealthClock::now() && entry.second.answer.error.empty() && entry.second.answer.rcode == 0) {
            for (const auto& record : entry.second.answer.records) if ((record.type == 1 || record.type == 28) && record.data == host) { mapped = true; break; }
            if (mapped) break;
        }
    }
    plan.eligible = force || (address && (config.parsePureIp || mapped));
    return plan;
}

bool sniffApply(SniffPlan& plan, const std::string& protocol, const SniffRead& result)
{
    if (result.status != SniffStatus::Found || sniffDomainMatches(plan.config->skipIndex, plan.config->skipLiterals, result.host)) return false;
    plan.route = result.host; plan.protocol = protocol;
    if (plan.config->protocols.at(protocol).overrideDestination) { plan.destination = result.host; plan.originalIps.clear(); }
    coreLog("debug", "[Sniffer] " + protocol + " " + plan.original + " -> " + result.host);
    return true;
}

void sniffTcp(int client, SniffPlan& plan, std::string& prefix)
{
    if (!plan.eligible) return;
    const auto deadline = HealthClock::now() + std::chrono::seconds(1);
    for (;;) {
        bool more = false;
        for (const std::string name : {"HTTP", "TLS"}) {
            if (!sniffProtocolPort(*plan.config, name, plan.port)) continue;
            const auto result = name == "HTTP" ? sniffHttp(prefix) : sniffTls(prefix);
            if (result.status == SniffStatus::Found) { sniffApply(plan, name, result); return; }
            more = more || result.status == SniffStatus::Need;
        }
        if (!more || prefix.size() >= SNIFF_LIMIT || HealthClock::now() >= deadline || !g_state.running.load()) return;
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - HealthClock::now()).count();
        pollfd watch{client, POLLIN, 0}; const int ready = poll(&watch, 1, static_cast<int>(std::min<int64_t>(100, std::max<int64_t>(1, remaining))));
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return;
        if (!ready) continue;
        char bytes[16384]; const auto count = recv(client, bytes, std::min(sizeof(bytes), SNIFF_LIMIT - prefix.size()), MSG_DONTWAIT);
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
        if (count <= 0) return;
        prefix.append(bytes, static_cast<size_t>(count));
    }
}
