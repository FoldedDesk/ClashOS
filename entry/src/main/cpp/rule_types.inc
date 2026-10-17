// Immutable compiled rule-provider snapshots; downloading never mutates a live matcher.
struct RuleDomainIndex {
    std::vector<unsigned char> labels;
    std::vector<uint32_t> edges;
    std::vector<uint64_t> leaves;
    bool matches(const std::string& host) const;
    std::vector<std::string> preview(size_t limit) const;
};
struct RuleIpRange {
    int family = 0;
    std::array<unsigned char,16> first{}, last{};
};
struct RuleData {
    size_t count = 0;
    RuleDomainIndex domains;
    std::vector<RuleIpRange> ranges;
    std::vector<ProxyRule> classical;
};
struct RuleProvider : ProxyProvider {
    std::string behavior, format = "yaml";
    std::shared_ptr<const RuleData> data;
};
struct RuleQuery {
    std::string host, source, network = "tcp";
    int port = 0;
    bool resolved = false;
    std::vector<std::string> ips;
    std::map<std::string,std::shared_ptr<const struct GeoDatabase>> geo;
};
enum class RuleVerdict { No, Yes, Unavailable };
