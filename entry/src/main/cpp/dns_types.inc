enum class DnsPurpose { General, Direct, Proxy, Bootstrap };
struct DnsEndpoint {
    std::string transport="udp",host,path="/dns-query",route="DIRECT";
    int port=53;
    bool bootstrap=false;
    bool routeExplicit=false;
    bool diagnostic=false;
};
struct DnsRecord {
    std::string name,data;
    uint16_t type=1;
    uint32_t ttl=0;
    int section=0;
    std::vector<unsigned char> raw;
};
struct DnsQueryOptions {
    bool edns=false,dnssecOk=false,checkingDisabled=false,cacheOnly=false;
    uint16_t udpSize=1232;
    std::vector<DnsEndpoint> servers;
};
struct DnsAnswer {
    std::string name,server,error;
    uint16_t type=1;
    int rcode=0,delay=0;
    bool cached=false,truncated=false;
    std::vector<DnsRecord> records;
    std::vector<unsigned char> wire;
    uint32_t wireAge=0;
    bool wireComplete=true;
};
struct DnsPolicy {
    std::string expression;
    std::shared_ptr<RuleDomainIndex> pattern;
    std::vector<DnsEndpoint> servers;
};
struct DnsHost {
    std::string expression;
    std::shared_ptr<RuleDomainIndex> pattern;
    std::vector<std::string> addresses;
};
struct DnsCacheEntry { DnsAnswer answer;HealthClock::time_point stored{},expires{},used{}; };
struct DnsConfig {
    bool enabled=false,ipv6=false,useHosts=true,respectRules=false,directFollowPolicy=false;
    bool geoipFallback=false;
    std::string geoipCode="cn";
    std::string enhancedMode="redir-host",listen;
    std::string listenHost;
    int listenPort=0;
    std::vector<DnsEndpoint> servers,bootstrap,proxy,direct,fallback;
    std::vector<DnsPolicy> policies,proxyPolicies;
    std::vector<DnsHost> hosts;
    std::vector<std::shared_ptr<RuleDomainIndex>> fallbackDomains;
    std::vector<RuleIpRange> fallbackRanges;
    std::vector<std::string> warnings;
    std::mutex cacheMutex;
    std::map<std::string,DnsCacheEntry> cache;
    uint64_t cacheHits=0,queries=0,cacheGeneration=0;
};
extern thread_local std::shared_ptr<DnsConfig> g_dnsTransportConfig;
struct DnsListener:std::enable_shared_from_this<DnsListener> {
    int tcp=-1,udp=-1,port=0;
    std::string host,address;
    std::mutex mutex;
    std::condition_variable wake;
    std::shared_ptr<DnsConfig> config;
    std::set<int> sockets;
    bool started=false,retired=false;
    std::atomic<bool> active{false};
    std::atomic<uint64_t> queries{0},rejected{0};
    std::thread thread;
    void activate(const std::shared_ptr<DnsConfig>&);
    void stop();
    ~DnsListener();
};
bool prepareDnsListener(const std::shared_ptr<DnsConfig>&,std::shared_ptr<DnsListener>&,std::string&);
void replaceDnsListenerLocked(const std::shared_ptr<DnsListener>&);
std::vector<std::string> resolveSystemAddresses(const std::string&,HealthClock::time_point = {});
std::vector<std::string> resolveDnsAddresses(const std::string&,DnsPurpose,HealthClock::time_point);
DnsAnswer queryDns(const std::string&,uint16_t,DnsPurpose,HealthClock::time_point,
    const std::shared_ptr<DnsConfig>& = nullptr,const DnsQueryOptions* = nullptr);
std::string dnsQueryResponse(const std::string&);
std::string dnsStatusJson();
thread_local bool g_dnsBootstrapConnection=false;
