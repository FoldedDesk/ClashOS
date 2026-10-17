// Explicit hosts overrides require no network access. Ordinary unmapped proxy
// destinations retain remote DNS; configured aliases and IPs stay authoritative.
const DnsHost* configuredDnsHost(const DnsConfig& config,const std::string& name)
{
    if(!config.useHosts)return nullptr;
    const DnsHost* selected=nullptr;
    for(const auto& host:config.hosts)if(host.expression=="*"||host.pattern->matches(name)) {
        std::string exact=lower(trim(host.expression));if(!exact.empty()&&exact.back()=='.')exact.pop_back();
        if(exact==name)return &host;
        if(!selected||host.expression.size()>selected->expression.size())selected=&host;
    }
    return selected;
}

struct DnsHostOverride {
    std::string route,destination,error;
    std::vector<std::string> addresses;
    bool mapped=false;
};

DnsHostOverride dnsHostOverride(const DnsConfig& config,const std::string& input,bool ipv6)
{
    DnsHostOverride result;result.route=result.destination=input;
    int family=0;std::array<unsigned char,16> ip{};std::string normalized;
    if(!config.useHosts||ruleIpAddress(input,family,ip)||!dnsNormalizeName(input,normalized)||!configuredDnsHost(config,normalized))return result;
    result.mapped=true;
    struct Candidate {std::string route,destination;int family=0;};
    std::vector<Candidate> candidates;std::set<std::string> path;size_t remaining=256;
    std::function<bool(const std::string&,size_t)> visit=[&](const std::string& name,size_t depth) {
        if(!remaining||depth>=8){result.error="Hosts alias expansion exceeds its limit";return false;}
        --remaining;
        if(!path.insert(name).second){result.error="Hosts alias loop";return false;}
        const auto* selected=configuredDnsHost(config,name);
        if(!selected)candidates.push_back({name,name,0});
        else for(const auto& address:selected->addresses) {
            int kind=0;std::array<unsigned char,16> bytes{};
            if(ruleIpAddress(address,kind,bytes)) {
                if(kind==4||(kind==6&&ipv6))candidates.push_back({name,address,kind});
            } else {
                std::string alias;
                if(!dnsNormalizeName(address,alias)||!visit(alias,depth+1)){if(result.error.empty())result.error="Invalid hosts alias";return false;}
            }
        }
        path.erase(name);return true;
    };
    if(!visit(normalized,0))return result;
    // Match resolver address-family preference while preserving configured order
    // within each family. Aliases with no local IP remain domain destinations.
    std::stable_sort(candidates.begin(),candidates.end(),[](const auto& a,const auto& b){
        const auto rank=[](int family){return family==4?0:family==6?1:2;};return rank(a.family)<rank(b.family);
    });
    if(candidates.empty()){result.error="Hosts mapping has no enabled destination address";return result;}
    result.route=candidates.front().route;result.destination=candidates.front().destination;
    for(const auto& candidate:candidates)if(candidate.family&&std::find(result.addresses.begin(),result.addresses.end(),candidate.destination)==result.addresses.end())result.addresses.push_back(candidate.destination);
    return result;
}

bool proxyDestination(const ProxyNode& node,const std::string& host,std::string& destination,std::string& error)
{
    destination=host;
    if(node.type!="ss"&&node.type!="vmess"&&node.type!="trojan"&&node.type!="vless"&&node.type!="http"&&node.type!="socks5")return true;
    auto config=node.destinationDns?node.destinationDns:g_dnsTransportConfig;
    if(!config){std::lock_guard<std::mutex> lock(g_state.mutex);config=g_state.dns;}
    if(!config)return true;
    const bool ipv6=node.destinationDns?node.destinationIpv6:g_state.ipv6.load()&&(!config->enabled||config->ipv6);
    const auto mapped=dnsHostOverride(*config,host,ipv6);
    if(!mapped.error.empty()){error=mapped.error;return false;}
    destination=mapped.destination;return true;
}

struct DestinationDnsScope {
    std::shared_ptr<DnsConfig> previous;
    explicit DestinationDnsScope(const ProxyNode& node):previous(g_dnsTransportConfig) {
        if(node.destinationDns)g_dnsTransportConfig=node.destinationDns;
    }
    ~DestinationDnsScope(){g_dnsTransportConfig=std::move(previous);}
};
