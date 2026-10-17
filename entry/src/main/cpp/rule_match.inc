using RuleSnapshots = std::map<std::string,std::pair<std::string,std::shared_ptr<const RuleData>>>;
#ifdef CLAHSOS_HOST_TEST
std::function<std::vector<std::string>(const std::string&)> g_testRuleResolver;
#endif

// A process-wide, bounded system-DNS queue keeps resolver waits outside the configuration lock.
// Resolver tasks own only their shared queue/query data, never the core or a connection descriptor.
std::vector<std::string> resolveSystemAddresses(const std::string& host,HealthClock::time_point deadline)
{
    struct Query {
        std::mutex mutex;std::condition_variable ready;bool done=false;
        HealthClock::time_point expires{};std::vector<std::string> addresses;
    };
    struct Resolver {
        std::mutex mutex;std::condition_variable wake;
        std::deque<std::pair<std::string,std::shared_ptr<Query>>> queue;
        std::map<std::string,std::shared_ptr<Query>> cache;
    };
    static auto resolver=std::make_shared<Resolver>();
    static std::once_flag started;
    std::call_once(started,[state=resolver]() {
        for(int worker=0;worker<4;++worker)try {
            std::thread([state]() {
                for(;;) {
                    std::pair<std::string,std::shared_ptr<Query>> task;
                    {std::unique_lock<std::mutex> lock(state->mutex);state->wake.wait(lock,[&]{return !state->queue.empty();});task=std::move(state->queue.front());state->queue.pop_front();}
                    addrinfo hints{};hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;addrinfo* result=nullptr;
                    std::vector<std::string> addresses;
                    if(getaddrinfo(task.first.c_str(),nullptr,&hints,&result)==0) {
                        for(auto* item=result;item!=nullptr&&addresses.size()<16;item=item->ai_next) {
                            char text[INET6_ADDRSTRLEN]{};const void* bytes=nullptr;
                            if(item->ai_family==AF_INET)bytes=&reinterpret_cast<sockaddr_in*>(item->ai_addr)->sin_addr;
                            else if(item->ai_family==AF_INET6)bytes=&reinterpret_cast<sockaddr_in6*>(item->ai_addr)->sin6_addr;
                            if(bytes&&inet_ntop(item->ai_family,bytes,text,sizeof(text))&&std::find(addresses.begin(),addresses.end(),text)==addresses.end())addresses.push_back(text);
                        }
                        freeaddrinfo(result);
                    }
                    {std::lock_guard<std::mutex> lock(task.second->mutex);task.second->addresses=std::move(addresses);task.second->done=true;
                     task.second->expires=HealthClock::now()+std::chrono::seconds(task.second->addresses.empty()?30:300);}
                    task.second->ready.notify_all();
                }
            }).detach();
        } catch(...) { /* Requests still have a bounded wait if a worker cannot be created. */ }
    });
    if(deadline==HealthClock::time_point{})deadline=HealthClock::now()+std::chrono::milliseconds(1500);
    else deadline=std::min(deadline,HealthClock::now()+std::chrono::milliseconds(1500));
    if(g_probeDeadline!=HealthClock::time_point{})deadline=std::min(deadline,g_probeDeadline);
    if(deadline<=HealthClock::now())return {};
    std::shared_ptr<Query> query;const std::string key=lower(host);
    {
        std::lock_guard<std::mutex> lock(resolver->mutex);
        auto found=resolver->cache.find(key);
        if(found!=resolver->cache.end()) {
            std::lock_guard<std::mutex> item(found->second->mutex);
            if(found->second->done&&HealthClock::now()>=found->second->expires)resolver->cache.erase(found);
            else query=found->second;
        }
        if(!query) {
            if(resolver->queue.size()>=32)return {};
            if(resolver->cache.size()>=128) {
                auto expired=std::find_if(resolver->cache.begin(),resolver->cache.end(),[](const auto& item){std::lock_guard<std::mutex> lock(item.second->mutex);return item.second->done;});
                if(expired==resolver->cache.end())return {};resolver->cache.erase(expired);
            }
            query=std::make_shared<Query>();resolver->cache[key]=query;resolver->queue.push_back({key,query});resolver->wake.notify_one();
        }
    }
    std::unique_lock<std::mutex> lock(query->mutex);
    if(!query->ready.wait_until(lock,deadline,[&]{return query->done;}))return {};
    return query->addresses;
}
std::vector<std::string> resolveRuleAddresses(const std::string& host)
{
#ifdef CLAHSOS_HOST_TEST
    if(g_testRuleResolver)return g_testRuleResolver(host);
#endif
    return resolveDnsAddresses(host,DnsPurpose::General,HealthClock::now()+std::chrono::milliseconds(1500));
}
RuleVerdict matchRuleAddresses(RuleQuery& query,bool noResolve,const std::function<bool(const std::string&)>& matches)
{
    int family;std::array<unsigned char,16> address{};
    if(ruleIpAddress(query.host,family,address))return matches(query.host)?RuleVerdict::Yes:RuleVerdict::No;
    if(!query.resolved&&!noResolve){query.ips=resolveRuleAddresses(query.host);query.resolved=true;}
    for(const auto& ip:query.ips)if(matches(ip))return RuleVerdict::Yes;
    return query.resolved&&query.ips.empty()&&!noResolve?RuleVerdict::Unavailable:RuleVerdict::No;
}
RuleVerdict evaluateRule(const ProxyRule& rule,RuleQuery& query,const RuleSnapshots& providers,bool noResolve=false,size_t depth=0)
{
    if(depth>32)return RuleVerdict::Unavailable;
    noResolve=noResolve||rule.noResolve;
    if(rule.kind=="rule-set") {
        const auto found=providers.find(rule.value);if(found==providers.end()||!found->second.second)return RuleVerdict::Unavailable;
        const auto& data=*found->second.second;
        if(found->second.first=="domain")return data.domains.matches(query.host)?RuleVerdict::Yes:RuleVerdict::No;
        if(found->second.first=="ipcidr")return matchRuleAddresses(query,noResolve,[&](const std::string& ip){return ruleRangesMatch(data.ranges,ip);});
        bool unknown=false;
        for(const auto& child:data.classical){const auto result=evaluateRule(child,query,providers,noResolve,depth+1);if(result==RuleVerdict::Yes)return result;if(result==RuleVerdict::Unavailable)unknown=true;}
        return unknown?RuleVerdict::Unavailable:RuleVerdict::No;
    }
    if(rule.kind=="and"||rule.kind=="or"||rule.kind=="not") {
        bool unknown=false;
        for(const auto& child:rule.conditions) {
            const auto result=evaluateRule(child,query,providers,noResolve,depth+1);
            if(rule.kind=="not")return result==RuleVerdict::Unavailable?result:result==RuleVerdict::Yes?RuleVerdict::No:RuleVerdict::Yes;
            if(rule.kind=="and"&&result==RuleVerdict::No)return RuleVerdict::No;
            if(rule.kind=="or"&&result==RuleVerdict::Yes)return RuleVerdict::Yes;
            if(result==RuleVerdict::Unavailable)unknown=true;
        }
        return unknown?RuleVerdict::Unavailable:rule.kind=="and"?RuleVerdict::Yes:RuleVerdict::No;
    }
    if(rule.kind=="geosite") {
        int family=0;std::array<unsigned char,16> address{};if(ruleIpAddress(query.host,family,address))return RuleVerdict::No;
        const auto found=query.geo.find("geosite");if(found==query.geo.end()||!found->second)return RuleVerdict::Unavailable;
        const auto matcher=geoSiteMatcher(*found->second,rule.value);if(!matcher->error.empty())return RuleVerdict::Unavailable;
        return geoSiteMatch(*matcher,query.host)?RuleVerdict::Yes:RuleVerdict::No;
    }
    if(rule.kind=="geoip"||rule.kind=="src-geoip"||rule.kind=="ip-asn"||rule.kind=="src-ip-asn") {
        const bool source=rule.kind.rfind("src-",0)==0,asn=rule.kind.find("asn")!=std::string::npos;
        int family=0;std::array<unsigned char,16> address{};
        if(!source&&noResolve&&!query.resolved&&!ruleIpAddress(query.host,family,address))return RuleVerdict::No;
        if(source&&!ruleIpAddress(query.source,family,address))return RuleVerdict::No;
        const auto found=query.geo.find(asn?"asn":"geoip");if(found==query.geo.end()||!found->second)return RuleVerdict::Unavailable;
        const auto& database=*found->second;
        if(!asn&&database.kind=="geoip"&&!database.ips.count(lower(rule.value)))return RuleVerdict::Unavailable;
        auto matches=[&](const std::string& ip) {
            if(!asn)return geoIpMatch(database,rule.value,ip);
            MMDB_lookup_result_s result{};MMDB_entry_data_s value{};
            return geoMmdbEntry(database,ip,result)&&MMDB_get_value(&result.entry,&value,"autonomous_system_number",nullptr)==MMDB_SUCCESS&&value.has_data&&value.type==MMDB_DATA_TYPE_UINT32&&value.uint32==std::strtoul(rule.value.c_str(),nullptr,10);
        };
        if(source)return matches(query.source)?RuleVerdict::Yes:RuleVerdict::No;
        return matchRuleAddresses(query,noResolve,matches);
    }
    if(rule.kind=="ip-cidr"||rule.kind=="ip-cidr6") {
        RuleIpRange range;if(!parseRuleCidr(rule.value,range))return RuleVerdict::No;
        return matchRuleAddresses(query,noResolve,[&](const std::string& ip){return ruleRangesMatch({range},ip);});
    }
    if(rule.kind=="src-ip-cidr"||rule.kind=="src-ip-cidr6") {RuleIpRange range;return parseRuleCidr(rule.value,range)&&ruleRangesMatch({range},query.source)?RuleVerdict::Yes:RuleVerdict::No;}
    if(rule.kind=="dst-port")return rulePortPattern(rule.value,query.port)?RuleVerdict::Yes:RuleVerdict::No;
    if(rule.kind=="domain-wildcard")return rule.domainPattern&&rule.domainPattern->matches(query.host)?RuleVerdict::Yes:RuleVerdict::No;
    if(rule.kind=="domain-regex")return rule.pattern&&rule.pattern->matches(query.host)?RuleVerdict::Yes:RuleVerdict::No;
    return ruleMatches(rule,query.host,query.port,query.network)?RuleVerdict::Yes:RuleVerdict::No;
}
