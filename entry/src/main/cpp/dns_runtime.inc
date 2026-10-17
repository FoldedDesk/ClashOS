thread_local unsigned g_dnsDepth=0;
thread_local std::shared_ptr<DnsConfig> g_dnsTransportConfig;
std::atomic<unsigned> g_dnsNetworkRequests{0};
#ifdef CLAHSOS_HOST_TEST
std::function<int(const DnsEndpoint&)> g_testDnsDatagram;
#endif
struct DnsTransportScope {
    bool previousBootstrap=g_dnsBootstrapConnection;
    std::shared_ptr<DnsConfig> previousConfig=g_dnsTransportConfig;
    explicit DnsTransportScope(const std::shared_ptr<DnsConfig>& config) {g_dnsBootstrapConnection=true;g_dnsTransportConfig=config;}
    ~DnsTransportScope(){g_dnsBootstrapConnection=previousBootstrap;g_dnsTransportConfig=previousConfig;}
};
int dnsRemaining(HealthClock::time_point deadline)
{
    return static_cast<int>(std::clamp<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline-HealthClock::now()).count(),0,60000));
}
std::string dnsEndpointLabel(const DnsEndpoint& endpoint)
{
    if(endpoint.transport=="system")return "system";
    return endpoint.transport+"://"+(endpoint.host.find(':')==std::string::npos?endpoint.host:"["+endpoint.host+"]")+":"+std::to_string(endpoint.port);
}
bool dnsListenerLoopback(int fd,const DnsEndpoint& endpoint)
{
    if(endpoint.diagnostic)return false;
    std::shared_ptr<DnsListener> listener;{std::lock_guard<std::mutex> lock(g_state.mutex);listener=g_state.dnsListener;}
    if(!listener||!listener->active.load()||endpoint.port!=listener->port)return false;
    UdpEndpoint local,remote;local.length=sizeof(local.address);remote.length=sizeof(remote.address);
    if(getsockname(fd,reinterpret_cast<sockaddr*>(&local.address),&local.length)!=0||getpeername(fd,reinterpret_cast<sockaddr*>(&remote.address),&remote.length)!=0)return false;
    const auto address=udpEndpointHost(local);return !address.empty()&&address==udpEndpointHost(remote)&&udpEndpointPort(remote)==listener->port;
}
ProxyNode dnsOutbound(const DnsEndpoint& endpoint,const std::shared_ptr<DnsConfig>& config,HealthClock::time_point deadline,std::string& error)
{
    ProxyNode node;node.name="DIRECT";node.type="direct";
    if(!g_state.running.load()){node.type="reject";error="DNS core is stopping";return node;}
    auto current=[&](){std::lock_guard<std::mutex> lock(g_state.mutex);return config==g_state.dns;};
    if(!current()){node.type="reject";error="DNS configuration changed before outbound selection";return node;}
    if(!endpoint.bootstrap&&(endpoint.route=="RULES"||(!endpoint.routeExplicit&&config->respectRules))) {
        std::vector<std::string> addresses;int family=0;std::array<unsigned char,16> ip{};
        if(ruleIpAddress(endpoint.host,family,ip))addresses={endpoint.host};
        else {auto a=queryDns(endpoint.host,1,DnsPurpose::Bootstrap,deadline,config);addresses=dnsAnswerAddresses(a);}
        if(addresses.empty()&&config->ipv6){auto aaaa=queryDns(endpoint.host,28,DnsPurpose::Bootstrap,deadline,config);addresses=dnsAnswerAddresses(aaaa);}
        // Existing numeric DNS servers need no bootstrap query.
        if(addresses.empty()){error="Cannot resolve DNS server for rule routing";node.type="reject";return node;}
        node=activeProxyNode(endpoint.host,endpoint.port,endpoint.transport=="udp"?"udp":"tcp","dns",&addresses);
        if(!current()){node.type="reject";error="DNS configuration changed during outbound selection";return node;}
    } else if(!endpoint.bootstrap&&endpoint.route!="DIRECT") {
        std::lock_guard<std::mutex> lock(g_state.mutex);RouteContext context{endpoint.host,"dns",endpoint.transport=="udp"?"udp":"tcp"};node=resolveProxyLocked(endpoint.route,&context);
        if(config!=g_state.dns){node.type="reject";error="DNS configuration changed during outbound selection";return node;}
        if(endpoint.transport=="udp")for(const auto& name:node.chain) {
            const auto group=std::find_if(g_state.groups.begin(),g_state.groups.end(),[&](const auto& group){return group.name==name;});
            if(group!=g_state.groups.end()&&group->disableUdp)node.type="reject";
        }
    }
    if(node.type=="reject")error="DNS outbound was rejected or is unavailable";
    return node;
}
bool dnsProxyDatagram(const DnsEndpoint& endpoint,const std::shared_ptr<DnsConfig>& config,ProxyNode node,
    const std::vector<unsigned char>& question,std::vector<unsigned char>& response,HealthClock::time_point deadline,std::string& error)
{
    if(!supportsUdp(node)){error="The selected DNS outbound does not support UDP";return false;}
    DnsTransportScope bootstrap(config);ProbeDeadlineScope scope(std::max(1,dnsRemaining(deadline)));
    const auto address=shadowsocksAddress(endpoint.host,endpoint.port);
    if(address.empty()){error="Invalid DNS datagram destination";return false;}
    if(node.chain.empty())node.chain.push_back(node.name);
    node.matchedRule="DNS "+dnsEndpointLabel(endpoint);
    UdpTarget target{endpoint.host,endpoint.port,address.size()};
    auto flow=openUdpFlow(g_currentClient,target,node);
    if(!flow){error="Cannot start the DNS UDP outbound";return false;}
    std::vector<unsigned char> packet(3,0);packet.insert(packet.end(),address.begin(),address.end());packet.insert(packet.end(),question.begin(),question.end());
    if(!writeUdpFlow(*flow,packet,target)){error="Cannot send DNS through the UDP outbound";return false;}
    for(int attempts=0;attempts<32&&dnsRemaining(deadline)>0;++attempts) {
        const bool pending=flow->streamed()&&flow->streamPending();
        pollfd watch{flow->streamed()?flow->notifyMain:flow->fd,POLLIN,0};int ready=0;
        if(!pending)do{ready=poll(&watch,1,dnsRemaining(deadline));}while(ready<0&&errno==EINTR);
        if(!pending&&ready<=0)break;
        std::vector<unsigned char> reply;size_t size=0;
        if(!readUdpFlow(*flow,reply,size)) {
            if(flow->failed||udpConnectionCancelled(flow->fd))break;
            if(errno==EAGAIN||errno==EWOULDBLOCK||errno==EALREADY||errno==EBADMSG)continue;
            error="Invalid DNS response from UDP outbound";return false;
        }
        UdpTarget source;if(!parseSocksUdp(reply,source)||source.port!=endpoint.port)continue;
        int family=0;std::array<unsigned char,16> ip{};
        if(ruleIpAddress(endpoint.host,family,ip)&&source.host!=endpoint.host)continue;
        const size_t start=3+source.headerSize;
        if(reply.size()-start<12||dnsRead16(reply,start)!=dnsRead16(question,0))continue;
        recordTransfer(flow->fd,false,reply.size()-start);
        response.assign(reply.begin()+start,reply.end());return true;
    }
    error="DNS UDP outbound response timed out or was cancelled";return false;
}
bool dnsStreamExchange(const DnsEndpoint& endpoint,const std::shared_ptr<DnsConfig>& config,
    const std::vector<unsigned char>& question,std::vector<unsigned char>& response,HealthClock::time_point deadline,std::string& error,uint32_t* responseAge=nullptr)
{
    DnsTransportScope bootstrap(config);ProbeDeadlineScope scope(std::max(1,dnsRemaining(deadline)));
    const ProxyNode node=dnsOutbound(endpoint,config,deadline,error);if(!error.empty())return false;
    if(endpoint.transport=="https") {
        std::string encoded=vmBase64(question);std::replace(encoded.begin(),encoded.end(),'+','-');std::replace(encoded.begin(),encoded.end(),'/','_');
        while(!encoded.empty()&&encoded.back()=='=')encoded.pop_back();
        ProxyProvider provider;provider.sizeLimit=65535;provider.timeout=std::max(1,dnsRemaining(deadline));provider.headers["Accept"]="application/dns-message";
        const std::string authority=endpoint.host.find(':')==std::string::npos?endpoint.host:"["+endpoint.host+"]";
        provider.url="https://"+authority+":"+std::to_string(endpoint.port)+endpoint.path+(endpoint.path.find('?')==std::string::npos?"?":"&")+"dns="+encoded;
        std::string body;std::map<std::string,std::string> headers;
        if(!providerHttpDownload(provider,node,body,headers,error))return false;
        const auto content=lower(trim(headers["content-type"].substr(0,headers["content-type"].find(';'))));
        if(content!="application/dns-message"){error="HTTPS DNS response is not application/dns-message";return false;}
        if(headers.count("age")) {
            size_t age=0;if(!providerDecimal(headers["age"],0xffffffffU,age)){error="Invalid HTTPS DNS cache Age";return false;}
            if(responseAge)*responseAge=static_cast<uint32_t>(age);
        }
        response.assign(body.begin(),body.end());return true;
    }
    ProxyStream stream;
    if(!openProxyStream(node,endpoint.host,endpoint.port,stream,error,std::max(1,dnsRemaining(deadline))))return false;
    if(node.type=="direct"&&dnsListenerLoopback(stream.fd,endpoint)){error="DNS upstream resolves to its own listener";return false;}
    HttpTunnel channel(stream);if(endpoint.transport=="tls"&&!channel.startTls(endpoint.host,error))return false;
    std::vector<unsigned char> framed;dnsPut16(framed,question.size());framed.insert(framed.end(),question.begin(),question.end());
    if(!channel.write(std::string(framed.begin(),framed.end()))){error="Cannot send DNS stream request";return false;}
    auto read=[&](unsigned char* data,size_t length) {
        size_t at=0;while(at<length){const auto n=channel.read(data+at,length-at);if(n<=0||static_cast<size_t>(n)>length-at)return false;at+=n;}return true;
    };
    std::array<unsigned char,2> size{};
    if(!read(size.data(),size.size())){error="DNS stream response timed out or closed";return false;}
    const size_t length=(static_cast<size_t>(size[0])<<8)|size[1];
    if(length<12){error="Invalid DNS stream response length";return false;}
    response.resize(length);if(!read(response.data(),length)){error="Truncated DNS stream response";return false;}return true;
}
bool dnsUdpExchange(const DnsEndpoint& endpoint,const std::shared_ptr<DnsConfig>& config,const std::vector<unsigned char>& question,
    std::vector<unsigned char>& response,HealthClock::time_point deadline,std::string& error)
{
    int fd=-1;
    const auto node=dnsOutbound(endpoint,config,deadline,error);if(!error.empty())return false;
    if(node.type!="direct")return dnsProxyDatagram(endpoint,config,node,question,response,deadline,error);
#ifdef CLAHSOS_HOST_TEST
    if(g_testDnsDatagram)fd=g_testDnsDatagram(endpoint);
    else
#endif
    {
        std::vector<std::string> addresses;int family=0;std::array<unsigned char,16> ip{};
        if(ruleIpAddress(endpoint.host,family,ip))addresses={endpoint.host};
        else {addresses=dnsAnswerAddresses(queryDns(endpoint.host,1,DnsPurpose::Bootstrap,deadline,config));if(addresses.empty()&&config->ipv6)addresses=dnsAnswerAddresses(queryDns(endpoint.host,28,DnsPurpose::Bootstrap,deadline,config));}
        for(const auto& ip:addresses) {
            sockaddr_storage address{};socklen_t length=0;
            if(inet_pton(AF_INET,ip.c_str(),&reinterpret_cast<sockaddr_in*>(&address)->sin_addr)==1){auto* a=reinterpret_cast<sockaddr_in*>(&address);a->sin_family=AF_INET;a->sin_port=htons(endpoint.port);length=sizeof(*a);}
            else if(inet_pton(AF_INET6,ip.c_str(),&reinterpret_cast<sockaddr_in6*>(&address)->sin6_addr)==1){auto* a=reinterpret_cast<sockaddr_in6*>(&address);a->sin6_family=AF_INET6;a->sin6_port=htons(endpoint.port);length=sizeof(*a);}
            if(!length)continue;fd=socket(address.ss_family,SOCK_DGRAM,0);if(fd<0)continue;
            if(connect(fd,reinterpret_cast<sockaddr*>(&address),length)==0)break;close(fd);fd=-1;
        }
    }
    if(fd<0){error="Cannot connect to DNS datagram server";return false;}
    trackSocket(fd);if(g_currentClient>=0)attachUpstream(g_currentClient,fd);
    struct Close{int fd;~Close(){closeSocket(fd);}}close{fd};
    if(!g_state.running.load()){error="DNS core is stopping";return false;}
    if(dnsListenerLoopback(fd,endpoint)){error="DNS upstream resolves to its own listener";return false;}
    socketTimeout(fd,std::max(1,dnsRemaining(deadline)));
    if(send(fd,question.data(),question.size(),UDP_SEND_FLAGS)!=static_cast<ssize_t>(question.size())){error="Cannot send DNS datagram";return false;}
    for(int attempts=0;attempts<16&&dnsRemaining(deadline)>0;++attempts) {
        pollfd wait{fd,POLLIN,0};int ready;do{ready=poll(&wait,1,dnsRemaining(deadline));}while(ready<0&&errno==EINTR);
        if(ready<=0)break;
        response.resize(65536);const auto size=recv(fd,response.data(),response.size(),0);if(size<=0)break;response.resize(size);
        if(response.size()>=12&&dnsRead16(response,0)==dnsRead16(question,0))return true;
    }
    error="DNS datagram response timed out";return false;
}
bool dnsPolicyMatches(const DnsPolicy& policy,const std::string& host,std::string& error)
{
    if(policy.expression=="*")return true;
    if(policy.pattern)return policy.pattern->matches(host);
    if(policy.expression.rfind("geosite:",0)==0) {
        std::shared_ptr<const GeoDatabase> data;{std::lock_guard<std::mutex> lock(g_state.mutex);for(const auto& resource:g_state.geo.resources)if(resource.kind=="geosite")data=resource.data;}
        if(!data){error="DNS GeoSite database is unavailable";return false;}
        std::istringstream categories(policy.expression.substr(8));std::string category,unavailable;
        while(std::getline(categories,category,',')) {
            const auto matcher=geoSiteMatcher(*data,trim(category));
            if(!matcher->error.empty()){unavailable=matcher->error;continue;}if(geoSiteMatch(*matcher,host))return true;
        }
        if(!unavailable.empty())error=unavailable;return false;
    }
    if(policy.expression.rfind("rule-set:",0)!=0)return false;
    const std::string name=policy.expression.substr(9);RuleSnapshots providers;
    {std::lock_guard<std::mutex> lock(g_state.mutex);for(const auto& provider:g_state.ruleProviders)providers[provider.name]={provider.behavior,provider.data};}
    ProxyRule rule;rule.kind="rule-set";rule.value=name;RuleQuery query;query.host=host;query.resolved=true;
    const auto verdict=evaluateRule(rule,query,providers,true);
    if(verdict==RuleVerdict::Unavailable)error="DNS policy rule provider is unavailable: "+name;
    return verdict==RuleVerdict::Yes;
}
DnsAnswer dnsAskServers(const std::string& name,uint16_t type,const std::vector<DnsEndpoint>& servers,
    const std::shared_ptr<DnsConfig>& config,HealthClock::time_point deadline,const DnsQueryOptions* options=nullptr)
{
    DnsAnswer answer;answer.name=name;answer.type=type;
    for(size_t index=0;index<servers.size()&&dnsRemaining(deadline)>0;++index) {
        const auto& endpoint=servers[index];answer={};answer.name=name;answer.type=type;answer.server=dnsEndpointLabel(endpoint);
        if(endpoint.transport=="system") {
            if(type!=1&&type!=28){answer.error="System resolver supports A/AAAA queries only";continue;}
            for(const auto& address:resolveSystemAddresses(name,deadline)) {
                const bool v6=address.find(':')!=std::string::npos;if(v6!=(type==28))continue;
                answer.records.push_back({name,address,type,60,0});
            }
            if(!answer.records.empty())return answer;answer.error="System DNS returned no address";continue;
        }
        struct Slot{bool active=false;Slot(){active=g_dnsNetworkRequests.fetch_add(1)<16;if(!active)g_dnsNetworkRequests.fetch_sub(1);}~Slot(){if(active)g_dnsNetworkRequests.fetch_sub(1);}}slot;
        if(!slot.active){answer.error="DNS query capacity is exhausted";break;}
        std::vector<unsigned char> random(2),question,response;
        if(!randomBytes(random)||!dnsBuildQuestion(name,type,(static_cast<uint16_t>(random[0])<<8)|random[1],question,options)){answer.error="Cannot build DNS query";break;}
        const int slice=std::max(300,dnsRemaining(deadline)/static_cast<int>(servers.size()-index));
        const auto attemptDeadline=std::min(deadline,HealthClock::now()+std::chrono::milliseconds(slice));std::string error;uint32_t responseAge=0;
        bool received=endpoint.transport=="udp"?dnsUdpExchange(endpoint,config,question,response,attemptDeadline,error):dnsStreamExchange(endpoint,config,question,response,attemptDeadline,error,&responseAge);
        DnsAnswer parsed;
        if(received&&dnsParseResponse(response,name,type,dnsRead16(question,0),parsed)) {
            if(parsed.truncated&&endpoint.transport=="udp") {
                DnsEndpoint tcp=endpoint;tcp.transport="tcp";received=dnsStreamExchange(tcp,config,question,response,deadline,error);
                if(!received||!dnsParseResponse(response,name,type,dnsRead16(question,0),parsed)){answer.error=error.empty()?parsed.error:error;continue;}
            }
            if(parsed.truncated){answer.error="Truncated DNS stream response";continue;}
            if(parsed.rcode==3||std::none_of(parsed.records.begin(),parsed.records.end(),[&](const auto& record){return record.section==0&&record.type==type;}))
                for(auto& record:parsed.records)if(record.section==1&&record.type==6&&record.raw.size()>=4)
                    record.ttl=std::min(record.ttl,std::min<uint32_t>(300,dnsRead32(record.raw,record.raw.size()-4)));
            if(responseAge>0)for(auto& record:parsed.records)record.ttl=record.ttl>responseAge?record.ttl-responseAge:0;
            parsed.wireAge=responseAge;
            parsed.server=dnsEndpointLabel(endpoint);
            if(parsed.rcode==0||parsed.rcode==3)return parsed;answer.error="DNS server returned RCODE "+std::to_string(parsed.rcode);
        } else answer.error=error.empty()?parsed.error:error;
    }
    if(answer.error.empty())answer.error="DNS query timed out or no server is configured";
    return answer;
}
DnsAnswer queryDns(const std::string& input,uint16_t type,DnsPurpose purpose,HealthClock::time_point deadline,const std::shared_ptr<DnsConfig>& provided,const DnsQueryOptions* options)
{
    DnsAnswer answer;answer.type=type;
    if(!dnsNormalizeName(input,answer.name)||type==0||type==251||type==252){answer.error="A valid ASCII/Punycode DNS name and query type are required";return answer;}
    struct Depth{Depth(){++g_dnsDepth;}~Depth(){--g_dnsDepth;}}depth;
    if(g_dnsDepth>8){answer.error="DNS resolution dependency loop";return answer;}
    if(deadline==HealthClock::time_point{})deadline=HealthClock::now()+std::chrono::milliseconds(3500);
    if(g_probeDeadline!=HealthClock::time_point{})deadline=std::min(deadline,g_probeDeadline);
    const auto started=HealthClock::now();
    std::shared_ptr<DnsConfig> config=provided?provided:g_dnsTransportConfig;
    uint64_t revision=0;{std::lock_guard<std::mutex> lock(g_state.mutex);if(!config)config=g_state.dns;revision=g_state.configRevision;}
    if(type==28&&(!g_state.ipv6.load()||(config->enabled&&!config->ipv6))){answer.server="IPv6 disabled";return answer;}
    std::string variant=std::to_string(options?(options->edns?1:0)|(options->dnssecOk?2:0)|(options->checkingDisabled?4:0):0);
    if(options&&!options->servers.empty()) {std::string identity;for(const auto& server:options->servers)identity+=dnsEndpointLabel(server)+'\0'+server.path+'\0'+server.route+'\0'+(server.routeExplicit?"explicit":"default")+'\0';variant+=providerHash(identity);}
    const std::string key=std::to_string(revision)+":"+std::to_string(static_cast<int>(purpose))+":"+std::to_string(type)+":"+variant+":"+answer.name;
    uint64_t cacheGeneration=0;
    {
        std::lock_guard<std::mutex> lock(config->cacheMutex);cacheGeneration=config->cacheGeneration;++config->queries;auto found=config->cache.find(key);
        if(found!=config->cache.end()) {
            if(started<found->second.expires) {
                answer=found->second.answer;answer.cached=true;++config->cacheHits;found->second.used=started;
                const uint32_t elapsed=static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(started-found->second.stored).count());
                answer.wireAge=std::min<uint64_t>(0xffffffffU,static_cast<uint64_t>(answer.wireAge)+elapsed);
                for(auto& record:answer.records)record.ttl=record.ttl>elapsed?record.ttl-elapsed:0;return answer;
            }
            config->cache.erase(found);
        }
    }
    if(config->useHosts&&purpose!=DnsPurpose::Bootstrap&&(type==1||type==28)&&(!options||options->servers.empty())) {
        const DnsHost* selected=configuredDnsHost(*config,answer.name);
        if(selected) {
            answer.server="hosts";
            for(const auto& address:selected->addresses) {
                int family=0;std::array<unsigned char,16> bytes{};
                if(ruleIpAddress(address,family,bytes)) {if((type==1&&family==4)||(type==28&&family==6))answer.records.push_back({answer.name,address,type,60,0});}
                else {
                    auto alias=queryDns(address,type,purpose,deadline,config,options);
                    if(!alias.error.empty()){answer.error=alias.error;return answer;}
                    answer.records.push_back({answer.name,alias.name,5,60,0});answer.records.insert(answer.records.end(),alias.records.begin(),alias.records.end());
                }
            }
            return answer;
        }
    }
    if(options&&options->cacheOnly){answer.error="DNS recursion was not requested";return answer;}
    std::vector<DnsEndpoint> servers=config->servers;bool policySelected=false;
    if(options&&!options->servers.empty()){servers=options->servers;policySelected=true;}
    else if(!config->enabled)servers={DnsEndpoint{"system","system"}};
    else if(purpose==DnsPurpose::Bootstrap) {servers=config->bootstrap.empty()?std::vector<DnsEndpoint>{DnsEndpoint{"system","system"}}:config->bootstrap;for(auto& endpoint:servers)endpoint.bootstrap=true;}
    else {
        const auto& policies=purpose==DnsPurpose::Proxy&&!config->proxy.empty()?config->proxyPolicies:config->policies;
        const bool usePolicy=purpose!=DnsPurpose::Direct||config->direct.empty()||config->directFollowPolicy;
        if(usePolicy)for(const auto& policy:policies)if(dnsPolicyMatches(policy,answer.name,answer.error)){servers=policy.servers;policySelected=true;break;}else if(!answer.error.empty())return answer;
        if(!policySelected&&purpose==DnsPurpose::Proxy&&!config->proxy.empty())servers=config->proxy;
        else if(!policySelected&&purpose==DnsPurpose::Direct&&!config->direct.empty())servers=config->direct;
    }
    bool forceFallback=false;
    if(config->enabled&&purpose!=DnsPurpose::Bootstrap&&!policySelected&&!config->fallback.empty())
        for(const auto& pattern:config->fallbackDomains)if(pattern->matches(answer.name)){forceFallback=true;break;}
    const auto primaryDeadline=!forceFallback&&!policySelected&&!config->fallback.empty()?std::min(deadline,started+(deadline-started)/2):deadline;
    answer=dnsAskServers(answer.name,type,forceFallback?config->fallback:servers,config,primaryDeadline,options);
    if(!forceFallback&&!policySelected&&config->enabled&&purpose!=DnsPurpose::Bootstrap&&!config->fallback.empty()) {
        bool rejected=!answer.error.empty();for(const auto& address:dnsAnswerAddresses(answer))if(ruleRangesMatch(config->fallbackRanges,address))rejected=true;
        if(config->geoipFallback&&!rejected) {
            std::shared_ptr<const GeoDatabase> data;
            {std::lock_guard<std::mutex> lock(g_state.mutex);if(config!=g_state.dns){answer.error="DNS configuration changed during GeoIP filtering";return answer;}const auto snapshots=geoSnapshotsLocked();const auto found=snapshots.find("geoip");if(found!=snapshots.end())data=found->second;}
            if(!data||(data->kind=="geoip"&&!data->ips.count(config->geoipCode))){answer.error="DNS fallback GeoIP database/category is unavailable";return answer;}
            for(const auto& address:dnsAnswerAddresses(answer))if(!geoIpMatch(*data,config->geoipCode,address))rejected=true;
        }
        if(rejected)answer=dnsAskServers(answer.name,type,config->fallback,config,deadline,options);
    }
    const bool hasAnswer=type==1||type==28?!dnsAnswerAddresses(answer).empty():std::any_of(answer.records.begin(),answer.records.end(),[&](const auto& record){return record.section==0&&record.type==type;});
    if(answer.error.empty()&&answer.rcode==0&&!hasAnswer) {
        auto alias=std::find_if(answer.records.begin(),answer.records.end(),[&](const auto& record){return record.section==0&&record.type==5&&record.name==answer.name;});
        if(alias!=answer.records.end()&&type!=5) {
            auto result=queryDns(alias->data,type,purpose,deadline,config,options);answer.wireComplete=false;
            if(!result.error.empty())answer.error=result.error;else {answer.records.insert(answer.records.end(),result.records.begin(),result.records.end());answer.rcode=result.rcode;}
        }
    }
    answer.delay=std::max(1,static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(HealthClock::now()-started).count()));
    uint32_t ttl=3600;bool cacheable=false;
    for(const auto& record:answer.records)if(record.section==0){ttl=std::min(ttl,record.ttl);cacheable=true;}
    const bool noTypedRecord=std::none_of(answer.records.begin(),answer.records.end(),[&](const auto& record){return record.section==0&&record.type==type;});
    if(answer.rcode==3||noTypedRecord)for(const auto& record:answer.records)if(record.type==6&&record.section==1) {
        const auto last=record.data.find_last_of(' ');const auto minimum=std::strtoul(record.data.substr(last+1).c_str(),nullptr,10);
        ttl=std::min(ttl,std::min<uint32_t>(record.ttl,std::min<unsigned long>(minimum,300)));cacheable=true;break;
    }
    if(answer.error.empty()&&cacheable&&ttl>0) {
        std::lock_guard<std::mutex> lock(config->cacheMutex);
        if(cacheGeneration!=config->cacheGeneration)return answer;
        if(config->cache.size()>=1024){auto old=std::min_element(config->cache.begin(),config->cache.end(),[](const auto& a,const auto& b){return a.second.used<b.second.used;});config->cache.erase(old);}
        config->cache[key]={answer,HealthClock::now(),HealthClock::now()+std::chrono::seconds(ttl),HealthClock::now()};
    }
    return answer;
}
std::vector<std::string> resolveDnsAddresses(const std::string& host,DnsPurpose purpose,HealthClock::time_point deadline)
{
    int family=0;std::array<unsigned char,16> address{};if(ruleIpAddress(host,family,address))return {host};
    std::shared_ptr<DnsConfig> config=g_dnsTransportConfig;if(!config){std::lock_guard<std::mutex> lock(g_state.mutex);config=g_state.dns;}
    auto a=queryDns(host,1,purpose,deadline,config);auto result=dnsAnswerAddresses(a);
    if(g_state.ipv6.load()&&(!config->enabled||config->ipv6)&&dnsRemaining(deadline)>0) {
        auto aaaa=queryDns(host,28,purpose,deadline,config);auto ipv6=dnsAnswerAddresses(aaaa);result.insert(result.end(),ipv6.begin(),ipv6.end());
    }
    return result;
}
std::string dnsQueryResponse(const std::string& path)
{
    const std::string kind=queryValue(path,"type"),name=queryValue(path,"name");uint16_t type=1;
    const std::map<std::string,uint16_t> known{{"A",1},{"AAAA",28},{"CNAME",5},{"NS",2},{"MX",15},{"TXT",16},{"SOA",6},{"PTR",12},{"SRV",33},{"HTTPS",65},{"SVCB",64}};
    if(!kind.empty()) {
        const auto found=known.find(kind);if(found!=known.end())type=found->second;
        else {char* end=nullptr;const auto parsed=std::strtoul(kind.c_str(),&end,10);if(end==kind.c_str()||*end||parsed==0||parsed>65535)return "{\"error\":\"Invalid DNS query type\"}";type=parsed;}
    }
    DnsQueryOptions options;const std::string server=queryValue(path,"server");
    if(!server.empty()) {DnsEndpoint endpoint;std::string error;if(!parseDnsEndpoint(server,endpoint,error))return "{\"error\":\""+jsonEscape(error)+"\"}";endpoint.diagnostic=true;options.servers.push_back(std::move(endpoint));}
    const auto answer=queryDns(name,type,DnsPurpose::General,HealthClock::now()+std::chrono::milliseconds(5000),nullptr,&options);
    if(!answer.error.empty())return "{\"error\":\""+jsonEscape(answer.error)+"\"}";
    std::ostringstream out;out<<"{\"Status\":"<<answer.rcode<<",\"Question\":[{\"name\":\""<<jsonEscape(answer.name)<<"\",\"type\":"<<type<<"}],\"Answer\":[";
    bool first=true;for(const auto& record:answer.records)if(record.section==0){if(!first)out<<',';first=false;out<<"{\"name\":\""<<jsonEscape(record.name)<<"\",\"type\":"<<record.type<<",\"TTL\":"<<record.ttl<<",\"data\":\""<<jsonEscape(record.data)<<"\"}";}
    out<<"],\"server\":\""<<jsonEscape(answer.server)<<"\",\"cached\":"<<(answer.cached?"true":"false")<<",\"delay\":"<<answer.delay<<'}';return out.str();
}
std::string dnsStatusJson()
{
    std::shared_ptr<DnsConfig> config;std::shared_ptr<DnsListener> listener;{std::lock_guard<std::mutex> lock(g_state.mutex);config=g_state.dns;listener=g_state.dnsListener;}
    std::lock_guard<std::mutex> lock(config->cacheMutex);std::ostringstream out;
    out<<"{\"enabled\":"<<(config->enabled?"true":"false")<<",\"ipv6\":"<<(config->ipv6?"true":"false")<<",\"nameservers\":"<<config->servers.size()<<",\"policies\":"<<config->policies.size()<<",\"hosts\":"<<config->hosts.size()<<",\"cacheEntries\":"<<config->cache.size()<<",\"queries\":"<<config->queries<<",\"cacheHits\":"<<config->cacheHits<<",\"warnings\":[";
    for(size_t i=0;i<config->warnings.size();++i){if(i)out<<',';out<<'"'<<jsonEscape(config->warnings[i])<<'"';}
    out<<"],\"listening\":"<<(listener&&listener->active.load()?"true":"false")<<",\"listen\":\""<<jsonEscape(listener?listener->address:config->listen)<<"\",\"listenerQueries\":"<<(listener?listener->queries.load():0)<<",\"listenerRejected\":"<<(listener?listener->rejected.load():0)<<'}';return out.str();
}
