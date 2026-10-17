// Provider lifecycle: download outside locks, validate, persist atomically, then replace the live snapshot.
struct ProviderUpdateJob {
    ProxyProvider provider;ProxyNode route;std::string profile;uint64_t epoch=0,generation=0;
};
bool sameProviderNodes(const std::vector<ProxyNode>& first,const std::vector<ProxyNode>& second)
{
    if(first.size()!=second.size())return false;
    for(size_t i=0;i<first.size();++i) {
        const auto& a=first[i];const auto& b=second[i];
        if(std::tie(a.name,a.type,a.server,a.port,a.cipher,a.password,a.username,a.httpHeaders,a.uuid,a.alterId,a.tls,a.udp,a.udpConfigured,a.network,a.wsPath,a.wsHeaders,a.serverName,a.skipCertVerify,a.alpn,a.transportError)!=
           std::tie(b.name,b.type,b.server,b.port,b.cipher,b.password,b.username,b.httpHeaders,b.uuid,b.alterId,b.tls,b.udp,b.udpConfigured,b.network,b.wsPath,b.wsHeaders,b.serverName,b.skipCertVerify,b.alpn,b.transportError))return false;
    }
    return true;
}
std::vector<ProviderUpdateJob> collectProviderUpdates(HealthClock::time_point now=HealthClock::now())
{
    std::lock_guard<std::mutex> guard(g_state.mutex);std::vector<ProviderUpdateJob> jobs;
    for(ProxyProvider& provider:g_state.providers) {
        if(provider.type=="inline"||provider.updating||(!provider.forceUpdate&&(now<provider.nextUpdate||(provider.interval==0&&provider.updateGeneration>0))))continue;
        provider.forceUpdate=false;provider.updating=true;++provider.updateGeneration;
        provider.nextUpdate=now+std::chrono::seconds(provider.interval>0?provider.interval:3600);
        jobs.push_back({provider,resolveProxyLocked(provider.downloadProxy),g_state.configPath,g_state.profileEpoch,provider.updateGeneration});
    }
    return jobs;
}
bool writeProviderCache(const ProviderUpdateJob& job,const std::string& body,std::string& error)
{
    if(job.profile.empty()){error="Provider cache directory is unavailable";return false;}
    const std::string destination=providerCachePath(job.profile,job.provider);
    const std::string temporary=destination+".tmp-"+std::to_string(getpid())+"-"+std::to_string(job.epoch)+"-"+std::to_string(job.generation);
    const int fd=open(temporary.c_str(),O_WRONLY|O_CREAT|O_EXCL,0600);
    if(fd<0){error="Cannot create provider cache";return false;}
    const std::string data="# ClahsOS provider source: "+providerIdentity(job.provider)+"\n"+body;
    size_t offset=0;bool ok=true;
    while(offset<data.size()) {
        const ssize_t count=write(fd,data.data()+offset,data.size()-offset);
        if(count<0&&errno==EINTR)continue;if(count<=0){ok=false;break;}offset+=static_cast<size_t>(count);
    }
    if(ok)ok=fsync(fd)==0;if(close(fd)!=0)ok=false;
    if(ok)ok=std::rename(temporary.c_str(),destination.c_str())==0;
    if(!ok){unlink(temporary.c_str());error="Cannot persist provider cache";}return ok;
}
void replaceProviderSnapshotLocked(ProxyProvider& provider,std::vector<ProxyNode> nodes)
{
    const bool changed=!sameProviderNodes(provider.nodes,nodes);
    provider.nodes=std::move(nodes);provider.updatedAt=utcNow();provider.lastError.clear();
    provider.health.health.clear();provider.health.checking=false;++provider.health.checkGeneration;provider.health.nextCheck={};
    if(changed){++g_state.configRevision;rebuildProviderNodesLocked();}
    coreLog("info","Provider "+provider.name+" updated: "+std::to_string(provider.nodes.size())+" proxies");
    wakeHealthChecks();
}
std::string importProviderFileLocked(const std::string& name,const std::string& body)
{
    auto provider=std::find_if(g_state.providers.begin(),g_state.providers.end(),[&](const ProxyProvider& item){return item.name==name;});
    if(provider==g_state.providers.end()||provider->type!="file")return "{\"error\":\"Select a file provider before importing\"}";
    std::vector<ProxyNode> nodes;std::string error;
    if(!parseProviderContent(*provider,body,nodes,error)||!providerNamesAvailableLocked(name,nodes,error))return "{\"error\":\""+jsonEscape(error)+"\"}";
    ++provider->updateGeneration;provider->updating=false;provider->forceUpdate=false;
    ProviderUpdateJob job{*provider,{},g_state.configPath,g_state.profileEpoch,provider->updateGeneration};
    if(!writeProviderCache(job,body,error))return "{\"error\":\""+jsonEscape(error)+"\"}";
    provider->nextUpdate=HealthClock::now()+std::chrono::seconds(std::max(1,provider->interval));
    replaceProviderSnapshotLocked(*provider,std::move(nodes));return "{}";
}
std::string resetProviderFileLocked(const std::string& name)
{
    auto provider=std::find_if(g_state.providers.begin(),g_state.providers.end(),[&](const ProxyProvider& item){return item.name==name;});
    if(provider==g_state.providers.end()||provider->type!="file")return "{\"error\":\"File provider not found\"}";
    const std::string source=resolveProviderFile(g_state.configPath,provider->path);std::string body,error;std::vector<ProxyNode> nodes;
    if(source.empty())return "{\"error\":\"Configured provider file is unavailable inside the configuration directory\"}";
    if(!readProviderFile(source,provider->sizeLimit,body,error)||!parseProviderContent(*provider,body,nodes,error)||!providerNamesAvailableLocked(name,nodes,error))return "{\"error\":\""+jsonEscape(error)+"\"}";
    const std::string cache=providerCachePath(g_state.configPath,*provider);
    if(unlink(cache.c_str())!=0&&errno!=ENOENT)return "{\"error\":\"Cannot remove the imported provider cache\"}";
    ++provider->updateGeneration;provider->updating=false;provider->forceUpdate=false;
    replaceProviderSnapshotLocked(*provider,std::move(nodes));return "{}";
}
bool applyProviderUpdate(const ProviderUpdateJob& job,const std::string& body,std::vector<ProxyNode> nodes,std::string error)
{
    std::lock_guard<std::mutex> guard(g_state.mutex);
    if(g_state.profileEpoch!=job.epoch)return false;
    auto current=std::find_if(g_state.providers.begin(),g_state.providers.end(),[&](const ProxyProvider& item){return item.name==job.provider.name;});
    if(current==g_state.providers.end()||current->updateGeneration!=job.generation||providerIdentity(*current)!=providerIdentity(job.provider))return false;
    if(!g_state.running.load()){current->updating=false;return false;}
    if(error.empty()&&!providerNamesAvailableLocked(current->name,nodes,error)){}
    if(error.empty()&&current->type=="http"&&!writeProviderCache(job,body,error)){}
    current->updating=false;
    if(!error.empty()) {
        current->lastError=error;
        current->nextUpdate=HealthClock::now()+std::chrono::seconds(current->interval>0?std::min(current->interval,60):60);
        coreLog("warning","Provider "+current->name+" update failed: "+error);return false;
    }
    replaceProviderSnapshotLocked(*current,std::move(nodes));return true;
}
void runProviderUpdate(const ProviderUpdateJob& job)
{
    std::string body,error;std::vector<ProxyNode> nodes;bool fetched=false;
    if(job.provider.type=="file") {
        std::string path;fetched=readManagedProviderCache(job.profile,job.provider,body,error,path);
        if(!fetched) {
            path=resolveProviderFile(job.profile,job.provider.path);
            if(path.empty())error="Provider file must be inside the configuration directory";
            else fetched=readProviderFile(path,job.provider.sizeLimit,body,error);
        }
    } else {
        ProxyNode route;
        {std::lock_guard<std::mutex> guard(g_state.mutex);if(g_state.profileEpoch!=job.epoch)return;
            TestTarget target;parseTestUrl(job.provider.url,target);const RouteContext context{target.host,"provider","tcp"};
            route=resolveProxyLocked(job.provider.downloadProxy,&context);}
        std::map<std::string,std::string> headers;fetched=providerHttpDownload(job.provider,route,body,headers,error);
    }
    if(fetched&&!parseProviderContent(job.provider,body,nodes,error))fetched=false;
    if(!fetched&&error.empty())error="Provider content is unavailable";
    applyProviderUpdate(job,body,std::move(nodes),error);
}
void providerLoop()
{
    while(g_state.running.load()) {
        const auto jobs=collectProviderUpdates();
        for(const ProviderUpdateJob& job:jobs) {
            if(!g_state.running.load())break;
            {std::lock_guard<std::mutex> guard(g_state.mutex);if(g_state.profileEpoch!=job.epoch)continue;}
            runProviderUpdate(job);
        }
        std::unique_lock<std::mutex> wait(g_healthWaitMutex);g_healthWake.wait_for(wait,std::chrono::milliseconds(500));
    }
}
std::string providerNodeJsonLocked(const ProxyNode& node)
{
    return proxyNodeJsonLocked(node);
}
std::string providerJsonLocked(const ProxyProvider& provider)
{
    std::string result="{\"name\":\""+jsonEscape(provider.name)+"\",\"type\":\"Proxy\",\"vehicleType\":\""+
        std::string(provider.type=="http"?"HTTP":provider.type=="file"?"File":"Inline")+"\",\"updatedAt\":\""+jsonEscape(provider.updatedAt)+
        "\",\"updating\":"+((provider.updating||provider.forceUpdate)?"true":"false")+",\"checking\":"+(provider.health.checking?"true":"false")+
        ",\"error\":\""+jsonEscape(provider.lastError)+"\",\"proxies\":[";
    for(size_t i=0;i<provider.nodes.size();++i){if(i>0)result+=',';result+=providerNodeJsonLocked(provider.nodes[i]);}
    return result+"]}";
}
std::string providersJsonLocked(const std::string& name)
{
    if(!name.empty()) {
        for(const ProxyProvider& provider:g_state.providers)if(provider.name==name)return providerJsonLocked(provider);
        return "{\"error\":\"Proxy provider not found\"}";
    }
    std::string result="{\"providers\":{";bool first=true;
    for(const ProxyProvider& provider:g_state.providers){if(!first)result+=',';first=false;result+='"'+jsonEscape(provider.name)+"\":"+providerJsonLocked(provider);}
    return result+"}}";
}

std::string providerMemberDelayResponse(const std::string& path)
{
    const size_t query=path.find('?');if(query==std::string::npos)return "{\"error\":\"Provider member probe URL is required\"}";
    const std::string rest=path.substr(19,query-19);const size_t slash=rest.find('/');
    if(slash==std::string::npos||rest.size()<slash+14||rest.substr(rest.size()-12)!="/healthcheck")return "{\"error\":\"Invalid provider member probe\"}";
    const std::string providerName=urlDecode(rest.substr(0,slash)),member=urlDecode(rest.substr(slash+1,rest.size()-slash-13));
    ProxyNode node;uint64_t revision;bool found=false;
    {
        std::lock_guard<std::mutex> guard(g_state.mutex);revision=g_state.configRevision;
        for(const ProxyProvider& provider:g_state.providers)if(provider.name==providerName)for(const ProxyNode& candidate:provider.nodes)if(candidate.name==member){node=candidate;found=true;break;}
    }
    if(!found)return "{\"error\":\"Provider member not found\"}";
    TestTarget target;if(!parseTestUrl(queryValue(path,"url"),target))return "{\"error\":\"A valid HTTP(S) probe URL is required\"}";
    const std::string expected=queryValue(path,"expected").empty()?"200-399":queryValue(path,"expected");
    if(!validProbeStatus(expected))return "{\"error\":\"Invalid expected HTTP status\"}";
    int timeout=std::atoi(queryValue(path,"timeout").c_str());timeout=std::clamp(timeout<=0?5000:timeout,100,60000);
    std::string error;const int delay=probeNode(node,target,timeout,expected,error);
    {std::lock_guard<std::mutex> guard(g_state.mutex);if(g_state.configRevision==revision)g_state.delays[member]=delay;}
    return delay>0?"{\"delay\":"+std::to_string(delay)+"}":"{\"error\":\""+jsonEscape(error)+"\"}";
}
