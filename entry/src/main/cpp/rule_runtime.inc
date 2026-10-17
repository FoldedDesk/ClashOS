struct RuleProviderJob {
    RuleProvider provider;std::string profile;uint64_t epoch=0,generation=0;
};
bool writeRuleCache(const RuleProviderJob& job,const std::string& body,std::string& error)
{
    if(job.profile.empty()){error="Rule provider cache directory is unavailable";return false;}
    const auto destination=ruleProviderCachePath(job.profile,job.provider);
    const auto temporary=destination+".tmp-"+std::to_string(getpid())+"-"+std::to_string(job.epoch)+"-"+std::to_string(job.generation);
    const int fd=open(temporary.c_str(),O_WRONLY|O_CREAT|O_EXCL,0600);
    if(fd<0){error="Cannot create rule provider cache";return false;}
    const std::string content="# ClahsOS rule source: "+ruleProviderIdentity(job.provider)+"\n"+body;
    size_t offset=0;bool ok=true;
    while(offset<content.size()){const ssize_t count=write(fd,content.data()+offset,content.size()-offset);if(count<0&&errno==EINTR)continue;if(count<=0){ok=false;break;}offset+=count;}
    if(ok)ok=fsync(fd)==0;if(close(fd)!=0)ok=false;
    if(ok)ok=std::rename(temporary.c_str(),destination.c_str())==0;
    if(!ok){unlink(temporary.c_str());error="Cannot persist rule provider cache";}return ok;
}
void replaceRuleSnapshotLocked(RuleProvider& provider,std::shared_ptr<const RuleData> data)
{
    provider.data=std::move(data);provider.updatedAt=utcNow();provider.lastError.clear();++g_state.configRevision;
    refreshGeoRequirementsLocked();
    coreLog("info","Rule provider "+provider.name+" updated: "+std::to_string(provider.data->count)+" rules");
}
std::vector<RuleProviderJob> collectRuleProviderUpdates(HealthClock::time_point now=HealthClock::now())
{
    std::lock_guard<std::mutex> lock(g_state.mutex);std::vector<RuleProviderJob> jobs;
    for(auto& provider:g_state.ruleProviders) {
        if(provider.type=="inline"||provider.updating||(!provider.forceUpdate&&(now<provider.nextUpdate||(provider.interval==0&&provider.updateGeneration>0))))continue;
        provider.forceUpdate=false;provider.updating=true;++provider.updateGeneration;
        provider.nextUpdate=now+std::chrono::seconds(provider.interval>0?provider.interval:86400);
        jobs.push_back({provider,g_state.configPath,g_state.profileEpoch,provider.updateGeneration});
    }
    return jobs;
}
bool applyRuleProviderUpdate(const RuleProviderJob& job,const std::string& body,std::shared_ptr<const RuleData> data,std::string error)
{
    std::lock_guard<std::mutex> lock(g_state.mutex);if(g_state.profileEpoch!=job.epoch)return false;
    auto found=std::find_if(g_state.ruleProviders.begin(),g_state.ruleProviders.end(),[&](const auto& provider){return provider.name==job.provider.name;});
    if(found==g_state.ruleProviders.end()||found->updateGeneration!=job.generation||ruleProviderIdentity(*found)!=ruleProviderIdentity(job.provider))return false;
    found->updating=false;if(!g_state.running.load())return false;
    if(error.empty()&&!validateRuleGraph(g_state.ruleProviders,found->name,data,error)){}
    if(error.empty()&&found->type=="http"&&!writeRuleCache(job,body,error)){}
    if(!error.empty()) {
        found->lastError=error;found->nextUpdate=HealthClock::now()+std::chrono::seconds(found->interval>0?std::min(found->interval,60):60);
        coreLog("warning","Rule provider "+found->name+" update failed: "+error);return false;
    }
    replaceRuleSnapshotLocked(*found,std::move(data));return true;
}
void runRuleProviderUpdate(const RuleProviderJob& job)
{
    std::string body,error;std::shared_ptr<const RuleData> data;bool read=false;
    if(job.provider.type=="file") {
        std::string path;read=readRuleCache(job.profile,job.provider,body,error,path);
        if(!read){path=resolveProviderFile(job.profile,job.provider.path);read=!path.empty()&&readProviderFile(path,job.provider.sizeLimit,body,error);if(path.empty())error="Rule provider file must be inside the configuration directory";}
    } else {
        ProxyNode route;
        {std::lock_guard<std::mutex> lock(g_state.mutex);if(g_state.profileEpoch!=job.epoch)return;TestTarget target;parseTestUrl(job.provider.url,target);
         const RouteContext context{target.host,"rule-provider","tcp"};route=resolveProxyLocked(job.provider.downloadProxy,&context);}
        std::map<std::string,std::string> headers;read=providerHttpDownload(job.provider,route,body,headers,error);
    }
    if(read&&!parseRuleContent(job.provider,body,data,error))read=false;
    if(!read&&error.empty())error="Cannot read rule provider resource";
    applyRuleProviderUpdate(job,body,std::move(data),error);
}
void ruleProviderLoop()
{
    while(g_state.running.load()) {
        auto jobs=collectRuleProviderUpdates();std::atomic<size_t> next{0};std::vector<std::thread> workers;
        auto run=[&](){for(;;){const size_t index=next.fetch_add(1);if(index>=jobs.size()||!g_state.running.load())break;runRuleProviderUpdate(jobs[index]);}};
        for(size_t i=1;i<std::min<size_t>(4,jobs.size());++i)try{workers.emplace_back(run);}catch(...){break;}
        run();for(auto& worker:workers)worker.join();
        std::unique_lock<std::mutex> wait(g_healthWaitMutex);g_healthWake.wait_for(wait,std::chrono::milliseconds(500));
    }
}
std::string ruleProviderJsonLocked(const RuleProvider& provider)
{
    return "{\"name\":\""+jsonEscape(provider.name)+"\",\"type\":\"Rule\",\"vehicleType\":\""+
        std::string(provider.type=="http"?"HTTP":provider.type=="file"?"File":"Inline")+"\",\"behavior\":\""+jsonEscape(provider.behavior)+
        "\",\"format\":\""+jsonEscape(provider.format)+"\",\"ruleCount\":"+std::to_string(provider.data?provider.data->count:0)+
        ",\"ready\":"+(provider.data?"true":"false")+",\"updating\":"+((provider.updating||provider.forceUpdate)?"true":"false")+
        ",\"updatedAt\":\""+jsonEscape(provider.updatedAt)+"\",\"error\":\""+jsonEscape(provider.lastError)+"\"}";
}
std::string ruleProvidersJsonLocked(const std::string& name)
{
    std::string json="{\"providers\":{";bool first=true;
    for(const auto& provider:g_state.ruleProviders) {
        if(!name.empty()&&provider.name!=name)continue;
        if(!name.empty())return ruleProviderJsonLocked(provider);
        if(!first)json+=',';first=false;json+="\""+jsonEscape(provider.name)+"\":"+ruleProviderJsonLocked(provider);
    }
    return name.empty()?json+"}}":"{\"error\":\"Rule provider not found\"}";
}
std::string rulePayloadJsonLocked(const RuleProvider& provider,size_t limit)
{
    std::vector<std::string> payload;bool truncated=false;
    if(provider.data) {
        if(provider.behavior=="domain")payload=provider.data->domains.preview(limit+1);
        else if(provider.behavior=="classical") {
            for(const auto& rule:provider.data->classical) {if(payload.size()>limit)break;payload.push_back(rule.kind+(rule.kind=="match"?"":","+rule.value)+(rule.noResolve?",no-resolve":""));}
        } else for(const auto& range:provider.data->ranges) {
            if(payload.size()>limit)break;
            char first[INET6_ADDRSTRLEN]{},last[INET6_ADDRSTRLEN]{};
            inet_ntop(range.family==4?AF_INET:AF_INET6,range.first.data()+(range.family==4?12:0),first,sizeof(first));
            inet_ntop(range.family==4?AF_INET:AF_INET6,range.last.data()+(range.family==4?12:0),last,sizeof(last));
            payload.push_back(std::string(first)+" - "+last);
        }
        if(payload.size()>limit){payload.resize(limit);truncated=true;}
        size_t bytes=0;
        for(size_t i=0;i<payload.size();++i) {
            if(payload[i].size()>128*1024-bytes){payload.resize(i);truncated=true;break;}
            bytes+=payload[i].size();
        }
    }
    std::string json="{\"ruleCount\":"+std::to_string(provider.data?provider.data->count:0)+",\"truncated\":"+(truncated?"true":"false")+",\"payload\":[";
    for(size_t i=0;i<payload.size();++i){if(i>0)json+=',';json+="\""+jsonEscape(payload[i])+"\"";}return json+"]}";
}
std::string ruleProviderControlLocked(const std::string& method,const std::string& path,const std::string& body)
{
    const bool fileApi=path.rfind("/clahsos/rule-providers/",0)==0;
    const size_t prefix=std::string(fileApi?"/clahsos/rule-providers/":"/providers/rules/").size(),end=path.find('?',prefix);
    const std::string rest=path.substr(prefix,end==std::string::npos?std::string::npos:end-prefix);
    const size_t slash=rest.find('/');const std::string name=urlDecode(rest.substr(0,slash));
    if(!fileApi&&method=="GET"&&rest.empty())return ruleProvidersJsonLocked("");
    auto found=std::find_if(g_state.ruleProviders.begin(),g_state.ruleProviders.end(),[&](const auto& provider){return provider.name==name;});
    if(found==g_state.ruleProviders.end())return "{\"error\":\"Rule provider not found\"}";
    if(fileApi) {
        if(slash==std::string::npos||rest.substr(slash+1)!="file"||found->type!="file"||queryValue(path,"profile")!=g_state.configPath)
            return "{\"error\":\"Select a file rule provider in the current profile\"}";
        std::string content,error,source;std::shared_ptr<const RuleData> data;
        if(method=="PUT") {
            const auto requested=bodyValue(body,"path");source=resolveProviderFile(g_state.configPath,requested);
            const size_t leaf=requested.find_last_of('/');const auto nameOnly=requested.substr(leaf==std::string::npos?0:leaf+1);
            if(source.empty()||nameOnly.rfind(".rule-import-",0)!=0)return "{\"error\":\"Select a rule file with the document picker\"}";
        } else if(method=="DELETE")source=resolveProviderFile(g_state.configPath,found->path);
        else return "{\"error\":\"Unsupported rule file operation\"}";
        if(source.empty()||!readProviderFile(source,found->sizeLimit,content,error)||!parseRuleContent(*found,content,data,error)||!validateRuleGraph(g_state.ruleProviders,found->name,data,error))
            return "{\"error\":\""+jsonEscape(error.empty()?"Configured rule file is unavailable":error)+"\"}";
        const uint64_t generation=found->updateGeneration+1;RuleProviderJob job{*found,g_state.configPath,g_state.profileEpoch,generation};
        if(method=="PUT"&&!writeRuleCache(job,content,error))return "{\"error\":\""+jsonEscape(error)+"\"}";
        if(method=="DELETE"&&unlink(ruleProviderCachePath(g_state.configPath,*found).c_str())!=0&&errno!=ENOENT)return "{\"error\":\"Cannot remove imported rule cache\"}";
        found->updating=false;found->forceUpdate=false;found->updateGeneration=generation;
        replaceRuleSnapshotLocked(*found,std::move(data));return "{}";
    }
    if(method=="GET"&&slash==std::string::npos)return ruleProviderJsonLocked(*found);
    if(method=="GET"&&rest.substr(slash+1)=="payload")return rulePayloadJsonLocked(*found,1000);
    if(method=="PUT"&&slash==std::string::npos) {
        const auto profile=queryValue(path,"profile");
        if(!profile.empty()&&profile!=g_state.configPath)return "{\"error\":\"Current profile changed before the rule update request\"}";
        if(found->type=="inline")return "{\"error\":\"Edit the current configuration to update inline rules\"}";
        found->forceUpdate=true;wakeHealthChecks();return "{}";
    }
    return "{\"error\":\"Unsupported rule provider operation\"}";
}
