struct GeoJob {GeoResource resource;std::string profile;uint64_t epoch=0;std::shared_ptr<DnsConfig> dns;};
std::string geoCachePath(const std::string& profile,const GeoResource& resource)
{
    const size_t slash=profile.find_last_of('/');if(slash==std::string::npos)return {};
    return profile.substr(0,slash)+"/.geodata-"+resource.kind+"-"+providerHash(resource.url).substr(0,24)+".cache";
}
GeoSnapshots geoSnapshotsLocked()
{
    GeoSnapshots result;
    for(const auto& resource:g_state.geo.resources) {
        if(resource.kind==(g_state.geo.dat?"geoip":"mmdb"))result["geoip"]=resource.data;
        else if(resource.kind=="geosite"||resource.kind=="asn")result[resource.kind]=resource.data;
    }
    return result;
}
void refreshGeoRequirementsLocked()
{
    for(auto& resource:g_state.geo.resources)resource.required=false;
    auto requireKind=[&](const std::string& kind){for(auto& resource:g_state.geo.resources)if(resource.kind==kind)resource.required=true;};
    std::function<void(const ProxyRule&)> scan=[&](const auto& rule) {
        if(rule.kind=="geoip"||rule.kind=="src-geoip")requireKind(g_state.geo.dat?"geoip":"mmdb");
        if(rule.kind=="geosite")requireKind("geosite");
        if(rule.kind=="ip-asn"||rule.kind=="src-ip-asn")requireKind("asn");
        for(const auto& child:rule.conditions)scan(child);
    };
    for(const auto& rule:g_state.rules)scan(rule);
    for(const auto& provider:g_state.ruleProviders)if(provider.data)for(const auto& rule:provider.data->classical)scan(rule);
    for(const auto* policies:{&g_state.dns->policies,&g_state.dns->proxyPolicies})for(const auto& policy:*policies)if(policy.expression.rfind("geosite:",0)==0)requireKind("geosite");
    if(g_state.dns->geoipFallback)requireKind(g_state.geo.dat?"geoip":"mmdb");
}
void initializeGeoLocked()
{
    for(auto& resource:g_state.geo.resources) {
        const auto path=geoCachePath(g_state.configPath,resource);if(path.empty())continue;
        std::shared_ptr<const GeoDatabase> data;std::string error;
        if(geoReadFile(resource.kind,path,data,error)) {
            resource.data=std::move(data);resource.updatedAt=providerFileTime(path);
            std::ifstream meta(path+".origin");std::string value;std::getline(meta,value);resource.imported=value=="import";
        } else if(access(path.c_str(),F_OK)==0)resource.error=error;
        resource.nextUpdate=resource.data?HealthClock::now()+std::chrono::hours(g_state.geo.interval):HealthClock::time_point{};
    }
    refreshGeoRequirementsLocked();
}
std::vector<GeoJob> collectGeoJobs()
{
    std::lock_guard<std::mutex> lock(g_state.mutex);std::vector<GeoJob> jobs;const auto now=HealthClock::now();
    if(g_state.configPath.empty())return jobs;
    for(auto& resource:g_state.geo.resources) {
        if(resource.updating)continue;
        const bool missing=resource.required&&!resource.data;
        const bool automatic=g_state.geo.autoUpdate&&resource.required&&!resource.imported;
        if(!resource.forceUpdate&&(!(missing||automatic)||now<resource.nextUpdate))continue;
        resource.forceUpdate=false;resource.updating=true;++resource.generation;jobs.push_back({resource,g_state.configPath,g_state.profileEpoch,g_state.dns});
    }
    return jobs;
}
bool geoStage(const GeoJob& job,const std::string& body,std::string& temporary,std::shared_ptr<const GeoDatabase>& data,std::string& error)
{
    const auto destination=geoCachePath(job.profile,job.resource);if(destination.empty()){error="GeoData storage directory is unavailable";return false;}
    if(body.empty()||body.size()>GEO_MAX_BYTES){error="GeoData file is empty or exceeds 64 MB";return false;}
    temporary=destination+".tmp-"+std::to_string(getpid())+"-"+std::to_string(job.epoch)+"-"+std::to_string(job.resource.generation);
    const int fd=open(temporary.c_str(),O_WRONLY|O_CREAT|O_EXCL,0600);
    if(fd<0){error="Cannot create GeoData staging file";return false;}
    bool valid=true;size_t offset=0;
    while(offset<body.size()){const auto count=write(fd,body.data()+offset,body.size()-offset);if(count<0&&errno==EINTR)continue;if(count<=0){valid=false;break;}offset+=count;}
    if(valid)valid=fsync(fd)==0;if(close(fd)!=0)valid=false;
    if(!valid){error="Cannot persist GeoData staging file";return false;}
    return geoReadFile(job.resource.kind,temporary,data,error);
}
bool geoCommit(const GeoJob& job,const std::string& temporary,std::shared_ptr<const GeoDatabase> data,std::string& error,bool imported)
{
    struct Remove{std::string path;~Remove(){if(!path.empty())unlink(path.c_str());}}remove{temporary};
    std::lock_guard<std::mutex> lock(g_state.mutex);
    auto found=std::find_if(g_state.geo.resources.begin(),g_state.geo.resources.end(),[&](const auto& resource){return resource.kind==job.resource.kind;});
    if(g_state.profileEpoch!=job.epoch||found==g_state.geo.resources.end()||found->generation!=job.resource.generation||found->url!=job.resource.url||!g_state.running.load()){error="GeoData configuration changed before update completed";return false;}
    found->updating=false;
    const auto destination=geoCachePath(job.profile,*found);
    if(error.empty()&&(!data||std::rename(temporary.c_str(),destination.c_str())!=0))error="Cannot activate the GeoData file";
    if(!error.empty()){found->error=error;found->nextUpdate=HealthClock::now()+std::chrono::seconds(60);return false;}
    found->data=std::move(data);found->error.clear();found->updatedAt=utcNow();found->imported=imported;found->nextUpdate=HealthClock::now()+std::chrono::hours(g_state.geo.interval);
    const auto metadata=destination+".origin";const int fd=open(metadata.c_str(),O_WRONLY|O_CREAT|O_TRUNC,0600);
    if(fd>=0){const std::string origin=imported?"import\n":"download\n";write(fd,origin.data(),origin.size());close(fd);}
    ++g_state.configRevision;coreLog("info","GeoData "+found->kind+" loaded: "+std::to_string(found->data->count)+" entries");return true;
}
void runGeoJob(const GeoJob& job)
{
    struct Bootstrap {
        bool previous=g_geoBootstrapDns;std::shared_ptr<DnsConfig> config=g_dnsTransportConfig;
        explicit Bootstrap(const std::shared_ptr<DnsConfig>& dns){g_geoBootstrapDns=true;g_dnsTransportConfig=dns;}
        ~Bootstrap(){g_geoBootstrapDns=previous;g_dnsTransportConfig=config;}
    }bootstrap(job.dns);
    ProxyNode route;std::string body,error,temporary;std::shared_ptr<const GeoDatabase> data;
    {std::lock_guard<std::mutex> lock(g_state.mutex);if(g_state.profileEpoch!=job.epoch)return;
     const std::string selected=g_state.groups.empty()?"DIRECT":g_state.groups.front().name;route=resolveProxyLocked(selected);}
    ProxyProvider source;source.url=job.resource.url;source.sizeLimit=GEO_MAX_BYTES;source.timeout=60000;
    std::map<std::string,std::string> headers;
    if(providerHttpDownload(source,route,body,headers,error))geoStage(job,body,temporary,data,error);
    geoCommit(job,temporary,std::move(data),error,false);
}
void geoLoop()
{
    while(g_state.running.load()) {
        for(const auto& job:collectGeoJobs()){if(!g_state.running.load())break;runGeoJob(job);}
        std::unique_lock<std::mutex> wait(g_healthWaitMutex);g_healthWake.wait_for(wait,std::chrono::milliseconds(500));
    }
}
std::string geoStatusLocked()
{
    std::string result="{\"mode\":\""+std::string(g_state.geo.dat?"dat":"mmdb")+"\",\"autoUpdate\":"+(g_state.geo.autoUpdate?"true":"false")+",\"interval\":"+std::to_string(g_state.geo.interval)+",\"resources\":[";
    bool first=true;for(const auto& resource:g_state.geo.resources) {
        if(!first)result+=',';first=false;
        result+="{\"kind\":\""+resource.kind+"\",\"ready\":"+(resource.data?"true":"false")+",\"required\":"+(resource.required?"true":"false")+",\"updating\":"+((resource.updating||resource.forceUpdate)?"true":"false")+",\"imported\":"+(resource.imported?"true":"false")+",\"sourceUrl\":\""+jsonEscape(resource.url)+"\",\"updatedAt\":\""+jsonEscape(resource.updatedAt)+"\",\"error\":\""+jsonEscape(resource.error)+"\",\"bytes\":"+std::to_string(resource.data?resource.data->bytes:0)+",\"count\":"+std::to_string(resource.data?resource.data->count:0)+",\"categories\":"+std::to_string(resource.data?resource.kind=="geoip"?resource.data->ips.size():resource.data->sites.size():0)+"}";
    }
    return result+"]}";
}
std::string geoControl(const std::string& method,const std::string& path,const std::string& body)
{
    if(path=="/clahsos/geodata"&&method=="GET"){std::lock_guard<std::mutex> lock(g_state.mutex);return geoStatusLocked();}
    const std::string rest=path.substr(std::min(path.size(),std::string("/clahsos/geodata/").size()));const size_t slash=rest.find('/');const auto kind=rest.substr(0,slash);
    GeoJob job;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);auto found=std::find_if(g_state.geo.resources.begin(),g_state.geo.resources.end(),[&](const auto& resource){return resource.kind==kind;});
        if(found==g_state.geo.resources.end())return "{\"error\":\"GeoData resource not found\"}";
        if(g_state.configPath.empty())return "{\"error\":\"Select a configuration before managing GeoData\"}";
        if(bodyValue(body,"profile")!=g_state.configPath)return "{\"error\":\"Active configuration changed; try again\"}";
        if(method=="PUT"&&slash==std::string::npos){found->forceUpdate=true;wakeHealthChecks();return "{}";}
        if(slash==std::string::npos||rest.substr(slash+1)!="file")return "{\"error\":\"Unsupported GeoData operation\"}";
        if(method=="DELETE") {
            ++found->generation;found->updating=false;found->forceUpdate=false;const auto cache=geoCachePath(g_state.configPath,*found);
            if(unlink(cache.c_str())!=0&&errno!=ENOENT)return "{\"error\":\"Cannot remove GeoData cache\"}";
            unlink((cache+".origin").c_str());found->data.reset();found->imported=false;found->updatedAt.clear();found->error.clear();found->nextUpdate=HealthClock::now()+std::chrono::seconds(60);++g_state.configRevision;return "{}";
        }
        if(method!="PUT")return "{\"error\":\"Unsupported GeoData method\"}";
        if(found->updating)return "{\"error\":\"GeoData is being updated; retry after it finishes\"}";
        found->forceUpdate=false;found->updating=true;++found->generation;job={*found,g_state.configPath,g_state.profileEpoch,g_state.dns};
    }
    const auto requested=bodyValue(body,"path");const size_t leaf=requested.find_last_of('/');
    std::string dataPath=resolveProviderFile(job.profile,requested),content,error,temporary;std::shared_ptr<const GeoDatabase> data;
    if(dataPath.empty()||requested.substr(leaf==std::string::npos?0:leaf+1).rfind(".geo-import-",0)!=0)error="Select a GeoData file using the document picker";
    else if(readProviderFile(dataPath,GEO_MAX_BYTES,content,error))geoStage(job,content,temporary,data,error);
    if(!geoCommit(job,temporary,std::move(data),error,true))return "{\"error\":\""+jsonEscape(error)+"\"}";return "{}";
}
