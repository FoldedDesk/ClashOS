// A bounded background probe sweep. State is committed only to the configuration/generation it tested.
bool isAutomaticGroup(const ProxyGroup& group) { return group.type=="URLTest"||group.type=="Fallback"; }
void chooseHealthyGroupLocked(ProxyGroup& group)
{
    if(!isAutomaticGroup(group))return;
    auto delay=[&](const std::string& member)->int {
        const auto sample=group.health.find(member);
        if(sample==group.health.end() || resolveProxyLocked(member).name!=sample->second.resolved)return -1;
        return sample->second.delay;
    };
    const std::string before=group.now;
    std::string selected;int best=INT32_MAX;
    if(!group.manual.empty()&&delay(group.manual)!=0)selected=group.manual;
    else {
        for(const std::string& member:group.proxies) {
            const int value=delay(member);
            if(value>0 && value<best){selected=member;best=value;if(group.type=="Fallback")break;}
        }
        if(group.type=="URLTest"&&!selected.empty()) {
            const int current=delay(group.now);
            if(current>0&&current<=best+group.tolerance)selected=group.now;
        }
        if(selected.empty())for(const std::string& member:group.proxies)if(delay(member)<0){selected=member;break;}
    }
    group.now=selected;
    if(before!=selected)coreLog("info","Automatic group "+group.name+" selected "+(selected.empty()?"no healthy member":selected));
}
struct GroupProbeJob {
    std::string group,member,url,expected;
    ProxyNode node;
    int timeout=5000;
    uint64_t revision=0,generation=0;
    std::string provider;
};
std::vector<GroupProbeJob> collectHealthJobs(HealthClock::time_point now=HealthClock::now())
{
    std::lock_guard<std::mutex> guard(g_state.mutex);std::vector<GroupProbeJob> jobs;
    for(ProxyGroup& group:g_state.groups) {
        if((!isAutomaticGroup(group)&&group.type!="LoadBalance")||group.checking)continue;
        const bool used=group.lastUsed!=HealthClock::time_point{}&&now-group.lastUsed<=std::chrono::seconds(std::max(1,group.interval));
        if(!group.forceCheck&&(group.interval==0||(group.lazy&&!used)||now<group.nextCheck))continue;
        group.forceCheck=false;group.nextCheck=now+std::chrono::seconds(std::max(1,group.interval));
        group.checking=!group.proxies.empty();++group.checkGeneration;
        for(const std::string& member:group.proxies)jobs.push_back({group.name,member,group.url,group.expectedStatus,
            resolveProxyLocked(member),group.timeout,g_state.configRevision,group.checkGeneration});
    }
    for(ProxyProvider& provider:g_state.providers) {
        ProxyGroup& health=provider.health;
        if((!provider.healthEnabled&&!health.forceCheck)||health.checking)continue;
        const bool used=health.lastUsed!=HealthClock::time_point{}&&now-health.lastUsed<=std::chrono::seconds(std::max(1,health.interval));
        if(!health.forceCheck&&(health.interval==0||(health.lazy&&!used)||now<health.nextCheck))continue;
        health.forceCheck=false;health.nextCheck=now+std::chrono::seconds(std::max(1,health.interval));health.checking=!provider.nodes.empty();++health.checkGeneration;
        for(const ProxyNode& node:provider.nodes)jobs.push_back({provider.name,node.name,health.url,health.expectedStatus,resolveProxyLocked(node.name),health.timeout,g_state.configRevision,health.checkGeneration,provider.name});
    }
    return jobs;
}
void commitHealthResult(const GroupProbeJob& job,int delay)
{
    std::lock_guard<std::mutex> guard(g_state.mutex);
    if(g_state.configRevision!=job.revision)return;
    if(!job.provider.empty()) {
        const auto provider=std::find_if(g_state.providers.begin(),g_state.providers.end(),[&](const ProxyProvider& item){return item.name==job.provider;});
        if(provider==g_state.providers.end()||provider->health.checkGeneration!=job.generation)return;
        const ProxyNode node=resolveProxyLocked(job.member);
        if(node.name==job.node.name&&node.provider==job.provider){provider->health.health[job.member]={delay,node.name};g_state.delays[node.name]=delay;}
        return;
    }
    auto group=std::find_if(g_state.groups.begin(),g_state.groups.end(),[&](const ProxyGroup& item){return item.name==job.group;});
    if(group==g_state.groups.end()||group->checkGeneration!=job.generation)return;
    if(resolveProxyLocked(job.member).name==job.node.name){
        group->health[job.member]={delay,job.node.name};g_state.delays[job.member]=delay;g_state.delays[job.node.name]=delay;
        chooseHealthyGroupLocked(*group);
    }
}
void runHealthJobs(const std::vector<GroupProbeJob>& jobs)
{
    std::atomic<size_t> index{0};std::vector<std::thread> threads;
    auto work=[&]() {
        while(g_state.running.load()) {
            const size_t next=index.fetch_add(1);if(next>=jobs.size())break;
            const GroupProbeJob& job=jobs[next];
            {std::lock_guard<std::mutex> guard(g_state.mutex);if(g_state.configRevision!=job.revision)continue;}
            TestTarget target;std::string error;
            const int delay=parseTestUrl(job.url,target)?probeNode(job.node,target,job.timeout,job.expected,error):0;
            if(g_state.running.load())commitHealthResult(job,delay);
        }
    };
    // Health checks do not occupy proxy/controller worker slots and have their own fixed bound.
    try { for(size_t i=0;i<std::min<size_t>(4,jobs.size());++i)threads.emplace_back(work); }
    catch(...) { coreLog("warning","Cannot create all proxy health-check workers"); }
    for(auto& thread:threads)thread.join();
    std::lock_guard<std::mutex> guard(g_state.mutex);
    for(const GroupProbeJob& job:jobs)if(g_state.configRevision==job.revision) {
        if(!job.provider.empty()) {
            const auto provider=std::find_if(g_state.providers.begin(),g_state.providers.end(),[&](const ProxyProvider& item){return item.name==job.provider;});
            if(provider!=g_state.providers.end()&&provider->health.checkGeneration==job.generation)provider->health.checking=false;
        } else {
            const auto group=std::find_if(g_state.groups.begin(),g_state.groups.end(),[&](const ProxyGroup& item){return item.name==job.group;});
            if(group!=g_state.groups.end()&&group->checkGeneration==job.generation)group->checking=false;
        }
    }
}
void healthLoop()
{
    while(g_state.running.load()) {
        runHealthJobs(collectHealthJobs());
        std::unique_lock<std::mutex> wait(g_healthWaitMutex);
        g_healthWake.wait_for(wait,std::chrono::milliseconds(500));
    }
}
