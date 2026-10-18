// Debug-only lifecycle observations. The counters have the same semantics as
// /connections: successfully accounted payload, not raw wire bytes or a claim
// that a partly failed write sent nothing. No headers, bodies, keys, rule names
// or proxy server addresses are included. Call the Locked variants only while
// holding sessionsMutex; diagnostic failures must never prevent socket cleanup.
std::string jsonEscape(const std::string& value);

void appendCoreLogLocked(const std::string& type, const std::string& payload)
{
    const int level=type=="debug"?0:type=="info"?1:(type=="warning"||type=="warn")?2:3;
    if(level<g_state.logLevel.load())return;
    g_state.logs.push_back({g_state.nextLogId++,utcNow(),type,payload});
    if(g_state.logs.size()>300)g_state.logs.pop_front();
}

void traceConnectionLocked(int client,const char* event,int error=0)
{
    if(g_state.logLevel.load()!=0)return;
    const auto found=g_state.connections.find(client);if(found==g_state.connections.end())return;
    const int saved=errno;
    try {
        const ConnectionInfo& item=found->second;
        const int64_t elapsed=item.startedAt==HealthClock::time_point{}?0:
            std::max<int64_t>(0,std::chrono::duration_cast<std::chrono::milliseconds>(HealthClock::now()-item.startedAt).count());
        std::ostringstream message;
        message<<"[connection] {\"id\":\""<<item.id<<"\",\"event\":\""<<event
            <<"\",\"network\":\""<<jsonEscape(item.network)<<"\",\"host\":\""<<jsonEscape(item.host)
            <<"\",\"port\":"<<item.port<<",\"upload\":"<<item.upload<<",\"download\":"<<item.download
            <<",\"elapsedMs\":"<<elapsed<<",\"errno\":"<<error
            <<",\"controllerCancelled\":"<<(item.cancelled?"true":"false")<<"}";
        appendCoreLogLocked("debug",message.str());
    } catch(...) {}
    errno=saved;
}

void traceConnection(int client,const char* event,int error=0)
{
    if(g_state.logLevel.load()!=0)return;
    const int saved=errno;
    try { std::lock_guard<std::mutex> guard(g_state.sessionsMutex);traceConnectionLocked(client,event,error); }
    catch(...) {}
    errno=saved;
}
