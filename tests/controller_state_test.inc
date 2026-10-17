// Real production stream workers, OS RSS measurement and data-plane socketpairs.
std::string stateWs(const std::string& path)
{
    std::string request = API_WS; request.replace(request.find("/traffic"), 8, path); return request;
}
std::string stateField(const std::string& value, const char* field)
{
    EditorYaml parsed; std::string error;
    require(parsed.parse(value, 1024*1024, error), "State stream emitted invalid JSON");
    return yamlText(yamlValue(parsed.document, yaml_document_get_root_node(&parsed.document), field));
}
std::string stateText(int fd)
{
    const auto frame = apiFrame(fd); require(frame.first == 1, "State WebSocket must emit text JSON"); return frame.second;
}
void controllerStateTests(const std::string& directory)
{
    stopCore(); workersIdle(); require(setControllerSecret(""), "Prepare optional auth default");
    const std::string profile = directory + "/state-streams.yaml";
    { std::ofstream out(profile); out << "port: 0\nsocks-port: 0\nlog-level: debug\nrules: ['MATCH,DIRECT']\n"; }
    std::string error; require(loadConfigLocked(profile, error), "Load public stream fixture");
    g_state.running.store(true);
    auto http = [](const std::string& path) { return "GET " + path + " HTTP/1.1\r\nHost: localhost\r\n"; };
    uint64_t resident = 0; require(controllerMemoryBytes(resident) && resident > 0, "Memory must use actual current process resident bytes");
    const std::string snapshot = apiHttp(http("/connections?interval=ignored-for-http") + "\r\n");
    require(snapshot.rfind("HTTP/1.1 200", 0) == 0 && snapshot.find("Content-Length:") != std::string::npos, "HTTP connections must stay a finite snapshot with query parameters");
    require(apiNumber(snapshot.substr(snapshot.find("\r\n\r\n")+4), "memory") > 0, "Connection snapshot must include actual process RSS");
    for (const std::string& path : {"/logs?level=invalid", "/logs?level=info&level=error", "/logs?level=%GG", "/logs?%6cevel=error&level=info", "/memory?unused=%00"})
        require(apiHttp(http(path)+"\r\n").rfind("HTTP/1.1 400",0)==0,"Invalid/ambiguous stream options must fail before subscription");
    for (const std::string& value : {"0", "-1", "99", "60001", "1.5", "1000ms", "999999999999999999", "%00", "100&interval=200"})
        require(apiHttp(stateWs("/connections?interval="+value)+"\r\n").rfind("HTTP/1.1 400",0)==0,"Connection tick interval must be unambiguous bounded milliseconds");
    for (const std::string& path : {"/logs", "/memory", "/traffic"})
        require(apiHttp(http(path)+"Content-Length: 1\r\n\r\n").rfind("HTTP/1.1 400",0)==0,"Body-bearing subscriptions must reject before waiting for the body");

    int memoryHttp=apiSubscribe(http("/memory")), memoryWs=apiSubscribe(stateWs("/memory"),true);
    require(apiNumber(apiReadLine(memoryHttp),"inuse")>0 && apiNumber(stateText(memoryWs),"inuse")>0,"HTTP and WS memory values must measure real resident bytes from the first tick");
    require(apiNumber(apiReadLine(memoryHttp),"oslimit")==0,"Unknown process memory limit must remain explicitly unspecified");
    close(memoryHttp);close(memoryWs);workersIdle();

    coreLog("error","PUBLIC-HISTORICAL-MUST-NOT-REPLAY");
    int logHttp=apiSubscribe(http("/logs?level=warning")), logWs=apiSubscribe(stateWs("/logs?level=debug&format=structured"),true);
    pollfd quiet{logHttp,POLLIN,0};require(poll(&quiet,1,150)==0,"Log subscription must wait for future events instead of replaying history or heartbeat data");
    coreLog("debug","PUBLIC-debug");coreLog("info","PUBLIC-info");
    const std::string escaped="PUBLIC-warning \"line\"\n第二行😀";
    coreLog("warning",escaped);coreLog("error","PUBLIC-error");
    const std::string warning=apiReadLine(logHttp), failure=apiReadLine(logHttp);
    require(stateField(warning,"type")=="warning"&&stateField(warning,"payload")==escaped,"HTTP logs must filter by threshold and JSON-escape event payloads");
    require(stateField(failure,"type")=="error"&&stateField(failure,"payload")=="PUBLIC-error","HTTP logs must deliver new events in order");
    for(const std::string& level:{"debug","info","warn","error"}) {
        const std::string value=stateText(logWs);
        require(stateField(value,"level")==level&&stateField(value,"time").size()==8&&value.find("\"fields\":[]")!=std::string::npos,"Structured WS logs must include real time, level, message and fields");
    }
    coreLog("info","PUBLIC-filtered");quiet={logHttp,POLLIN,0};require(poll(&quiet,1,150)==0,"Below-threshold events must not appear on an existing stream");
    close(logHttp);close(logWs);workersIdle();
    int silent=apiSubscribe(stateWs("/logs?level=silent"),true);coreLog("error","PUBLIC-silent");
    sendAll(silent,apiMasked(9,"quiet"));auto control=apiFrame(silent);require(control.first==10&&control.second=="quiet","Silent log streams must retain responsive WebSocket control frames");
    quiet={silent,POLLIN,0};require(poll(&quiet,1,150)==0,"Silent level must suppress every normal log event");close(silent);workersIdle();
    ControllerStreamOptions options;require(controllerStreamOptions("/logs?level=debug",options),"Parse debug threshold");
    uint64_t cursor=0;for(int i=0;i<350;++i)coreLog("info","PUBLIC-ring-"+std::to_string(i));
    auto batch=controllerLogSamples(cursor,options);require(batch.size()==300&&stateField(batch.front(),"payload")=="PUBLIC-ring-50"&&stateField(batch.back(),"payload")=="PUBLIC-ring-349","Slow log readers must use the bounded actual ring and skip evicted events");
    require(controllerLogSamples(cursor,options).empty(),"A cursor must never redeliver an event");

    int connections=apiSubscribe(stateWs("/connections?interval=100"),true);
    require(stateText(connections).find("\"connections\":[]")!=std::string::npos,"Connections must send their first snapshot immediately");
    int client[2],origin[2];pairFor(client);pairFor(origin);
    g_testConnector=[fd=origin[0]](const std::string&,int,int){return fd;};
    dispatchWorker(client[0],0);sendAll(client[1],"CONNECT stream-state.test:443 HTTP/1.1\r\nHost: stream-state.test:443\r\n\r\n");
    require(readUntilHeaders(client[1]).find("200 Connection Established")!=std::string::npos,"Open an actual production data-plane worker");
    sendAll(client[1],"upload-state");require(receiveN(origin[1],12)=="upload-state","Forward real upload bytes");
    sendAll(origin[1],"download-state");require(receiveN(client[1],14)=="download-state","Forward real download bytes");
    std::string live;
    for(int i=0;i<12;++i){live=stateText(connections);if(live.find("stream-state.test")!=std::string::npos&&live.find("\"download\":14")!=std::string::npos)break;}
    require(live.find("stream-state.test")!=std::string::npos&&live.find("\"upload\":12")!=std::string::npos&&live.find("\"download\":14")!=std::string::npos,"Live connection stream must carry actual active connection counters");
    require(apiNumber(live,"memory")>0,"Connection WS must include RSS");
    std::string id;{std::lock_guard<std::mutex>lock(g_state.sessionsMutex);id=g_state.connections.at(client[0]).id;}
    require(apiHttp("DELETE /connections/"+id+" HTTP/1.1\r\nHost: localhost\r\n\r\n").rfind("HTTP/1.1 204",0)==0,"Disconnect API must acknowledge without a response body");
    for(int i=0;i<12;++i){live=stateText(connections);if(live.find("stream-state.test")==std::string::npos)break;}
    require(live.find("stream-state.test")==std::string::npos,"Disconnect must remove the actual connection from subsequent snapshots");
    close(client[1]);close(origin[1]);g_testConnector=nullptr;close(connections);workersIdle();

    // Every stream shares one quota and the same auth/revocation/shutdown policy.
    std::vector<int> clients;
    for(int i=0;i<16;++i)clients.push_back(apiSubscribe(stateWs(i%3==0?"/logs?level=silent":i%3==1?"/memory":"/connections?interval=60000"),true));
    require(apiHttp(http("/traffic")+"\r\n").rfind("HTTP/1.1 429",0)==0,"Mixed stream endpoints must share the 16-subscriber quota");
    require(apiHttp(http("/version")+"\r\n").rfind("HTTP/1.1 200",0)==0,"Stream saturation must reserve ordinary API capacity");
    for(int fd:clients)close(fd);workersIdle();require(g_state.controllerStreams.load()==0,"Mixed disconnected clients must release quota");
    const std::string secret="PUBLIC-state-auth";require(setControllerSecret(secret),"Enable auth for every new endpoint");
    for(const std::string& path:{"/logs","/memory","/connections"})
        require(apiHttp(http(path)+"\r\n").rfind("HTTP/1.1 401",0)==0,"All state reads require managed credentials");
    clients.clear();
    for(const std::string& path:{"/logs?level=silent&token=","/memory?token=","/connections?interval=60000&token="})clients.push_back(apiSubscribe(stateWs(path+secret),true));
    int idleHttp=apiSubscribe(http("/logs?level=silent")+"Authorization: Bearer "+secret+"\r\n");
    require(setControllerSecret(""),"Disable auth and invalidate old state subscribers");
    for(int fd:clients){control=apiFrame(fd);while(control.first==1)control=apiFrame(fd);require(control.first==8&&control.second==std::string("\3\360",2),"Auth changes must policy-close all old state WS streams");close(fd);}
    char byte;require(recv(idleHttp,&byte,1,0)==0,"Even idle HTTP log subscribers must close promptly after an auth change");close(idleHttp);workersIdle();
    clients={apiSubscribe(stateWs("/logs?level=silent"),true),apiSubscribe(stateWs("/memory"),true),apiSubscribe(stateWs("/connections"),true)};
    stopCore();for(int fd:clients)close(fd);
    require(g_state.controllerStreams.load()==0&&g_state.workers.load()==0&&g_state.sockets.empty(),"Stopping core must clean up every state stream including idle logs");
}
