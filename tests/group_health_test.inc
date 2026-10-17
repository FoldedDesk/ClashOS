void httpsProbeTests()
{
    std::ifstream rootFile(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/vmess/ca.pem");
    const std::string roots((std::istreambuf_iterator<char>(rootFile)),{});
    g_state.running.store(true);
    auto exercise=[&](const std::string& kind,int alter,const std::string& fault,const std::string& expected) {
        std::cerr<<"HTTPS probe: "<<kind<<" alter="<<alter<<" fault="<<fault<<'\n';
        VmessReferencePeer peer(alter,kind,fault,"https_reference_peer.py");
        g_testVmessTrust=fault=="untrusted"?nullptr:roots.c_str();
        g_testConnector=[&](const std::string&,int,int){return peer.take();};
        ProxyNode node;
        if(kind=="direct"){node.name="DIRECT";node.type="direct";}
        else if(kind=="ss"){node.name="SS";node.type="ss";node.server="node.invalid";node.port=443;node.password="probe-password";node.cipher="aes-256-gcm";}
        else node=vmTestNode(alter,kind.find("-ws")!=std::string::npos?"ws-tls":"tcp","auto");
        node.skipCertVerify=true; // This must not disable verification of the HTTPS destination.
        TestTarget target;require(parseTestUrl("https://"+std::string(fault=="wronghost"?"wrong.test":"vmess.test")+"/probe?ok=1#discard",target),"HTTPS fixture URL parsing failed");
        std::string error;const auto start=HealthClock::now();
        const int delay=probeNode(node,target,fault=="slow"?150:4000,expected,error);
        g_testConnector=nullptr;
        const bool success=fault.empty()||(fault=="status"&&expected=="503");
        require(success?delay>0:delay==0&&!error.empty(),"HTTPS endpoint validation did not match independent TLS peer");
        if(fault=="slow")require(HealthClock::now()-start<std::chrono::seconds(2),"Probe timeout must cover the complete response, not restart after each byte");
        peer.finish();
    };
    for(const std::string kind:{"direct","ss","vmess","vmess-ws-tls"})exercise(kind,0,"","204");
    exercise("vmess-ws-tls",1,"","200-299/302");
    for(const std::string fault:{"wronghost","untrusted","status","slow"})exercise("ss",0,fault,"200-399");
    exercise("direct",0,"status","503");
    exercise("vmess-ws-tls",0,"wronghost","204");
    exercise("vmess-ws-tls",0,"untrusted","204");
    require(validProbeStatus("200/302/400-503")&&validProbeStatus("*"),"HTTP expected-status ranges");
    require(!validProbeStatus("204/")&&!validProbeStatus("300-200")&&!validProbeStatus("200junk")&&!validProbeStatus("999"),"Malformed HTTP expected-status must not be accepted");
    TestTarget target;
    require(parseTestUrl("https://[2001:db8::1]:8443/?a=1",target)&&target.host=="2001:db8::1"&&target.port==8443&&target.tls,"HTTPS IPv6 authority parsing");
    require(!parseTestUrl(std::string("http://a.test/\0evil",19),target)&&!parseTestUrl("https://user:secret@a.test/",target),"Probe URL must reject control bytes and URL credentials");
    g_testVmessTrust=nullptr;g_testConnector=nullptr;g_state.running.store(false);
}

void groupHealthTests(const std::string& directory)
{
    ProxyNode a,b,c; a.name="first";b.name="second";c.name="third";a.type=b.type=c.type="direct";
    ProxyGroup group;group.name="Automatic";group.type="URLTest";group.proxies={a.name,b.name,c.name};group.now=a.name;group.checkGeneration=1;
    group.checking=true;group.tolerance=50;
    auto reset=[&](const ProxyGroup& value) {
        std::lock_guard<std::mutex> lock(g_state.mutex);++g_state.configRevision;g_state.nodes={a,b,c};g_state.groups={value};
        g_state.delays.clear();g_state.mode="Rule";g_state.rules={{"match","",value.name}};g_state.configPath=directory+"/automatic.yaml";
    };
    auto job=[&](const std::string& name) {
        std::lock_guard<std::mutex> lock(g_state.mutex);const auto& current=g_state.groups[0];
        return GroupProbeJob{current.name,name,current.url,current.expectedStatus,resolveProxyLocked(name),current.timeout,g_state.configRevision,current.checkGeneration};
    };
    reset(group);
    commitHealthResult(job(a.name),100);commitHealthResult(job(b.name),80);
    require(g_state.groups[0].now==a.name,"URLTest must retain current node inside tolerance");
    commitHealthResult(job(b.name),20);require(g_state.groups[0].now==b.name,"URLTest must switch when the faster node exceeds tolerance");
    commitHealthResult(job(b.name),0);require(g_state.groups[0].now==a.name,"URLTest must leave a failed current node");
    commitHealthResult(job(a.name),0);commitHealthResult(job(c.name),0);
    require(g_state.groups[0].now.empty()&&activeProxyNode("test.invalid",443).type=="reject","All-failed automatic groups must not silently use DIRECT");
    commitHealthResult(job(c.name),30);require(g_state.groups[0].now==c.name,"Automatic group must recover after a node recovers");
    commitHealthResult(job(a.name),100);
    require(responseFor("PUT","/proxies/Automatic","{\"name\":\"first\"}")=="{}","Manual selection of URLTest node failed");
    commitHealthResult(job(c.name),1);require(g_state.groups[0].now==a.name&&g_state.groups[0].manual==a.name,"Healthy manual override must survive lower delay elsewhere");
    commitHealthResult(job(a.name),0);require(g_state.groups[0].now==c.name,"Failed manual override must yield to an available member");
    commitHealthResult(job(a.name),100);require(g_state.groups[0].now==a.name,"Recovered manual override should become usable again");
    require(responseFor("POST","/clahsos/groups/Automatic/auto","")=="{}"&&g_state.groups[0].manual.empty()&&g_state.groups[0].forceCheck,"Restore automatic selection control action failed");
    commitHealthResult(job(c.name),1);require(g_state.groups[0].now==c.name,"Restored automatic policy must choose the best available node");
    std::ifstream persisted(directory+"/automatic.yaml.selections");const std::string selections((std::istreambuf_iterator<char>(persisted)),{});
    require(selections.find("Automatic")==std::string::npos,"Automatic computed choices must not be persisted as manual overrides");
    group.type="Fallback";group.manual.clear();group.now=c.name;group.checking=true;reset(group);
    commitHealthResult(job(a.name),900);commitHealthResult(job(b.name),1);commitHealthResult(job(c.name),2);
    require(g_state.groups[0].now==a.name,"Fallback priority follows configuration order, not lowest RTT");
    commitHealthResult(job(a.name),0);require(g_state.groups[0].now==b.name,"Fallback must select the first available alternative");
    const auto stale=job(a.name);++g_state.configRevision;commitHealthResult(stale,1);
    require(g_state.groups[0].now==b.name,"Hot reload must reject stale probe results");
    const auto oldGeneration=job(a.name);++g_state.groups[0].checkGeneration;commitHealthResult(oldGeneration,1);
    require(g_state.groups[0].now==b.name,"Old health sweep must not overwrite newer group state");
    group.checking=false;group.lazy=true;group.lastUsed={};group.forceCheck=false;group.nextCheck={};reset(group);
    require(collectHealthJobs().empty(),"Unused lazy group must not be probed");
    {std::lock_guard<std::mutex> lock(g_state.mutex);markProxyUsedLocked(group.name);}
    auto jobs=collectHealthJobs();require(jobs.size()==3&&g_state.groups[0].checking,"Using a lazy group must schedule its actual candidates");
    require(collectHealthJobs().empty(),"An in-flight group must not schedule duplicate probes");
    g_state.groups[0].checking=false;g_state.groups[0].interval=0;
    require(collectHealthJobs().empty(),"interval: 0 must disable periodic checking");
    responseFor("POST","/clahsos/groups/Automatic/healthcheck","");require(collectHealthJobs().size()==3,"Explicit health check must run even with interval: 0");
    g_state.groups[0].disableUdp=true;
    require(activeProxyNode("test.invalid",443,"udp").type=="reject"&&activeProxyNode("test.invalid",443,"tcp").type=="direct","Group disable-udp must constrain the actual routing path");
    ParsedConfig parsed;std::string error;
    const std::string config="proxy-groups: [{name: automatic, type: url-test, proxies: [DIRECT], url: 'https://example.test/', interval: 30, timeout: 1234, tolerance: 25, lazy: false, expected-status: '204/200-299', disable-udp: true}]";
    require(parseConfigText(config,parsed,error)&&parsed.groups[0].interval==30&&parsed.groups[0].timeout==1234&&parsed.groups[0].tolerance==25&&!parsed.groups[0].lazy&&parsed.groups[0].disableUdp,"Health YAML fields must reach production group state");
    ParsedConfig invalid;
    require(!parseConfigText("proxy-groups: [{name: g, type: url-test, proxies: [DIRECT], timeout: bad}]",invalid,error),"Bad group health timeout must fail configuration validation");
    require(!parseConfigText("proxy-groups: [{name: g, type: fallback, proxies: [DIRECT], expected-status: 700}]",invalid,error),"Bad expected status must fail configuration validation");
    // Exercise a real sweep through SS encryption and an independent OpenSSL HTTPS endpoint.
    std::ifstream rootFile(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/vmess/ca.pem");const std::string roots((std::istreambuf_iterator<char>(rootFile)),{});g_testVmessTrust=roots.c_str();
    VmessReferencePeer first(0,"ss","status","https_reference_peer.py"),second(0,"ss","","https_reference_peer.py");
    a.type=b.type="ss";a.server=b.server="fixture.invalid";a.cipher=b.cipher="aes-256-gcm";a.password=b.password="probe-password";a.port=1001;b.port=1002;
    group.proxies={a.name,b.name};group.type="Fallback";group.now=a.name;group.lazy=false;group.interval=1;group.url="https://vmess.test/probe?ok=1";group.expectedStatus="204";reset(group);
    g_state.running.store(true);g_testConnector=[&](const std::string&,int port,int){return port==1001?first.take():second.take();};
    runHealthJobs(collectHealthJobs());g_testConnector=nullptr;
    require(g_state.groups[0].now==b.name&&!g_state.groups[0].checking,"Real HTTPS health sweep did not bypass the failing first SS node");
    require(activeProxyNode("target.invalid",443).name==b.name,"Health-selected member must be used by actual routing");
    first.finish();second.finish();
    // Execute the real coordinator and stopCore with a probe blocked in TLS input.
    int stalled[2];makePair(stalled);group.proxies={a.name};group.now=a.name;group.forceCheck=true;group.timeout=60000;reset(group);
    g_testConnector=[&](const std::string&,int,int){return stalled[0];};
    require(g_state.serverFd<0&&g_state.listeners.empty()&&!g_healthThread.joinable(),"Health shutdown fixture requires no unrelated listeners");
    g_healthThread=std::thread(healthLoop);
    awaitCondition([&] {std::lock_guard<std::mutex> lock(g_state.sessionsMutex);return g_state.sockets.count(stalled[0])>0;},"Health coordinator did not begin its scheduled request");
    const auto stopping=HealthClock::now();stopCore();
    require(HealthClock::now()-stopping<std::chrono::seconds(2)&&!g_healthThread.joinable(),"Stopping the core must cancel a long health probe and join its coordinator promptly");
    require(g_state.groups[0].health.empty(),"Cancelled health probes must not commit failed samples after shutdown");
    {std::lock_guard<std::mutex> lock(g_state.sessionsMutex);require(g_state.sockets.empty(),"Health probes must release tracked sockets after shutdown");}
    close(stalled[1]);g_testConnector=nullptr;g_testVmessTrust=nullptr;
}
