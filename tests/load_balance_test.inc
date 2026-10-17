void loadBalanceTests(const std::string& directory)
{
    const std::pair<const char*,const char*> domains[]={
        {"WWW.Example.COM.","example.com"},{"a.service.example.co.uk","example.co.uk"},
        {"a.user.github.io","user.github.io"},{"b.other.github.io","other.github.io"},
        {"a.b.ck","a.b.ck"},{"a.www.ck","www.ck"},{"www.city.kawasaki.jp","city.kawasaki.jp"},
        {"a.foo.kawasaki.jp","a.foo.kawasaki.jp"},{"a.b.unknownsuffix","b.unknownsuffix"},
        {"localhost","localhost"},{"co.uk","co.uk"},{"8.8.8.8","8.8.8.8"},
        {"2001:0db8:0:0::1","2001:db8::1"},{"a.example.公司.cn","example.公司.cn"},
        {"a.example.xn--55qx5d.cn","example.xn--55qx5d.cn"}
    };
    for(const auto& item:domains)require(balanceDestinationKey(item.first)==item.second,"Public suffix/IP routing key differs from suffix, wildcard or exception semantics");
    ProxyNode a,b,c;a.name="alpha";b.name="beta";c.name="gamma";a.type=b.type=c.type="direct";
    ProxyGroup group;group.name="Balance";group.type="LoadBalance";group.proxies={a.name,b.name,c.name};group.lazy=false;
    auto reset=[&](const std::string& strategy) {
        group.strategy=strategy;group.roundRobin=0;group.lastSelected.clear();group.now.clear();group.sessions.clear();group.health.clear();
        std::lock_guard<std::mutex> lock(g_state.mutex);++g_state.configRevision;g_state.providers.clear();g_state.nodes={a,b,c};
        g_state.groups={group};g_state.rules={{"match","",group.name}};g_state.mode="Rule";g_state.configPath=directory+"/balance.yaml";
    };
    reset("round-robin");
    for(int i=0;i<9;++i)require(activeProxyNode("target.example.com",443).name==group.proxies[i%3],"Round-robin must distribute real routing requests in configured order");
    const auto cursor=g_state.groups[0].roundRobin;
    for(int i=0;i<10;++i){resolveProxyLocked(group.name);responseFor("GET","/proxies","");}
    require(g_state.groups[0].roundRobin==cursor,"Group API reads and health snapshots must not consume round-robin slots");
    g_state.groups[0].health[b.name]={0,b.name};
    require(activeProxyNode("x.test",80).name==a.name&&activeProxyNode("x.test",80).name==c.name,"Round-robin must skip health-check failures");
    g_state.groups[0].health[a.name]={0,a.name};g_state.groups[0].health[c.name]={0,c.name};
    require(activeProxyNode("x.test",80).type=="reject","All failed balance members must not leak a DIRECT route");
    g_state.groups[0].health[b.name]={10,b.name};require(activeProxyNode("x.test",80).name==b.name,"A recovered balanced member must resume routing");
    require(responseFor("PUT","/proxies/Balance","{\"name\":\"alpha\"}").find("error")!=std::string::npos,"Load balancing must not accept a fake manual fixed selection");
    persistSelectionsLocked();require(readTestFile(directory+"/balance.yaml.selections").find("Balance")==std::string::npos,"A per-request balanced selection must not be persisted as a fixed choice");
    reset("round-robin");
    std::array<std::atomic<int>,3> counts{};std::atomic<bool> unexpected{false};std::vector<std::thread> clients;
    for(int i=0;i<6;++i)clients.emplace_back([&] {for(int n=0;n<200;++n) {
        const std::string selected=activeProxyNode("concurrent.test",443).name;
        const auto position=std::find(group.proxies.begin(),group.proxies.end(),selected);
        if(position==group.proxies.end())unexpected.store(true);else counts[position-group.proxies.begin()].fetch_add(1);
    }});
    for(auto& client:clients)client.join();
    require(!unexpected&&counts[0]==400&&counts[1]==400&&counts[2]==400,"Concurrent connections must preserve round-robin distribution");
    reset("consistent-hashing");
    const std::string chosen=activeProxyNode("www.example.co.uk",443).name;
    for(const std::string host:{"api.example.co.uk","cdn.example.co.uk","EXAMPLE.CO.UK."})
        require(activeProxyNode(host,80,"tcp","192.0.2.9").name==chosen,"Consistent hashing must share an eTLD+1 across ports and source addresses");
    std::map<std::string,std::string> before;std::set<std::string> distributed;
    for(int i=0;i<500;++i){const std::string host="site"+std::to_string(i)+".example";before[host]=activeProxyNode(host,443).name;distributed.insert(before[host]);}
    require(distributed.size()==3,"Hash policy must distribute distinct destinations among eligible nodes");
    std::reverse(g_state.groups[0].proxies.begin(),g_state.groups[0].proxies.end());bool stable=true;
    for(const auto& item:before)stable=stable&&activeProxyNode(item.first,443).name==item.second;
    require(stable,"Provider member reordering must not change consistent hashing");
    ProxyNode d;d.name="delta";d.type="direct";g_state.nodes.push_back(d);g_state.groups[0].proxies.push_back(d.name);
    size_t added=0;stable=true;
    for(const auto& item:before){const auto name=activeProxyNode(item.first,443).name;if(name==d.name)++added;else stable=stable&&name==item.second;}
    require(stable&&added>50&&added<200,"Adding one member must only move destinations assigned to that new member");
    g_state.groups[0].health[chosen]={0,chosen};
    require(activeProxyNode("example.co.uk",443).name!=chosen,"Consistent hashing must replace a failed selected member");
    g_state.groups[0].health[chosen]={10,chosen};g_state.groups[0].proxies=group.proxies;
    require(activeProxyNode("example.co.uk",443).name==chosen,"Consistent hashing must restore a recovered mapping");
    reset("sticky-sessions");
    const auto now=HealthClock::now();const RouteContext first{"a.example.com","192.0.2.1","tcp",now};
    std::string sticky;
    {std::lock_guard<std::mutex> lock(g_state.mutex);sticky=resolveProxyLocked(group.name,&first).name;}
    RouteContext repeated{"b.example.com","192.0.2.1","udp",now+std::chrono::minutes(9)};
    require(resolveProxyLocked(group.name,&repeated).name==sticky&&g_state.groups[0].sessions.size()==1,"Sticky sessions must pin source plus registrable destination across TCP/UDP and subdomains");
    const std::string sessionKey=first.source+'\0'+balanceDestinationKey(first.host);
    require(g_state.groups[0].sessions.at(sessionKey).expires==now+std::chrono::minutes(10),"Sticky TTL is measured from allocation, not extended by every packet");
    repeated.source="192.0.2.2";resolveProxyLocked(group.name,&repeated);
    require(g_state.groups[0].sessions.size()==2,"Different client source addresses require distinct sticky allocations");
    repeated.source=first.source;repeated.now=now+std::chrono::minutes(10);resolveProxyLocked(group.name,&repeated);
    require(g_state.groups[0].sessions.at(sessionKey).expires==now+std::chrono::minutes(20),"Expired sticky session must allocate a fresh ten-minute entry");
    const std::string prior=g_state.groups[0].sessions.at(sessionKey).member;g_state.groups[0].health[prior]={0,prior};
    require(resolveProxyLocked(group.name,&repeated).name!=prior,"Sticky allocation must leave a failed member immediately");
    g_state.groups[0].health.clear();
    for(int i=0;i<1100;++i){repeated.source="client-"+std::to_string(i);resolveProxyLocked(group.name,&repeated);}
    require(g_state.groups[0].sessions.size()==1000,"Sticky cache must have a hard 1000-entry bound");
    require(responseFor("POST","/clahsos/groups/Balance/reset-sessions","")=="{}"&&g_state.groups[0].sessions.empty(),"Context-menu action must clear actual sticky allocation state");
    require(responseFor("POST","/clahsos/groups/Balance/healthcheck","")=="{}","Load balance must expose health check action");
    auto jobs=collectHealthJobs();require(jobs.size()==3&&g_state.groups[0].checking,"Load-balance health scheduling must include every member");
    commitHealthResult(jobs[0],0);commitHealthResult(jobs[1],10);commitHealthResult(jobs[2],0);
    require(activeProxyNode("example.test",443).name==b.name&&g_state.groups[0].now.empty(),"Health completion must constrain routing without manufacturing a fixed now selection");
    reset("round-robin");g_state.nodes[0].udpConfigured=true;g_state.nodes[0].udp=false;g_state.nodes[1].udpConfigured=true;g_state.nodes[1].udp=false;
    require(activeProxyNode("udp.test",443,"udp").name==c.name,"UDP load balancing must skip nodes which disable UDP");
    g_state.groups[0].disableUdp=true;require(activeProxyNode("udp.test",443,"udp").type=="reject","disable-udp must apply to the balanced group itself");
    reset("round-robin");
    ProxyGroup inner=group;inner.name="Inner";inner.proxies={a.name,b.name};inner.strategy="round-robin";
    g_state.groups[0].proxies={inner.name,c.name};g_state.groups.push_back(inner);
    g_state.nodes[0].udpConfigured=true;g_state.nodes[0].udp=false;
    require(activeProxyNode("nested.udp.test",443,"udp").name==b.name,"Nested balance eligibility must inspect the full UDP-capable candidate set");
    require(g_state.groups[1].roundRobin==0&&g_state.groups[1].lastSelected==b.name,"Nested eligibility inspection must not consume extra round-robin slots");
    require(activeProxyNode("nested.udp.test",443,"udp").name==c.name,"Outer load balance must keep its own distribution cursor");
    g_state.groups[1].strategy="sticky-sessions";g_state.groups[0].strategy="consistent-hashing";
    const RouteContext peek{"test.example","192.0.2.1","tcp",HealthClock::now(),false};
    resolveProxyLocked(group.name,&peek);
    require(g_state.groups[1].sessions.empty()&&g_state.groups[1].sessionSerial==0,"A nested eligibility probe must never allocate or evict sticky sessions");
    reset("round-robin");ProxyGroup outer;outer.name="Outer";outer.now=group.name;outer.proxies={group.name};g_state.groups.insert(g_state.groups.begin(),outer);g_state.rules={{"match","",outer.name}};
    const auto nested=activeProxyNode("nested.test",443);
    require(nested.name==a.name&&nested.loadBalanced&&nested.chain==std::vector<std::string>({a.name,group.name,outer.name}),"A selector around a balanced group must preserve the actual outbound chain");
    g_state.groups[1].proxies={outer.name};
    require(activeProxyNode("cycle.test",443).type=="reject","Cyclic balanced groups must reject safely without recursion or direct fallback");
    ParsedConfig parsed;std::string error;
    require(parseConfigText("proxy-groups: [{name: b, type: load-balance, proxies: [DIRECT], strategy: sticky-sessions}]",parsed,error)&&parsed.groups[0].strategy=="sticky-sessions"&&parsed.groups[0].now.empty(),"Load-balance strategy and absence of fixed selection must survive configuration parsing");
    for(const std::string field:{"strategy: random","hash-key: in-user","default-selected: DIRECT","url: 'ftp://x.test/'","expected-status: 900"})
        require(!parseConfigText("proxy-groups: [{name: b, type: load-balance, proxies: [DIRECT], "+field+"}]",parsed,error),"Invalid or unsupported balance fields must fail validation");
    // Real HTTP CONNECT and SOCKS -> SS/VMess -> independent Python/OpenSSL HTTPS endpoints.
    a.name="SS balanced";a.type="ss";a.server="ss-balanced.test";a.port=1001;a.password="probe-password";a.cipher="aes-256-gcm";a.udp=true;
    b=vmTestNode(0,"tcp","auto");b.name="VMess balanced";b.udp=true;group.proxies={a.name,b.name};reset("round-robin");
    const std::string roots=readTestFile(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/vmess/ca.pem");g_testVmessTrust=roots.c_str();g_state.running.store(true);
    for(int request=0;request<4;++request) {
        VmessReferencePeer peer(0,request%2?"vmess":"ss","","https_reference_peer.py");
        const ProxyNode expected=request%2?b:a;
        std::atomic<bool> correctDestination{true};
        g_testConnector=[&](const std::string& host,int port,int){correctDestination.store(host==expected.server&&port==expected.port);return peer.take();};
        int client[2];pairFor(client);dispatchWorker(client[0],request>=2?1:0);
        if(request<2){sendAll(client[1],"CONNECT vmess.test:443 HTTP/1.1\r\nHost: vmess.test\r\n\r\n");require(readUntilHeaders(client[1]).find("200 Connection Established")!=std::string::npos,"Balanced HTTP CONNECT failed");}
        else {VmBytes greeting{5,1,0,5,1,0};vmAppend(greeting,shadowsocksAddress("vmess.test",443));sendAll(client[1],greeting);require(receiveN(client[1],2)==std::string("\5\0",2)&&receiveN(client[1],10)[1]==0,"Balanced SOCKS CONNECT failed");}
        const std::string snapshot=connectionsJson();require(snapshot.find(expected.name)!=std::string::npos&&snapshot.find(group.name)!=std::string::npos,"Balanced inbound must report the real proxy and group chain");
        TlsChannel tls(client[1]);require(tls.start("vmess.test",false,error,roots.c_str()),"HTTPS through balanced inbound failed certificate verification");
        const std::string get="GET /probe?ok=1 HTTP/1.1\r\nHost: vmess.test\r\nConnection: close\r\n\r\n";
        require(tls.writeBytes(reinterpret_cast<const unsigned char*>(get.data()),get.size()),"Balanced HTTPS request failed to write");
        std::string reply;unsigned char buffer[2048];
        while(reply.find("\r\n\r\n")==std::string::npos){const auto size=tls.readBytes(buffer,sizeof(buffer));if(size<=0)break;reply.append(reinterpret_cast<const char*>(buffer),size);}
        require(reply.find("204 No Content")!=std::string::npos,"Independent HTTPS endpoint did not respond through selected balanced outbound");
        shutdown(client[1],SHUT_RDWR);close(client[1]);workersIdle();g_testConnector=nullptr;peer.finish();
        require(correctDestination,"Real round-robin request dialed the wrong proxy server");
    }
    stopCore();g_testVmessTrust=nullptr;
    // Three datagrams of the same target remain on one SS UDP flow; a new target gets the next member.
    b=a;b.name="SS second";b.server="ss-second.test";b.port=1002;group.proxies={a.name,b.name};reset("round-robin");g_state.running.store(true);
    {
        UdpHarness harness;const int left=harness.add(a.server,a.port),right=harness.add(b.server,b.port);
        const auto master=evpBytesToKey("probe-password",32);VmBytes plain;
        for(int i=0;i<3;++i) {
            harness.inject(udpTestPacket("first.balance.test",443,"packet-"+std::to_string(i)));
            const auto packet=receiveTestDatagram(left);
            require(decryptShadowsocksUdp(master,packet,plain)&&plain.size()>=8&&text({plain.end()-8,plain.end()})=="packet-"+std::to_string(i),"A balanced UDP flow must keep all datagrams on its original encrypted outbound");
        }
        harness.inject(udpTestPacket("second.balance.test",443,"second"));
        require(decryptShadowsocksUdp(master,receiveTestDatagram(right),plain),"A new UDP target must consume the next balanced member");
        {std::lock_guard<std::mutex> lock(harness.mutex);require(harness.dials.size()==2&&harness.dials[0].first==a.server&&harness.dials[1].first==b.server,"Round-robin UDP must choose per flow rather than redial for each packet");}
        const int reloaded=harness.add(b.server,b.port);
        {std::lock_guard<std::mutex> lock(g_state.mutex);++g_state.configRevision;g_state.groups[0].roundRobin=1;}
        harness.inject(udpTestPacket("first.balance.test",443,"reload"));
        require(decryptShadowsocksUdp(master,receiveTestDatagram(reloaded),plain),"Config reload must release the old balanced UDP pin and allocate a new outbound");
    }
    stopCore();require(g_state.sockets.empty()&&g_state.connections.empty(),"Balanced traffic must release all sockets and connection records");
    // Real provider rebuilds must retain named sticky members, prune removed ones and ignore legacy fixed selections.
    const std::string profile=directory+"/balanced-provider.yaml",source=directory+"/balanced-nodes.yaml";
    {std::ofstream file(source);file<<"proxies: [{name: alpha, type: direct}, {name: beta, type: direct}]\n";}
    {std::ofstream file(profile+".selections");file<<"\"Balance\" \"alpha\"\n";}
    const std::string configuration="proxy-providers: {feed: {type: file, path: './balanced-nodes.yaml'}}\nproxy-groups: [{name: Balance, type: load-balance, strategy: sticky-sessions, use: [feed], interval: 0}]\nrules: ['MATCH,Balance']\n";
    loadProviderProfile(profile,configuration);
    require(g_state.groups[0].now.empty()&&g_state.groups[0].manual.empty()&&g_state.groups[0].pendingSelection.empty(),"Legacy fixed selections must not disable a restored balanced provider group");
    const std::string pinned=activeProxyNode("a.example.com",443,"tcp","192.0.2.5").name;
    const std::string updatePath="/clahsos/providers/feed/file?profile="+urlEncode(profile);
    require(responseFor("PUT",updatePath,"proxies: [{name: beta, type: direct}, {name: alpha, type: direct}, {name: gamma, type: direct}]")=="{}","Balanced provider import failed");
    require(activeProxyNode("b.example.com",443,"tcp","192.0.2.5").name==pinned&&g_state.groups[0].sessions.size()==1,"A real provider reorder/addition must preserve the live sticky member by name");
    const std::string alternative=pinned=="alpha"?"beta":"alpha";
    require(responseFor("PUT",updatePath,"proxies: [{name: "+alternative+", type: direct}]")=="{}","Balanced provider member removal failed");
    require(g_state.groups[0].sessions.empty()&&activeProxyNode("example.com",443,"tcp","192.0.2.5").name==alternative,"A removed provider member must invalidate its cached sticky allocations");
    loadProviderProfile(profile,configuration);
    require(g_state.groups[0].now.empty()&&g_state.groups[0].sessions.empty()&&activeProxyNode("example.com",443).name==alternative,"Restart must restore the real provider cache and balance policy without a fake fixed node");
    stopCore();
}
