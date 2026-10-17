void dialerGraphTests(const std::string& directory)
{
    const auto check=[](const std::string& yaml,bool valid) {
        ParsedConfig parsed;std::string error;const bool actual=parseConfigText(yaml,parsed,error);
        require(actual==valid,valid?("Valid chain rejected: "+error).c_str():"Invalid proxy chain accepted");
        if(!valid)require(!error.empty(),"Invalid chains need an actionable validation error");
    };
    check("proxies: [{name: A, type: direct, dialer-proxy: B}, {name: B, type: direct}]",true);
    for(const std::string tail:{"A","missing","[]","{}"})check("proxies: [{name: A, type: direct, dialer-proxy: "+tail+"}]",false);
    check("proxies: [{name: A, type: direct, dialer-proxy: B}, {name: B, type: direct, dialer-proxy: A}]",false);
    check("proxies: [{name: A, type: direct, dialer-proxy: Parent}]\nproxy-groups: [{name: Parent, type: select, proxies: [A]}]",false);
    check("proxies: [{name: A, type: direct, dialer-proxy: Parent}]\nproxy-groups: [{name: Parent, type: select, include-all-proxies: true}]",false);
    check("proxy-providers: {P: {type: inline, override: {dialer-proxy: Parent}, payload: [{name: A, type: direct}]}}\nproxy-groups: [{name: Parent, type: select, use: [P]}]",false);
    check("proxy-providers: {P: {type: inline, override: {dialer-proxy: Parent}, payload: [{name: A, type: direct}, {name: B, type: direct}]}}\nproxy-groups: [{name: Parent, type: select, use: [P], filter: '^absent$'}]",true);
    for(int count:{8,9}) {
        std::string yaml="proxies:\n";
        for(int i=0;i<count;++i)yaml+="  - {name: A"+std::to_string(i)+", type: direct, dialer-proxy: "+(i+1<count?"A"+std::to_string(i+1):"End")+"}\n";
        yaml+="proxy-groups: [{name: End, type: select, proxies: [DIRECT]}]\nrules: ['MATCH,A0']\n";
        check(yaml,count==8);
        if(count==8){loadProviderProfile(directory+"/dialer-depth.yaml",yaml);auto route=activeProxyNode("target.test",443,"udp");require(supportsUdp(route)&&supportsDialerTcp(route),"Eight outbounds ending in builtin DIRECT must remain usable");}
    }
    // Memoized graph branches must obey the total nesting limit as well.
    std::vector<ProxyNode> local(2);local[0].name="A";local[0].type="direct";local[0].dialerProxy="G0";local[1].name="Z";local[1].type="direct";local[1].dialerProxy="Root";
    std::vector<ProxyGroup> groups;
    for(int i=0;i<62;++i){ProxyGroup group;group.name="G"+std::to_string(i);group.proxies={i==61?"DIRECT":"G"+std::to_string(i+1)};groups.push_back(group);}
    ProxyGroup root;root.name="Root";root.proxies={"A"};groups.push_back(root);std::string error;
    require(!validateDialerGraph(local,{},groups,error),"A shared graph suffix cannot bypass the nesting bound");
    const std::string yaml="proxies: [{name: Exit, type: direct, dialer-proxy: Gateway}, {name: EntryA, type: direct}, {name: EntryB, type: direct}]\nproxy-groups: [{name: Gateway, type: select, proxies: [EntryA, EntryB]}, {name: Route, type: select, proxies: [Exit]}]\nrules: ['MATCH,Route']\n";
    loadProviderProfile(directory+"/dialer-snapshot.yaml",yaml);
    const auto first=activeProxyNode("target.test",443);
    require(first.dialerNode&&first.dialerNode->name=="EntryA"&&first.chain==std::vector<std::string>({"Exit","EntryA","Gateway","Route"}),"Connection metadata must include actual immutable entry and exit paths");
    require(responseFor("PUT","/proxies/Gateway","{\"name\":\"EntryB\"}")=="{}","Dialer selector must be switchable through the real controller");
    const auto second=activeProxyNode("target.test",443);
    require(second.dialerNode&&second.dialerNode->name=="EntryB"&&first.dialerNode->name=="EntryA","A selection change affects new sessions and preserves existing snapshots");
    GroupProbeJob stale{"Route","Exit","https://vmess.test/probe?ok=1","204",first,5000,g_state.configRevision,0};
    commitHealthResult(stale,120);
    require(g_state.groups[1].health.empty(),"A probe from a previous dialer selection must not mark the new route healthy");
    require(!matchesProxyHealth(second,{120,first.name,first.chain})&&matchesProxyHealth(second,{120,second.name,second.chain}),"Health samples must belong to the complete entry/exit path");
    loadProviderProfile(directory+"/dialer-deferred.yaml","proxies: [{name: Exit, type: direct, dialer-proxy: missing}]\nproxy-providers: {P: {type: http, url: 'https://example.com/nodes.yaml'}}\nrules: ['MATCH,Exit']\n");
    auto unavailable=activeProxyNode("target.test",443,"udp");bool dialed=false;g_testConnector=[&](const std::string&,int,int){dialed=true;return -1;};
    {ProxyStream stream;require(!openProxyStream(unavailable,"target.test",443,stream,error)&&!dialed&&!supportsUdp(unavailable),"Unfetched dialers must reject without falling back to a physical direct connection");}g_testConnector=nullptr;
    stopCore();
}

void dialerProviderTests(const std::string& directory)
{
    const std::string profile=directory+"/dialer-providers.yaml",source=directory+"/dialer-source.yaml";
    const auto body=[](const std::string& dialer){return "proxies: [{name: Exit, type: ss, server: inner.chain.test, port: 443, cipher: aes-256-gcm, password: probe-password, udp: true, dialer-proxy: "+dialer+"}]\n";};
    const std::string local="proxies: [{name: EntryA, type: http, server: outer.chain.test, port: 443, username: 'fixture用户', password: 'p@ss:word测试', headers: {X-Test: native-peer}}, {name: EntryB, type: direct}]\n";
    const std::string yaml=local+"proxy-providers: {P: {type: file, path: dialer-source.yaml}}\nproxy-groups: [{name: Route, type: select, use: [P]}]\nrules: ['MATCH,Route']\n";
    {std::ofstream file(source);file<<body("EntryA");}loadProviderProfile(profile,yaml);
    require(activeProxyNode("target.test",443).dialerNode->name=="EntryA","File providers must resolve declarative dialers after hydration");
    {
        VmessReferencePeer destination(0,"ss","","https_reference_peer.py");const int downstream=destination.take();VmessReferencePeer gateway(0,"http",std::to_string(downstream),"chain_relay_reference_peer.py");close(downstream);
        g_testConnector=[&](const std::string& host,int port,int){require(host=="outer.chain.test"&&port==443,"Provider member healthcheck must use its resolved dialer");return gateway.take();};
        const auto result=controlRequest("GET","/providers/proxies/P/Exit/healthcheck?timeout=5000&expected=204&url="+urlEncode("https://vmess.test/probe?ok=1"));g_testConnector=nullptr;
        require(result.find("\"delay\":")!=std::string::npos,"Provider member controller probe must support chained outbounds");gateway.finish();destination.finish();
    }
    const auto revision=g_state.configRevision;
    {std::lock_guard<std::mutex> lock(g_state.mutex);require(importProviderFileLocked("P",body("EntryB"))=="{}","Changing only a provider node dialer must commit");}
    require(g_state.configRevision==revision+1&&activeProxyNode("target.test",443).dialerNode->name=="EntryB","Dialer-only updates must replace the actual live routing snapshot");
    const std::string cache=providerCachePath(profile,g_state.providers[0]),before=readTestFile(cache);
    for(const std::string invalid:{"Route","absent"}) {
        std::lock_guard<std::mutex> lock(g_state.mutex);require(importProviderFileLocked("P",body(invalid))!="{}"&&readTestFile(cache)==before,"Circular/unavailable provider updates must preserve the valid cache and route");
    }
    loadProviderProfile(profile,yaml);require(activeProxyNode("target.test",443).dialerNode->name=="EntryB","A cache-only restart must retain the edited provider dialer");
    loadProviderProfile(profile,local+"proxy-providers: {P: {type: file, path: dialer-source.yaml, override: {dialer-proxy: EntryB}}}\nproxy-groups: [{name: Route, type: select, use: [P]}]\nrules: ['MATCH,Route']\n");
    require(activeProxyNode("target.test",443).dialerNode->name=="EntryB","Provider override must replace an inherited node dialer");
    stopCore();
}

void dialerStreamUdpTests(const std::string& roots)
{
    for(const std::string entry:{"http","socks5","ss"})for(const std::string transport:{"tcp","ws-tls"}) {
        std::cerr<<"Dialer VLESS UDP: "<<entry<<" -> "<<transport<<'\n';
        ProxyNode parent=forwardTestNode(entry+"-tcp");parent.name="Entry";parent.server="outer.chain.test";parent.port=443;
        if(entry=="ss"){parent.type="ss";parent.cipher="aes-256-gcm";parent.password="pässword-测试";}
        auto node=vlessTestNode(transport);node.name="Exit";node.server="inner.chain.test";node.port=443;node.dialerProxy="Entry";
        {std::lock_guard<std::mutex> lock(g_state.mutex);g_state.nodes={parent,node};g_state.localNodes=g_state.nodes;g_state.groups.clear();g_state.rules={{"match","","Exit"}};g_state.mode="Rule";}
        VmessReferencePeer destination(0,transport,"udp","vless_reference_peer.py");const int downstream=destination.take();
        VmessReferencePeer gateway(0,entry,std::to_string(downstream),"chain_relay_reference_peer.py");close(downstream);
        std::atomic<int> connections{0};g_testConnector=[&](const std::string& host,int port,int){require(host=="outer.chain.test"&&port==443,"UDP-over-stream may only dial its physical entry");++connections;return gateway.take();};
        const auto up=g_state.uploadTotal.load(),down=g_state.downloadTotal.load();size_t sent=0,received=0;
        {
            UdpHarness harness;
            for(int i=0;i<4;++i){std::string body=i==0?"packet-0":i==2?std::string(4096,'P'):"";if(i==3){body.resize(65507-3-15);for(size_t j=0;j<body.size();++j)body[j]=static_cast<char>(j);}
                sent+=body.size();harness.inject(udpTestPacket("target.test",443,body));auto packet=receiveTestDatagram(harness.relay);UdpTarget source;
                require(parseSocksUdp(packet,source)&&source.host=="target.test"&&source.port==443,"Chained streamed UDP must retain its destination");
                const std::string expected=i==3?body:"udp-response:"+std::string(body.rbegin(),body.rend());received+=expected.size();
                require(text({packet.begin()+3+source.headerSize,packet.end()})==expected,"Chained streamed UDP damaged payload or empty datagram");
            }
            for(const std::string expected:{"A","","B"}){auto packet=receiveTestDatagram(harness.relay);UdpTarget source;require(parseSocksUdp(packet,source)&&text({packet.begin()+3+source.headerSize,packet.end()})==expected,"Chained coalesced UDP must retain every datagram");received+=expected.size();}
            awaitCondition([&]{return g_state.uploadTotal.load()-up==sent&&g_state.downloadTotal.load()-down==received;},"Streamed chain counters must count only the application payload once");
            require(connections==1,"One streamed UDP session needs one physical entry connection");
        }
        g_testConnector=nullptr;gateway.finish();destination.finish();require(g_dialerWorkers==0&&g_state.connections.empty(),"Streamed UDP chain leaked session or bridge resources");
    }
}

void dialerNativeUdpTests(const std::string& directory)
{
    for(const std::string kind:{"aes-128-gcm","aes-256-gcm","chacha20-ietf-poly1305","direct","socks5","vless+aes-256-gcm"}) {
        std::cerr<<"Dialer native UDP: ss -> "<<kind<<'\n';
        const bool streamed=kind.rfind("vless+",0)==0;const std::string cipher=streamed?kind.substr(6):kind;
        ProxyNode parent;parent.name="Entry";parent.type="ss";parent.server="outer.chain.test";parent.port=443;parent.cipher="aes-256-gcm";parent.password="pässword-测试";parent.udp=true;
        ProxyNode node;node.name="Exit";node.type=kind=="direct"?"direct":kind=="socks5"?"socks5":"ss";node.server="inner.chain.test";node.port=443;node.password=parent.password;node.cipher=cipher;node.udp=true;node.dialerProxy="Entry";
        if(kind=="socks5"){node=forwardTestNode("socks5-tcp");node.name="Exit";node.server="inner.chain.test";node.dialerProxy="Entry";}
        if(streamed){parent=vlessTestNode("tcp");parent.name="Entry";parent.server="outer.chain.test";node.dialerProxy="Alias";}
        {std::lock_guard<std::mutex> lock(g_state.mutex);g_state.nodes={parent,node};if(streamed){ProxyNode alias;alias.name="Alias";alias.type="direct";alias.dialerProxy="Entry";g_state.nodes.push_back(alias);}g_state.localNodes=g_state.nodes;g_state.groups.clear();g_state.rules={{"match","","Exit"}};g_state.mode="Rule";}
        const std::string marker=directory+"/dialer-udp-"+kind;unlink(marker.c_str());
        VmessReferencePeer peer(0,kind,marker,"chain_udp_reference_peer.py",!streamed);
        std::unique_ptr<VmessReferencePeer> control,gateway;
        if(kind=="socks5"){control=std::make_unique<VmessReferencePeer>(0,"control","","chain_udp_reference_peer.py");const int downstream=control->take();gateway=std::make_unique<VmessReferencePeer>(0,"ss",std::to_string(downstream),"chain_relay_reference_peer.py");close(downstream);}
        int tcpDials=0,udpDials=0;g_testConnector=[&](const std::string& host,int port,int){require((kind=="socks5"||streamed)&&host=="outer.chain.test"&&port==443,"Only a streamed carrier or SOCKS control may open a TCP entry");++tcpDials;return streamed?peer.take():gateway->take();};
        const size_t carrier=streamed?65507:65507-48-shadowsocksAddress(kind=="direct"?"target.test":kind=="socks5"?"192.0.2.1":"inner.chain.test",kind=="socks5"?18096:443).size();
        const size_t maximum=carrier-(kind=="direct"?0:kind=="socks5"?3+15:shadowsocksKeySize(shadowsocksCipher(cipher))+16+15);
        const auto up=g_state.uploadTotal.load(),down=g_state.downloadTotal.load();size_t sent=0,received=0;
        {
            UdpHarness harness;
            g_udpTestHooks.connect=[&](const std::string& host,int port,UdpEndpoint& remote){require(!streamed&&host=="outer.chain.test"&&port==443,"Native UDP chains may only dial the outer SS entry");remote=udpTestEndpoint("192.0.2.1",443);++udpDials;return peer.take();};
            for(int i=0;i<4;++i){std::string body=i==0?"packet-0":i==2?std::string(4096,'P'):"";if(i==3){harness.inject(udpTestPacket("target.test",443,std::string(maximum+1,'X')));body.resize(maximum);for(size_t j=0;j<body.size();++j)body[j]=static_cast<char>(j);}
                sent+=body.size();harness.inject(udpTestPacket("target.test",443,body));auto packet=receiveTestDatagram(harness.relay);UdpTarget source;
                const std::string host=i==1?"2001:db8::1":i==2?"answer.test":"8.8.8.8";
                require(parseSocksUdp(packet,source)&&source.host==host&&source.port==53+i,("UDP chain must preserve the exit's actual response source, packet "+std::to_string(i)).c_str());
                const std::string expected=i==1?"":i==3?body:"udp-response:"+std::string(body.rbegin(),body.rend());received+=expected.size();
                require(text({packet.begin()+3+source.headerSize,packet.end()})==expected,"Native UDP chain damaged data, salt, or zero-length packet");
            }
            for(const std::string expected:{"A","","B"}){auto packet=receiveTestDatagram(harness.relay);UdpTarget source;require(parseSocksUdp(packet,source)&&text({packet.begin()+3+source.headerSize,packet.end()})==expected,"Native UDP boundaries and empty replies must survive nested carriers");received+=expected.size();}
            awaitCondition([&]{return g_state.uploadTotal.load()-up==sent&&g_state.downloadTotal.load()-down==received;},"Native chain counters must exclude all intermediate headers and rejected oversize packets");
            require(udpDials==(streamed?0:1)&&tcpDials==(kind=="socks5"||streamed?1:0),"A UDP chain must keep a single carrier and SOCKS control association");
            const auto id=connectionId("target.test");require(!id.empty(),"UDP chain requires one visible application session");
            {std::lock_guard<std::mutex> lock(g_state.sessionsMutex);require(g_state.connections.size()==1,"Internal carrier flows must not appear as duplicate application connections");}
            controlRequest("DELETE","/connections/"+id);awaitCondition([]{return connectionId("target.test").empty()&&g_dialerWorkers==0;},"Disconnect must close the complete UDP chain and its SOCKS control channel");
            {std::ofstream ack(marker);ack<<"verified";}
        }
        g_testConnector=nullptr;peer.finish();if(gateway){gateway->finish();control->finish();}unlink(marker.c_str());require(g_state.connections.empty()&&g_state.sockets.empty(),"UDP chain cleanup leaked descriptors or accounting records");
    }
}

void dialerProxyTests(const std::string& directory)
{
    dialerGraphTests(directory);
    const std::string roots=readTestFile(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/vmess/ca.pem");
    g_testVmessTrust=roots.c_str();g_state.running.store(true);
    dialerProviderTests(directory);g_state.running.store(true);
    for(const std::string entry:{"http","socks5","ss"})for(const std::string exit:{"ss","vmess","vmess-ws-tls","trojan-tls","vless","vless-ws-tls","forward-http-tls","forward-socks5-tls"}) {
        std::cerr<<"Dialer HTTPS: "<<entry<<" -> "<<exit<<'\n';
        ProxyNode parent;
        if(entry=="ss"){parent.name="Entry";parent.type="ss";parent.cipher="aes-256-gcm";parent.password="pässword-测试";}
        else {parent=forwardTestNode(entry+"-tcp");parent.name="Entry";}
        parent.server="outer.chain.test";parent.port=443;
        ProxyNode node;
        if(exit=="ss"){node.type="ss";node.cipher="aes-256-gcm";node.password="probe-password";}
        else if(exit.rfind("vmess",0)==0)node=vmTestNode(0,exit=="vmess-ws-tls"?"ws-tls":"tcp","auto");
        else if(exit.rfind("vless",0)==0){node.type="vless";node.uuid="11111111-2222-4333-8444-555555555555";node.tls=exit=="vless-ws-tls";node.network=node.tls?"ws":"tcp";node.wsPath="/vless?test=1";node.wsHeaders={{"Host","cdn.test"},{"X-Test","native-peer"}};}
        else if(exit=="trojan-tls"){node.type="trojan";node.password="probe-password";node.tls=true;}
        else node=forwardTestNode(exit.substr(8));
        node.name="Exit";node.server="inner.chain.test";node.port=443;node.serverName="vmess.test";node.dialerProxy=parent.name;node.dialerNode=std::make_shared<const ProxyNode>(parent);
        VmessReferencePeer destination(0,exit,"","https_reference_peer.py");const int downstream=destination.take();
        VmessReferencePeer gateway(0,entry,std::to_string(downstream),"chain_relay_reference_peer.py");close(downstream);
        int connections=0;g_testConnector=[&](const std::string& host,int port,int){require(host=="outer.chain.test"&&port==443,"Only the chain entry may be dialed directly");++connections;return gateway.take();};
        TestTarget target;parseTestUrl("https://vmess.test/probe?ok=1",target);std::string error;
        const int delay=probeNode(node,target,5000,"204",error);
        g_testConnector=nullptr;
        require(delay>0&&connections==1,("Chained HTTPS probe failed: "+error).c_str());
        gateway.finish();destination.finish();
        require(g_dialerWorkers.load()==0,"Chained probe must release its bridge worker");
    }
    for(int protocol:{0,1}) {
        ProxyNode parent=forwardTestNode("http-tcp");parent.name="Entry";parent.server="outer.chain.test";
        auto middle=parent;middle.name="Middle";middle.type="ss";middle.server="inner.chain.test";middle.cipher="aes-256-gcm";middle.password="pässword-测试";middle.dialerProxy="Entry";
        auto node=vlessTestNode("tcp");node.name="Exit";node.server="inner.chain.test";node.dialerProxy="Middle";
        {std::lock_guard<std::mutex> lock(g_state.mutex);g_state.nodes={parent,middle,node};g_state.localNodes=g_state.nodes;g_state.groups.clear();g_state.rules={{"match","","Exit"}};g_state.mode="Rule";}
        const auto marker=directory+"/dialer-three-hop";unlink(marker.c_str());
        VmessReferencePeer destination(0,"tcp","duplex-version|"+marker,"vless_reference_peer.py");int downstream=destination.take();VmessReferencePeer second(0,"ss",std::to_string(downstream),"chain_relay_reference_peer.py");close(downstream);
        downstream=second.take();VmessReferencePeer first(0,"http",std::to_string(downstream),"chain_relay_reference_peer.py");close(downstream);
        int physical=0;g_testConnector=[&](const std::string& host,int port,int){require(host=="outer.chain.test"&&port==443,"Three-hop ingress must only connect the first gateway");++physical;return first.take();};
        VmBytes payload(50000);for(size_t i=0;i<payload.size();++i)payload[i]=static_cast<unsigned char>(i*17+3);auto expected=vmBytes("vless-response:");expected.insert(expected.end(),payload.rbegin(),payload.rend());
        const auto up=g_state.uploadTotal.load(),down=g_state.downloadTotal.load();int client[2];pairFor(client);socketTimeout(client[1],5000);dispatchWorker(client[0],protocol);
        if(protocol==0){sendAll(client[1],"CONNECT target.test:443 HTTP/1.1\r\nHost: target.test\r\n\r\n");require(readUntilHeaders(client[1]).find("200 Connection Established")!=std::string::npos,"Three-hop HTTP ingress must establish");}
        else{VmBytes greeting{5,1,0,5,1,0};vmAppend(greeting,shadowsocksAddress("target.test",443));sendAll(client[1],greeting);require(receiveN(client[1],2)==std::string("\5\0",2)&&receiveN(client[1],10)[1]==0,"Three-hop SOCKS ingress must establish");}
        require(sendAll(client[1],reinterpret_cast<const char*>(payload.data()),16),"Three-hop initial payload write");awaitCondition([&]{return access(marker.c_str(),F_OK)==0;},"Three-hop partial response must reach the exit");
        require(sendAll(client[1],reinterpret_cast<const char*>(payload.data()+16),payload.size()-16),"Three-hop partial replies must not block later upload");shutdown(client[1],SHUT_WR);
        require(receiveN(client[1],expected.size())==text(expected),"Three-hop ingress must preserve fragmented response payload");char byte;require(recv(client[1],&byte,1,0)==0,"Three-hop half-close must reach the client");close(client[1]);workersIdle();g_testConnector=nullptr;
        first.finish();second.finish();destination.finish();unlink(marker.c_str());require(physical==1&&g_dialerWorkers==0&&g_state.uploadTotal.load()-up==payload.size()&&g_state.downloadTotal.load()-down==expected.size(),"Three-hop counters and worker cleanup must exclude intermediate traffic");
    }
    {
        std::vector<std::unique_ptr<DialerWorkerSlot>> slots;for(int i=0;i<128;++i)slots.push_back(std::make_unique<DialerWorkerSlot>());
        ProxyNode parent;parent.name="DIRECT";parent.type="direct";ProxyNode node=parent;node.name="Exit";node.dialerProxy="Gateway";node.dialerNode=std::make_shared<const ProxyNode>(parent);
        bool physical=false;g_testConnector=[&](const std::string&,int,int){physical=true;return -1;};ProxyStream stream;std::string error;
        require(!openProxyStream(node,"target.test",443,stream,error)&&!physical&&error.find("limit")!=std::string::npos,"Bridge exhaustion must reject before opening extra sockets");g_testConnector=nullptr;slots.clear();require(g_dialerWorkers==0,"Reserved chain slots must be released exactly once");
    }
    dialerStreamUdpTests(roots);dialerNativeUdpTests(directory);
    g_testVmessTrust=nullptr;stopCore();
}
