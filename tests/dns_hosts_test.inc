void dnsHostsTests(const std::string& directory)
{
    stopCore();workersIdle();g_testConnector=nullptr;g_testResolvedConnector=nullptr;g_udpTestHooks={};
    const std::string profile=directory+"/hosts.yaml",roots=readTestFile(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/vmess/ca.pem");
    g_testVmessTrust=roots.c_str();int lookups=0;
    g_testRuleResolver=[&](const std::string&){++lookups;return std::vector<std::string>{"198.51.100.9"};};
    auto load=[&](const std::string& hosts,const std::string& settings="",const std::string& rules="['MATCH,DIRECT']") {
        loadProviderProfile(profile,"ipv6: true\nproxies: []\nproxy-groups: []\nrules: "+rules+"\ndns:\n  enable: false\n  ipv6: true\n"+settings+"hosts: "+hosts+"\n");
    };
    load("{'*.fixture.test': 192.0.2.8, source.fixture.test: alias.fixture.test, alias.fixture.test: [192.0.2.9, '2001:db8::9']}");
    auto mapped=dnsHostOverride(*g_state.dns,"SOURCE.FIXTURE.TEST.",true);
    require(mapped.mapped&&mapped.error.empty()&&mapped.route=="alias.fixture.test"&&mapped.destination=="192.0.2.9"&&mapped.addresses==std::vector<std::string>({"192.0.2.9","2001:db8::9"}),"Hosts aliases and exact-name priority must retain both enabled address families");
    require(dnsHostOverride(*g_state.dns,"other.fixture.test",true).destination=="192.0.2.8","Wildcard hosts mapping must apply to proxy targets");
    require(dnsHostOverride(*g_state.dns,"192.0.2.100",true).destination=="192.0.2.100","Explicit IP destinations bypass domain hosts overrides");
    load("{'+.fixture.test': 192.0.2.8, 'FIXTURE.TEST.': 192.0.2.9}");
    require(dnsHostOverride(*g_state.dns,"fixture.test",true).destination=="192.0.2.9","An exact root-domain mapping must win even when the suffix expression has more characters");
    require(dnsAnswerAddresses(queryDns("fixture.test",1,DnsPurpose::General,HealthClock::now()+std::chrono::seconds(1)))==std::vector<std::string>{"192.0.2.9"},"DNS answers and proxy destinations must agree on exact-root precedence");
    load("{source.fixture.test: target.test}");mapped=dnsHostOverride(*g_state.dns,"source.fixture.test",true);
    require(mapped.route=="target.test"&&mapped.destination=="target.test"&&mapped.addresses.empty()&&lookups==0,"Unmapped alias targets retain remote DNS without performing an unsolicited lookup");
    load("{source.fixture.test: '2001:db8::9'}");
    require(!dnsHostOverride(*g_state.dns,"source.fixture.test",false).error.empty(),"An IPv6-only hosts mapping cannot fall back to remote DNS when IPv6 is disabled");
    for(const std::string hosts:{"{source.fixture.test: alias.fixture.test, alias.fixture.test: source.fixture.test}","{source.fixture.test: []}"}) {
        load(hosts);require(!dnsHostOverride(*g_state.dns,"source.fixture.test",true).error.empty(),"Cyclic and empty explicit mappings must fail closed");
        require(activeProxyNode("source.fixture.test",443).type=="reject","A broken hosts mapping cannot bypass policy into DIRECT");
        for(const std::string mode:{"Direct","Global"}){g_state.mode=mode;require(activeProxyNode("source.fixture.test",443).type=="reject","Direct/global mode cannot bypass a broken explicit hosts mapping");}g_state.mode="Rule";
    }
    load("{source.fixture.test: source.fixture.test}","  use-hosts: false\n");
    require(!dnsHostOverride(*g_state.dns,"source.fixture.test",true).mapped&&activeProxyNode("source.fixture.test",443).type=="direct","use-hosts false disables target rewriting and alias-loop rejection");
    load("{source.fixture.test: 192.0.2.9}","","['IP-CIDR,192.0.2.0/24,REJECT,no-resolve','MATCH,DIRECT']");
    require(activeProxyNode("source.fixture.test",443).type=="reject"&&lookups==0,"Explicit hosts IPs must participate in no-resolve routing without querying DNS");
    load("{source.fixture.test: target.test}","","['DOMAIN,target.test,REJECT','MATCH,DIRECT']");
    require(activeProxyNode("source.fixture.test",443).type=="reject"&&lookups==0,"Host aliases must be applied before domain routing");

    auto makeNode=[&](const std::string& kind) {
        ProxyNode node;
        if(kind=="ss"){node.name="Public SS";node.type="ss";node.server="ss.invalid";node.port=443;node.cipher="aes-256-gcm";node.password="pässword-测试";}
        else if(kind.rfind("trojan",0)==0)node=trojanTestNode(kind.find("ws")!=std::string::npos?"ws-tls":"tls");
        else node=vmTestNode(0,kind.find("ws")!=std::string::npos?"ws-tls":"tls","aes-128-gcm");
        node.udp=true;return node;
    };
    auto install=[&](const std::string& kind,int scenario) {
        const std::string address=scenario==0?"192.0.2.9":scenario==1?"2001:db8::9":scenario==2?"target.test":"203.0.113.10";
        load("{source.fixture.test: alias.fixture.test, alias.fixture.test: '"+address+"'}");
        ProxyNode node=makeNode(kind);
        {std::lock_guard<std::mutex> lock(g_state.mutex);g_state.nodes={node};g_state.rules={{"match","",node.name}};}
        return node;
    };
    VmBytes payload(6000);for(size_t i=0;i<payload.size();++i)payload[i]=static_cast<unsigned char>(i*17+3);
    for(const std::string kind:{"ss","vmess-tls","vmess-ws-tls","trojan-tls","trojan-ws-tls"}) {
        for(int protocol:{0,1}) {
            std::cerr<<"Hosts TCP: "<<kind<<" inbound="<<protocol<<'\n';
            auto node=install(kind,0);VmessReferencePeer peer(0,kind,"tcp","hosts_reference_peer.py");
            g_testConnector=[&](const std::string& host,int port,int){require(host==node.server&&port==443,"Hosts destinations must never replace the proxy server endpoint");return peer.take();};
            int client[2];pairFor(client);socketTimeout(client[1],5000);dispatchWorker(client[0],protocol);
            if(protocol==0){require(sendAll(client[1],"CONNECT source.fixture.test:443 HTTP/1.1\r\n\r\n")&&readUntilHeaders(client[1]).find("200")!=std::string::npos,"Hosts HTTP CONNECT opens an encrypted outbound");}
            else {VmBytes greeting{5,1,0,5,1,0};vmAppend(greeting,shadowsocksAddress("source.fixture.test",443));sendAll(client[1],greeting);require(receiveN(client[1],2)==std::string("\5\0",2)&&receiveN(client[1],10)[1]==0,"Hosts SOCKS CONNECT opens an encrypted outbound");}
            require(sendAll(client[1],payload),"Send actual client bytes through hosts-aware encryption");shutdown(client[1],SHUT_WR);
            std::string response;while(response.size()<14){char data[14];const auto count=recv(client[1],data,14-response.size(),0);if(count<=0)break;response.append(data,static_cast<size_t>(count));}
            close(client[1]);workersIdle();g_testConnector=nullptr;peer.finish();
            require(response=="hosts-response","Mapped encrypted TCP response must reach the original client");
        }
        for(int scenario:{1,2}) {
            std::cerr<<"Hosts UDP: "<<kind<<" scenario="<<scenario<<'\n';
            auto node=install(kind,scenario);VmessReferencePeer peer(scenario,kind,"udp","hosts_reference_peer.py",kind=="ss");
            g_testConnector=[&](const std::string& host,int,int){require(host==node.server,"Streamed UDP still dials the proxy server");return peer.take();};
            {
                UdpHarness harness;
                if(kind=="ss"){std::lock_guard<std::mutex> lock(harness.mutex);harness.pending[node.server+":443"].push_back({peer.take(),udpTestEndpoint("192.0.2.10",443)});}
                harness.inject(udpTestPacket("source.fixture.test",443,"packet-0"));const auto reply=receiveTestDatagram(harness.relay);UdpTarget source;
                require(parseSocksUdp(reply,source)&&text({reply.begin()+3+source.headerSize,reply.end()})=="hosts-response","Hosts-aware encrypted UDP must preserve application payloads and packet boundaries");
                require(source.host==(kind.rfind("vmess",0)==0?"source.fixture.test":scenario==1?"2001:db8::9":"target.test"),"UDP replies retain their protocol's actual response endpoint");
            }
            g_testConnector=nullptr;peer.finish();
        }
    }
    {
        std::cerr<<"Hosts SS maximum UDP\n";
        auto node=install("ss",0);VmessReferencePeer peer(0,"ss","udp-max","hosts_reference_peer.py",true);
        UdpHarness harness;{std::lock_guard<std::mutex> lock(harness.mutex);harness.pending[node.server+":443"].push_back({peer.take(),udpTestEndpoint("192.0.2.10",443)});}
        std::string body(65507-32-16-shadowsocksAddress("192.0.2.9",443).size(),'x');for(size_t i=0;i<body.size();++i)body[i]=static_cast<char>(i);
        harness.inject(udpTestPacket("source.fixture.test",443,body));const auto reply=receiveTestDatagram(harness.relay);UdpTarget source;
        require(parseSocksUdp(reply,source)&&text({reply.begin()+3+source.headerSize,reply.end()})=="hosts-response","SS UDP size limits must use the mapped address rather than the longer original domain");peer.finish();
    }
    {
        std::cerr<<"Hosts ordinary HTTP\n";
        auto node=install("ss",0);VmessReferencePeer peer(0,"ss","http","hosts_reference_peer.py");g_testConnector=[&](const std::string&,int,int){return peer.take();};
        int client[2];pairFor(client);dispatchWorker(client[0],0);
        require(sendAll(client[1],"GET http://source.fixture.test:443/test HTTP/1.1\r\nHost: source.fixture.test\r\n\r\n")&&readUntilHeaders(client[1]).find("204 No Content")!=std::string::npos,"Ordinary HTTP preserves its original Host header after encrypted hosts rewriting");
        close(client[1]);workersIdle();g_testConnector=nullptr;peer.finish();
    }
    // A selected connection owns a DNS snapshot even if the next profile is
    // activated before its protocol handshake starts; nested DNS state restores.
    auto node=install("ss",0);const auto selected=activeProxyNode("source.fixture.test",443);const auto oldDns=selected.destinationDns;
    std::cerr<<"Hosts profile snapshot\n";
    install("ss",3);auto parent=g_state.dns;g_dnsTransportConfig=parent;
    {
        VmessReferencePeer peer(0,"ss","tcp","hosts_reference_peer.py");g_testConnector=[&](const std::string&,int,int){require(g_dnsTransportConfig==oldDns,"Selected DNS snapshot controls proxy-server resolution too");return peer.take();};
        ProxyStream stream;std::string error;require(openProxyStream(selected,"source.fixture.test",443,stream,error),"Open selected outbound after a profile switch");
        require(g_dnsTransportConfig==parent,"Outbound lookup restores the enclosing DNS transport context");
        require(streamWrite(stream,reinterpret_cast<const char*>(payload.data()),payload.size()),"Send snapshot-protected payload");shutdown(stream.fd,SHUT_WR);
        VmBytes response;require(streamRead(stream,response)&&text(response)=="hosts-response","Selected hosts snapshot cannot be replaced by the next profile");g_testConnector=nullptr;peer.finish();
    }
    g_dnsTransportConfig=nullptr;
    auto current=activeProxyNode("source.fixture.test",443);std::string destination,error;
    require(proxyDestination(current,"source.fixture.test",destination,error)&&destination=="203.0.113.10","New connections use the newly activated hosts mapping");
    require(proxyDestination(current,"198.51.100.7",destination,error)&&destination=="198.51.100.7","Sniffer override-destination false preserves the original literal destination");
    for(const std::string kind:{"ss","vmess-tls","vmess-ws-tls","trojan-tls","trojan-ws-tls"}) {
        load("{vmess.test: 192.0.2.9}");auto probe=makeNode(kind);probe.password="probe-password";
        VmessReferencePeer peer(0,kind,"hosts","https_reference_peer.py");g_testConnector=[&](const std::string&,int,int){return peer.take();};
        TestTarget target;require(parseTestUrl("https://vmess.test/probe?ok=1",target),"Parse hosts-aware HTTPS fixture");std::string probeError;
        require(probeNode(probe,target,5000,"204",probeError)>0,"Hosts-aware HTTPS must verify the original website name and preserve Host and SNI through every encrypted transport");
        g_testConnector=nullptr;peer.finish();
    }
    g_testRuleResolver=nullptr;g_testVmessTrust=nullptr;g_testConnector=nullptr;stopCore();
    require(g_state.connections.empty()&&g_state.sockets.empty(),"Hosts interoperability tests must release all tracked streams and associations");
}

void vmessDuplexTests(const std::string& directory)
{
    const std::string profile=directory+"/duplex.yaml",marker=directory+"/duplex-ready",roots=readTestFile(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/vmess/ca.pem");
    g_testVmessTrust=roots.c_str();
    for(int alter:{0,1})for(const std::string transport:{"tcp","tls","ws","ws-tls"})for(const std::string cipher:{"aes-128-gcm","chacha20-poly1305","none"}) {
        if(alter&&cipher!="aes-128-gcm")continue;
        for(const std::string phase:{"header","header-body","length","payload"}) {
            if(alter&&phase=="header-body")continue;
            std::cerr<<"VMess duplex: alter="<<alter<<" "<<transport<<" "<<cipher<<" partial="<<phase<<'\n';
            unlink(marker.c_str());loadProviderProfile(profile,"ipv6: false\nproxies: []\nrules: ['MATCH,DIRECT']\nhosts: {source.fixture.test: 192.0.2.9}\n");
            auto node=vmTestNode(alter,transport,cipher);
            {std::lock_guard<std::mutex> lock(g_state.mutex);g_state.mode="Rule";g_state.nodes={node};g_state.rules={{"match","",node.name}};}
            VmessReferencePeer peer(alter,transport,phase+"|"+marker,"vmess_duplex_reference_peer.py");g_testConnector=[&](const std::string&,int,int){return peer.take();};
            int client[2];pairFor(client);socketTimeout(client[1],2500);dispatchWorker(client[0],0);
            require(sendAll(client[1],"CONNECT source.fixture.test:443 HTTP/1.1\r\n\r\n")&&readUntilHeaders(client[1]).find("200")!=std::string::npos,"Open actual VMess ingress for partial-response duplex test");
            require(sendAll(client[1],"first"),"Send first VMess application bytes");
            const auto deadline=HealthClock::now()+std::chrono::seconds(2);
            while(access(marker.c_str(),F_OK)!=0&&HealthClock::now()<deadline)std::this_thread::sleep_for(std::chrono::milliseconds(1));
            require(access(marker.c_str(),F_OK)==0,"Independent peer confirms a partial reply was actually sent");
            pollfd watch{client[1],POLLIN,0};require(poll(&watch,1,50)==0,"Unauthenticated partial VMess replies must not release application bytes");
            require(sendAll(client[1],"tail"),"A partial remote reply must permit later client data");shutdown(client[1],SHUT_WR);
            require(receiveN(client[1],4)=="done","VMess must complete its reply after receiving the later client payload");
            char byte;require(recv(client[1],&byte,1,0)==0,"Incremental VMess receive preserves authenticated EOF");
            close(client[1]);workersIdle();g_testConnector=nullptr;peer.finish();unlink(marker.c_str());
        }
    }
    g_testVmessTrust=nullptr;stopCore();
}
