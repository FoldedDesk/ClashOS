void dnsTests(const std::string& directory)
{
    g_testConnector=nullptr;g_testRuleResolver=nullptr;g_testResolvedConnector=nullptr;
    std::vector<std::unique_ptr<VmessReferencePeer>> peers;
    std::string fault;int datagrams=0,streams=0;std::vector<std::string> contacted;
    auto peer=[&](const std::string& transport,int variant,const std::string& failure) {
        auto item=std::make_unique<VmessReferencePeer>(variant,transport,failure,"dns_reference_peer.py",transport=="udp");
        const int fd=item->take();peers.push_back(std::move(item));return fd;
    };
    g_testDnsDatagram=[&](const DnsEndpoint& endpoint) {
        ++datagrams;contacted.push_back(endpoint.host);return peer("udp",endpoint.host=="198.51.100.53"?20:endpoint.host=="203.0.113.53"?30:10,fault);
    };
    g_testResolvedConnector=[&](const std::string& host,int port,int) {
        ++streams;contacted.push_back(host+":"+std::to_string(port));return peer(port==853?"tls":port==443?"https":port==80?"relay":"tcp",10,fault=="truncated"?"":fault);
    };
    const std::string profile=directory+"/dns.yaml";
    auto load=[&](const std::string& dns,const std::string& extra="") {
        loadProviderProfile(profile,"ipv6: true\nproxies: []\nproxy-groups: []\nrules: ['MATCH,DIRECT']\ndns:\n  enable: true\n"+dns+extra);contacted.clear();
    };
    auto ask=[&](const std::string& name="a.fixture.test",uint16_t type=1,DnsPurpose purpose=DnsPurpose::General,int timeout=2500) {
        return queryDns(name,type,purpose,HealthClock::now()+std::chrono::milliseconds(timeout));
    };
    auto address=[&](const DnsAnswer& answer,const std::string& expected) {
        require(answer.error.empty(),"Independent DNS exchange failed");const auto addresses=dnsAnswerAddresses(answer);
        require(addresses.size()==1&&addresses[0]==expected,"DNS address must come from the requested owner/type or its CNAME chain");
    };
    std::string error;ParsedConfig parsed;
    DnsEndpoint namedOutbound;
    require(parseDnsEndpoint("udp://192.0.2.53#🔰 选择节点",namedOutbound,error)&&namedOutbound.route=="🔰 选择节点","DNS outbound names can contain Unicode and spaces used by real proxy groups");
    require(parseDnsEndpoint("udp://192.0.2.53#DNS%20Resolver",namedOutbound,error)&&namedOutbound.route=="DNS Resolver","URL-encoded DNS outbound names are decoded");
    require(!parseDnsEndpoint("udp://192.0.2.53#bad%0Aname",namedOutbound,error),"DNS outbound names cannot contain control characters");
    for(const std::string& bad:{"enable: [true]","enable: true\n  nameserver: [quic://1.1.1.1]","enable: true\n  nameserver: [udp://1.1.1.1:0]","enable: true\n  nameserver: [1.1.1.1]\n  default-nameserver: [dns.fixture.test]","enable: true\n  respect-rules: true\n  nameserver: [1.1.1.1]"}) {
        ParsedConfig invalid;require(!parseConfigText("dns:\n  "+bad,invalid,error),"Invalid DNS configuration must be rejected");
    }
    std::vector<unsigned char> question;require(dnsBuildQuestion("A.Fixture.Test.",1,0x1234,question),"DNS input case/trailing-dot normalization");
    require(question==hex("1234010000010000000000000161076669787475726504746573740000010001"),"DNS query must match the independent RFC wire vector");
    require(!dnsBuildQuestion(std::string(64,'a')+".test",1,0,question),"Oversized DNS label rejected");
    require(!dnsBuildQuestion("bad..test",1,0,question),"Empty DNS label rejected");
    require(!dnsBuildQuestion("a.fixture.test",252,0,question),"Zone transfers are not resolver queries");
    const auto golden=hex("1234818000010001000000000161076669787475726504746573740000010001c00c00010001000000780004c000020a");
    DnsAnswer decoded;require(dnsParseResponse(golden,"a.fixture.test",1,0x1234,decoded),"Independent compressed DNS response vector");address(decoded,"192.0.2.10");
    auto extended=golden;dnsSet16(extended,10,1);const auto opt=hex("00002904d0010000000000");extended.insert(extended.end(),opt.begin(),opt.end());
    require(dnsParseResponse(extended,"a.fixture.test",1,0x1234,decoded)&&decoded.rcode==16,"Extended EDNS response codes must not be mistaken for successful answers");
    auto invalidOpt=extended;invalidOpt[invalidOpt.size()-5]=1;
    require(!dnsParseResponse(invalidOpt,"a.fixture.test",1,0x1234,decoded),"An unknown EDNS response version must be rejected");
    invalidOpt=extended;invalidOpt.back()=1;invalidOpt.push_back(0);
    require(!dnsParseResponse(invalidOpt,"a.fixture.test",1,0x1234,decoded),"Truncated EDNS option headers must be rejected");
    invalidOpt=extended;dnsSet16(invalidOpt,10,2);invalidOpt.insert(invalidOpt.end(),opt.begin(),opt.end());
    require(!dnsParseResponse(invalidOpt,"a.fixture.test",1,0x1234,decoded),"Duplicate OPT response records must be rejected");
    invalidOpt=extended;dnsSet16(invalidOpt,10,0);dnsSet16(invalidOpt,6,2);
    require(!dnsParseResponse(invalidOpt,"a.fixture.test",1,0x1234,decoded),"OPT records belong only in the additional section");
    for(size_t length=0;length<golden.size();++length)require(!dnsParseResponse(std::vector<unsigned char>(golden.begin(),golden.begin()+length),"a.fixture.test",1,0x1234,decoded),"Every truncated wire-vector prefix must fail safely");
    load("  nameserver: [192.0.2.53]\n  ipv6: true\n");
    auto a=ask();address(a,"192.0.2.10");require(a.server=="udp://192.0.2.53:53"&&!a.cached,"DNS result identifies the configured transport/server");
    const int before=datagrams;a=ask();require(a.cached&&datagrams==before,"Unexpired DNS cache must not issue another request");
    {std::lock_guard<std::mutex> lock(g_state.dns->cacheMutex);for(auto& item:g_state.dns->cache)item.second.stored-=std::chrono::seconds(5);}
    require(ask().records[0].ttl<=115,"Cached DNS TTL decreases with elapsed time");
    {std::lock_guard<std::mutex> lock(g_state.dns->cacheMutex);for(auto& item:g_state.dns->cache)item.second.expires=HealthClock::now()-std::chrono::seconds(1);}
    require(!ask().cached&&datagrams==before+1,"Expired DNS records must be queried again");
    address(ask("a.fixture.test",28),"2001:db8::10");address(ask("alias.fixture.test"),"192.0.2.10");address(ask("follow.fixture.test"),"192.0.2.10");
    require(ask("mx.fixture.test",15).records[0].data=="10 mail.fixture.test","MX wire fields decoded");
    require(ask("txt.fixture.test",16).records[0].data=="\"hello\" \"world\"","TXT character strings decoded");
    require(responseFor("GET","/dns/query?name=api.fixture.test&type=A","").find("192.0.2.10")!=std::string::npos,"Standard DNS query API uses the configured resolver");
    require(responseFor("GET","/dns/query?name=bad..test&type=A","").find("error")!=std::string::npos,"DNS query API rejects malformed input");
    require(responseFor("GET","/dns/query?name=a.test&type=65536","").find("error")!=std::string::npos,"DNS query API bounds query types");
    require(responseFor("DELETE","/clahsos/dns/cache","")=="{}"&&g_state.dns->cache.empty(),"DNS cache flush clears current profile cache");
    for(const std::string& failure:{"id-mismatch","truncated","truncated-always","question-mismatch","bad-address-length","pointer-loop","servfail","negative","zero-ttl"}) {
        fault=failure;load("  nameserver: [192.0.2.53]\n");a=ask();
        if(failure=="id-mismatch"||failure=="truncated")address(a,"192.0.2.10");
        else if(failure=="truncated-always")require(!a.error.empty(),"A still-truncated TCP response cannot be accepted");
        else if(failure=="negative") {require(a.error.empty()&&a.rcode==3&&dnsAnswerAddresses(a).empty(),"NXDOMAIN is an explicit negative answer");const int count=datagrams;require(ask().cached&&datagrams==count,"SOA minimum bounds negative caching");}
        else if(failure=="zero-ttl") {address(a,"192.0.2.10");require(!ask().cached,"Zero TTL answers must not be cached");}
        else require(!a.error.empty()&&dnsAnswerAddresses(a).empty(),"Malformed, mismatched or SERVFAIL responses are not addresses");
    }
    fault.clear();
    fault="timeout";load("  nameserver: [192.0.2.53]\n");const auto timed=HealthClock::now();a=ask("timeout.fixture.test",1,DnsPurpose::General,180);
    require(!a.error.empty()&&HealthClock::now()-timed<std::chrono::milliseconds(700),"DNS datagram timeout is bounded by the caller deadline");
    require(contacted==std::vector<std::string>{"192.0.2.53"},"Configured DNS failure cannot silently query a system/public resolver");fault.clear();
    fault="alias-loop";load("  nameserver: [192.0.2.53]\n");require(!ask("loop.fixture.test").error.empty(),"CNAME dependency loops terminate without producing addresses");fault.clear();
    load("  nameserver: [192.0.2.53]\n  nameserver-policy: {'+.policy.test': [198.51.100.53]}\n  proxy-server-nameserver: [203.0.113.53]\n  direct-nameserver: [203.0.113.53]\n");
    address(ask("a.policy.test"),"192.0.2.20");address(ask("a.policy.test",1,DnsPurpose::Proxy),"192.0.2.30");
    address(ask("a.policy.test",1,DnsPurpose::Direct),"192.0.2.30");require(ask("a.policy.test",28).records.empty(),"Disabled IPv6 returns an empty AAAA answer");
    load("  nameserver: [192.0.2.53]\n  nameserver-policy: {'*': 198.51.100.53}\n");address(ask("deep.a.fixture.test"),"192.0.2.20");
    load("  nameserver: [192.0.2.53]\n  use-hosts: true\n","hosts: {override.fixture.test: [203.0.113.10, '2001:db8::1'], alias-host.fixture.test: override.fixture.test}\n");
    address(ask("override.fixture.test"),"203.0.113.10");address(ask("alias-host.fixture.test"),"203.0.113.10");require(contacted.empty(),"Hosts overrides and aliases must not contact a resolver");
    load("  nameserver: [192.0.2.53]\n","hosts: {a.fixture.test: b.fixture.test, b.fixture.test: a.fixture.test}\n");require(!ask().error.empty()&&contacted.empty(),"Hosts alias loops fail without DNS leakage");
    load("  nameserver: [192.0.2.53]\n  use-hosts: false\n","hosts: {override.fixture.test: 203.0.113.10}\n");address(ask("override.fixture.test"),"192.0.2.10");
    load("  nameserver: [192.0.2.53]\n  fallback: [198.51.100.53]\n  fallback-filter: {geoip: false, domain: ['+.fallback.test'], ipcidr: [192.0.2.0/24]}\n");
    address(ask("force.fallback.test"),"192.0.2.20");require(contacted.size()==1&&contacted[0]=="198.51.100.53","Fallback domain filter selects fallback before the primary query");
    address(ask("cidr.fixture.test"),"192.0.2.20");
    load("  nameserver: [192.0.2.53]\n  nameserver-policy: {'rule-set:policy': 198.51.100.53}\n","rule-providers: {policy: {type: inline, behavior: domain, payload: ['+.policy.test']}}\n");
    address(ask("a.policy.test"),"192.0.2.20");
    load("  nameserver: [192.0.2.53]\n  nameserver-policy: {'rule-set:policy': 198.51.100.53}\n","rule-providers: {policy: {type: file, behavior: domain, path: missing-rules.yaml}}\n");
    require(!ask().error.empty()&&contacted.empty(),"Unavailable DNS rule-set policy cannot fall through to an unrelated resolver");
    std::ifstream rootFile(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/vmess/ca.pem");const std::string roots((std::istreambuf_iterator<char>(rootFile)),{});g_testVmessTrust=roots.c_str();
    for(const std::string& transport:{"tcp://192.0.2.53","tls://vmess.test","https://vmess.test/dns-query"}) {
        load("  nameserver: ['"+transport+"']\n  default-nameserver: [192.0.2.53]\n");a=ask();address(a,"192.0.2.10");
        require(a.server.rfind(transport.substr(0,transport.find("://")),0)==0,"DNS TCP/TLS/HTTPS use the declared transport");
    }
    fault="bad-content-type";load("  nameserver: ['https://vmess.test/dns-query']\n  default-nameserver: [192.0.2.53]\n");
    require(!ask().error.empty(),"HTTPS DNS must reject a wrong Content-Type even when body bytes look valid");fault.clear();
    fault="http-age";load("  nameserver: ['https://vmess.test/dns-query']\n  default-nameserver: [192.0.2.53]\n");require(ask().records[0].ttl==90,"HTTPS cache Age is subtracted from DNS TTL");fault.clear();
    g_testVmessTrust=nullptr;load("  nameserver: ['tls://vmess.test']\n  default-nameserver: [192.0.2.53]\n");require(!ask().error.empty(),"Untrusted DNS TLS certificate must fail closed");g_testVmessTrust=roots.c_str();
    // A cache flush must also invalidate answers from requests already in flight.
    load("  nameserver: [192.0.2.53]\n");
    std::promise<void> pending,release;auto released=release.get_future().share();
    auto datagramHook=g_testDnsDatagram;
    g_testDnsDatagram=[&](const DnsEndpoint& endpoint){pending.set_value();released.wait();return datagramHook(endpoint);};
    auto inFlight=std::async(std::launch::async,[&]{return ask("flush.fixture.test");});pending.get_future().wait();
    require(responseFor("DELETE","/clahsos/dns/cache","")=="{}","Cache can be flushed while DNS I/O is active");release.set_value();address(inFlight.get(),"192.0.2.10");
    require(g_state.dns->cache.empty(),"A flushed in-flight DNS answer cannot repopulate the cache");g_testDnsDatagram=datagramHook;
    // IP rule re-evaluation must resolve again if another profile changes the DNS policy.
    load("  nameserver: [192.0.2.53]\n");{std::lock_guard<std::mutex> lock(g_state.mutex);g_state.rules={{"ip-cidr","192.0.2.10/32","REJECT"},{"match","","DIRECT"}};}
    std::promise<void> routingPending,routingRelease;auto routingReleased=routingRelease.get_future().share();bool firstQuery=true;
    g_testDnsDatagram=[&](const DnsEndpoint& endpoint){if(firstQuery){firstQuery=false;routingPending.set_value();routingReleased.wait();}return datagramHook(endpoint);};
    auto routing=std::async(std::launch::async,[&]{return activeProxyNode("routing.fixture.test",80);});routingPending.get_future().wait();
    {std::lock_guard<std::mutex> lock(g_state.mutex);load("  nameserver: [198.51.100.53]\n");g_state.rules={{"ip-cidr","192.0.2.10/32","REJECT"},{"match","","DIRECT"}};}
    routingRelease.set_value();require(routing.get().type=="direct","Routing after a profile change must not reuse addresses from the old DNS configuration");g_testDnsDatagram=datagramHook;
    for(const std::string& kind:{"ss-aes-128-gcm","ss-aes-256-gcm","ss-chacha20-ietf-poly1305","vmess-tcp","vmess-ws-tls","trojan-tls","trojan-ws-tls"}) {
        load("  nameserver: ['udp://192.0.2.53#DNS Resolver']\n");
        ProxyNode node;
        if(kind.rfind("ss-",0)==0){node.name=kind;node.type="ss";node.cipher=kind.substr(3);node.server="dns-ss.invalid";node.port=443;node.password="pässword-测试";}
        else if(kind.rfind("vmess-",0)==0)node=vmTestNode(0,kind.substr(6),"aes-128-gcm");
        else node=trojanTestNode(kind.substr(7));
        node.udp=true;ProxyGroup group;group.name="DNS Resolver";group.type="Selector";group.now=node.name;group.proxies={node.name};
        g_state.nodes.push_back(node);g_state.groups.push_back(group);
        auto proxyPeer=[&](){auto item=std::make_unique<VmessReferencePeer>(0,kind,"","dns_proxy_reference_peer.py",node.type=="ss");const int fd=item->take();peers.push_back(std::move(item));return fd;};
        g_testConnector=[&](const std::string& host,int port,int){require(host==node.server&&port==node.port,"DNS proxy must connect to the configured node, not the DNS target directly");return proxyPeer();};
        g_udpTestHooks.connect=[&](const std::string& host,int port,UdpEndpoint&){require(host==node.server&&port==node.port,"Encrypted UDP DNS must dial the configured node");return proxyPeer();};
        address(ask("proxied.fixture.test"),"192.0.2.10");
        g_state.groups[0].disableUdp=true;responseFor("DELETE","/clahsos/dns/cache","");
        require(!ask("disabled.fixture.test").error.empty(),"A DNS outbound must respect disable-udp on its explicit group");
        g_testConnector=nullptr;g_udpTestHooks={};
    }
    load("  nameserver: [192.0.2.53]\n");
    ProxyNode direct;direct.name="DIRECT";direct.type="direct";ProxyStream stream;
    require(openProxyStream(direct,"a.fixture.test",80,stream,error,2500),"DIRECT TCP must use configured DNS before connecting");
    require(std::find(contacted.begin(),contacted.end(),"192.0.2.10:80")!=contacted.end(),"Resolved destination address reaches the production connector");
    const std::string request="GET /verify HTTP/1.1\r\nHost: a.fixture.test\r\n\r\n";
    require(streamWrite(stream,request.data(),request.size()),"Resolved DIRECT HTTP write");
    std::vector<unsigned char> received;require(streamRead(stream,received)&&text(received).find("204")!=std::string::npos,"Configured DNS leads to an actual HTTP response");
    for(auto& item:peers)item->finish();peers.clear();
    g_testDnsDatagram=nullptr;g_testResolvedConnector=nullptr;g_testVmessTrust=nullptr;g_state.running.store(false);
}
