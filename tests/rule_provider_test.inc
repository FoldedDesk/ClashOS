void ruleCodecTests()
{
    const std::string fixtures=std::string(CLAHSOS_TEST_ROOT)+"/fixtures/rules/";
    RuleProvider domain;domain.behavior="domain";std::string error;std::shared_ptr<const RuleData> yaml,mrs;
    require(parseRuleContent(domain,readTestFile(fixtures+"domain.yaml"),yaml,error),"Domain YAML rule fixture must compile");
    domain.format="mrs";require(parseRuleContent(domain,readTestFile(fixtures+"domain.mrs"),mrs,error),"Independent MRS domain trie failed to decode");
    const std::vector<std::pair<std::string,bool>> queries={
        {"exact.test",true},{"EXACT.TEST.",true},{"www.exact.test",false},{"badexact.test",false},
        {"suffix.test",true},{"a.suffix.test",true},{"a.b.suffix.test",true},{"suffix.test.invalid",false},
        {"subonly.test",false},{"a.subonly.test",true},{"a.b.subonly.test",true},
        {"single.test",false},{"a.single.test",true},{"a.b.single.test",false},
        {"api.us.wild.test",true},{"api.eu.wild.test",true},{"api.a.b.wild.test",false},{"www.us.wild.test",false},
        {"one.nested.two.test",true},{"a.b.nested.two.test",false},{"例子.测试",true},{"a.例子.测试",true},
        {"a.b.例子.测试",true},{"",false},{"..suffix.test",false},{"suffix.test..",false}
    };
    for(const auto& query:queries) {
        require(yaml->domains.matches(query.first)==query.second,"Domain YAML exact/suffix/wildcard/Unicode semantics failed");
        require(mrs->domains.matches(query.first)==query.second,"MRS trie matching differs from independent expected query result");
    }
    require(mrs->count==8&&!mrs->domains.preview(3).empty()&&mrs->domains.preview(3).size()<=3,"MRS count and bounded preview failed");
    for(const std::string name:{"bad-magic","bad-behavior","negative-count","huge-extra","truncated-strategy","trailing-data","huge-bitmap","bad-trie-topology","bad-trie-padding","bad-trie-utf8","short-trie-utf8","truncated-zstd","trailing-zstd"})
        require(!parseRuleContent(domain,readTestFile(fixtures+name+".mrs"),mrs,error)&&!error.empty(),"Malformed MRS input must fail without replacing its previous snapshot");
    RuleProvider ip;ip.behavior="ipcidr";ip.format="text";std::shared_ptr<const RuleData> text,binary;
    require(parseRuleContent(ip,readTestFile(fixtures+"ipcidr.txt"),text,error),"Text IP rule fixture must compile");ip.format="mrs";
    require(parseRuleContent(ip,readTestFile(fixtures+"ipcidr.mrs"),binary,error),"Independent MRS IP ranges failed to decode");
    for(const auto& query:std::vector<std::pair<std::string,bool>>{{"192.0.2.0",true},{"192.0.2.255",true},{"192.0.3.0",false},{"198.51.100.127",false},{"198.51.100.128",true},
        {"2001:db8::",true},{"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",true},{"2001:db9::1",true},{"2001:db9:1::1",false},{"::ffff:192.0.2.7",true},{"host.test",false}}) {
        require(ruleRangesMatch(text->ranges,query.first)==query.second,"Text IP range boundary or family handling failed");
        require(ruleRangesMatch(binary->ranges,query.first)==query.second,"MRS IPv4/IPv6 range lookup failed");
    }
    require(!parseRuleContent(ip,readTestFile(fixtures+"bad-ip-range.mrs"),binary,error),"Reversed MRS IP interval must fail");
    domain.format="yaml";
    for(const std::string body:{"payload: [bad/domain]","payload: ['foo*bar.test']","payload: ['a..test']","payload: [null, {bad: map}]","payload: []\n---\npayload: []"})
        require(!parseRuleContent(domain,body,yaml,error),"Invalid domain rule payload must fail strict validation");
    require(parseRuleContent(domain,"payload: []",yaml,error)&&yaml->count==0&&!yaml->domains.matches("x.test"),"An explicitly empty provider is a ready empty set");
    RuleProvider classic;classic.behavior="classical";
    require(parseRuleContent(classic,R"rules({"payload":["AND,((DOMAIN-SUFFIX,example.test),(OR,((NETWORK,tcp),(DST-PORT,53))))","NOT,((DOMAIN,skip.test))","IP-CIDR,192.0.2.0/24,no-resolve","SRC-IP-CIDR,10.0.0.0/8","DOMAIN-REGEX,^api[.].*[.]test$","DOMAIN-WILDCARD,*.single.test"]})rules",yaml,error),"Classical logical/regex/source/port rules failed to compile");
    RuleSnapshots snapshots{{"classic",{"classical",yaml}}};RuleQuery query;query.host="api.example.test";query.network="tcp";query.port=443;query.source="10.1.2.3";
    require(evaluateRule(yaml->classical[0],query,snapshots)==RuleVerdict::Yes,"Nested AND/OR rule must match actual query metadata");
    query.host="skip.test";require(evaluateRule(yaml->classical[1],query,snapshots)==RuleVerdict::No,"NOT rule must negate its condition");
    require(evaluateRule(yaml->classical[3],query,snapshots)==RuleVerdict::Yes,"Source CIDR matching must use the actual ingress source");
    query.host="api.us.test";require(evaluateRule(yaml->classical[4],query,snapshots)==RuleVerdict::Yes,"Classical domain regex failed");
    query.host="a.single.test";require(evaluateRule(yaml->classical[5],query,snapshots)==RuleVerdict::Yes,"Compiled classical wildcard failed");
    for(const std::string rule:{"AND,((NETWORK,tcp)","NOT,((NETWORK,tcp),(DST-PORT,443))","IP-CIDR,192.0.2.0/garbage","DST-PORT,443/8000-7000","DOMAIN,x,DIRECT","GEOIP,CN/invalid","RULE-SET,"}) {
        ProxyRule invalid;require(!parseRuleExpression(rule,invalid,true,error),"Malformed/unsupported classical expression must fail explicitly");
    }
    const char* live=std::getenv("CLAHSOS_MRS_DOMAIN_FILE");
    if(live&&*live) {domain.format="mrs";require(parseRuleContent(domain,readTestFile(live),mrs,error),"Pinned real-world mihomo MRS resource must decode");
        require(mrs->count>100&&mrs->domains.matches("google.com")&&mrs->domains.matches("www.google.com"),"Real-world Google MRS must match known domains");std::cout<<"Verified real MRS resource: "<<mrs->count<<" rules\n";}
}

void ruleForwardingTests(const std::string& directory)
{
    const std::string roots=readTestFile(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/vmess/ca.pem");g_testVmessTrust=roots.c_str();
    const std::string nodes="proxies: [{name: encrypted-route, type: ss, server: node.invalid, port: 443, cipher: aes-256-gcm, password: probe-password, udp: true}]\nproxy-groups: [{name: Route, type: select, proxies: [encrypted-route]}]\n";
    const std::string config=nodes+"rule-providers: {Sites: {type: inline, behavior: domain, payload: [vmess.test]}}\nrules: ['RULE-SET,Sites,Route','MATCH,REJECT']\n";
    for(int protocol:{0,1}) {
        loadProviderProfile(directory+"/rule-forward.yaml",config);
        VmessReferencePeer peer(0,"ss","","https_reference_peer.py");g_testConnector=[&](const std::string& host,int port,int) {
            require(host=="node.invalid"&&port==443,"Rule-set forwarding must dial its selected encrypted node, never DIRECT");return peer.take();
        };
        int client[2];pairFor(client);socketTimeout(client[1],5000);dispatchWorker(client[0],protocol);
        if(protocol==0){sendAll(client[1],"CONNECT vmess.test:443 HTTP/1.1\r\nHost: vmess.test\r\n\r\n");require(readUntilHeaders(client[1]).find("200 Connection Established")!=std::string::npos,"Rule-set HTTP CONNECT failed");}
        else {VmBytes greeting{5,1,0,5,1,0};vmAppend(greeting,shadowsocksAddress("vmess.test",443));sendAll(client[1],greeting);require(receiveN(client[1],2)==std::string("\5\0",2)&&receiveN(client[1],10)[1]==0,"Rule-set SOCKS CONNECT failed");}
        require(controlRequest("GET","/connections").find("rule-set:Sites")!=std::string::npos,"Real TCP connections must identify their matched rule set");
        {
            TlsChannel tls(client[1]);std::string error;require(tls.start("vmess.test",false,error,roots.c_str()),"Rule-set-selected SS route must carry verified destination HTTPS");
            const std::string request="GET /probe?ok=1 HTTP/1.1\r\nHost: vmess.test\r\nConnection: close\r\n\r\n";
            require(tls.writeBytes(reinterpret_cast<const unsigned char*>(request.data()),request.size()),"Rule-set HTTPS request write failed");
            std::string response;unsigned char bytes[4096];
            while(response.find("\r\n\r\n")==std::string::npos){const auto count=tls.readBytes(bytes,sizeof(bytes));require(count>0,"Rule-set HTTPS response interrupted");response.append(reinterpret_cast<char*>(bytes),count);}
            require(response.rfind("HTTP/1.1 204",0)==0,"Independent HTTPS endpoint must return 204 through rule-set routing");
        }
        shutdown(client[1],SHUT_RDWR);close(client[1]);workersIdle();g_testConnector=nullptr;peer.finish();
    }
    loadProviderProfile(directory+"/rule-download-route.yaml",nodes+
        "rule-providers:\n  remote: {type: http, behavior: domain, url: 'https://vmess.test/provider', proxy: Route, interval: 0, header: {Authorization: ['Bearer private-test-token'], X-Private-Test: private-header}}\nrules: ['RULE-SET,remote,REJECT','MATCH,DIRECT']\n");
    {
        VmessReferencePeer peer(0,"ss-https","chunk-gzip","rule_provider_reference_peer.py");g_testConnector=[&](const std::string& host,int,int){require(host=="node.invalid","Rule provider bootstrap must use its explicit outbound independently of the unavailable rule set");return peer.take();};
        const auto jobs=collectRuleProviderUpdates();require(jobs.size()==1,"Encrypted rule download job missing");runRuleProviderUpdate(jobs[0]);g_testConnector=nullptr;peer.finish();
        require(g_state.ruleProviders[0].data&&activeProxyNode("downloaded.test",443).type=="reject","Encrypted HTTPS rule download must populate the actual routing matcher");
    }
    const std::string udpNodes="proxies: [{name: encrypted-route, type: ss, server: node.invalid, port: 443, cipher: aes-256-gcm, password: 'pässword-测试', udp: true}]\nproxy-groups: [{name: Route, type: select, proxies: [encrypted-route]}]\n";
    loadProviderProfile(directory+"/rule-udp.yaml",udpNodes+"rule-providers: {UDP: {type: inline, behavior: classical, payload: ['AND,((NETWORK,udp),(DOMAIN,target.test))']}}\nrules: ['RULE-SET,UDP,Route','MATCH,REJECT']\n");
    {
        VmessReferencePeer peer(0,"aes-256-gcm","udp","ss_reference_peer.py",true);UdpHarness harness;
        {std::lock_guard<std::mutex> lock(harness.mutex);harness.pending["node.invalid:443"].push_back({peer.take(),udpTestEndpoint("192.0.2.10",443)});}
        for(int round=0;round<3;++round) {
            std::string body=round==0?"packet-0":"";
            if(round==2){body.resize(UDP_MAX_PACKET-32-16-shadowsocksAddress("target.test",443).size());for(size_t i=0;i<body.size();++i)body[i]=static_cast<char>(i);}
            harness.inject(udpTestPacket("target.test",443,body));const auto reply=receiveTestDatagram(harness.relay);UdpTarget source;
            const auto expected=round==2?std::string("max-accepted"):"udp-response:"+std::string(body.rbegin(),body.rend());
            require(parseSocksUdp(reply,source)&&source.host=="8.8.8.8"&&text({reply.begin()+3+source.headerSize,reply.end()})==expected,"Rule-set-selected encrypted UDP must preserve empty/maximum datagrams and payload");
            if(round==0)require(controlRequest("GET","/connections").find("rule-set:UDP")!=std::string::npos,"UDP connection metadata must identify its matched classical rule set");
        }
        peer.finish();
    }
    g_testVmessTrust=nullptr;
}

void ruleProviderTests(const std::string& directory)
{
    ruleCodecTests();std::string error;
    auto load=[&](const std::string& name,const std::string& definitions,const std::string& rules) {
        const std::string path=directory+"/rule-"+name+".yaml";
        loadProviderProfile(path,"rule-providers:\n"+definitions+"\nrules:\n"+rules+"\n");return path;
    };
    const std::string domain="  sites: {type: inline, behavior: domain, payload: ['+.blocked.test']}";
    load("inline",domain,"  - RULE-SET,sites,REJECT\n  - MATCH,DIRECT");
    require(activeProxyNode("api.blocked.test",443).type=="reject"&&activeProxyNode("other.test",443).type=="direct","Inline RULE-SET must control actual routing");
    require(activeProxyNode("blocked.test",443).matchedRule=="rule-set:sites","Connection metadata must identify the matched rule provider");
    require(responseFor("GET","/providers/rules","").find("\"ruleCount\":1")!=std::string::npos&&responseFor("GET","/providers/rules/sites","").find("\"ready\":true")!=std::string::npos,"Standard rule-provider API must publish actual readiness/count");
    require(responseFor("GET","/providers/rules/sites/payload","").find("blocked.test")!=std::string::npos,"Rule preview must expose actual compiled entries");
    require(responseFor("PUT","/providers/rules/sites","").find("error")!=std::string::npos,"Inline rules must direct users to edit their configuration");
    ParsedConfig parsed;
    for(const auto& invalid:std::vector<std::string>{
        "rule-providers: []", "rule-providers: {p: {type: inline, behavior: bad, payload: []}}", "rule-providers: {p: {type: inline, behavior: classical, format: mrs, payload: []}}",
        "rule-providers: {p: {type: inline, behavior: domain}}", "rule-providers: {p: {type: http, behavior: domain, url: bad}}",
        "rule-providers: {p: {type: inline, behavior: classical, payload: ['RULE-SET,missing']}}",
        "rule-providers: {a: {type: inline, behavior: classical, payload: ['RULE-SET,b']}, b: {type: inline, behavior: classical, payload: ['RULE-SET,a']}}",
        "rules: ['RULE-SET,missing,DIRECT']", "rules: ['AND,((RULE-SET,missing),(NETWORK,tcp)),DIRECT']"})
        require(!parseConfigText(invalid,parsed,error),"Invalid rule definitions/references/cycles must fail before replacing the active profile");

    int lookups=0;g_testRuleResolver=[&](const std::string& host) {
        require(g_state.mutex.try_lock(),"DNS routing must not hold the core configuration mutex");g_state.mutex.unlock();++lookups;
        return host=="resolved.test"?std::vector<std::string>{"192.0.2.10","2001:db8::10"}:std::vector<std::string>{};
    };
    const std::string ip="  ips: {type: inline, behavior: ipcidr, payload: [192.0.2.0/24, '2001:db8::/32']}";
    load("no-resolve",ip,"  - RULE-SET,ips,REJECT,no-resolve\n  - MATCH,DIRECT");
    require(responseFor("GET","/rules","").find("\"noResolve\":true")!=std::string::npos,"Rule API must preserve no-resolve for copying and display");
    require(activeProxyNode("resolved.test",443).type=="direct"&&lookups==0,"no-resolve must not start DNS for a hostname");
    require(activeProxyNode("192.0.2.255",443).type=="reject"&&activeProxyNode("2001:db8::1",443).type=="reject","IP rules must match literals without DNS");
    load("resolve",ip,"  - RULE-SET,ips,REJECT\n  - MATCH,DIRECT");
    require(activeProxyNode("resolved.test",443).type=="reject"&&lookups==1,"Rule-set IP matching must use resolved destination addresses");
    require(activeProxyNode("unresolved.test",443).type=="reject"&&activeProxyNode("unresolved.test",443).matchedRule.find("unavailable")!=std::string::npos,"Failed required DNS must not bypass a rule set into DIRECT");
    g_testRuleResolver=[&](const std::string&){load("changed-during-dns",domain,"  - RULE-SET,sites,REJECT\n  - MATCH,DIRECT");return std::vector<std::string>{"192.0.2.10"};};
    require(activeProxyNode("race.test",443).type=="direct","A profile change during DNS must re-evaluate the new routing snapshot");
    g_testRuleResolver=nullptr;

    const std::string fixtureRoot=std::string(CLAHSOS_TEST_ROOT)+"/fixtures/rules/";
    const std::string file=directory+"/rule-source.mrs";{std::ofstream out(file,std::ios::binary);out<<readTestFile(fixtureRoot+"domain.mrs");}
    const std::string fileDefinitions="  disk: {type: file, path: rule-source.mrs, behavior: domain, format: mrs, interval: 0}";
    const auto profile=load("file",fileDefinitions,"  - RULE-SET,disk,REJECT\n  - MATCH,DIRECT");
    require(activeProxyNode("suffix.test",443).type=="reject","File MRS provider must be active at startup");
    const std::string temporary=directory+"/.rule-import-binary.tmp";{std::ofstream out(temporary,std::ios::binary);out<<readTestFile(fixtureRoot+"domain.mrs");}
    const std::string api="/clahsos/rule-providers/disk/file?profile="+urlEncode(profile);
    require(responseFor("PUT",api,"{\"path\":\""+jsonEscape(temporary)+"\"}")=="{}","Document-picker binary MRS import failed");
    const auto cache=ruleProviderCachePath(profile,g_state.ruleProviders[0]);struct stat permissions{};require(stat(cache.c_str(),&permissions)==0&&(permissions.st_mode&0777)==0600,"Rule caches must be owner-only");
    unlink(file.c_str());load("file",fileDefinitions,"  - RULE-SET,disk,REJECT\n  - MATCH,DIRECT");
    require(activeProxyNode("suffix.test",443).type=="reject","Imported binary rules must survive restart without access to their source URI");
    require(responseFor("DELETE",api,"").find("error")!=std::string::npos&&activeProxyNode("suffix.test",443).type=="reject","Resetting an unreadable source must preserve its working imported rules");
    require(responseFor("PUT","/clahsos/rule-providers/disk/file?profile=stale","{\"path\":\""+jsonEscape(temporary)+"\"}").find("error")!=std::string::npos,"Stale-profile rule import must fail");
    {std::ofstream out(file,std::ios::binary);out<<readTestFile(fixtureRoot+"domain.mrs");}
    require(responseFor("DELETE",api,"")=="{}"&&access(cache.c_str(),F_OK)!=0,"Resetting a valid file provider must remove its managed override");
    const std::string before=g_state.configPath;
    std::string invalidPath=directory+"/bad-rule-profile.yaml";{std::ofstream out(invalidPath);out<<"rule-providers: {bad: {type: inline, behavior: domain, payload: [bad/domain]}}";}
    require(responseFor("PUT","/configs","{\"path\":\""+jsonEscape(invalidPath)+"\"}").find("error")!=std::string::npos&&g_state.configPath==before,"Invalid rule configuration reload must preserve the running profile");

    const std::string roots=readTestFile(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/vmess/ca.pem");g_testVmessTrust=roots.c_str();
    auto httpDefinitions=[](const std::string& format="yaml",const std::string& behavior="domain",const std::string& url="https://vmess.test/provider") {
        return "  remote:\n    type: http\n    behavior: "+behavior+"\n    format: "+format+"\n    url: '"+url+"'\n    interval: 0\n    header:\n      Authorization: [Bearer private-test-token]\n      X-Private-Test: private-header";
    };
    const auto httpProfile=load("http",httpDefinitions(),"  - RULE-SET,remote,REJECT\n  - MATCH,DIRECT");
    require(activeProxyNode("anything.test",443).type=="reject"&&activeProxyNode("anything.test",443).matchedRule.find("unavailable")!=std::string::npos,"An unavailable rule provider must not silently bypass its routing policy");
    auto update=[&](const std::string& mode) {
        VmessReferencePeer peer(0,"https",mode,"rule_provider_reference_peer.py");g_testConnector=[&](const std::string&,int,int){return peer.take();};
        require(responseFor("PUT","/providers/rules/remote","")=="{}","Rule provider manual update request failed");auto jobs=collectRuleProviderUpdates();
        require(jobs.size()==1,"Manual rule update must schedule exactly one resource");runRuleProviderUpdate(jobs[0]);g_testConnector=nullptr;peer.finish();
    };
    require(responseFor("PUT","/providers/rules/remote?profile=stale","").find("error")!=std::string::npos,"A delayed rule update action must not affect another selected profile");
    update("chunk-gzip");require(activeProxyNode("api.downloaded.test",443).type=="reject"&&activeProxyNode("other.test",443).type=="direct","Downloaded compressed/chunked rule list must drive actual routing");
    const auto httpCache=ruleProviderCachePath(httpProfile,g_state.ruleProviders[0]);const auto original=readTestFile(httpCache);
    for(const std::string fault:{"bad-yaml","status","bad-gzip"}) {update(fault);require(!g_state.ruleProviders[0].lastError.empty()&&readTestFile(httpCache)==original&&activeProxyNode("downloaded.test",443).type=="reject","Failed rule updates must preserve cache and active matching");}
    load("http",httpDefinitions(),"  - RULE-SET,remote,REJECT\n  - MATCH,DIRECT");require(activeProxyNode("downloaded.test",443).type=="reject","HTTP rule cache must work offline after restart");
    update("v2");require(activeProxyNode("downloaded.test",443).type=="direct"&&activeProxyNode("changed.test",443).type=="reject","Successful rule update must replace old matching atomically");
    load("http",httpDefinitions("yaml","domain","https://vmess.test/provider?account=changed"),"  - RULE-SET,remote,REJECT\n  - MATCH,DIRECT");
    require(!g_state.ruleProviders[0].data,"Changing the rule provider source must not reuse another account cache");
    for(const auto& spec:std::vector<std::pair<std::string,std::string>>{{"mrs","mrs"},{"text","text"},{"yaml","gzip"}}) {
        load("formats-"+spec.first,httpDefinitions(spec.first),"  - RULE-SET,remote,REJECT\n  - MATCH,DIRECT");update(spec.second);
        require(g_state.ruleProviders[0].data&&g_state.ruleProviders[0].lastError.empty(),"HTTP rule resource format failed to become ready");
    }
    require(responseFor("GET","/providers/rules/remote","").find("Authorization")==std::string::npos,"Rule API must not expose source headers or subscription credentials");
    auto stale=collectRuleProviderUpdates();responseFor("PUT","/providers/rules/remote","");stale=collectRuleProviderUpdates();require(stale.size()==1,"Prepare stale rule download");
    std::shared_ptr<const RuleData> candidate;require(parseRuleContent(stale[0].provider,"payload: [stale.test]",candidate,error),"Stale rule fixture failed to compile");
    load("replacement",domain,"  - RULE-SET,sites,REJECT\n  - MATCH,DIRECT");
    require(!applyRuleProviderUpdate(stale[0],"payload: [stale.test]",candidate,"")&&g_state.ruleProviders[0].name=="sites","Stale rule downloads must not replace a newly loaded profile");
    const std::string cycleSource=directory+"/cycle-rule.yaml";{std::ofstream out(cycleSource);out<<"payload: ['DOMAIN,leaf.test']";}
    const auto cycleProfile=load("cycle","  a: {type: inline, behavior: classical, payload: ['RULE-SET,b']}\n  b: {type: file, behavior: classical, path: cycle-rule.yaml}","  - RULE-SET,a,REJECT\n  - MATCH,DIRECT");
    const std::string cycleImport=directory+"/.rule-import-cycle.tmp";{std::ofstream out(cycleImport);out<<"payload: ['RULE-SET,a']";}
    require(responseFor("PUT","/clahsos/rule-providers/b/file?profile="+urlEncode(cycleProfile),"{\"path\":\""+jsonEscape(cycleImport)+"\"}").find("error")!=std::string::npos&&
        activeProxyNode("leaf.test",443).type=="reject","Introducing a cycle through a rule resource update must retain the old working matcher");
    ruleForwardingTests(directory);
    load("shutdown",httpDefinitions(),"  - RULE-SET,remote,REJECT\n  - MATCH,DIRECT");g_state.ruleProviders[0].timeout=60000;
    int stalled[2];makePair(stalled);g_testConnector=[&](const std::string&,int,int){return stalled[0];};
    require(!g_ruleProviderThread.joinable(),"Rule provider coordinator fixture must start once");g_ruleProviderThread=std::thread(ruleProviderLoop);
    awaitCondition([&]{std::lock_guard<std::mutex> lock(g_state.sessionsMutex);return g_state.sockets.count(stalled[0])>0;},"Rule coordinator did not start a real download");
    const auto stopping=HealthClock::now();stopCore();g_testConnector=nullptr;close(stalled[1]);
    require(HealthClock::now()-stopping<std::chrono::seconds(2)&&!g_ruleProviderThread.joinable(),"Stopping the core must cancel rule downloads and join the bounded worker coordinator");
    g_testVmessTrust=nullptr;require(g_state.sockets.empty()&&g_state.connections.empty(),"Rule provider tests leaked sockets or connections");
}
