std::string readTestFile(const std::string& path) {
    std::ifstream file(path,std::ios::binary);return {std::istreambuf_iterator<char>(file),{}};
}
std::string providerProfile(const std::string& url="https://vmess.test:443/provider?token=private-subscription",size_t limit=0) {
    return "proxies: [{name: local-node, type: direct}]\nproxy-providers:\n  feed:\n    type: http\n    url: '"+url+"'\n    size-limit: "+std::to_string(limit)+
        "\n    header:\n      Authorization: ['Bearer private-test-token']\n      X-Private-Test: private-header\n    health-check: {enable: true, interval: 0, lazy: false, url: 'https://vmess.test/probe?ok=1', expected-status: 204}\nproxy-groups:\n  - name: Resources\n    type: select\n    use: [feed]\nrules: ['MATCH,Resources']\n";
}
void loadProviderProfile(const std::string& path,const std::string& content) {
    g_state.running.store(false);{std::ofstream file(path);file<<content;}
    std::string error;require(loadConfigLocked(path,error),"Provider profile activation failed");g_state.running.store(true);
}
void providerTests(const std::string& directory) {
    std::ifstream rootFile(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/vmess/ca.pem");const std::string roots((std::istreambuf_iterator<char>(rootFile)),{});
    const std::string profile=directory+"/providers.yaml";
    {std::ofstream selections(profile+".selections");selections<<"\"Resources\" \"remote-b\"\n";}
    loadProviderProfile(profile,providerProfile());g_testVmessTrust=roots.c_str();
    require(g_state.providers.size()==1&&g_state.providers[0].nodes.empty()&&g_state.groups[0].proxies.empty(),"Unfetched provider must not fabricate candidates");
    require(activeProxyNode("vmess.test",443).type=="reject","An unavailable provider must not fall through to DIRECT");
    auto update=[&](const std::string& mode,const std::string& kind="https") {
        std::cerr<<"Provider fixture: "<<kind<<" mode="<<mode<<'\n';
        VmessReferencePeer peer(0,kind,mode,"provider_reference_peer.py");
        g_testConnector=[&](const std::string&,int,int){return peer.take();};
        require(responseFor("PUT","/providers/proxies/feed","")=="{}","Provider update API rejected request");
        auto jobs=collectProviderUpdates();require(jobs.size()==1,"Provider update was not queued exactly once");
        runProviderUpdate(jobs[0]);g_testConnector=nullptr;peer.finish();
    };
    update("gzip");
    require(g_state.providers[0].nodes.size()==2&&g_state.groups[0].proxies.size()==2&&g_state.groups[0].now=="remote-b","Downloaded nodes must populate use groups and restore deferred saved selection");
    require(activeProxyNode("vmess.test",443).provider=="feed"&&activeProxyNode("vmess.test",443).name=="remote-b","Actual routing must resolve the provider member");
    require(g_state.proxyNames.size()==g_state.nodes.size(),"Provider rebuild must not duplicate proxy-name state");
    const std::string cache=providerCachePath(profile,g_state.providers[0]);
    const std::string validCache=readTestFile(cache);
    struct stat permissions{};require(stat(cache.c_str(),&permissions)==0&&(permissions.st_mode&0777)==0600,"Provider credentials must be persisted in a private atomic cache");
    require(cache.substr(cache.size()-6)==".cache","Provider caches must not be listed as imported YAML profiles");
    const std::string api=responseFor("GET","/providers/proxies","");
    require(api.find("\"providers\":{\"feed\"")!=std::string::npos&&api.find("remote-b")!=std::string::npos,"Provider API must describe actual loaded nodes");
    require(api.find("probe-password")==std::string::npos&&api.find("private-subscription")==std::string::npos&&api.find("private-test-token")==std::string::npos,"Provider API must not expose node credentials or subscription authentication");
    {
        VmessReferencePeer a(0,"ss","","https_reference_peer.py"),b(0,"ss","","https_reference_peer.py");std::atomic<int> calls{0};
        g_testConnector=[&](const std::string&,int,int){return calls.fetch_add(1)==0?a.take():b.take();};
        require(responseFor("GET","/providers/proxies/feed/healthcheck","")=="{}","Provider health API must accept a check request");
        auto jobs=collectHealthJobs();require(jobs.size()==2&&jobs[0].provider=="feed","Provider health checks must schedule actual collection members");
        runHealthJobs(jobs);g_testConnector=nullptr;a.finish();b.finish();
        require(g_state.delays["remote-a"]>0&&g_state.delays["remote-b"]>0&&!g_state.providers[0].health.checking,"Provider health replies must update real node delays and finish checking state");
    }
    for(const std::string mode:{"chunked","chunk-gzip","deflate","interim","eof"}) {
        update(mode);require(g_state.providers[0].lastError.empty()&&g_state.providers[0].nodes.size()==2,"Valid HTTP body framing/encoding must preserve all provider nodes");
    }
    const std::string beforeFailure=readTestFile(cache);
    for(const std::string mode:{"status","bad-yaml","duplicate","conflict","bad-gzip","bad-chunk","ambiguous","truncated","eof-truncated-tls"}) {
        update(mode);require(!g_state.providers[0].lastError.empty()&&g_state.groups[0].now=="remote-b"&&g_state.providers[0].nodes.size()==2,"Failed provider updates must preserve usable nodes and current selection");
        require(readTestFile(cache)==beforeFailure,"Failed provider updates must preserve the previous cache byte-for-byte");
    }
    // The retained provider node must still carry real HTTPS traffic after rejected updates.
    {
        VmessReferencePeer peer(0,"ss","","https_reference_peer.py");g_testConnector=[&](const std::string&,int,int){return peer.take();};
        TestTarget target;parseTestUrl("https://vmess.test/probe?ok=1",target);std::string error;
        require(probeNode(activeProxyNode(target.host,443),target,4000,"204",error)>0,"Retained provider member must still forward traffic after a failed update");
        g_testConnector=nullptr;peer.finish();
    }
    {
        VmessReferencePeer peer(0,"ss","","https_reference_peer.py");g_testConnector=[&](const std::string&,int,int){return peer.take();};
        const std::string response=controlRequest("GET","/providers/proxies/feed/remote-b/healthcheck?timeout=4000&expected=204&url="+urlEncode("https://vmess.test/probe?ok=1"));
        g_testConnector=nullptr;peer.finish();require(response.find("\"delay\":")!=std::string::npos,"Standard provider member health endpoint must probe the requested member");
        require(responseFor("GET","/providers/proxies/feed/remote-b","").find("\"alive\":true")!=std::string::npos,"Provider member metadata must expose measured liveness");
    }
    update("v2");require(g_state.groups[0].now=="remote-b"&&g_state.groups[0].proxies==std::vector<std::string>({"remote-b","remote-c"}),"Successful updates must preserve surviving selection and replace removed members");
    const std::string updatedCache=readTestFile(cache);
    loadProviderProfile(profile,providerProfile());
    require(g_state.providers[0].nodes.size()==2&&g_state.groups[0].now=="remote-b"&&!g_state.providers[0].updatedAt.empty(),"Restart must recover provider cache and selection before network access");
    loadProviderProfile(profile,providerProfile("https://vmess.test:443/provider?token=changed-account"));
    require(g_state.providers[0].nodes.empty(),"A cache from different provider credentials must not be reused");
    loadProviderProfile(profile,providerProfile());
    require(readTestFile(cache)==updatedCache&&g_state.providers[0].nodes.size()==2,"Credential changes must not overwrite the previous source cache");
    // A disk-write failure is transactional, including the in-memory routing table.
    {
        responseFor("PUT","/providers/proxies/feed","");auto jobs=collectProviderUpdates();require(jobs.size()==1,"Cache failure update fixture scheduling");
        const auto& job=jobs[0];const std::string temporary=cache+".tmp-"+std::to_string(getpid())+"-"+std::to_string(job.epoch)+"-"+std::to_string(job.generation);
        {std::ofstream obstruction(temporary);obstruction<<"test-only obstruction";}
        VmessReferencePeer peer(0,"https","","provider_reference_peer.py");g_testConnector=[&](const std::string&,int,int){return peer.take();};
        runProviderUpdate(job);g_testConnector=nullptr;peer.finish();unlink(temporary.c_str());
        require(readTestFile(cache)==updatedCache&&g_state.providers[0].nodes[0].name=="remote-b"&&!g_state.providers[0].lastError.empty(),"Cache persistence failure must not partially replace live nodes");
    }
    // Decoded sizes are bounded independently of the compressed Content-Length.
    loadProviderProfile(directory+"/limited.yaml",providerProfile("https://vmess.test:443/provider",512));
    for(const std::string mode:{"oversize","gzip-bomb"}){update(mode);require(!g_state.providers[0].lastError.empty()&&g_state.providers[0].nodes.empty(),"Provider download and decompression limits must both be enforced");}
    // Provider downloads can themselves use the production SS and VMess transports.
    for(const std::string kind:{"ss-https","vmess-https","vmess-ws-tls"}) {
        loadProviderProfile(directory+"/routed.yaml",providerProfile());
        ProxyNode route;if(kind=="ss-https"){route.name="download-route";route.type="ss";route.server="node.invalid";route.port=443;route.cipher="aes-256-gcm";route.password="probe-password";}
        else {route=vmTestNode(0,kind=="vmess-ws-tls"?"ws-tls":"tcp","auto");route.name="download-route";}
        g_state.localNodes.push_back(route);g_state.nodes.push_back(route);g_state.providers[0].downloadProxy=route.name;
        update("chunk-gzip",kind);require(g_state.providers[0].lastError.empty()&&g_state.providers[0].nodes.size()==2,"Provider download through a real encrypted proxy failed");
    }
    // Redirects retain same-origin authentication but strip all custom headers across origins.
    for(const bool cross:{false,true}) {
        loadProviderProfile(directory+"/redirect.yaml",providerProfile("http://vmess.test:443/provider"));
        VmessReferencePeer origin(0,"plain",cross?"redirect-cross":"redirect-same","provider_reference_peer.py");
        VmessReferencePeer destination(0,"plain",cross?"cross-target":"same-target","provider_reference_peer.py");int calls=0;
        g_testConnector=[&](const std::string& host,int,int){++calls;if(calls==1)return origin.take();require(host==(cross?"other.test":"vmess.test"),"Unexpected provider redirect host");return destination.take();};
        responseFor("PUT","/providers/proxies/feed","");auto jobs=collectProviderUpdates();runProviderUpdate(jobs[0]);g_testConnector=nullptr;
        require(g_state.providers[0].lastError.empty()&&calls==2,"Provider redirect failed");origin.finish();destination.finish();
    }
    loadProviderProfile(directory+"/downgrade.yaml",providerProfile());update("downgrade");
    require(!g_state.providers[0].lastError.empty(),"HTTPS provider redirects must not downgrade to HTTP");
    loadProviderProfile(directory+"/untrusted.yaml",providerProfile());g_testVmessTrust=nullptr;update("untrusted");
    require(!g_state.providers[0].lastError.empty(),"Untrusted provider TLS certificate must reject the download");g_testVmessTrust=roots.c_str();
    // Inline and local providers feed the same runtime and support group filtering.
    const std::string inlineConfig=R"(proxies: [{name: local-node, type: direct}]
proxy-providers:
  built-in:
    type: inline
    payload:
      - {name: HK A, type: ss, server: fixture.invalid, port: 443, cipher: aes-256-gcm, password: dummy}
      - {name: JP B, type: direct}
    filter: '(?i)hk'
    override: {additional-prefix: '[inline] ', udp: true}
proxy-groups:
  - {name: Resources, type: select, use: [built-in]}
  - {name: All, type: select, include-all: true, exclude-filter: local-node}
rules: ['MATCH,Resources']
)";
    loadProviderProfile(directory+"/inline.yaml",inlineConfig);
    require(g_state.groups[0].proxies==std::vector<std::string>({"[inline] HK A"})&&g_state.nodes.back().udp,"Inline filters and supported overrides must reach real candidates");
    require(g_state.groups[1].proxies==g_state.groups[0].proxies,"include-all and exclude-filter must compose provider membership");
    require(responseFor("PUT","/providers/proxies/built-in","").find("error")!=std::string::npos,"Inline providers must direct users to edit configuration");
    const std::string file=directory+"/resource-file.yaml";
    {std::ofstream resource(file);resource<<"proxies: [{name: file-node, type: direct}]\n";}
    const std::string fileConfig="proxy-providers: {disk: {type: file, path: resource-file.yaml}}\nproxy-groups: [{name: Resources, type: select, use: [disk]}]\nrules: ['MATCH,Resources']\n";
    loadProviderProfile(directory+"/file.yaml",fileConfig);
    require(g_state.groups[0].proxies==std::vector<std::string>({"file-node"}),"Local provider files must load before activation");
    const std::string fileApi="/clahsos/providers/disk/file?profile="+urlEncode(g_state.configPath);
    const std::string imported="proxies: [{name: imported-from-picker, type: direct}]";
    require(responseFor("PUT",fileApi,imported)=="{}"&&g_state.groups[0].proxies==std::vector<std::string>({"imported-from-picker"}),"File picker payload must atomically become the selected file-provider resource");
    const std::string fileCache=providerCachePath(g_state.configPath,g_state.providers[0]);const std::string importedCache=readTestFile(fileCache);
    require(responseFor("PUT",fileApi,"proxies: [").find("error")!=std::string::npos&&readTestFile(fileCache)==importedCache,"Bad file imports must preserve the last working provider cache");
    require(responseFor("PUT","/clahsos/providers/disk/file?profile=stale",imported).find("error")!=std::string::npos,"File import must reject a changed active profile");
    loadProviderProfile(directory+"/file.yaml",fileConfig);
    require(g_state.groups[0].proxies==std::vector<std::string>({"imported-from-picker"}),"Imported local resource must survive reopening without accessing the original picker URI");
    require(responseFor("DELETE",fileApi,"")=="{}"&&g_state.groups[0].proxies==std::vector<std::string>({"file-node"}),"Resetting the imported file must restore the configured source");
    const std::string subdirectory=directory+"/safe-provider-home";mkdir(subdirectory.c_str(),0700);
    symlink(file.c_str(),(subdirectory+"/outside-link.yaml").c_str());
    const std::string escaped="proxy-providers: {disk: {type: file, path: outside-link.yaml}}\nproxy-groups: [{name: Resources, type: select, use: [disk]}]\nrules: ['MATCH,Resources']\n";
    loadProviderProfile(subdirectory+"/profile.yaml",escaped);
    require(g_state.providers[0].nodes.empty()&&!g_state.providers[0].lastError.empty(),"Provider symlinks must not escape the configuration directory");
    {
        ProxyProvider override;override.name="udp-disabled";override.overrideUdp=0;ProxyNode direct;direct.name="explicit-direct";direct.type="direct";
        std::vector<ProxyNode> nodes{direct};std::string error;
        require(applyProviderOptions(override,nodes,error)&&!supportsUdp(nodes[0]),"Provider UDP overrides must constrain DIRECT resources as well as encrypted nodes");
    }
    ParsedConfig invalid;std::string error;
    require(!parseConfigText("proxy-providers: {p: {type: inline, payload: []}}\nproxy-groups: [{name: g, use: [missing]}]",invalid,error),"Unknown provider use reference must fail validation");
    require(!parseConfigText("proxy-providers: {p: {type: http, url: 'http://a.test/', header: {X-Test: \"bad\\r\\nheader\"}}}",invalid,error),"Provider request header injection must fail validation");
    require(!parseConfigText("proxy-providers: {p: {type: inline, filter: '[', payload: []}}",invalid,error),"Invalid provider filters must fail validation");
    // Stale downloads cannot write into a newly loaded profile's cache or node graph.
    loadProviderProfile(directory+"/stale.yaml",providerProfile());responseFor("PUT","/providers/proxies/feed","");auto old=collectProviderUpdates();
    loadProviderProfile(directory+"/replacement.yaml",inlineConfig);const auto epoch=g_state.profileEpoch;
    const std::string raw="proxies: [{name: stale-node, type: direct}]";std::vector<ProxyNode> staleNodes;
    require(parseProviderContent(old[0].provider,raw,staleNodes,error),"Stale download fixture must be valid independent data");
    require(!applyProviderUpdate(old[0],raw,staleNodes,"")&&g_state.profileEpoch==epoch&&g_state.providers[0].name=="built-in","Stale provider work must not replace another profile");
    {
        const std::string protectedPath=directory+"/protected-mode";const int fd=open(protectedPath.c_str(),O_WRONLY|O_CREAT|O_TRUNC,0644);
        require(fd>=0&&protectFileDescriptor(fd),"Native file helper must secure a newly created profile/cache descriptor");struct stat info{};fstat(fd,&info);
        require((info.st_mode&0777)==0600&&!protectFileDescriptor(-1),"Native profile permissions must be owner-only and reject invalid descriptors");close(fd);
    }
    {
        int client[2];makePair(client);dispatchWorker(client[0],3);
        sendAll(client[1],"PUT /clahsos/providers/disk/file HTTP/1.1\r\nContent-Length: 8388609\r\n\r\n");
        require(readUntilHeaders(client[1]).find("413 Payload Too Large")!=std::string::npos,"Controller must reject oversized resource imports before reading their body");close(client[1]);workersIdle();
    }
    // Real provider coordinator shutdown must interrupt a long socket read.
    loadProviderProfile(directory+"/shutdown.yaml",providerProfile());g_state.providers[0].timeout=60000;
    int stalled[2];makePair(stalled);g_testConnector=[&](const std::string&,int,int){return stalled[0];};
    require(!g_providerThread.joinable(),"Provider thread fixture must start without another coordinator");g_providerThread=std::thread(providerLoop);
    awaitCondition([&]{std::lock_guard<std::mutex> lock(g_state.sessionsMutex);return g_state.sockets.count(stalled[0])>0;},"Provider coordinator did not start its download");
    const auto stopping=HealthClock::now();stopCore();g_testConnector=nullptr;
    require(HealthClock::now()-stopping<std::chrono::seconds(2)&&!g_providerThread.joinable(),"Core stop must promptly cancel provider I/O and join the coordinator");
    {std::lock_guard<std::mutex> lock(g_state.sessionsMutex);require(g_state.sockets.empty(),"Provider requests must not leak tracked descriptors");}
    close(stalled[1]);g_testVmessTrust=nullptr;
}
