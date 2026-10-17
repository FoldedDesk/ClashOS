void geoTests(const std::string& directory)
{
    stopCore();g_testConnector=nullptr;g_testResolvedConnector=nullptr;g_testRuleResolver=nullptr;
    const std::string fixtures=std::string(CLAHSOS_TEST_ROOT)+"/fixtures/geodata/";
    ProviderPattern digits(R"(^(?:srv|node)\d+\.test$)"),unicode(R"(\p{Han}+)"),invalid(R"((?<=node)test)");
    require(digits.valid&&digits.matches("srv123.test")&&!digits.matches("srvx.test"),"Provider and GeoSite regex use real RE2 digit/noncapturing-group semantics");
    require(unicode.valid&&unicode.matches("日本节点")&&!invalid.valid,"RE2 Unicode properties and unsupported lookbehind validation");
    std::shared_ptr<const GeoDatabase> ips,sites,country,asn;std::string error;
    require(geoReadFile("geoip",fixtures+"geoip.dat",ips,error),"Independent GeoIP protobuf fixture must load");
    require(geoIpMatch(*ips,"CN","192.0.2.9")&&!geoIpMatch(*ips,"CN","198.51.100.9")&&geoIpMatch(*ips,"cn","2001:db8:1::9"),"GeoIP DAT IPv4/IPv6 and case-insensitive categories");
    require(geoIpMatch(*ips,"not-cn","198.51.100.9")&&!geoIpMatch(*ips,"not-cn","192.0.2.9"),"GeoIP inverse-match sets follow the protobuf flag");
    require(geoReadFile("geosite",fixtures+"geosite.dat",sites,error),"Independent GeoSite protobuf fixture must load");
    auto matcher=geoSiteMatcher(*sites,"fixture");require(matcher->error.empty(),"GeoSite matcher must compile valid fixture records");
    for(const std::string& host:{"fixture.test","www.fixture.test","exact.example.invalid","has-keywordfixture.invalid","srv12.regex.invalid"})require(geoSiteMatch(*matcher,host),"GeoSite full/suffix/keyword/regex matching");
    for(const std::string& host:{"wrongfixture.test","sub.exact.example.invalid","srvx.regex.invalid"})require(!geoSiteMatch(*matcher,host),"GeoSite matching must not widen exact/domain boundaries");
    auto filtered=geoSiteMatcher(*sites,"fixture@cn"),inverse=geoSiteMatcher(*sites,"fixture@!cn");
    require(geoSiteMatch(*filtered,"www.fixture.test")&&!geoSiteMatch(*filtered,"exact.example.invalid"),"GeoSite attribute inclusion");
    require(!geoSiteMatch(*inverse,"www.fixture.test")&&geoSiteMatch(*inverse,"exact.example.invalid"),"GeoSite attribute exclusion");
    require(!geoSiteMatcher(*sites,"missing")->error.empty(),"A missing GeoSite category must be reported");
    for(const std::string& filename:{"invalid-prefix.dat","duplicate.dat","truncated.dat","varint-overflow.dat"}) {
        std::shared_ptr<const GeoDatabase> rejected;require(!geoReadFile("geoip",fixtures+filename,rejected,error),"Malformed GeoIP protobuf must be rejected");
    }
    std::shared_ptr<const GeoDatabase> future;require(geoReadFile("geoip",fixtures+"unknown-field.dat",future,error)&&geoIpMatch(*future,"CN","192.0.2.9"),"Unknown future protobuf fields may be skipped without changing known categories");
    require(geoReadFile("mmdb",fixtures+"GeoIP2-Country-Test.mmdb",country,error),"Pinned upstream MaxMind country fixture must load");
    require(geoReadFile("asn",fixtures+"GeoLite2-ASN-Test.mmdb",asn,error),"Pinned upstream MaxMind ASN fixture must load");
    for(const std::string& name:{"GeoIP2-Country-Test","GeoLite2-ASN-Test"}) {
        std::ifstream expected(fixtures+name+".tsv");std::string line;size_t checked=0;
        while(std::getline(expected,line)) {
            const auto tab=line.find('\t');require(tab!=std::string::npos,"Malformed independent MMDB expectation");RuleIpRange range;
            require(parseRuleCidr(line.substr(0,tab),range),"Independent MMDB test prefix must parse");
            char ip[INET6_ADDRSTRLEN]{};inet_ntop(range.family==4?AF_INET:AF_INET6,range.first.data()+(range.family==4?12:0),ip,sizeof(ip));const auto value=line.substr(tab+1);
            if(name.find("Country")!=std::string::npos)require(geoIpMatch(*country,value,ip),("MMDB country lookup differs from independent source JSON: "+line.substr(0,tab)).c_str());
            else {
                ProxyRule rule;rule.kind="ip-asn";rule.value=value;RuleQuery query;query.host=ip;query.geo["asn"]=asn;
                require(evaluateRule(rule,query,{})==RuleVerdict::Yes,("ASN MMDB lookup differs from independent source JSON: "+line.substr(0,tab)).c_str());
            }
            ++checked;
        }
        require(checked>10,"MMDB independent expectation list is empty");
    }
    std::shared_ptr<const GeoDatabase> wrong;require(!geoReadFile("asn",fixtures+"GeoIP2-Country-Test.mmdb",wrong,error),"MMDB resource kinds must not be interchangeable");
    for(const std::string& name:{"cyclic-data-structure.mmdb","invalid-data-record-offset.mmdb","libmaxminddb-corrupt-search-tree.mmdb","libmaxminddb-deep-array-nesting.mmdb","MaxMind-DB-test-broken-pointers-24.mmdb"})
        require(!geoReadFile("mmdb",fixtures+name,wrong,error),"Malformed MMDB trees, data pointers and nesting must be rejected before replacing a working database");
    ProxyRule rule;require(parseRuleExpression("GEOIP,CN,REJECT,no-resolve",rule,false,error),"GeoIP rule fields must be parsed strictly");
    RuleQuery query;query.host="a.fixture.test";query.geo["geoip"]=ips;
    int resolutions=0;g_testRuleResolver=[&](const std::string&){++resolutions;return std::vector<std::string>{"192.0.2.10"};};
    require(evaluateRule(rule,query,{})==RuleVerdict::No&&resolutions==0,"no-resolve must not trigger GeoIP DNS resolution");rule.noResolve=false;
    require(evaluateRule(rule,query,{})==RuleVerdict::Yes&&resolutions==1,"GeoIP rules use the actual configured DNS result");
    RuleQuery unavailable;unavailable.host="192.0.2.10";require(evaluateRule(rule,unavailable,{})==RuleVerdict::Unavailable,"Missing GeoIP data must not skip to a permissive rule");
    rule.kind="geosite";rule.value="missing";query.geo["geosite"]=sites;require(evaluateRule(rule,query,{})==RuleVerdict::Unavailable,"Missing GeoSite categories fail explicitly");
    require(parseRuleExpression("AND,((GEOSITE,fixture),(GEOIP,CN)),REJECT",rule,false,error)&&evaluateRule(rule,query,{})==RuleVerdict::Yes,"GeoData rules compose inside logical rules");
    g_testRuleResolver=nullptr;
    const auto profile=directory+"/geodata.yaml";
    auto content=[&](const std::string& pathSuffix="",const std::string& rules="['MATCH,DIRECT']") {
        return "geodata-mode: true\ngeo-auto-update: false\ngeox-url:\n  mmdb: http://geo.fixture.test/"+pathSuffix+"country.mmdb\n  geoip: http://geo.fixture.test/"+pathSuffix+"geoip.dat\n  geosite: http://geo.fixture.test/"+pathSuffix+"geosite.dat\n  asn: http://geo.fixture.test/"+pathSuffix+"asn.mmdb\nproxies: []\nrules: "+rules+"\n";
    };
    loadProviderProfile(profile,content());require(collectGeoJobs().empty(),"Unused GeoData resources must not download without a request");
    auto body=[&](const std::string& file=""){return "{\"profile\":\""+jsonEscape(profile)+"\",\"path\":\""+jsonEscape(file)+"\"}";};
    auto imported=[&](const std::string& kind,const std::string& fixture) {
        const auto path=directory+"/.geo-import-"+kind+".tmp";{std::ofstream out(path,std::ios::binary);out<<readTestFile(fixtures+fixture);}
        return responseFor("PUT","/clahsos/geodata/"+kind+"/file",body(path));
    };
    require(imported("geoip","geoip.dat")=="{}"&&imported("geosite","geosite.dat")=="{}"&&imported("mmdb","GeoIP2-Country-Test.mmdb")=="{}","GeoData document-picker files import through the real controller API");
    const auto cache=geoCachePath(profile,g_state.geo.resources[1]);const auto cacheBytes=readTestFile(cache);const auto snapshot=g_state.geo.resources[1].data;
    struct stat permissions{};require(stat(cache.c_str(),&permissions)==0&&(permissions.st_mode&0777)==0600,"Imported GeoData cache must have private permissions");
    require(imported("geoip","truncated.dat").find("error")!=std::string::npos&&g_state.geo.resources[1].data==snapshot&&readTestFile(cache)==cacheBytes,"Bad GeoData imports preserve live routing and the previous cache");
    loadProviderProfile(profile,content());require(g_state.geo.resources[1].data&&g_state.geo.resources[1].imported,"GeoData imports and their origin must persist across core restarts");
    {std::lock_guard<std::mutex> lock(g_state.mutex);g_state.rules={{"geoip","cn","REJECT"},{"match","","DIRECT"}};}
    require(activeProxyNode("192.0.2.9",80).type=="reject"&&activeProxyNode("198.51.100.9",80).type=="direct","Production routing must select the GeoIP action and preserve ordinary fallback");
    {std::lock_guard<std::mutex> lock(g_state.mutex);g_state.rules={{"geosite","fixture","REJECT"},{"match","","DIRECT"}};}
    require(activeProxyNode("www.fixture.test",80).type=="reject"&&activeProxyNode("other.invalid",80).type=="direct","Production routing must apply actual GeoSite membership");
    auto update=[&](const std::string& filename) {
        VmessReferencePeer peer(0,"plain",fixtures+filename,"geo_reference_peer.py");g_testConnector=[&](const std::string&,int,int){return peer.take();};
        require(responseFor("PUT","/clahsos/geodata/geoip",body())=="{}","GeoData manual download API");auto jobs=collectGeoJobs();require(jobs.size()==1,"GeoData update must queue one requested resource");
        runGeoJob(jobs[0]);g_testConnector=nullptr;peer.finish();
    };
    update("geoip.dat");require(g_state.geo.resources[1].data&&!g_state.geo.resources[1].imported&&g_state.geo.resources[1].error.empty(),"A real HTTP GeoData update activates verified data");
    const auto retained=g_state.geo.resources[1].data;update("truncated.dat");
    require(g_state.geo.resources[1].data==retained&&!g_state.geo.resources[1].error.empty()&&readTestFile(cache)==cacheBytes,"A failed HTTP GeoData update preserves working data and disk cache");
    {
        std::vector<std::unique_ptr<VmessReferencePeer>> peers;std::vector<std::string> contacted;
        g_testDnsDatagram=[&](const DnsEndpoint& endpoint){contacted.push_back(endpoint.host);auto peer=std::make_unique<VmessReferencePeer>(endpoint.host=="198.51.100.53"?20:10,"udp","","dns_reference_peer.py",true);const int fd=peer->take();peers.push_back(std::move(peer));return fd;};
        const auto dns="dns:\n  enable: true\n  nameserver: [192.0.2.53]\n";
        loadProviderProfile(profile,content()+dns+"  nameserver-policy: {'geosite:fixture,empty': 198.51.100.53}\n");
        auto answer=queryDns("a.fixture.test",1,DnsPurpose::General,HealthClock::now()+std::chrono::seconds(2));
        require(answer.error.empty()&&dnsAnswerAddresses(answer)==std::vector<std::string>{"192.0.2.20"}&&contacted==std::vector<std::string>{"198.51.100.53"},"DNS GeoSite policy must select the real matching category and resolver");
        g_state.geo.resources[2].data.reset();contacted.clear();
        answer=queryDns("new.fixture.test",1,DnsPurpose::General,HealthClock::now()+std::chrono::seconds(2));
        require(!answer.error.empty()&&contacted.empty(),"Missing DNS GeoSite data cannot leak a query to the default resolver");
        for(const std::string& code:{"CN","JP"}) {
            loadProviderProfile(profile,content()+dns+"  fallback: [198.51.100.53]\n  fallback-filter: {geoip: true, geoip-code: "+code+"}\n");contacted.clear();
            answer=queryDns("fallback.fixture.test",1,DnsPurpose::General,HealthClock::now()+std::chrono::seconds(2));
            require(answer.error.empty()&&dnsAnswerAddresses(answer)==std::vector<std::string>{code=="CN"?"192.0.2.10":"192.0.2.20"},"DNS fallback filtering must use the selected GeoIP country database");
        }
        g_state.geo.resources[1].data.reset();answer=queryDns("no-data.fixture.test",1,DnsPurpose::General,HealthClock::now()+std::chrono::seconds(2));
        require(!answer.error.empty(),"A required missing DNS GeoIP database cannot be silently ignored");
        loadProviderProfile(profile,content()+"dns: {enable: true, nameserver: [198.51.100.53], default-nameserver: [192.0.2.53], nameserver-policy: {'geosite:missing': 198.51.100.53}}\n");
        VmessReferencePeer downloader(0,"plain",fixtures+"geoip.dat","geo_reference_peer.py");
        g_testResolvedConnector=[&](const std::string& ip,int,int){require(ip=="192.0.2.10","GeoData bootstrap must use default-nameserver even when normal policy depends on missing GeoSite data");return downloader.take();};
        require(responseFor("PUT","/clahsos/geodata/geoip",body())=="{}","GeoData bootstrap fixture request");auto jobs=collectGeoJobs();require(jobs.size()==1,"GeoData bootstrap fixture queued");runGeoJob(jobs[0]);
        require(g_state.geo.resources[1].error.empty(),"GeoData bootstrap download must break its DNS database dependency cycle");
        g_testResolvedConnector=nullptr;downloader.finish();g_testDnsDatagram=nullptr;for(auto& peer:peers)peer->finish();
    }
    loadProviderProfile(profile,content("changed/"));require(!g_state.geo.resources[1].data,"GeoData source changes must not reuse another URL's cached database");
    loadProviderProfile(profile,content());require(g_state.geo.resources[1].data!=nullptr,"The original source cache survives configuration changes");
    require(responseFor("PUT","/clahsos/geodata/geoip","{\"profile\":\"changed\"}").find("error")!=std::string::npos,"Stale GeoData actions cannot affect a different active configuration");
    require(responseFor("PUT","/clahsos/geodata/geoip",body())=="{}","Stale job fixture request");auto stale=collectGeoJobs();require(stale.size()==1,"Stale job fixture queued");
    std::string temporary;std::shared_ptr<const GeoDatabase> staged;require(geoStage(stale[0],cacheBytes,temporary,staged,error),"Stale job fixture staged");
    loadProviderProfile(profile,content("changed/"));require(!geoCommit(stale[0],temporary,staged,error,false)&&access(temporary.c_str(),F_OK)!=0&&!g_state.geo.resources[1].data,"A stale GeoData job cannot commit across profile/source changes");
    loadProviderProfile(profile,content("automatic/","['GEOIP,CN,REJECT','GEOSITE,fixture,REJECT','IP-ASN,15169,REJECT','MATCH,DIRECT']"));
    auto needed=collectGeoJobs();require(needed.size()==3&&g_state.geo.resources[0].required==false,"A newly referenced GeoIP/GeoSite/ASN resource must download without a manual request");
    g_state.running.store(false);
    {
        const int controller=dnsTestPort(),http=dnsTestPort(),socks=dnsTestPort();const auto stopProfile=directory+"/geo-stop.yaml";
        {std::ofstream out(stopProfile);out<<content("shutdown/","['GEOIP,CN,REJECT','MATCH,DIRECT']")<<"port: "<<http<<"\nsocks-port: "<<socks<<'\n';}
        VmessReferencePeer stalled(0,"plain","timeout","geo_reference_peer.py");std::atomic<int> connected{-1};
        g_testConnector=[&](const std::string&,int,int){const int fd=stalled.take();connected.store(fd);return fd;};
        require(startCore(stopProfile,controller),"GeoData shutdown test must start the production update thread");
        bool registered=false;const auto deadline=HealthClock::now()+std::chrono::seconds(2);
        while(!registered&&HealthClock::now()<deadline){{std::lock_guard<std::mutex> lock(g_state.sessionsMutex);registered=connected.load()>=0&&g_state.sockets.count(connected.load());}if(!registered)std::this_thread::sleep_for(std::chrono::milliseconds(1));}
        require(registered,"GeoData shutdown test requires an actual in-flight download socket");
        const auto beforeStop=HealthClock::now();stopCore();require(HealthClock::now()-beforeStop<std::chrono::seconds(2)&&!g_geoThread.joinable(),"Core shutdown cancels GeoData network waits and joins the updater");
        g_testConnector=nullptr;stalled.finish();
    }
    for(const std::string& kind:{"mmdb","geoip","geosite"})if(const char* path=std::getenv(("CLAHSOS_REAL_"+kind).c_str())) {
        std::shared_ptr<const GeoDatabase> real;require(geoReadFile(kind,path,real,error),"Real GeoData file must load with the production reader");
        if(kind=="geosite"){const auto google=geoSiteMatcher(*real,"google");require(google->error.empty()&&geoSiteMatch(*google,"www.google.com"),"Real GeoSite Google category must match the actual domain");}
        else require(geoIpMatch(*real,"CN","223.5.5.5"),"Real GeoIP database must classify the configured Chinese DNS address");
        std::cout<<"Verified real GeoData "<<kind<<": "<<real->count<<" records\n";
    }
}
