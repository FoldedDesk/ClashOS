int dnsTestBind(int type,int port,int& actual)
{
    const int fd=socket(AF_INET,type,0);if(fd<0)return -1;sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(port);inet_pton(AF_INET,"127.0.0.1",&address.sin_addr);
    socklen_t length=sizeof(address);
    if(bind(fd,reinterpret_cast<sockaddr*>(&address),length)!=0||(type==SOCK_STREAM&&listen(fd,8)!=0)||getsockname(fd,reinterpret_cast<sockaddr*>(&address),&length)!=0){close(fd);return -1;}
    actual=ntohs(address.sin_port);return fd;
}
int dnsTestPort()
{
    static std::set<int> used;
    for(int i=0;i<20;++i){int port=0;const int fd=dnsTestBind(SOCK_STREAM,0,port);require(fd>=0,"Host loopback binding unavailable for real DNS listener checks");close(fd);if(used.insert(port).second)return port;}
    throw std::runtime_error("Cannot reserve distinct local test ports");
}
int dnsTestConnect(int type,int port)
{
    const int fd=socket(AF_INET,type,0);if(fd<0)return -1;socketTimeout(fd,1800);
    sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(port);inet_pton(AF_INET,"127.0.0.1",&address.sin_addr);
    if(connect(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))!=0){close(fd);return -1;}return fd;
}
std::vector<unsigned char> dnsTestTcpRead(int fd)
{
    std::array<char,2> bytes{};require(readExact(fd,bytes.data(),2),"DNS TCP response length unavailable");
    const size_t length=(static_cast<unsigned char>(bytes[0])<<8)|static_cast<unsigned char>(bytes[1]);require(length>=12,"DNS TCP response length invalid");
    std::vector<unsigned char> packet(length);require(readExact(fd,reinterpret_cast<char*>(packet.data()),length),"DNS TCP response body unavailable");return packet;
}
void dnsListenerTests(const std::string& directory)
{
    stopCore();g_testConnector=nullptr;g_testResolvedConnector=nullptr;g_udpTestHooks={};
    std::mutex peerMutex;std::vector<std::unique_ptr<VmessReferencePeer>> peers;std::atomic<int> upstreamQueries{0},lastUpstreamFd{-1};std::string fault;
    g_testDnsDatagram=[&](const DnsEndpoint&) {
        ++upstreamQueries;auto peer=std::make_unique<VmessReferencePeer>(10,"udp",fault,"dns_reference_peer.py",true);const int fd=peer->take();
        {std::lock_guard<std::mutex> lock(peerMutex);peers.push_back(std::move(peer));}lastUpstreamFd.store(fd);return fd;
    };
    const int controller=dnsTestPort(),http=dnsTestPort(),socks=dnsTestPort(),firstPort=dnsTestPort(),nextPort=dnsTestPort();
    auto profile=[&](const std::string& filename,int dnsPort,bool enabled=true,int httpOverride=0) {
        const std::string path=directory+"/"+filename;std::ofstream out(path);
        out<<"ipv6: true\nport: "<<(httpOverride?httpOverride:http)<<"\nsocks-port: "<<socks<<"\nproxies: []\nrules: ['MATCH,DIRECT']\ndns:\n  enable: "<<(enabled?"true":"false")<<"\n  ipv6: true\n  listen: '127.0.0.1:"<<dnsPort<<"'\n  nameserver: [192.0.2.53]\nhosts:\n  large.fixture.test: [";
        for(int n=1;n<=32;++n){if(n>1)out<<',';out<<"'2001:db8::"<<std::hex<<n<<std::dec<<"'";}out<<"]\n";out.close();return path;
    };
    const auto first=profile("dns-listener-first.yaml",firstPort);require(startCore(first,controller),"Production DNS/controller/proxy listeners must start together");
    require(g_state.dnsListener&&g_state.dnsListener->active.load()&&g_state.dnsListener->port==firstPort,"DNS status must reflect the bound service");
    for(const std::string& listen:{"127.0.0.1:1053","0.0.0.0:1053","[::]:1053"})for(const std::string& scheme:{"udp","tcp"}) {
        ParsedConfig parsed;std::string error;
        require(!parseConfigText("dns: {enable: true, listen: '"+listen+"', nameserver: ['"+scheme+"://127.0.0.1:1053']}",parsed,error),"A DNS listener must reject its own direct upstream before applying configuration");
    }
    auto udp=[&](int port,const std::vector<unsigned char>& question) {
        const int fd=dnsTestConnect(SOCK_DGRAM,port);require(fd>=0,"DNS UDP client connect failed");
        require(send(fd,question.data(),question.size(),0)==static_cast<ssize_t>(question.size()),"DNS UDP query send failed");
        std::vector<unsigned char> response(65536);const auto count=recv(fd,response.data(),response.size(),0);close(fd);
        require(count>=12,"DNS UDP response unavailable");response.resize(count);return response;
    };
    auto question=hex("3456010000010000000000000161076669787475726504746573740000010001");
    for(size_t i=12;i<question.size()-4;++i)if(i%2&&std::isalpha(question[i]))question[i]=std::toupper(question[i]);
    auto response=udp(firstPort,question);
    std::vector<unsigned char> expected=hex("345681800001000100000000");expected.insert(expected.end(),question.begin()+12,question.end());const auto rr=hex("c00c00010001000000780004c000020a");expected.insert(expected.end(),rr.begin(),rr.end());
    require(response==expected,"UDP service must preserve client ID/case and independent upstream wire bytes");
    const int before=upstreamQueries;dnsSet16(question,0,0xabcd);response=udp(firstPort,question);
    require(dnsRead16(response,0)==0xabcd&&upstreamQueries==before,"DNS cache replies must replace the transaction ID without another upstream request");
    DnsQueryOptions edns;edns.edns=true;edns.dnssecOk=true;edns.checkingDisabled=true;
    const int beforeEdns=upstreamQueries;dnsBuildQuestion("a.fixture.test",1,0x2211,question,&edns);response=udp(firstPort,question);
    require(upstreamQueries==beforeEdns+1,"DNSSEC DO/CD query state must be isolated from a plain cached query");
    require(dnsRead16(response,10)==1&&(dnsRead16(response,2)&0x10)&&response[response.size()-4]==0x80,"EDNS DO/CD fields must survive the resolver path");
    auto badVersion=question;badVersion[badVersion.size()-5]=1;const int count=upstreamQueries;response=udp(firstPort,badVersion);
    require((dnsRead16(response,2)&15)==0&&response[response.size()-6]==1&&upstreamQueries==count,"Unknown EDNS version returns BADVERS locally");
    auto malformed=question;malformed.push_back(0);response=udp(firstPort,malformed);
    require((dnsRead16(response,2)&15)==1,"Trailing DNS query bytes return FORMERR");
    dnsBuildQuestion("uncached.fixture.test",1,0x3322,question);question[2]=0;const int noRecursion=upstreamQueries;response=udp(firstPort,question);
    require((dnsRead16(response,2)&15)==5&&upstreamQueries==noRecursion,"RD=0 must not trigger recursion for an uncached name");
    for(const std::pair<std::string,int>& item:std::vector<std::pair<std::string,int>>{{"follow.fixture.test",1},{"mx.fixture.test",15},{"txt.fixture.test",16},{".",2}}) {
        dnsBuildQuestion(item.first,item.second,0x4433,question);response=udp(firstPort,question);DnsAnswer parsed;
        require(dnsParseResponse(response,item.first,item.second,0x4433,parsed)&&parsed.rcode==0&&!parsed.records.empty(),"DNS listener handles CNAME completion and common RR types");
    }
    dnsBuildQuestion("opaque.fixture.test",65280,0x4545,question);response=udp(firstPort,question);
    require(response.size()>=5&&std::vector<unsigned char>(response.end()-5,response.end())==hex("00ffc00c01"),"Unknown DNS record RDATA must pass through byte-for-byte without interpreting compression-like bytes");
    fault="negative";dnsBuildQuestion("missing.fixture.test",1,0x4646,question);response=udp(firstPort,question);DnsAnswer negative;
    require(dnsParseResponse(response,"missing.fixture.test",1,0x4646,negative)&&negative.rcode==3&&negative.records.size()==1&&negative.records[0].ttl==30,"Wire negative responses must cap SOA TTL at the SOA minimum");
    const int beforeNegative=upstreamQueries;
    {std::lock_guard<std::mutex> lock(g_state.dns->cacheMutex);for(auto& item:g_state.dns->cache)item.second.stored-=std::chrono::seconds(5);}
    response=udp(firstPort,question);
    require(dnsParseResponse(response,"missing.fixture.test",1,0x4646,negative)&&negative.records[0].ttl<=25&&upstreamQueries==beforeNegative,"Cached negative wire responses age the SOA TTL without another upstream request");fault.clear();
    dnsBuildQuestion("large.fixture.test",28,0x5544,question);response=udp(firstPort,question);
    require(response.size()<=512&&(dnsRead16(response,2)&0x0200)&&dnsRead16(response,6)==0,"Large UDP answers return a bounded TC reply");
    const int tcp=dnsTestConnect(SOCK_STREAM,firstPort);require(tcp>=0,"DNS TCP service not reachable");
    std::vector<unsigned char> pipeline;dnsPut16(pipeline,question.size());pipeline.insert(pipeline.end(),question.begin(),question.end());dnsSet16(question,0,0x6655);dnsPut16(pipeline,question.size());pipeline.insert(pipeline.end(),question.begin(),question.end());
    require(sendAll(tcp,pipeline),"Pipelined DNS TCP queries failed");
    auto firstReply=dnsTestTcpRead(tcp),secondReply=dnsTestTcpRead(tcp);
    require(dnsRead16(firstReply,0)==0x5544&&dnsRead16(secondReply,0)==0x6655&&dnsRead16(firstReply,6)==32&&firstReply.size()>1232,"Persistent DNS TCP must return complete pipelined answers in order");
    const auto same=profile("dns-listener-same-port.yaml",firstPort);
    {std::ofstream out(same,std::ios::app);out<<"  reload.fixture.test: 203.0.113.5\n";}
    require(responseFor("PUT","/configs?force=true","{\"path\":\""+jsonEscape(same)+"\"}")=="{}","DNS profile can reload while keeping its listen port");
    dnsBuildQuestion("reload.fixture.test",1,0x9911,question);pipeline.clear();dnsPut16(pipeline,question.size());pipeline.insert(pipeline.end(),question.begin(),question.end());require(sendAll(tcp,pipeline),"Persistent DNS client write after profile change");
    auto reloaded=dnsTestTcpRead(tcp);DnsAnswer reloadedAnswer;require(dnsParseResponse(reloaded,"reload.fixture.test",1,0x9911,reloadedAnswer)&&dnsAnswerAddresses(reloadedAnswer)==std::vector<std::string>{"203.0.113.5"},"An existing DNS TCP connection must use the newly loaded configuration");
    const auto next=profile("dns-listener-next.yaml",nextPort);
    require(responseFor("PUT","/configs?force=true","{\"path\":\""+jsonEscape(next)+"\"}")=="{}","DNS listen address reload failed");
    char byte;require(recv(tcp,&byte,1,0)<=0,"Retiring a DNS listener closes persistent clients");close(tcp);
    const int retired=dnsTestConnect(SOCK_STREAM,firstPort);require(retired<0,"Retired DNS TCP port must be released");if(retired>=0)close(retired);
    int occupied=0;const int busy=dnsTestBind(SOCK_DGRAM,0,occupied);require(busy>=0,"Cannot create a busy UDP port");
    const int unusedHttp=dnsTestPort();const auto invalid=profile("dns-listener-busy.yaml",occupied,true,unusedHttp);
    require(responseFor("PUT","/configs?force=true","{\"path\":\""+jsonEscape(invalid)+"\"}").find("error")!=std::string::npos,"A busy UDP port must refuse a DNS configuration reload");
    require(g_state.configPath==next&&g_state.httpPort==http&&g_state.dnsListener->port==nextPort,"DNS bind failure must preserve the profile, proxy ports, and DNS service");
    close(busy);dnsBuildQuestion("after-rollback.fixture.test",1,0x7766,question);response=udp(nextPort,question);require(dnsRead16(response,6)==1,"Original DNS service remains usable after a rejected reload");
    int occupiedTcp=0;const int busyTcp=dnsTestBind(SOCK_STREAM,0,occupiedTcp);require(busyTcp>=0,"Cannot create a busy TCP port");
    const auto invalidTcp=profile("dns-listener-busy-tcp.yaml",occupiedTcp);
    require(responseFor("PUT","/configs?force=true","{\"path\":\""+jsonEscape(invalidTcp)+"\"}").find("error")!=std::string::npos&&g_state.configPath==next&&g_state.dnsListener->port==nextPort,"A busy DNS TCP port preserves the existing profile and listener");close(busyTcp);
    int occupiedProxy=0;const int busyProxy=dnsTestBind(SOCK_STREAM,0,occupiedProxy);require(busyProxy>=0,"Cannot create a busy proxy port");
    const int stagedPort=dnsTestPort();const auto invalidProxy=profile("dns-listener-busy-proxy.yaml",stagedPort,true,occupiedProxy);
    require(responseFor("PUT","/configs?force=true","{\"path\":\""+jsonEscape(invalidProxy)+"\"}").find("error")!=std::string::npos&&g_state.configPath==next&&g_state.dnsListener->port==nextPort,"A proxy bind failure must roll back a staged DNS listener too");
    int rebound=0;const int stagedUdp=dnsTestBind(SOCK_DGRAM,stagedPort,rebound);require(stagedUdp>=0,"A rejected reload must release its staged UDP DNS port");close(stagedUdp);
    const int stagedTcp=dnsTestBind(SOCK_STREAM,stagedPort,rebound);require(stagedTcp>=0,"A rejected reload must release its staged TCP DNS port and waiting thread");close(stagedTcp);close(busyProxy);
    const auto datagramHook=g_testDnsDatagram;
    g_testDnsDatagram=[&](const DnsEndpoint& endpoint){if(endpoint.host=="127.0.0.1"||endpoint.host=="loop.fixture.test")return dnsTestConnect(SOCK_DGRAM,nextPort);return datagramHook(endpoint);};
    const uint64_t listenerCount=g_state.dnsListener->queries.load();
    const auto diagnostic=responseFor("GET","/dns/query?name=diagnostic.fixture.test&type=A&server=udp%3A%2F%2F127.0.0.1%3A"+std::to_string(nextPort),"");
    require(diagnostic.find("192.0.2.10")!=std::string::npos&&g_state.dnsListener->queries.load()==listenerCount+1,"Explicit diagnostic server queries must actually traverse the configured UDP listener");
    const std::string loop=directory+"/dns-listener-loop.yaml";
    {std::ofstream out(loop);out<<"ipv6: true\nport: "<<http<<"\nsocks-port: "<<socks<<"\ndns: {enable: true, listen: '127.0.0.1:"<<nextPort<<"', nameserver: ['loop.fixture.test:"<<nextPort<<"'], default-nameserver: [192.0.2.53]}\n";}
    require(responseFor("PUT","/configs?force=true","{\"path\":\""+jsonEscape(loop)+"\"}")=="{}","Runtime self-resolution check requires an applied hostname upstream");
    const uint64_t beforeLoop=g_state.dnsListener->queries.load();dnsBuildQuestion("loop-guard.fixture.test",1,0x7777,question);const auto loopStarted=HealthClock::now();response=udp(nextPort,question);
    require((dnsRead16(response,2)&15)==2&&HealthClock::now()-loopStarted<std::chrono::seconds(1)&&g_state.dnsListener->queries.load()==beforeLoop+1,"An upstream resolving back to the listener must fail without recursive DNS workers");
    g_testDnsDatagram=datagramHook;require(responseFor("PUT","/configs?force=true","{\"path\":\""+jsonEscape(next)+"\"}")=="{}","Restore ordinary DNS after runtime loop check");
    const auto disabled=profile("dns-listener-disabled.yaml",nextPort,false);require(responseFor("PUT","/configs?force=true","{\"path\":\""+jsonEscape(disabled)+"\"}")=="{}"&&!g_state.dnsListener,"Disabling DNS removes the UDP/TCP service");
    require(responseFor("GET","/clahsos/dns","").find("\"listening\":false")!=std::string::npos,"DNS status must report disabled listeners truthfully");
    require(responseFor("PUT","/configs?force=true","{\"path\":\""+jsonEscape(next)+"\"}")=="{}","DNS listeners restart on their configured ports");
    fault="timeout";lastUpstreamFd.store(-1);const int pending=dnsTestConnect(SOCK_STREAM,nextPort);require(pending>=0,"Stalled DNS client connect failed");dnsBuildQuestion("stalled.fixture.test",1,0x8877,question);pipeline.clear();dnsPut16(pipeline,question.size());pipeline.insert(pipeline.end(),question.begin(),question.end());require(sendAll(pending,pipeline),"Stalled DNS query send failed");
    bool registered=false;const auto waitUntil=HealthClock::now()+std::chrono::seconds(2);
    while(!registered&&HealthClock::now()<waitUntil){{std::lock_guard<std::mutex> lock(g_state.sessionsMutex);registered=lastUpstreamFd.load()>=0&&g_state.sockets.count(lastUpstreamFd.load());}if(!registered)std::this_thread::sleep_for(std::chrono::milliseconds(1));}
    require(registered,"Shutdown check requires an actual in-flight DNS socket");
    const auto stopping=HealthClock::now();stopCore();require(HealthClock::now()-stopping<std::chrono::seconds(2),"Stopping the core cancels DNS clients and blocked network waits");
    close(pending);require(g_state.workers.load()==0&&g_dnsWireWorkers.load()==0&&!g_state.dnsListener,"No DNS workers or listeners survive core shutdown");
    g_testDnsDatagram=nullptr;for(auto& peer:peers)peer->finish();
}
