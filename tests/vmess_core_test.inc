#include <spawn.h>
#include <sys/wait.h>
extern char **environ;

struct VmessReferencePeer {
    int fd = -1;
    pid_t pid = -1;
    VmessReferencePeer(int alter, const std::string& transport, const std::string& failure, const std::string& scriptName="vmess_reference_peer.py",bool datagram=false) {
        int pair[2];require(socketpair(AF_UNIX,datagram?SOCK_DGRAM:SOCK_STREAM,0,pair)==0,"Independent peer transport unavailable");fd = pair[0];
        if(datagram)for(int socket:pair){int size=262144;setsockopt(socket,SOL_SOCKET,SO_SNDBUF,&size,sizeof(size));setsockopt(socket,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size));}
        // The reference peer receives exactly one inherited socket, never an application config.
        const char* python = std::getenv("CLAHSOS_REFERENCE_PYTHON");
        require(python != nullptr, "Reference Python interpreter is required");
        const std::string script = std::string(CLAHSOS_TEST_ROOT) + "/" + scriptName;
        const std::string number = std::to_string(pair[1]), count = std::to_string(alter);
        char* args[] = {const_cast<char*>(python), const_cast<char*>(script.c_str()), const_cast<char*>(number.c_str()),
            const_cast<char*>(count.c_str()), const_cast<char*>(transport.c_str()), const_cast<char*>(failure.c_str()), nullptr};
        posix_spawn_file_actions_t actions; posix_spawn_file_actions_init(&actions);
        posix_spawn_file_actions_addclose(&actions, pair[0]);
        const int result = posix_spawn(&pid, python, &actions, nullptr, args, environ);
        posix_spawn_file_actions_destroy(&actions); close(pair[1]);
        require(result == 0, "Independent VMess peer failed to start");
    }
    ~VmessReferencePeer() {
        if (fd >= 0) close(fd);
        if (pid > 0) { kill(pid, SIGKILL); int status; waitpid(pid, &status, 0); }
    }
    int take() { const int result = fd; fd = -1; return result; }
    void finish() {
        int status = 0; require(waitpid(pid, &status, 0) == pid, "Cannot collect independent VMess peer"); pid = -1;
        require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "Independent VMess server rejected wire exchange");
    }
};
ProxyNode vmTestNode(int alter, const std::string& transport, const std::string& cipher) {
    ProxyNode node; node.name="VMess fixture"; node.type="vmess"; node.server="node.invalid"; node.port=443;
    node.uuid="11111111-2222-4333-8444-555555555555"; node.alterId=alter; node.cipher=cipher;
    node.tls=transport.find("tls")!=std::string::npos; node.network=transport.find("ws")!=std::string::npos ? "ws":"tcp";
    node.serverName="vmess.test";node.wsPath="/vmess?test=1";node.wsHeaders={{"Host","cdn.test"},{"X-Test","native-peer"}};
    return node;
}
void vmessTests(const std::string& directory) {
    require(vmessCryptoSelfTest() && vmessTrustStoreSelfTest(), "Device VMess/CA diagnostics must validate known answers");
    const auto id=vmUuid("11111111-2222-4333-8444-555555555555");
    require(vmCommandKey(id)==hex("21fb68641c5a02b1cf67dd3b6bd1e58d"), "Independent VMess command-key vector");
    require(vmAlterId(id)==hex("3de7fe46da2151470ae22706f841f95f"), "Independent VMess alterId vector");
    require(vmAlterId(vmAlterId(id))==hex("6b801f39a3cc7b034bf8b64f6c8204bf"), "VMess alternate IDs form a chain");
    require(vmKdf(vmCommandKey(id),{vmBytes("VMess Header AEAD Key"),VmBytes(16,1),VmBytes(8,2)})==
        hex("b94f1937547dca019ef31e11256f127421704bdfeb8d8f35e9afc5cbadcc366d"), "Nested HMAC VMess AEAD KDF differs from independent reference");
    VmessMask mask;VmBytes seed(16);for(size_t i=0;i<seed.size();++i)seed[i]=i;mask.init(seed);
    const auto shake=hex("98481946de85c670a7a84432");
    for(size_t i=0;i<shake.size();i+=2)require(mask.next()==((shake[i]<<8)|shake[i+1]), "Streaming SHAKE128 differs from hashlib");
    std::ifstream rootFile(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/vmess/ca.pem");
    const std::string roots((std::istreambuf_iterator<char>(rootFile)),{});
    require(!roots.empty(),"TLS test CA unavailable");g_testVmessTrust=roots.c_str();
    VmBytes payload(6000);for(size_t i=0;i<payload.size();++i)payload[i]=static_cast<unsigned char>(i*17+3);
    VmBytes expected=vmBytes("vmess-response:");expected.insert(expected.end(),payload.rbegin(),payload.rend());
    g_state.running.store(true);
    auto exercise=[&](int alter,const std::string& transport,const std::string& cipher,const std::string& failure) {
        std::cerr << "VMess peer: alter=" << alter << " transport=" << transport << " cipher=" << cipher << " fault=" << failure << '\n';
        VmessReferencePeer peer(alter,transport,failure);
        g_testConnector=[&](const std::string& host,int port,int timeout) {
            require(host=="node.invalid"&&port==443,"VMess must connect to configured endpoint");return peer.take();
        };
        ProxyNode node=vmTestNode(alter,transport,cipher);
        if(failure=="tls-reject-host")node.serverName="wrong.test";
        if(failure=="skip-cert")node.skipCertVerify=true;
        if(failure=="tls-reject-ca"||failure=="skip-cert")g_testVmessTrust=nullptr;else g_testVmessTrust=roots.c_str();
        ProxyStream stream;std::string error;
        const bool opened=openProxyStream(node,"target.test",443,stream,error,4000);g_testConnector=nullptr;
        const bool reject=failure=="tls-reject-host"||failure=="tls-reject-ca"||failure=="ws-accept";
        if(reject) {
            require(!opened&&!error.empty(),"Invalid TLS identity or WS acceptance must fail startup");
            stream.vmess.reset();if(stream.fd>=0){closeSocket(stream.fd);stream.fd=-1;}peer.finish();return;
        }
        if(!opened)std::cerr<<"VMess start error: "<<error<<'\n';
        require(opened,"Production VMess stream could not start");
        require(streamWrite(stream,reinterpret_cast<const char*>(payload.data()),payload.size()),"VMess chunked write failed");
        require(stream.vmess->finish(),"VMess request termination failed");
        VmBytes response,chunk;
        while(streamRead(stream,chunk))vmAppend(response,chunk);
        if(failure=="auth"||failure=="tag"||failure=="length")
            require(response.empty()&&errno==EBADMSG,"Unauthenticated VMess response must never reach application");
        else require(response==expected&&errno==0,"VMess fragmented reply or authenticated EOF differs from peer");
        stream.vmess.reset();if(stream.fd>=0){closeSocket(stream.fd);stream.fd=-1;}
        peer.finish();
    };
    for(int alter:{0,1,3})for(const std::string transport:{"tcp","ws","tls","ws-tls"})exercise(alter,transport,"auto","");
    for(const std::string cipher:{"aes-128-gcm","chacha20-poly1305","none","zero"})exercise(0,"tcp",cipher,"");
    exercise(0,"tls","auto","tls-reject-ca");exercise(0,"tls","auto","tls-reject-host");exercise(0,"tls","auto","skip-cert");
    exercise(0,"ws","auto","ws-accept");
    for(int alter:{0,1})for(const std::string fault:{"auth","tag"})exercise(alter,"ws","auto",fault);
    exercise(0,"tcp","auto","length");
    for (int alter : {0,1}) for (const std::string transport : {"tcp","ws-tls"}) {
        std::cerr << "VMess UDP peer: alter=" << alter << " transport=" << transport << '\n';
        VmessReferencePeer peer(alter,transport,"");
        g_testVmessTrust=roots.c_str();
        g_testConnector=[&](const std::string&,int,int){return peer.take();};
        ProxyNode node=vmTestNode(alter,transport,"auto");node.udp=true;node.chain={"VMess fixture"};
        UdpTarget target;target.host="target.test";target.port=443;
        auto flow=openUdpFlow(-1,target,node);g_testConnector=nullptr;
        require(flow!=nullptr&&flow->vmess!=nullptr,"VMess UDP flow did not start");
        const auto address=shadowsocksAddress(target.host,target.port);
        const std::vector<VmBytes> datagrams={VmBytes(payload.begin(),payload.begin()+512),VmBytes(payload.end()-1024,payload.end())};
        for(const auto& data:datagrams){
            VmBytes packet(3,0);vmAppend(packet,address);vmAppend(packet,data);UdpTarget parsed;
            require(parseSocksUdp(packet,parsed)&&writeUdpFlow(*flow,packet,parsed),"VMess UDP could not enqueue datagram");
        }
        for(size_t i=0;i<datagrams.size();++i){
            pollfd watch{flow->notifyMain,POLLIN,0};
            require(flow->streamPending()||poll(&watch,1,5000)==1,"VMess UDP reply timed out");
            VmBytes packet;size_t size=0;
            require(readUdpFlow(*flow,packet,size),"VMess UDP reply decode failed");
            VmBytes expectedPacket(3,0);vmAppend(expectedPacket,address);vmAppend(expectedPacket,vmBytes("udp-response:"+std::to_string(i)));vmAppend(expectedPacket,datagrams[i]);
            require(packet==expectedPacket&&size==datagrams[i].size()+14,"VMess UDP must preserve payload, target and datagram boundary");
        }
        flow.reset();peer.finish();
    }
    for (int protocol : {0,1}) {
        VmessReferencePeer peer(1,"ws-tls","");g_testVmessTrust=roots.c_str();
        g_testConnector=[&](const std::string&,int,int){return peer.take();};
        ProxyNode node=vmTestNode(1,"ws-tls","auto");
        { std::lock_guard<std::mutex> lock(g_state.mutex);
          g_state.mode="Rule";g_state.nodes={node};ProxyGroup group;group.name="PROXY";group.now=node.name;group.proxies={node.name};
          g_state.groups={group};g_state.rules={{"match","","PROXY"}}; }
        const uint64_t up=g_state.uploadTotal.load(),down=g_state.downloadTotal.load();
        int client[2];makePair(client);socketTimeout(client[1],5000);dispatchWorker(client[0],protocol);
        if(protocol==0) {
            sendAll(client[1],"CONNECT target.test:443 HTTP/1.1\r\nHost: target.test\r\n\r\n");
            require(readUntilHeaders(client[1]).find("200 Connection Established")!=std::string::npos,"VMess HTTP CONNECT negotiation failed");
        } else {
            VmBytes greeting={5,1,0,5,1,0};vmAppend(greeting,shadowsocksAddress("target.test",443));sendAll(client[1],greeting);
            require(receiveN(client[1],2)==std::string("\5\0",2)&&receiveN(client[1],10)[1]==0,"VMess SOCKS5 CONNECT negotiation failed");
        }
        require(!connectionId("target.test").empty(),"VMess relayed request must appear in connection table");
        sendAll(client[1],payload);shutdown(client[1],SHUT_WR);
        require(receiveN(client[1],expected.size())==text(expected),"Full HTTP/SOCKS -> VMess+WS+TLS relay corrupted payload");
        char byte;require(recv(client[1],&byte,1,0)==0,"VMess authenticated EOF must finish application response");
        close(client[1]);workersIdle();g_testConnector=nullptr;peer.finish();
        require(g_state.uploadTotal.load()-up==payload.size()&&g_state.downloadTotal.load()-down==expected.size(),"VMess accounting must exclude TLS, WebSocket and protocol overhead");
    }
    VmessSession bounded(-1);bounded.sendCounter=65536;bounded.requestKey=VmBytes(16);bounded.requestIv=VmBytes(16);bounded.sendMask.init(VmBytes(16));
    const unsigned char byte=1;require(!bounded.chunk(&byte,1)&&errno==EOVERFLOW,"VMess must not reuse a GCM nonce after counter exhaustion");
    bounded.receiveCounter=65536;bounded.responseReady=true;VmBytes out;
    require(!bounded.read(out)&&out.empty()&&errno==EOVERFLOW,"VMess receive counter must not wrap");
    ParsedConfig config;std::string error;
    const std::string source=R"({"proxies":[{"name":"vm","type":"vmess","server":"node.invalid","port":443,"uuid":"11111111-2222-4333-8444-555555555555","alterId":1,"network":"ws","tls":true,"servername":"vmess.test","ws-opts":{"path":"/vmess?test=1","headers":{"Host":"cdn.test"}}}]})";
    require(parseConfigText(source,config,error)&&config.nodes[0].network=="ws"&&config.nodes[0].tls&&config.nodes[0].serverName=="vmess.test"&&
        config.nodes[0].wsHeaders["Host"]=="cdn.test"&&config.nodes[0].wsPath=="/vmess?test=1","VMess YAML/JSON transport settings were not preserved");
    const std::string invalid="proxies: [{name: broken, type: vmess, server: x, port: 443, uuid: invalid}]";
    require(!parseConfigText(invalid,config,error),"Invalid VMess UUID must fail before replacing active configuration");
    g_testVmessTrust=nullptr;g_testConnector=nullptr;g_state.running.store(false);
}
