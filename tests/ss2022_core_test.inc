std::string ss2022TestPassword(const std::string& method,int identities=0)
{
    const size_t size=method.find("aes-128")!=std::string::npos?16:32;std::string out;
    for(int layer=0;layer<=identities;++layer){SsBytes key(size);for(size_t i=0;i<size;++i)key[i]=static_cast<unsigned char>(i+31*layer);unsigned char encoded[65];size_t length=0;
        require(!mbedtls_base64_encode(encoded,sizeof(encoded),&length,key.data(),key.size()),"Encode public SS2022 key");if(layer)out+=':';out.append(reinterpret_cast<char*>(encoded),length);}
    return out;
}
ProxyNode ss2022TestNode(const std::string& method,int identities=0)
{
    ProxyNode node;node.name="SS2022 fixture";node.type="ss";node.server="ss2022.test";node.port=443;node.udp=true;
    node.cipher=method;node.password=ss2022TestPassword(method,identities);return node;
}
void ss2022Tests(const std::string& directory)
{
    require(ss2022CryptoSelfTest(),"Device SS2022 diagnostic uses independent known answers");
    require(ss2022Hash({},32)==hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),"BLAKE3 official empty-message known answer");
    require(ss2022HChaCha(hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),hex("000000090000004a00000000314159270000000000000000"))==hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"),"HChaCha20 independent known answer");
    const std::vector<std::string> methods={"2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305"};
    SsBytes payload(70000);for(size_t i=0;i<payload.size();++i)payload[i]=static_cast<unsigned char>(i*17+3);
    SsBytes expected=vmBytes("ss2022-response:");expected.insert(expected.end(),payload.rbegin(),payload.rend());
    for(const auto& method:methods) {
        std::cerr<<"SS2022 method: "<<method<<'\n';
        const auto cipher=shadowsocksCipher(method);auto node=ss2022TestNode(method);
        require(isSs2022(cipher)&&supportsDialerTcp(node)&&supportsUdp(node),"SS2022 must expose actual TCP/UDP capabilities");
        ParsedConfig config;std::string error;const auto source="proxies: [{name: Test, type: ss, server: ss2022.test, port: 443, cipher: "+method+", password: '"+node.password+"', udp: true}]\n";
        require(parseConfigText(source,config,error),"Valid SS2022 configuration must load");
        ObjectEditItem object;object.name="Test";object.content="{name: Test, type: ss, server: ss2022.test, port: 443, cipher: "+method+", password: '"+node.password+"', udp: true}";
        require(editorObjectValid(object,false,error),"SS2022 must be editable in the production node editor");
        const std::string link=shareLinksJson("ss://"+method+":"+node.password+"@ss2022.test:443#SS2022");EditorYaml linked;
        require(linked.parse(link,8*1024*1024,error),"SS2022 share-link result parses");const auto* linkedRoot=yaml_document_get_root_node(&linked.document);
        require(yamlText(yamlValue(linked.document,const_cast<yaml_node_t*>(linkedRoot),"error")).empty(),"SS2022 SIP002 raw userinfo imports through production link validation");
        for(const std::string invalid:std::vector<std::string>{"password","!!!!",node.password+"=",ss2022TestPassword(method==methods[0]?methods[1]:methods[0]),":"+node.password,node.password+":"}) {
            auto bad=node;bad.password=invalid;std::atomic<bool> dialed{false};g_testConnector=[&](const std::string&,int,int){dialed=true;return -1;};ProxyStream stream;
            require(!openProxyStream(bad,"target.test",443,stream,error)&&!dialed&&!error.empty(),"Invalid SS2022 keys must fail before dialing, with no DIRECT fallback");g_testConnector=nullptr;
            require(ss2022Keys(cipher,invalid).empty(),"Invalid key syntax/length/empty identity cannot be coerced into another key");
        }
        if(cipher==SsCipher::ChaCha2022)require(ss2022Keys(cipher,node.password+":"+node.password).empty(),"AES-only identity headers cannot be silently used with ChaCha2022");
        else require(ss2022Keys(cipher,ss2022TestPassword(method,8)).size()==9&&ss2022Keys(cipher,ss2022TestPassword(method,9)).empty(),"Identity-chain allocation is bounded");

        const auto vectorPath=directory+"/ss2022-vector";
        {VmessReferencePeer peer(0,method,"vectors|"+vectorPath,"ss2022_reference_peer.py");peer.finish();}
        std::ifstream vectorFile(vectorPath);std::string keyHex,saltHex,wireHex;std::getline(vectorFile,keyHex);std::getline(vectorFile,saltHex);std::getline(vectorFile,wireHex);unlink(vectorPath.c_str());
        const auto key=hex(keyHex),salt=hex(saltHex),wire=hex(wireHex);const size_t firstEnd=key.size()*2+47;
        require(!wire.empty(),"Independent Rust/PyCryptodome response vector exists");
        for(size_t cut=0;cut<=wire.size();++cut) {
            int sockets[2];pairFor(sockets);socketTimeout(sockets[0],500);Ss2022Session session(sockets[0],cipher,{key});session.requestSalt=salt;SsBytes plain{1};std::string result;
            require(sendAll(sockets[1],reinterpret_cast<const char*>(wire.data()),cut),"Split SS2022 response vector");
            const auto started=HealthClock::now();while(session.read(plain,true))result+=text(plain);
            const std::string prefix=cut>=firstEnd?std::string("head")+(cut==wire.size()?"tail":""):"";
            require(result==prefix&&plain.empty()&&errno==EAGAIN&&HealthClock::now()-started<std::chrono::milliseconds(250),"Every SS2022 salt/header/payload/tag split must yield promptly without plaintext leakage");
            require(sendAll(sockets[1],reinterpret_cast<const char*>(wire.data()+cut),wire.size()-cut),"Resume independent SS2022 response vector");shutdown(sockets[1],SHUT_WR);
            while(session.read(plain,cut%2==0))result+=text(plain);
            require(result=="headtail"&&plain.empty()&&errno==0,"SS2022 incremental receive state must survive EAGAIN and retain nonce order");close(sockets[0]);close(sockets[1]);
            pairFor(sockets);Ss2022Session shortSession(sockets[0],cipher,{key});shortSession.requestSalt=salt;result.clear();
            require(sendAll(sockets[1],reinterpret_cast<const char*>(wire.data()),cut),"Independent SS2022 EOF at every byte");shutdown(sockets[1],SHUT_WR);
            while(shortSession.read(plain,true))result+=text(plain);
            const bool boundary=cut==0||cut==firstEnd||cut==wire.size();
            require(result==prefix&&plain.empty()&&errno==(boundary?0:ECONNRESET),"SS2022 EOF is clean only at complete authenticated record boundaries");close(sockets[0]);close(sockets[1]);
        }
        for(size_t position:{key.size(),key.size()*2+26,firstEnd-1}) {
            int sockets[2];pairFor(sockets);Ss2022Session rejected(sockets[0],cipher,{key});rejected.requestSalt=salt;auto bad=wire;bad[position]^=1;require(sendAll(sockets[1],bad),"Independent SS2022 ciphertext mutation");SsBytes plain{1};
            require(!rejected.read(plain,true)&&plain.empty()&&errno==EBADMSG,"Mutated SS2022 header/payload/tag must never expose plaintext");close(sockets[0]);close(sockets[1]);
        }
        {
            Ss2022Session exhausted(-1,cipher,{key});exhausted.requestSalt=salt;exhausted.stage=Ss2022Session::Stage::Length;exhausted.receiveNonce.assign(12,0xff);SsBytes plain{1};
            require(!exhausted.read(plain,true)&&plain.empty()&&errno==EOVERFLOW,"SS2022 nonce exhaustion must fail before socket I/O");
            Ss2022Datagram datagram(cipher,{key});datagram.counter=UINT64_MAX;SsBytes packet;
            require(datagram.encode(shadowsocksAddress("target.test",443),packet)&&datagram.exhausted&&!datagram.encode(shadowsocksAddress("target.test",443),packet)&&packet.empty()&&errno==EOVERFLOW,"SS2022 UDP packet IDs must never wrap or reuse a nonce");
        }

        for(int identities:{0,1,2}) {
            if(cipher==SsCipher::ChaCha2022&&identities)continue;node=ss2022TestNode(method,identities);
            std::cerr<<"SS2022 TCP/UDP identity keys: "<<identities<<'\n';
            g_state.running=true;{std::lock_guard<std::mutex> lock(g_state.mutex);g_state.mode="Rule";g_state.nodes={node};g_state.groups.clear();g_state.rules={{"match","",node.name}};g_state.dns=std::make_shared<DnsConfig>();}
            for(int ingress:{0,1}) {
                VmessReferencePeer peer(identities,method,"tcp","ss2022_reference_peer.py");g_testConnector=[&](const std::string& host,int port,int){require(host==node.server&&port==node.port,"SS2022 must dial its configured endpoint");return peer.take();};
                const auto up=g_state.uploadTotal.load(),down=g_state.downloadTotal.load();int client[2];pairFor(client);socketTimeout(client[1],3000);dispatchWorker(client[0],ingress);
                if(ingress==0){sendAll(client[1],"CONNECT target.test:443 HTTP/1.1\r\nHost: target.test\r\n\r\n");require(readUntilHeaders(client[1]).find("200 Connection Established")!=std::string::npos,"SS2022 HTTP ingress opens");}
                else{SsBytes request{5,1,0,5,1,0};ss2022Append(request,shadowsocksAddress("target.test",443));sendAll(client[1],request);require(receiveN(client[1],2)==std::string("\5\0",2)&&receiveN(client[1],10)[1]==0,"SS2022 SOCKS ingress opens");}
                require(sendAll(client[1],payload),"Large SS2022 request writes");shutdown(client[1],SHUT_WR);
                require(receiveN(client[1],expected.size())==text(expected),"Independent SS2022 server accepts headers, identity chain and 65535-byte chunks");char byte;require(recv(client[1],&byte,1,0)==0,"SS2022 relay retains half-close and EOF");
                close(client[1]);workersIdle();g_testConnector=nullptr;peer.finish();require(g_state.uploadTotal.load()-up==payload.size()&&g_state.downloadTotal.load()-down==expected.size(),"SS2022 traffic counts exclude framing and padding");
            }
            {
                VmessReferencePeer peer(identities,method,"udp","ss2022_reference_peer.py",true);UdpHarness harness;
                {std::lock_guard<std::mutex> lock(harness.mutex);harness.pending[node.server+":"+std::to_string(node.port)].push_back({peer.take(),udpTestEndpoint("192.0.2.10",443)});}
                const size_t maximum=65507-ss2022UdpOverhead(node)-shadowsocksAddress("target.test",443).size();
                for(int i=0;i<4;++i){const std::string body=i==0?"packet-0":i==1?"":std::string(i==2?4096:maximum,i==2?'P':'L');harness.inject(udpTestPacket("target.test",443,body));
                    const auto packet=receiveTestDatagram(harness.relay);UdpTarget source;const std::string response=i==3?body.substr(0,body.size()-8):"udp-response:"+std::string(body.rbegin(),body.rend());
                    require(parseSocksUdp(packet,source)&&source.host=="target.test"&&source.port==443&&text({packet.begin()+3+source.headerSize,packet.end()})==response,"SS2022 UDP payloads/maximum sizes and invalid-header/authentication/replay controls");}
                for(const std::string response:{"late","old","ahead","","restart","retained"}){const auto packet=receiveTestDatagram(harness.relay);UdpTarget source;require(parseSocksUdp(packet,source)&&text({packet.begin()+3+source.headerSize,packet.end()})==response,"UDP replay window accepts authenticated reordering, empty replies and server restarts without forgetting the previous server");}
                for(int i=0;i<30;++i){const auto packet=receiveTestDatagram(harness.relay);UdpTarget source;require(parseSocksUdp(packet,source)&&text({packet.begin()+3+source.headerSize,packet.end()})=="new-"+std::to_string(i),"SS2022 new authenticated server sessions retain independent replay state");}
                {const auto packet=receiveTestDatagram(harness.relay);UdpTarget source;require(parseSocksUdp(packet,source)&&text({packet.begin()+3+source.headerSize,packet.end()})=="existing","A full server-session cache rejects overflow without discarding an association younger than 60 seconds");}
                pollfd watch{harness.relay,POLLIN,0};require(poll(&watch,1,30)==0,"Duplicate or out-of-window SS2022 packets must never reach the client");peer.finish();
            }
            require(g_state.connections.empty(),"SS2022 UDP cleans up connection records");
        }
        node=ss2022TestNode(method);
        {std::lock_guard<std::mutex> lock(g_state.mutex);g_state.nodes={node};}
        for(const std::string fault:{"type","stale","future","request-salt","header-tag","short-header"}) {
            std::cerr<<"SS2022 negative response: "<<fault<<'\n';
            VmessReferencePeer peer(0,method,fault,"ss2022_reference_peer.py");g_testConnector=[&](const std::string&,int,int){return peer.take();};
            {ProxyStream stream;std::string error;require(openProxyStream(node,"target.test",443,stream,error),"SS2022 negative response fixture starts");require(streamWrite(stream,reinterpret_cast<const char*>(payload.data()),payload.size()),"SS2022 negative request payload");shutdown(stream.fd,SHUT_WR);SsBytes plain{1};require(!streamRead(stream,plain)&&plain.empty()&&errno!=0,"Invalid SS2022 response type/time/request binding/tag/truncation cannot expose data");}
            g_testConnector=nullptr;peer.finish();
        }
        for(const std::string phase:{"duplex-salt","duplex-header","duplex-payload","duplex-server-first"})for(int ingress:{0,1}) {
            std::cerr<<"SS2022 duplex: "<<phase<<" ingress="<<ingress<<'\n';
            const auto marker=directory+"/ss2022-ready";unlink(marker.c_str());VmessReferencePeer peer(0,method,phase+"|"+marker,"ss2022_reference_peer.py");g_testConnector=[&](const std::string&,int,int){return peer.take();};
            int client[2];pairFor(client);socketTimeout(client[1],2000);dispatchWorker(client[0],ingress);
            if(!ingress){sendAll(client[1],"CONNECT target.test:443 HTTP/1.1\r\nHost: target.test\r\n\r\n");require(readUntilHeaders(client[1]).find("200 Connection Established")!=std::string::npos,"SS2022 duplex HTTP opens");}
            else{SsBytes request{5,1,0,5,1,0};ss2022Append(request,shadowsocksAddress("target.test",443));sendAll(client[1],request);require(receiveN(client[1],2)==std::string("\5\0",2)&&receiveN(client[1],10)[1]==0,"SS2022 duplex SOCKS opens");}
            if(phase!="duplex-server-first")sendAll(client[1],"first");awaitCondition([&]{return access(marker.c_str(),F_OK)==0;},"Independent SS2022 peer sends partial reply");
            pollfd watch{client[1],POLLIN,0};require(poll(&watch,1,30)==0,"Incomplete SS2022 response must not expose plaintext");
            if(phase=="duplex-server-first")sendAll(client[1],"first");sendAll(client[1],"tail");shutdown(client[1],SHUT_WR);
            require(receiveN(client[1],4)=="done","Partial SS2022 salt/header/payload must not block later upload");close(client[1]);workersIdle();g_testConnector=nullptr;peer.finish();unlink(marker.c_str());
        }
    }
    const std::string roots=readTestFile(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/vmess/ca.pem");
    for(const auto& method:methods)for(const std::string fault:{"","status","wronghost","untrusted"}) {
        std::cerr<<"SS2022 HTTPS: "<<method<<" control="<<fault<<'\n';
        VmessReferencePeer peer(0,"ss2022-"+method,fault,"https_reference_peer.py");g_testConnector=[&](const std::string&,int,int){return peer.take();};
        g_testVmessTrust=fault=="untrusted"?nullptr:roots.c_str();TestTarget target;parseTestUrl(std::string("https://")+(fault=="wronghost"?"wrong.test":"vmess.test")+"/probe?ok=1",target);std::string error;
        const int delay=probeNode(ss2022TestNode(method),target,5000,"204",error);
        require(fault.empty()?delay>0:delay==0&&!error.empty(),"HTTPS latency probes over SS2022 retain target TLS/hostname/status validation");
        g_testConnector=nullptr;g_testVmessTrust=nullptr;peer.finish();
    }
    stopCore();require(g_state.sockets.empty()&&g_state.connections.empty(),"SS2022 interop leaked sockets or connection metadata");
}
