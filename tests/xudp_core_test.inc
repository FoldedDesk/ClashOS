namespace xudp_tests {
struct Peer {
    std::deque<VmBytes> incoming;
    VmBytes outgoing;
    bool eof = false, failWrite = false;
    size_t writes = 0;
    std::unique_ptr<XudpSession> session;
    Peer(const std::string& host,int port,VmBytes id = {}) {
        session=std::make_unique<XudpSession>(host,port,"original.example",std::move(id),
            [this](const unsigned char* data,size_t length){++writes;if(failWrite){errno=ECONNRESET;return false;}outgoing.insert(outgoing.end(),data,data+length);return true;},
            [this](VmBytes& output,bool){if(incoming.empty()){errno=eof?0:EAGAIN;return false;}output=std::move(incoming.front());incoming.pop_front();return true;},
            [this](){return !incoming.empty();});
    }
};
void wireVectors() {
    std::ifstream source(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/xudp-wire.json");
    std::string text((std::istreambuf_iterator<char>(source)),{}),error;EditorYaml fixture;
    require(fixture.parse(text,65536,error),"Read independent Python XUDP vectors");
    auto* root=yaml_document_get_root_node(&fixture.document);
    require(root&&root->type==YAML_SEQUENCE_NODE,"XUDP vectors must be an array");
    for(auto* item=root->data.sequence.items.start;item<root->data.sequence.items.top;++item) {
        auto* entry=yaml_document_get_node(&fixture.document,*item);
        auto get=[&](const char* key){return yamlText(yamlValue(fixture.document,entry,key));};
        const auto payload=hex(get("payload")),response=hex(get("response"));const int port=std::stoi(get("port"));
        Peer writer(get("host"),port,hex(get("identity")));
        require(writer.session->writeDatagram(payload)&&writer.outgoing==hex(get("new")),"Initial XUDP frame matches independent address/global-ID vector");
        writer.outgoing.clear();require(writer.session->writeDatagram(payload)&&writer.outgoing==hex(get("keep")),"Following XUDP frame uses Keep and excludes initial global identity");
        for(size_t split=0;split<=response.size();++split) {
            Peer receiver(get("host"),port);VmBytes output{9};
            if(split)receiver.incoming.emplace_back(response.begin(),response.begin()+split);
            const bool ready=receiver.session->readDatagram(output,true);
            if(split<response.size()) {
                require(!ready&&errno==EAGAIN&&output.empty(),"Every partial XUDP frame yields without exposing a prefix");
                receiver.incoming.emplace_back(response.begin()+split,response.end());
                require(receiver.session->pending()&&receiver.session->readDatagram(output,true),"Fragmented XUDP record resumes after more authenticated stream data");
            } else require(ready,"Complete XUDP frame returns immediately");
            VmBytes expected=hex(get("source"));vmAppend(expected,payload);
            require(output==expected,"Actual IPv4/IPv6/domain reply source and binary payload are preserved");
        }
        for(size_t split=0;split<response.size();++split) {
            Peer receiver(get("host"),port);receiver.eof=true;VmBytes output;
            if(split)receiver.incoming.emplace_back(response.begin(),response.begin()+split);
            require(!receiver.session->readDatagram(output)&&output.empty()&&errno==(split?EPROTO:0),"EOF at every frame position distinguishes clean end from truncated metadata/payload");
        }
        Peer implicit(get("host"),port);implicit.incoming.push_back(hex(get("implicit")));VmBytes output;
        require(implicit.session->readDatagram(output,true),"Address-free Keep frame is supported");
        VmBytes expected=hex(get("fallback"));vmAppend(expected,payload);require(output==expected,"Missing reply source preserves the original pre-hosts destination");
        Peer controls(get("host"),port);VmBytes stream;
        for(int i=0;i<64;++i)vmAppend(stream,hex("000400000400"));vmAppend(stream,response);vmAppend(stream,response);controls.incoming.push_back(stream);
        for(int i=0;i<2;++i)require(!controls.session->readDatagram(output,true)&&errno==EAGAIN&&controls.session->pending(),"Control-only bursts yield after a bounded batch and retain pending bytes");
        require(controls.session->readDatagram(output,true)&&controls.session->pending(),"Coalesced packet remains pending after controls");
        require(controls.session->readDatagram(output,true),"Second coalesced packet is not lost");
        const size_t metadata=(response[0]<<8)|response[1],prefix=metadata+4;
        VmBytes empty(response.begin(),response.begin()+prefix);empty[prefix-2]=0;empty[prefix-1]=0;
        Peer zero(get("host"),port);zero.incoming.push_back(empty);
        require(zero.session->readDatagram(output,true)&&output==hex(get("source")),"Zero-length UDP payload is delivered as a packet, never TCP EOF");
        VmBytes large(response.begin(),response.begin()+prefix);large[prefix-2]=XudpSession::MaxPayload>>8;large[prefix-1]=XudpSession::MaxPayload&255;
        large.insert(large.end(),XudpSession::MaxPayload,0xa5);Peer maximum(get("host"),port);
        for(size_t start=0;start<large.size();start+=1337)maximum.incoming.emplace_back(large.begin()+start,large.begin()+std::min(large.size(),start+1337));
        require(maximum.session->readDatagram(output,true)&&output.size()==hex(get("source")).size()+XudpSession::MaxPayload&&output.back()==0xa5,"Maximum physical UDP payload survives many carrier fragments");
        const auto before=writer.outgoing;require(!writer.session->writeDatagram(VmBytes(XudpSession::MaxPayload+1))&&errno==EMSGSIZE&&writer.outgoing==before,"Oversize writes send no frame or state transition");
        require(writer.session->writeDatagram({}),"Empty outbound datagram has a nonempty XUDP frame");
    }
}
void rejectionAndConfiguration() {
    const auto valid=hex("000c000002010214b401c6336404000400017fff");
    for(const auto& bad:std::vector<VmBytes>{hex("0003"),hex("1001"),hex("000400010201"),hex("000400000101"),hex("000400000204"),hex("00050000020101"),hex("00080000020102000001")}) {
        Peer peer("192.0.2.1",53);peer.incoming.push_back(bad);peer.eof=true;VmBytes output;
        require(!peer.session->readDatagram(output,true)&&errno==EPROTO&&output.empty(),"Malformed length/session/status/options/address is rejected without payload");
        peer.incoming.push_back(valid);require(!peer.session->readDatagram(output,true)&&errno==EPROTO&&output.empty(),"A malformed session cannot resume and expose a later packet");
    }
    for(const auto& frame:std::vector<VmBytes>{hex("000400000300"),hex("000400000202")}) {
        Peer peer("192.0.2.1",53);peer.incoming.push_back(frame);VmBytes output;
        require(!peer.session->readDatagram(output,true)&&output.empty()&&errno==(frame[4]==3?0:ECONNRESET),"Remote End and remote error remain distinct");
        require(!peer.session->pending(),"Terminated sessions cannot spin on buffered controls");
    }
    Peer failed("192.0.2.1",53);failed.failWrite=true;
    require(!failed.session->writeDatagram({1,2})&&errno==ECONNRESET,"Wire write failure is preserved");
    require(!failed.session->writeDatagram({1,2})&&failed.writes==1,"A partly failed XUDP frame is never replayed");
    const std::string uuid="11111111-2222-4333-8444-555555555555";
    require(VlessSession::header(uuid,"",0,true,true)==hex("00111111112222433384445555555555550003"),"VLESS Mux handshake omits the legacy UDP destination");
    for(const std::string protocol:{"vless","vmess"}) {
        ParsedConfig config;std::string error;
        const std::string base="proxies: [{name: public, type: "+protocol+", server: public.invalid, port: 443, uuid: "+uuid+", udp: true, ";
        require(parseConfigText(base+"packet-encoding: xudp}]",config,error)&&config.nodes[0].packetEncoding=="xudp"&&config.nodes[0].transportError.empty(),"Standard XUDP configuration is available for TCP and UDP");
        auto previous=config.nodes[0];previous.packetEncoding.clear();require(!sameProviderNodes({previous},config.nodes),"Provider changes limited to UDP encoding replace the live route");
        require(parseConfigText(base+"xudp: true}]",config,error)&&config.nodes[0].packetEncoding=="xudp","Legacy XUDP boolean is normalized");
        require(parseConfigText(base+"packet-encoding: packetaddr}]",config,error)&&!config.nodes[0].transportError.empty(),"Unimplemented packet encodings cannot silently use legacy UDP");
        require(!parseConfigText(base+"xudp: 1}]",config,error),"Non-boolean legacy encoding switches fail validation");
    }
}
ProxyNode node(int scenario,const std::string& transport) {
    ProxyNode result=scenario==0?vlessTestNode(transport):vmTestNode(scenario==5?64:0,transport,scenario==2?"chacha20-poly1305":scenario==3?"none":scenario==4?"zero":"aes-128-gcm");
    result.udp=true;result.udpConfigured=true;result.packetEncoding="xudp";result.wsPath="/xudp?test=1";return result;
}
void route(const ProxyNode& value) {
    std::lock_guard<std::mutex> lock(g_state.mutex);g_state.nodes={value};g_state.groups.clear();g_state.mode="Rule";g_state.rules={{"match","",value.name}};
}
void reply(UdpHarness& harness,const std::string& host,int port,const std::string& body) {
    const auto packet=receiveTestDatagram(harness.relay);UdpTarget source;
    require(parseSocksUdp(packet,source)&&source.host==host&&source.port==port,"XUDP SOCKS reply must retain the server-reported source, not substitute the original destination");
    require(text({packet.begin()+3+source.headerSize,packet.end()})==body,"XUDP response body and datagram boundaries changed");
}
void independentStreams(const std::string& directory) {
    const auto roots=readTestFile(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/vmess/ca.pem");g_testVmessTrust=roots.c_str();g_state.running.store(true);
    struct Reset {~Reset(){g_testConnector=nullptr;g_testVmessTrust=nullptr;}} reset;
    for(const std::string transport:{"tcp","tls","ws","ws-tls"}) {
        // The UDP option must not turn ordinary TCP requests into Mux requests.
        for(int scenario:{0,1})for(int inbound:{0,1}) {
            VmessReferencePeer peer(0,transport,"",scenario==0?"vless_reference_peer.py":"vmess_reference_peer.py");
            auto value=node(scenario,transport);value.wsPath=scenario==0?"/vless?test=1":"/vmess?test=1";route(value);
            g_testConnector=[&](const std::string&,int,int){return peer.take();};
            VmBytes body(scenario==0?50000:6000);for(size_t i=0;i<body.size();++i)body[i]=static_cast<unsigned char>(i*17+3);
            VmBytes expected=vmBytes(scenario==0?"vless-response:":"vmess-response:");expected.insert(expected.end(),body.rbegin(),body.rend());
            const auto up=g_state.uploadTotal.load(),down=g_state.downloadTotal.load();int client[2];pairFor(client);dispatchWorker(client[0],inbound);
            if(inbound==0){sendAll(client[1],"CONNECT target.test:443 HTTP/1.1\r\nHost: target.test\r\n\r\n");require(readUntilHeaders(client[1]).find("200 Connection Established")!=std::string::npos,"XUDP-enabled nodes must accept ordinary HTTP CONNECT");}
            else {VmBytes request{5,1,0,5,1,0};vmAppend(request,shadowsocksAddress("target.test",443));sendAll(client[1],request);require(receiveN(client[1],2)==std::string("\5\0",2)&&receiveN(client[1],10)[1]==0,"XUDP-enabled nodes must accept ordinary SOCKS TCP CONNECT");}
            require(sendAll(client[1],body),"Send real TCP payload through XUDP-configured node");shutdown(client[1],SHUT_WR);
            require(receiveN(client[1],expected.size())==text(expected),"UDP packet encoding must preserve ordinary TCP stream framing");
            char byte;require(recv(client[1],&byte,1,0)==0,"Ordinary TCP EOF remains independent of XUDP configuration");close(client[1]);workersIdle();
            require(g_state.uploadTotal.load()-up==body.size()&&g_state.downloadTotal.load()-down==expected.size(),"Ordinary TCP accounting is unchanged by UDP packet encoding");
            g_testConnector=nullptr;peer.finish();
        }
        for(int scenario=0;scenario<=5;++scenario) {
            std::cerr<<"XUDP independent peer: scenario="<<scenario<<" transport="<<transport<<'\n';
            VmessReferencePeer peer(scenario,transport,"udp","xudp_reference_peer.py");
            g_testConnector=[&](const std::string&,int,int){return peer.take();};route(node(scenario,transport));
            const auto up=g_state.uploadTotal.load(),down=g_state.downloadTotal.load();
            uint64_t total=0;
            {
                UdpHarness harness;
                for(int index=0;index<5;++index) {
                    std::string body=index==0?"packet-0":index==3?std::string(8192,'P'):std::string(index==1?0:index==2?1400:65485,'\0');
                    if(index==2)for(size_t i=0;i<body.size();++i)body[i]=static_cast<char>(i*17+3);
                    if(index==4)for(size_t i=0;i<body.size();++i)body[i]=static_cast<char>(i);
                    total+=body.size();harness.inject(udpTestPacket("target.test",443,body));
                    const std::string source=index==0?"192.0.2.80":index==1?"reply.test":index==3?"target.test":"2001:db8::9";
                    reply(harness,source,index==3?443:5400+index,std::string(body.rbegin(),body.rend()));
                }
                awaitCondition([&]{return g_state.uploadTotal.load()-up==total&&g_state.downloadTotal.load()-down==total;},"XUDP counters must exclude mux, address, crypto and keepalive framing");
            }
            g_testConnector=nullptr;peer.finish();require(g_state.connections.empty(),"Closing the SOCKS association releases all XUDP sessions");
        }
        for(int scenario:{0,1,4}) {
            const std::string marker=directory+"/xudp-duplex-ready";unlink(marker.c_str());
            VmessReferencePeer peer(scenario,transport,"duplex|"+marker,"xudp_reference_peer.py");
            g_testConnector=[&](const std::string&,int,int){return peer.take();};route(node(scenario,transport));
            {
                UdpHarness harness;harness.inject(udpTestPacket("target.test",443,"packet-0"));
                awaitCondition([&]{return access(marker.c_str(),F_OK)==0;},"Peer must publish its partial XUDP response before next client upload");
                harness.inject(udpTestPacket("target.test",443,std::string(8192,'P')));
                reply(harness,"192.0.2.80",5400,"packet-0");reply(harness,"2001:db8::9",5401,std::string(8192,'P'));
            }
            g_testConnector=nullptr;peer.finish();unlink(marker.c_str());
        }
        for(int scenario:{0,1})for(const std::string fault:{"bad-session","bad-network"}) {
            VmessReferencePeer peer(scenario,transport,fault,"xudp_reference_peer.py");
            g_testConnector=[&](const std::string&,int,int){return peer.take();};route(node(scenario,transport));const auto down=g_state.downloadTotal.load();
            {
                UdpHarness harness;harness.inject(udpTestPacket("target.test",443,"packet-0"));peer.finish();
                pollfd watch{harness.relay,POLLIN,0};require(poll(&watch,1,100)==0&&g_state.downloadTotal.load()==down,"Invalid mux session/network must release no SOCKS UDP data or account unauthenticated bytes");
            }
            g_testConnector=nullptr;
        }
    }
    for(const std::string transport:{"tcp","tls"})for(int scenario:{1,2,5}) {
        VmessReferencePeer peer(scenario,transport,"tag","xudp_reference_peer.py");
        g_testConnector=[&](const std::string&,int,int){return peer.take();};route(node(scenario,transport));const auto down=g_state.downloadTotal.load();
        {
            UdpHarness harness;harness.inject(udpTestPacket("target.test",443,"packet-0"));peer.finish();pollfd watch{harness.relay,POLLIN,0};
            require(poll(&watch,1,100)==0&&g_state.downloadTotal.load()==down,"VMess authentication remains mandatory before XUDP decoding");
        }
        g_testConnector=nullptr;
    }
    for(const std::string transport:{"tls","ws-tls"})for(int scenario:{0,1})for(const std::string fault:{"tls-reject-ca","tls-reject-host"}) {
        VmessReferencePeer peer(scenario,transport,fault,"xudp_reference_peer.py");
        auto value=node(scenario,transport);if(fault=="tls-reject-host")value.serverName="wrong.test";
        g_testVmessTrust=fault=="tls-reject-ca"?nullptr:roots.c_str();route(value);
        g_testConnector=[&](const std::string&,int,int){return peer.take();};const auto up=g_state.uploadTotal.load(),down=g_state.downloadTotal.load();
        {
            UdpHarness harness;harness.inject(udpTestPacket("target.test",443,"packet-0"));peer.finish();pollfd watch{harness.relay,POLLIN,0};
            require(poll(&watch,1,100)==0&&g_state.uploadTotal.load()==up&&g_state.downloadTotal.load()==down,"XUDP cannot bypass the configured proxy TLS trust/hostname policy");
        }
        g_testConnector=nullptr;
    }
    g_testVmessTrust=roots.c_str();
    std::vector<std::string> identities;
    for(int association=0;association<2;++association) {
        VmessReferencePeer first(0,"tcp","record|"+directory+"/xudp-id-a","xudp_reference_peer.py");
        VmessReferencePeer second(0,"tcp","record|"+directory+"/xudp-id-b","xudp_reference_peer.py");int connection=0;
        g_testConnector=[&](const std::string&,int,int){return connection++==0?first.take():second.take();};route(node(0,"tcp"));
        {
            UdpHarness harness;harness.inject(udpTestPacket("target.test",443,"identity-probe"));reply(harness,"target.test",443,"identity-probe");
            harness.inject(udpTestPacket("second.test",443,"identity-probe"));reply(harness,"second.test",443,"identity-probe");
        }
        g_testConnector=nullptr;first.finish();second.finish();
        const auto a=readTestFile(directory+"/xudp-id-a"),b=readTestFile(directory+"/xudp-id-b");
        require(a==b,"One client UDP association retains its XUDP identity across destination flows");identities.push_back(a);
    }
    require(identities[0]!=identities[1],"Unrelated client UDP associations cannot share a remote XUDP identity");
}
} // namespace xudp_tests
void xudpTests(const std::string& directory) {
    xudp_tests::wireVectors();xudp_tests::rejectionAndConfiguration();xudp_tests::independentStreams(directory);
}
