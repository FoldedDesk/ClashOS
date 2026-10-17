#include "ss_aead_vectors.h"

void ssAeadTests()
{
    require(shadowsocksCryptoSelfTest(),"Device SS AEAD self-test must validate all shipping cipher engines");
    const std::string password="pässword-测试";
    for(const auto& vector:SS_AEAD_VECTORS) {
        const SsCipher method=shadowsocksCipher(vector.method);const size_t size=shadowsocksKeySize(method);
        const auto master=evpBytesToKey(password,size),salt=hex(vector.salt),key=hex(vector.key);
        require(master==hex(vector.master)&&hkdfSha1(salt,master,"ss-subkey",size)==key,"SS per-cipher password/HKDF derivation differs from independent reference");
        int pair[2];pairFor(pair);std::vector<unsigned char> nonce(12),plain;
        require(shadowsocksSendChunk(pair[0],key,nonce,vmBytes("hello world"),method)&&
            shadowsocksSendChunk(pair[0],key,nonce,vmBytes("next frame"),method),"SS per-cipher frame writes failed");
        require(receiveN(pair[1],hex(vector.client).size())==text(hex(vector.client))&&nonce[0]==4,"SS TCP bytes or little-endian nonce progression differs from independent vectors");
        close(pair[0]);close(pair[1]);
        pairFor(pair);const auto packet=hex(vector.server);
        std::thread peer([&]{for(unsigned char byte:packet)if(!sendAll(pair[1],reinterpret_cast<const char*>(&byte),1))break;shutdown(pair[1],SHUT_WR);});
        bool received=false;std::vector<unsigned char> receiveKey;nonce.assign(12,0);
        const bool first=shadowsocksReceive(pair[0],master,received,receiveKey,nonce,plain,method)&&text(plain)=="HTTP/1.1 204 No Content\r\n\r\n";
        const bool second=shadowsocksReceive(pair[0],master,received,receiveKey,nonce,plain,method)&&text(plain)=="server data";
        peer.join();close(pair[0]);close(pair[1]);
        require(first&&second&&received&&receiveKey==hex(vector.remoteKey)&&nonce[0]==4,"SS server salt, fragmented reads or second-chunk nonce differs from reference");
        for(size_t corruptAt:{size_t(5),size_t(20)}) {
            pairFor(pair);auto corrupt=hex(vector.client);corrupt[corruptAt]^=1;
            sendAll(pair[1],corrupt);shutdown(pair[1],SHUT_WR);nonce.assign(12,0);plain={1,2,3};
            require(!shadowsocksReadChunk(pair[0],key,nonce,plain,method)&&plain.empty()&&errno==EBADMSG,"SS must reject length or payload authentication failures without releasing stale plaintext");
            close(pair[0]);close(pair[1]);
        }
        pairFor(pair);sendAll(pair[1],hex(vector.reservedLength));shutdown(pair[1],SHUT_WR);nonce.assign(12,0);plain={1};
        require(!shadowsocksReadChunk(pair[0],key,nonce,plain,method)&&plain.empty()&&errno==EPROTO,"SS authenticated length must still reject reserved high bits");
        close(pair[0]);close(pair[1]);
        nonce.assign(12,0xff);errno=0;
        require(!shadowsocksSendChunk(-1,key,nonce,vmBytes("x"),method)&&errno==EOVERFLOW,"SS sender must refuse nonce counter wrap");
        plain={1};require(!shadowsocksReadChunk(-1,key,nonce,plain,method)&&plain.empty()&&errno==EOVERFLOW,"SS receiver must refuse nonce counter wrap");
        std::vector<unsigned char> wire;
        require(encryptShadowsocksUdp(master,salt,hex(vector.udpPlain),wire,method)&&wire==hex(vector.udpPacket),"SS UDP bytes differ from independent AEAD vector");
        require(decryptShadowsocksUdp(master,wire,plain,method)&&plain==hex(vector.udpPlain),"SS UDP reference decrypt failed");
        auto corrupt=wire;corrupt.back()^=1;plain={1};
        require(!decryptShadowsocksUdp(master,corrupt,plain,method)&&plain.empty(),"SS UDP authentication failure released data");
        require(decryptShadowsocksUdp(master,hex(vector.emptyPacket),plain,method)&&plain==hex(vector.emptyPlain),"SS must accept an empty UDP payload addressed to a one-character domain");
        require(encryptShadowsocksUdp(master,salt,hex(vector.emptyPlain),wire,method)&&wire==hex(vector.emptyPacket),"SS empty UDP reference encode failed");
        const std::vector<unsigned char> maximum(UDP_MAX_PACKET-size-16,1);
        require(encryptShadowsocksUdp(master,salt,maximum,wire,method)&&wire.size()==UDP_MAX_PACKET&&decryptShadowsocksUdp(master,wire,plain,method)&&plain==maximum,"SS maximum UDP size must account for the selected salt length");
        require(!encryptShadowsocksUdp(master,salt,std::vector<unsigned char>(maximum.size()+1,1),wire,method)&&wire.empty(),"SS over-limit UDP packet must be rejected before network output");
        require(!encryptShadowsocksUdp(master,std::vector<unsigned char>(size-1),hex(vector.udpPlain),wire,method),"SS must reject a salt with the wrong cipher-specific length");
        bool rejected=true;
        const auto good=hex(vector.udpPacket);
        for(size_t n=0;n<size+16+5;++n){plain={1};rejected=rejected&&!decryptShadowsocksUdp(master,{good.begin(),good.begin()+n},plain,method)&&plain.empty();}
        require(rejected,"SS truncated UDP salt/header/tag must not release plaintext");
        ProxyNode node;node.type="ss";node.cipher=vector.method;node.udp=true;
        require(supportsUdp(node),"All implemented SS AEAD methods must expose actual UDP capability");
    }
    const auto master=evpBytesToKey(password,32);const auto salt=hex(SS_AEAD_VECTORS[1].salt);
    require(rememberUdpSalt(master,salt,SsCipher::Aes256Gcm)&&rememberUdpSalt(master,salt,SsCipher::ChaCha20Poly1305),"Replay cache must distinguish independently keyed cipher methods");
    require(!rememberUdpSalt(master,salt,SsCipher::Aes256Gcm),"A duplicate salt within the same method must still be rejected");
    require(shadowsocksCipher("chacha20-poly1305")==SsCipher::ChaCha20Poly1305&&shadowsocksCipher("aead_aes_128_gcm")==SsCipher::Aes128Gcm,"SS documented cipher aliases must resolve to the same engine");
    g_state.running.store(true);
    VmBytes payload(50000);for(size_t i=0;i<payload.size();++i)payload[i]=static_cast<unsigned char>(i*17+3);
    VmBytes expected=vmBytes("ss-response:");expected.insert(expected.end(),payload.rbegin(),payload.rend());
    for(const auto& vector:SS_AEAD_VECTORS) {
        ProxyNode node;node.name=vector.method;node.type="ss";node.cipher=vector.method;node.password=password;node.server="ss-interop.test";node.port=443;node.udp=true;
        {std::lock_guard<std::mutex> lock(g_state.mutex);g_state.mode="Rule";g_state.nodes={node};ProxyGroup group;group.name="SS interop";group.now=node.name;group.proxies={node.name};g_state.groups={group};g_state.rules={{"match","",group.name}};}
        for(int protocol:{0,1}) {
            VmessReferencePeer peer(0,vector.method,"tcp","ss_reference_peer.py");std::atomic<bool> correct{true};
            g_testConnector=[&](const std::string& host,int port,int){correct.store(host==node.server&&port==node.port);return peer.take();};
            const uint64_t up=g_state.uploadTotal.load(),down=g_state.downloadTotal.load();
            int client[2];pairFor(client);dispatchWorker(client[0],protocol);
            if(protocol==0){sendAll(client[1],"CONNECT target.test:443 HTTP/1.1\r\nHost: target.test\r\n\r\n");require(readUntilHeaders(client[1]).find("200 Connection Established")!=std::string::npos,"New SS method HTTP CONNECT failed");}
            else {VmBytes greeting{5,1,0,5,1,0};vmAppend(greeting,shadowsocksAddress("target.test",443));sendAll(client[1],greeting);require(receiveN(client[1],2)==std::string("\5\0",2)&&receiveN(client[1],10)[1]==0,"New SS method SOCKS5 CONNECT failed");}
            const std::string snapshot=connectionsJson();require(snapshot.find(node.name)!=std::string::npos&&snapshot.find("SS interop")!=std::string::npos,"SS connection must retain real method/node and group metadata");
            sendAll(client[1],payload);shutdown(client[1],SHUT_WR);
            require(receiveN(client[1],expected.size())==text(expected),"Independent SS server response after client half-close or multi-chunk relay was corrupted");
            char byte;require(recv(client[1],&byte,1,0)==0,"SS remote EOF must finish the application stream");
            close(client[1]);workersIdle();g_testConnector=nullptr;peer.finish();
            require(correct&&g_state.uploadTotal.load()-up==payload.size()&&g_state.downloadTotal.load()-down==expected.size(),"SS relay endpoint or plaintext accounting is incorrect");
        }
        for(const std::string fault:{"tcp-length-tag","tcp-payload-tag","tcp-short-salt"}) {
            VmessReferencePeer peer(0,vector.method,fault,"ss_reference_peer.py");g_testConnector=[&](const std::string&,int,int){return peer.take();};
            {
            ProxyStream stream;std::string error;require(openProxyStream(node,"target.test",443,stream,error),"SS fault fixture outbound failed to open");
            require(streamWrite(stream,reinterpret_cast<const char*>(payload.data()),payload.size()),"SS fault fixture payload failed to write");shutdown(stream.fd,SHUT_WR);
            VmBytes plain{1};require(!streamRead(stream,plain)&&plain.empty()&&errno!=0,"SS reference server authentication/truncated salt must fail without returning data");
            }
            g_testConnector=nullptr;peer.finish();
        }
        {
            VmessReferencePeer peer(0,vector.method,"udp","ss_reference_peer.py",true);
            UdpHarness harness;
            {std::lock_guard<std::mutex> lock(harness.mutex);harness.pending[node.server+":"+std::to_string(node.port)].push_back({peer.take(),udpTestEndpoint("192.0.2.10",node.port)});}
            const size_t maximum=UDP_MAX_PACKET-shadowsocksKeySize(shadowsocksCipher(vector.method))-16-shadowsocksAddress("target.test",443).size();
            for(int round=0;round<3;++round) {
                std::string body=round==0?"packet-0":"";
                if(round==2){body.resize(maximum);for(size_t i=0;i<body.size();++i)body[i]=static_cast<char>(i);}
                const std::string response=round==2?"max-accepted":std::string("udp-response:")+std::string(body.rbegin(),body.rend());
                harness.inject(udpTestPacket("target.test",443,body));
                const auto wire=receiveTestDatagram(harness.relay);UdpTarget source;
                require(parseSocksUdp(wire,source)&&source.host=="8.8.8.8"&&text({wire.begin()+3+source.headerSize,wire.end()})==response,"Independent SS UDP echo, empty payload, max datagram, reflection/authentication/replay filtering failed");
            }
            peer.finish();
        }
        require(g_state.connections.empty(),"SS UDP association must clean up all connection records");
    }
    const std::string roots=readTestFile(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/vmess/ca.pem");g_testVmessTrust=roots.c_str();
    for(const std::string kind:{"ss-aes128","ss-chacha"}) {
        VmessReferencePeer peer(0,kind,"","https_reference_peer.py");g_testConnector=[&](const std::string&,int,int){return peer.take();};
        ProxyNode node;node.type="ss";node.cipher=kind=="ss-aes128"?"aes-128-gcm":"chacha20-ietf-poly1305";node.server="ss.test";node.port=443;node.password="probe-password";
        TestTarget target;parseTestUrl("https://vmess.test/probe?ok=1",target);std::string error;
        require(probeNode(node,target,5000,"204",error)>0,"Verified HTTPS probe must work through each newly implemented SS cipher");
        g_testConnector=nullptr;peer.finish();
    }
    std::atomic<bool> dialed{false};g_testConnector=[&](const std::string&,int,int){dialed.store(true);return -1;};
    ProxyNode unsupported;unsupported.type="ss";unsupported.cipher="unsupported";unsupported.server="invalid";unsupported.port=443;unsupported.udp=true;
    ProxyStream rejected;std::string error;
    require(!openProxyStream(unsupported,"target.test",443,rejected,error)&&!supportsUdp(unsupported)&&!dialed&&!error.empty(),"Unsupported SS methods must fail explicitly before dialing and must never use DIRECT");
    g_testConnector=nullptr;g_testVmessTrust=nullptr;stopCore();
    require(g_state.sockets.empty()&&g_state.connections.empty(),"SS interoperability tests leaked tracked descriptors or connections");
}
