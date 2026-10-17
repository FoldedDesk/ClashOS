std::string httpTestAll(int fd) {
    std::string result;char bytes[8192];ssize_t count;
    while((count=recv(fd,bytes,sizeof(bytes),0))>0)result.append(bytes,static_cast<size_t>(count));return result;
}
std::string httpTestHead(int fd) {
    std::string result;while(result.find("\r\n\r\n")==std::string::npos&&result.size()<65536)result+=receiveN(fd,1);return result;
}
void httpIngressTests(const std::string& directory)
{
    setupRuntime();
    { std::lock_guard<std::mutex> lock(g_state.mutex); g_state.mode = "Direct"; }
    const char* selected = std::getenv("CLAHSOS_HTTP_CASE");
    const std::string only = selected ? selected : "";
    if(only.empty()||only=="unread-response")for(const std::string framing:{"length","chunked","eof","empty","invalid"}) {
        VmessReferencePeer peer(0,"unread-early",framing,"http_ingress_reference_peer.py");
        ProxyStream stream;stream.fd=peer.take();peer.finish();
        HttpIngress::Head head;HttpIngress::Request request;
        require(HttpIngress::parseHead("POST http://origin.fixture.test/upload HTTP/1.1\r\nHost: origin.fixture.test\r\nContent-Length: 1024\r\n\r\n",head)&&HttpIngress::request(head,request),"Parse the request used by an origin that closes before reading it");
        int client[2];pairFor(client);trackSocket(client[0]);std::string input="unsubmitted-body";
        const auto result=HttpIngress::exchange(client[0],stream,request,input);closeSocket(client[0]);const auto response=httpTestAll(client[1]);close(client[1]);
        const bool valid=framing!="empty"&&framing!="invalid";
        require(result==HttpIngress::Result::Close&&input=="unsubmitted-body","Failed origin writes must close without replaying or consuming unused application bytes");
        const std::string suffix=framing=="chunked"?"8\r\ndenied!!\r\n0\r\n\r\n":"denied!!";
        require(valid?response.find("413 Payload Too Large")!=std::string::npos&&response.size()>=suffix.size()&&response.substr(response.size()-suffix.size())==suffix:
            response.find("502 Bad Gateway")!=std::string::npos&&response.find("private-response")==std::string::npos,"A failed HTTP write must preserve a valid queued origin response and still reject absent or invalid origin responses");
    }
    if(only.empty()||only=="early-final")for(const std::string framing:{"length","chunked","eof"}) {
        const auto marker=directory+"/http-early-final";unlink(marker.c_str());
        VmessReferencePeer peer(0,"early-final",framing+"|"+marker,"http_ingress_reference_peer.py");
        g_testConnector=[&](const std::string&,int,int){return peer.take();};
        int client[2];pairFor(client);dispatchWorker(client[0],0);
        const auto request=std::string("POST http://origin.fixture.test/upload HTTP/1.1\r\nHost: origin.fixture.test\r\nExpect: 100-continue\r\n")+
            (framing=="chunked"?"Transfer-Encoding: chunked\r\n":"Content-Length: 1024\r\n")+"\r\n";
        require(sendAll(client[1],request),"Send an upload that the independent origin rejects before its body");
        const auto head=httpTestHead(client[1]);require(head.find("413 Payload Too Large")!=std::string::npos&&head.find("Connection: close")!=std::string::npos,"Early final response must reach the client before its upload");
        if(framing=="chunked")require(sendAll(client[1],"not-a-chunk\r\n"),"Queue unused upload bytes after an early final response");
        else shutdown(client[1],SHUT_WR);
        {std::ofstream file(marker);file<<"client stopped its rejected upload\n";require(file.good(),"Write the independent response release signal");}
        const auto body=httpTestAll(client[1]);close(client[1]);workersIdle();g_testConnector=nullptr;peer.finish();unlink(marker.c_str());
        require(body==(framing=="chunked"?"8\r\ndenied!!\r\n0\r\n\r\n":"denied!!"),"Stopping a rejected HTTP upload must not truncate the independent origin's later response body");
    }
    if(only.empty()||only=="upload-failure") {
        const auto roots=readTestFile(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/vmess/ca.pem");const auto previousRoots=g_testVmessTrust;g_testVmessTrust=roots.c_str();
        for(const std::string kind:{"direct:tcp","ss:aes-128-gcm","ss:aes-256-gcm","ss:chacha20-ietf-poly1305","vmess:tcp","vmess:tls","vmess:ws","vmess:ws-tls","trojan:tls","trojan:ws-tls","vless:tcp","vless:tls","vless:ws","vless:ws-tls","http:tcp","http:tls","socks5:tcp","socks5:tls"})
        for(const std::string fault:{"valid","closed-upload","corrupt"}) {
            const auto colon=kind.find(':');const auto protocol=kind.substr(0,colon),transport=kind.substr(colon+1);
            if(fault=="corrupt"&&(protocol=="direct"||(protocol=="http"||protocol=="socks5")&&transport=="tcp"))continue;
            std::cerr<<"Upload-failure reply: "<<kind<<" fault="<<fault<<'\n';
            VmessReferencePeer peer(0,kind,fault,"relay_response_reference_peer.py");
            g_testConnector=[&](const std::string&,int,int){return peer.take();};
            ProxyNode node;
            if(protocol=="trojan")node=trojanTestNode(transport);
            else if(protocol=="vmess")node=vmTestNode(0,transport,"auto");
            else if(protocol=="vless")node=vlessTestNode(transport);
            else if(protocol=="http"||protocol=="socks5")node=forwardTestNode(protocol+"-"+transport);
            else {node.name="Queued response fixture";node.type=protocol;node.server="node.invalid";node.port=443;node.cipher=transport;node.password="pässword-测试";}
            ProxyStream stream;std::string error;VmBytes payload(6000);for(size_t i=0;i<payload.size();++i)payload[i]=static_cast<unsigned char>(i*17+3);
            require(openProxyStream(node,"192.0.2.9",443,stream,error),"Open independent queued-response upload-failure fixture");
            int capacity=262144;require(setsockopt(stream.fd,SOL_SOCKET,SO_RCVBUF,&capacity,sizeof(capacity))==0,"Provide capacity for the independent queued binary response");
            require(streamWrite(stream,reinterpret_cast<const char*>(payload.data()),payload.size()),"Send initial application request");
            peer.finish();g_testConnector=nullptr;
            int client[2];pairFor(client);trackSocket(client[0]);require(sendAll(client[1],"late upload"),"Queue client data after upstream closed with an unread response");
            std::thread relay([&]{relayStream(client[0],stream,fault!="closed-upload");closeSocket(client[0]);});
            const auto response=httpTestAll(client[1]);close(client[1]);relay.join();
            std::string expected(50000,'\0');for(size_t i=0;i<expected.size();++i)expected[i]=static_cast<char>(i*23+11);
            require(fault=="corrupt"?response.empty():response==expected,"Upload failure must retain every independently authenticated response chunk and must never release a corrupt response");
        }
        g_testVmessTrust=previousRoots;
    }
    if(only.empty()||only=="closed-response") {
        const auto roots=readTestFile(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/vmess/ca.pem");const auto previousRoots=g_testVmessTrust;g_testVmessTrust=roots.c_str();
        VmessReferencePeer peer(0,"trojan-tls","tcp","hosts_reference_peer.py");
        g_testConnector=[&](const std::string&,int,int){return peer.take();};
        ProxyStream stream;std::string error;VmBytes payload(6000);for(size_t i=0;i<payload.size();++i)payload[i]=static_cast<unsigned char>(i*17+3);
        require(openProxyStream(trojanTestNode("tls"),"192.0.2.9",443,stream,error),"Open independent TLS half-close fixture");
        require(streamWrite(stream,reinterpret_cast<const char*>(payload.data()),payload.size()),"Send complete request before the remote closes");
        // The peer exits only after its authenticated response is in our socket.
        // No receive is performed until the client's FIN is queued as well.
        peer.finish();g_testConnector=nullptr;
        int client[2];pairFor(client);trackSocket(client[0]);shutdown(client[1],SHUT_WR);
        relayStream(client[0],stream);closeSocket(client[0]);const auto response=httpTestAll(client[1]);close(client[1]);
        g_testVmessTrust=previousRoots;
        require(response=="hosts-response","Failure to notify a closed TLS peer about client EOF must not discard its already authenticated pending response");
    }
    if (only.empty() || only == "pipeline") {
        VmessReferencePeer first(1, "pipeline", "", "http_ingress_reference_peer.py");
        VmessReferencePeer second(2, "pipeline", "", "http_ingress_reference_peer.py");
        std::atomic<int> opened{0};
        g_testConnector = [&](const std::string& host, int port, int) {
            require(port == 80, "Pipelined request must retain its actual target port");
            ++opened;
            return host == "origin1.fixture.test" ? first.take() : host == "origin2.fixture.test" ? second.take() : -1;
        };
        int client[2]; pairFor(client); socketTimeout(client[1], 5000);
        const std::string request = "GET http://origin1.fixture.test/1 HTTP/1.1\r\nHost: origin1.fixture.test\r\nProxy-Authorization: Basic cHVibGljOnNlY3JldA==\r\n\r\n"
            "GET http://origin2.fixture.test/2 HTTP/1.1\r\nHost: origin2.fixture.test\r\nProxy-Authorization: Basic cHVibGljOnNlY3JldA==\r\nConnection: close\r\n\r\n";
        require(sendAll(client[1], request), "Cannot queue public pipelined requests"); dispatchWorker(client[0], 0);
        std::string response; char bytes[4096]; ssize_t count;
        while ((count = recv(client[1], bytes, sizeof(bytes), 0)) > 0) response.append(bytes, count);
        close(client[1]); workersIdle(); g_testConnector = nullptr;
        require(opened == 2 && response.find("origin-1") != std::string::npos && response.find("origin-2") != std::string::npos,
            "Pipelined HTTP requests must route separately and retain both complete responses without leaking proxy credentials");
        first.finish(); second.finish();
    }
    if (only.empty() || only == "upgrade") {
        VmessReferencePeer peer(0, "upgrade", "", "http_ingress_reference_peer.py");
        g_testConnector = [&](const std::string& host, int port, int) { require(host == "origin.fixture.test" && port == 80, "Upgrade must retain its routed origin"); return peer.take(); };
        int client[2]; pairFor(client); socketTimeout(client[1], 5000); dispatchWorker(client[0], 0);
        const std::string frame("\x81\x82\x01\x02\x03\x04ik", 8);
        sendAll(client[1], "GET http://origin.fixture.test/socket HTTP/1.1\r\nHost: origin.fixture.test\r\nConnection: keep-alive, Upgrade, X-Hop\r\nUpgrade: websocket\r\nX-Hop: private-hop\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n" + frame);
        const auto response = readUntilHeaders(client[1]);
        require(response.find("101 Switching Protocols") != std::string::npos && lower(response).find("connection: upgrade") != std::string::npos,
            "Plain HTTP ingress must preserve the WebSocket Upgrade handshake");
        auto suffix = response.substr(response.find("\r\n\r\n") + 4);
        while (suffix.size() < 11) suffix += receiveN(client[1], 11 - suffix.size());
        require(suffix == std::string("\x81\x05hello\x88\x02\x03\xe8", 11), "Coalesced WebSocket frames must stay byte-identical in both directions");
        close(client[1]); workersIdle(); g_testConnector = nullptr; peer.finish();
    }
    if(!only.empty())return;
    const std::string body("data\0xyz",8),chunks=std::string("4;ext=\"a,b\"\r\ndata\r\n4\r\n")+body.substr(4)+"\r\n0\r\nX-Trailer: ok\r\n\r\n";
    // Request bodies and a following request arrive with arbitrary TCP splits.
    for(int kind:{0,1})for(size_t split:{size_t(1),size_t(7),size_t(4096)}) {
        VmessReferencePeer first(kind,"body","","http_ingress_reference_peer.py"),second(2,"pipeline","","http_ingress_reference_peer.py");
        std::atomic<int> calls{0};g_testConnector=[&](const std::string& host,int port,int){require(port==80,"Body request port changed");++calls;return host=="origin1.fixture.test"?first.take():host=="origin2.fixture.test"?second.take():-1;};
        int client[2];pairFor(client);socketTimeout(client[1],5000);dispatchWorker(client[0],0);
        const auto wire="POST http://origin1.fixture.test/1 HTTP/1.1\r\nHost: origin1.fixture.test\r\n"+std::string(kind?"Transfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n":"Content-Length: 8, 8\r\n")+"\r\n"+(kind?chunks:body)+
            "GET http://origin2.fixture.test/2 HTTP/1.1\r\nHost: origin2.fixture.test\r\nProxy-Authorization: Basic cHVibGljOnNlY3JldA==\r\nConnection: close\r\n\r\n";
        for(size_t at=0;at<wire.size();at+=split)require(sendAll(client[1],wire.substr(at,split)),"Fragmented request upload failed");
        const auto response=httpTestAll(client[1]);close(client[1]);workersIdle();g_testConnector=nullptr;
        require(calls==2&&response.find("origin-1")!=std::string::npos&&response.find("origin-2")!=std::string::npos,"Body boundary swallowed a following routed request");first.finish();second.finish();
    }
    {
        VmessReferencePeer first(1,"head","","http_ingress_reference_peer.py"),second(2,"pipeline","","http_ingress_reference_peer.py");
        g_testConnector=[&](const std::string& host,int,int){return host=="origin1.fixture.test"?first.take():second.take();};
        int client[2];pairFor(client);socketTimeout(client[1],5000);dispatchWorker(client[0],0);
        sendAll(client[1],"HEAD http://origin1.fixture.test/1 HTTP/1.1\r\nHost: origin1.fixture.test\r\n\r\nGET http://origin2.fixture.test/2 HTTP/1.1\r\nHost: origin2.fixture.test\r\nConnection: close\r\n\r\n");
        require(httpTestHead(client[1]).find("Content-Length: 999")!=std::string::npos,"HEAD metadata length must be retained without reading a body");
        require(httpTestHead(client[1]).find("200 OK")!=std::string::npos&&receiveN(client[1],8)=="origin-2","HEAD response consumed the next response as body");
        close(client[1]);workersIdle();g_testConnector=nullptr;first.finish();second.finish();
    }
    {
        VmessReferencePeer peer(0,"expect","","http_ingress_reference_peer.py");g_testConnector=[&](const std::string&,int,int){return peer.take();};
        int client[2];pairFor(client);socketTimeout(client[1],5000);dispatchWorker(client[0],0);
        sendAll(client[1],"POST http://origin.fixture.test/upload HTTP/1.1\r\nHost: origin.fixture.test\r\nContent-Length: 8\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n");
        require(httpTestHead(client[1]).find("103 Early Hints")!=std::string::npos&&httpTestHead(client[1]).find("100 Continue")!=std::string::npos,"Interim responses must reach the client before its body is available");
        sendAll(client[1],body);const auto response=httpTestAll(client[1]);close(client[1]);workersIdle();g_testConnector=nullptr;
        require(response.find("200 OK")!=std::string::npos&&response.find("uploaded")!=std::string::npos,"Expect upload did not complete after Continue");peer.finish();
    }
    for(const std::string fault:{"chunked","equal-length","bad-length","truncated-length","eof","bad-status","bad-te","bad-upgrade","too-many-interim","bad-chunk","bad-trailer","canonical-host","http10","http10-chunked"}) {
        for(int split:{0,1,6}) {
            VmessReferencePeer peer(split,"response",fault,"http_ingress_reference_peer.py");
            g_testConnector=[&](const std::string& host,int port,int){require(host==(fault=="canonical-host"&&split==6?"2001:db8::1":"origin.fixture.test")&&port==(fault=="canonical-host"?8080:80),"Absolute URI must govern actual host/port routing");return peer.take();};
            int client[2];pairFor(client);socketTimeout(client[1],5000);dispatchWorker(client[0],0);
            const auto target=fault=="canonical-host"?(split==6?"[2001:db8::1]:8080":"origin.fixture.test:8080"):"origin.fixture.test";
            const auto request="GET http://"+std::string(target)+"/verify "+(fault.rfind("http10",0)==0?"HTTP/1.0":"HTTP/1.1")+"\r\nHost: "+(fault=="canonical-host"?"wrong.fixture.test":"origin.fixture.test")+"\r\nAuthorization: Bearer public-origin\r\nConnection: close, X-Hop\r\nX-Hop: private-hop\r\n\r\n";
            sendAll(client[1],request);const auto response=httpTestAll(client[1]);close(client[1]);workersIdle();g_testConnector=nullptr;
            const auto end=response.find("\r\n\r\n");require(end!=std::string::npos,"HTTP origin outcome must include a complete response header");const auto head=response.substr(0,end+4),payload=response.substr(end+4);
            if(fault=="bad-length"||fault=="bad-status"||fault=="bad-te"||fault=="bad-upgrade")require(head.find("502 Bad Gateway")!=std::string::npos&&payload.empty(),"Invalid origin headers must fail before exposing payload");
            else if(fault=="bad-chunk"||fault=="bad-trailer")require(head.find("200 OK")!=std::string::npos&&payload.find("private-response")==std::string::npos&&payload.find("Proxy-Authorization")==std::string::npos&&payload.find("0\r\n\r\n")==std::string::npos,"Invalid body framing/trailers must close without a fake successful termination or protected fields");
            else if(fault=="too-many-interim")require(response.find("502 Bad Gateway")!=std::string::npos,"Unbounded informational replies must fail explicitly");
            else if(fault=="truncated-length")require(head.find("Content-Length: 99")!=std::string::npos&&payload=="short","Truncated response must remain truncated without replay or a second status line");
            else if(fault=="chunked")require(head.find("Content-Length")==std::string::npos&&head.find("X-Hop")==std::string::npos&&payload==chunks,"Chunked response must remove conflicting length/hop fields and preserve binary chunks/trailers");
            else require(payload==body&&(fault!="http10-chunked"||head.find("Transfer-Encoding")==std::string::npos&&head.find("Trailer:")==std::string::npos),"HTTP framed, dechunked or EOF-delimited body changed");
            peer.finish();
        }
    }
    const std::vector<std::string> invalid={
        "Host: a.test\r\nHost: b.test\r\n", "", "Host: bad\thost\r\n", "Host : a.test\r\n", "Host: a.test\r\n Fold: value\r\n",
        "Host: a.test\r\nContent-Length: -1\r\n", "Host: a.test\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n",
        "Host: a.test\r\nContent-Length: 1,2\r\n", "Host: a.test\r\nContent-Length: 18446744073709551616\r\n",
        "Host: a.test\r\nTransfer-Encoding: gzip\r\n", "Host: a.test\r\nTransfer-Encoding: chunked,gzip\r\n", "Host: a.test\r\nTransfer-Encoding: chunked,chunked\r\n",
        "Host: a.test\r\nProxy-Authorization: one\r\nProxy-Authorization: two\r\n", "Host: a.test\r\nConnection: bad token\r\n",
        "Host: a.test\r\nConnection: Upgrade\r\nUpgrade: websocket/\r\n"};
    for(const auto& fields:invalid) {
        std::atomic<int> calls{0};g_testConnector=[&](const std::string&,int,int){++calls;return -1;};
        int client[2];pairFor(client);dispatchWorker(client[0],0);sendAll(client[1],"GET http://origin.fixture.test/ HTTP/1.1\r\n"+fields+"\r\n");
        const auto response=httpTestAll(client[1]);close(client[1]);workersIdle();g_testConnector=nullptr;
        require(calls==0&&response.find("400 Bad Request")!=std::string::npos,"Ambiguous or malformed request headers must reject before dialing");
    }
    for(const auto& tail:std::vector<std::string>{"+4\r\ndata\r\n0\r\n\r\n","4\r\ndataXX","0\r\nProxy-Authorization: public-secret\r\n\r\n","10000000000000000\r\n",std::string(8200,'1')}) {
        VmessReferencePeer peer(0,"invalid-body","","http_ingress_reference_peer.py");g_testConnector=[&](const std::string&,int,int){return peer.take();};
        int client[2];pairFor(client);dispatchWorker(client[0],0);
        sendAll(client[1],"POST http://origin.fixture.test/upload HTTP/1.1\r\nHost: origin.fixture.test\r\nTransfer-Encoding: chunked\r\n\r\n"+tail);shutdown(client[1],SHUT_WR);
        const auto response=httpTestAll(client[1]);close(client[1]);workersIdle();g_testConnector=nullptr;
        require(response.find("400 Bad Request")!=std::string::npos,"Malformed chunk or forbidden authentication trailer must fail explicitly");peer.finish();
    }
    {
        VmessReferencePeer peer(1,"pipeline","","http_ingress_reference_peer.py");std::atomic<int> calls{0};g_testConnector=[&](const std::string&,int,int){++calls;return peer.take();};
        {std::lock_guard<std::mutex> lock(g_state.mutex);g_state.inbound.users={{"public","secret"}};}
        int client[2];pairFor(client);socketTimeout(client[1],5000);dispatchWorker(client[0],0);
        sendAll(client[1],"GET http://origin1.fixture.test/1 HTTP/1.1\r\nHost: origin1.fixture.test\r\nProxy-Authorization: Basic cHVibGljOnNlY3JldA==\r\n\r\nGET http://origin2.fixture.test/2 HTTP/1.1\r\nHost: origin2.fixture.test\r\n\r\n");
        const auto response=httpTestAll(client[1]);close(client[1]);workersIdle();g_testConnector=nullptr;
        require(calls==1&&response.find("origin-1")!=std::string::npos&&response.find("407 Proxy Authentication Required")!=std::string::npos,"Every persistent proxy request must authenticate independently");peer.finish();
        {std::lock_guard<std::mutex> lock(g_state.mutex);g_state.inbound.users.clear();}
    }
    {
        int client[2];pairFor(client);trackSocket(client[0]);
        require(beginConnection(client[0],"old.fixture.test",80,{"DIRECT"},"MATCH"),"Prepare an active reusable HTTP connection");
        const auto id=connectionId("old.fixture.test");require(cancelConnections(id),"Cancel the reusable HTTP connection");
        require(!beginConnection(client[0],"next.fixture.test",80,{"DIRECT"},"MATCH")&&connectionId("old.fixture.test")==id&&connectionId("next.fixture.test").empty(),"A queued request cannot resurrect a canceled client descriptor or replace its cancellation metadata");
        closeSocket(client[0]);close(client[1]);
    }
    forwardingTests();
}
