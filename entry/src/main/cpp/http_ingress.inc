namespace HttpIngress {
bool alive(int client) {
    if(!g_state.running.load())return false;
    std::lock_guard<std::mutex> lock(g_state.sessionsMutex);const auto found=g_state.connections.find(client);
    return found==g_state.connections.end()||!found->second.cancelled;
}
void errorReply(int client,const std::string& status) {
    sendAll(client,"HTTP/1.1 "+status+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}
bool clientHead(int client,std::string& pending,Head& head,std::string& raw,std::string& error) {
    auto started=pending.empty()?HealthClock::time_point{}:HealthClock::now();
    const auto idle=HealthClock::now()+std::chrono::minutes(5);
    while(alive(client)) {
        const auto end=pending.find("\r\n\r\n");
        if(end!=std::string::npos){
            if(end+4>headerLimit){error="431 Request Header Fields Too Large";return false;}
            raw=pending.substr(0,end+4);pending.erase(0,end+4);
            if(!parseHead(raw,head)){error="400 Bad Request";return false;}return true;
        }
        if(pending.size()>=headerLimit){error="431 Request Header Fields Too Large";return false;}
        const auto deadline=started==HealthClock::time_point{}?idle:started+std::chrono::seconds(10);
        const auto remaining=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-HealthClock::now()).count();
        if(remaining<=0){if(!pending.empty())error="408 Request Timeout";return false;}
        pollfd watch{client,POLLIN,0};const int ready=poll(&watch,1,static_cast<int>(remaining));
        if(ready<0&&errno==EINTR)continue;if(ready<=0){if(!pending.empty())error="408 Request Timeout";return false;}
        char bytes[16384];const auto count=recv(client,bytes,sizeof(bytes),MSG_DONTWAIT);
        if(count<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))continue;
        if(count<=0){if(!pending.empty())error="400 Bad Request";return false;}
        if(started==HealthClock::time_point{})started=HealthClock::now();pending.append(bytes,static_cast<size_t>(count));
    }
    return false;
}
bool buffered(const ProxyStream& stream) {
    return (stream.vmess&&stream.vmess->pending())||(stream.trojan&&stream.trojan->pending())||
        (stream.vless&&stream.vless->pending())||(stream.forward&&stream.forward->pending());
}
bool toClient(int client,const std::string& data) {
    if(data.empty())return true;if(!sendAll(client,data))return false;recordTransfer(client,false,data.size());return true;
}
enum class Result {Close,Next,Upgrade,Drain};
Result exchange(int client,ProxyStream& stream,const Request& request,std::string& input) {
    Body upload(request.body,request.head.connection),download;
    Response response;std::string remote,output;bool final=false,finalSent=false,keep=false;
    unsigned interim=0;
    auto fail=[&](const char* status){if(!finalSent)errorReply(client,status);return Result::Close;};
    const char* uploadError=nullptr;HealthClock::time_point responseDeadline{};
    auto stopUpload=[&](const char* error){if(!uploadError){uploadError=error;responseDeadline=HealthClock::now()+std::chrono::seconds(6);shutdown(stream.fd,SHUT_WR);}};
    if(!sendPayload(client,stream,forwarded(request)))stopUpload("502 Bad Gateway");
    while(alive(client)) {
        // A final origin response ends this upload, including an unsent Expect
        // body. Parse it before touching any more client bytes or write errors.
        if(!final)while(true) {
            const auto end=remote.find("\r\n\r\n");
            if(end==std::string::npos){if(remote.size()>headerLimit)return fail("502 Bad Gateway");break;}
            Head head;if(end+4>headerLimit||!parseHead(remote.substr(0,end+4),head)||!HttpIngress::response(head,request,response))return fail("502 Bad Gateway");
            remote.erase(0,end+4);
            if(response.interim){
                if(++interim>16)return fail("502 Bad Gateway");if(!toClient(client,rendered(response,request,false)))return Result::Close;
                continue;
            }
            if(response.upgrade){
                if(uploadError||!upload.done())return fail("502 Bad Gateway");
                if(!toClient(client,rendered(response,request,false))||!toClient(client,remote))return Result::Close;
                const bool sent=sendPayload(client,stream,input);input.clear();return sent?Result::Upgrade:Result::Drain;
            }
            keep=request.persistent&&!request.upgrade&&!uploadError&&upload.done()&&response.body.kind!=BodyKind::Eof;
            if(!toClient(client,rendered(response,request,!keep)))return Result::Close;
            finalSent=final=true;download=Body(response.body,response.head.connection);
            download.dechunk=request.version=="HTTP/1.0"&&response.body.kind==BodyKind::Chunked;break;
        }
        if(final){
            if(!download.consume(remote,output))return Result::Close;
            if(!toClient(client,output))return Result::Close;
            if(download.done())return keep?Result::Next:Result::Close;
        }
        if(!final&&!uploadError&&!upload.done()) {
            if(!upload.consume(input,output))return fail("400 Bad Request");
            if(!sendPayload(client,stream,output))stopUpload("502 Bad Gateway");
        }
        const bool pending=buffered(stream);
        int wait=300000;
        if(uploadError&&!final){const auto remaining=std::chrono::duration_cast<std::chrono::milliseconds>(responseDeadline-HealthClock::now()).count();if(remaining<=0)return fail(uploadError);wait=static_cast<int>(remaining);}
        pollfd watches[2]={{final||uploadError||upload.done()?-1:client,POLLIN,0},{stream.fd,POLLIN,0}};
        const int ready=poll(watches,2,pending?0:wait);
        if(ready<0&&errno==EINTR)continue;if(ready<0||!ready&&!pending)return uploadError&&!final?fail(uploadError):Result::Close;
        if(pending)watches[1].revents|=POLLIN;
        if(watches[1].revents){
            std::vector<unsigned char> bytes;
            if(streamRead(stream,bytes,true))remote.append(reinterpret_cast<const char*>(bytes.data()),bytes.size());
            else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR){
                if(errno==0&&final&&download.framing.kind==BodyKind::Eof)return Result::Close;
                return fail(uploadError?uploadError:"502 Bad Gateway");
            }
        }
        if(watches[0].revents){
            char bytes[16384];const auto count=recv(client,bytes,sizeof(bytes),MSG_DONTWAIT);
            if(count>0)input.append(bytes,static_cast<size_t>(count));
            else if(!count)stopUpload("400 Bad Request");
            else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)return Result::Close;
        }
    }
    return Result::Close;
}
std::string openFailure(const ProxyNode& node) {
    return node.type=="reject"?"403 Forbidden":node.type!="ss"&&node.type!="direct"&&node.type!="vmess"&&node.type!="trojan"&&node.type!="vless"&&node.type!="http"&&node.type!="socks5"?"501 Not Implemented":"502 Bad Gateway";
}
void connect(int client,const Request& request,std::string& prefix) {
    auto plan=sniffPlan(request.host,request.port,clientSourceAddress(client));bool acknowledged=false;
    if(plan.eligible){
        if(!sendAll(client,"HTTP/1.1 200 Connection Established\r\n\r\n"))return;
        acknowledged=true;sniffTcp(client,plan,prefix);
    }
    const auto node=activeProxyNode(plan.route,request.port,"tcp",plan.source,plan.originalIps.empty()?nullptr:&plan.originalIps);
    if(!beginConnection(client,plan.route,request.port,node.chain,node.matchedRule))return;
    ProxyStream stream;std::string error;
    if(!openProxyStream(node,plan.destination,request.port,stream,error)){
        coreLog("error",request.host+":"+std::to_string(request.port)+" via "+node.name+": "+error);
        if(!acknowledged)errorReply(client,openFailure(node));return;
    }
    attachUpstream(client,stream.fd);coreLog("info",request.host+":"+std::to_string(request.port)+" via "+node.name);
    if(acknowledged||sendAll(client,"HTTP/1.1 200 Connection Established\r\n\r\n"))relayStream(client,stream,sendPayload(client,stream,prefix));
}
} // namespace HttpIngress

void handleHttpProxyClient(int client)
{
    // A descriptor has exactly one owner even when an HTTP connection carries
    // several separately routed requests or changes into an upgraded tunnel.
    struct Client {int fd;~Client(){shutdown(fd,SHUT_RDWR);closeSocket(fd);}} owner{client};
    std::string pending;
    while(HttpIngress::alive(client)) {
        InboundConfig policy;std::string source;
        if(!inboundHandshakePolicy(client,policy,source))return;
        HttpIngress::Head head;std::string raw,error;
        if(!HttpIngress::clientHead(client,pending,head,raw,error)){if(!error.empty())HttpIngress::errorReply(client,error);return;}
        HttpIngress::Request request;
        if(!HttpIngress::request(head,request)){HttpIngress::errorReply(client,"400 Bad Request");return;}
        if(!inboundHandshakePolicy(client,policy,source))return;
        if(!inboundHttpAuthenticated(policy,source,raw)){
            sendAll(client,"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"ClashOS\", charset=\"UTF-8\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");return;
        }
        if(!HttpIngress::alive(client))return;
        if(request.tunnel){HttpIngress::connect(client,request,pending);return;}
        auto plan=sniffPlan(request.host,request.port,clientSourceAddress(client));
        if(plan.eligible&&sniffProtocolPort(*plan.config,"HTTP",request.port))sniffApply(plan,"HTTP",sniffHttp(raw));
        // Explicit HTTP sniffing on a literal/forced destination retains the
        // sniffed virtual host; ordinary absolute-form requests use their URI.
        if(plan.protocol=="HTTP")request.host=plan.route;
        const auto node=activeProxyNode(plan.route,request.port,"tcp",plan.source,plan.originalIps.empty()?nullptr:&plan.originalIps);
        if(!beginConnection(client,plan.route,request.port,node.chain,node.matchedRule))return;
        ProxyStream stream;
        if(!openProxyStream(node,plan.destination,request.port,stream,error)){
            coreLog("error",request.host+":"+std::to_string(request.port)+" via "+node.name+": "+error);
            HttpIngress::errorReply(client,HttpIngress::openFailure(node));return;
        }
        attachUpstream(client,stream.fd);coreLog("info",request.host+":"+std::to_string(request.port)+" via "+node.name);
        const auto result=HttpIngress::exchange(client,stream,request,pending);
        if(result==HttpIngress::Result::Upgrade||result==HttpIngress::Result::Drain){relayStream(client,stream,result==HttpIngress::Result::Upgrade);return;}
        if(result==HttpIngress::Result::Close)return;
    }
}
