// A datagram carrier reuses the real UDP implementations without exposing their
// internal sessions or counting encapsulated bytes as application traffic.
struct DialerDatagramBridge {
    DialerWorkerSlot slot;
    std::unique_ptr<UdpFlow> upstream;
    UdpTarget target;
    int peer=-1,client=-1;
    bool preserveSource=false,internalOwner=true,ready=false;
    std::string ownerId;
    std::thread worker;
    std::mutex startMutex;
    std::condition_variable startWake;
    std::atomic<bool> stopping{false},done{false};
    std::atomic<size_t> pending{0};
    bool cancelled() {
        if(stopping.load())return true;
        if(internalOwner)return false;
        std::lock_guard<std::mutex> lock(g_state.sessionsMutex);
        const auto found=g_state.connections.find(client);
        return found==g_state.connections.end()||found->second.id!=ownerId||found->second.cancelled;
    }
    void run() {
        {std::unique_lock<std::mutex> lock(startMutex);startWake.wait(lock,[&](){return ready||stopping.load();});}
        while(g_state.running.load()&&!cancelled()) {
            const bool buffered=upstream->streamed()&&upstream->streamPending();
            pollfd watches[2]={{peer,POLLIN,0},{upstream->streamed()?upstream->notifyMain:upstream->fd,POLLIN,0}};
            const int count=poll(watches,2,buffered?0:500);
            if(count<0){if(errno==EINTR)continue;break;}
            if(cancelled())break;
            if(watches[0].revents&(POLLHUP|POLLERR|POLLNVAL))break;
            bool ok=true;
            if(watches[0].revents)for(int burst=0;burst<16;++burst) {
                VmBytes payload(65536);iovec buffer{payload.data(),payload.size()};msghdr message{};message.msg_iov=&buffer;message.msg_iovlen=1;
                const auto received=recvmsg(peer,&message,MSG_DONTWAIT);
                if(received<0){if(errno==EINTR)continue;if(errno!=EAGAIN&&errno!=EWOULDBLOCK)ok=false;break;}
                if((message.msg_flags&MSG_TRUNC)||static_cast<size_t>(received)>UDP_MAX_PACKET)continue;
                payload.resize(static_cast<size_t>(received));
                VmBytes packet(3,0);vmAppend(packet,shadowsocksAddress(target.host,target.port));vmAppend(packet,payload);
                if(cancelled()){ok=false;break;}
                if(!writeUdpFlow(*upstream,packet,target)){ok=false;break;}
            }
            if(!ok)break;
            if((watches[1].revents&(POLLHUP|POLLNVAL))&&!buffered)break;
            if(buffered||watches[1].revents)for(int burst=0;burst<16;++burst) {
                VmBytes reply;size_t ignored=0;
                if(!readUdpFlow(*upstream,reply,ignored)) {
                    if(upstream->failed||(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR&&errno!=EBADMSG&&errno!=EALREADY&&errno!=EMSGSIZE&&errno!=EPROTO))ok=false;
                    break;
                }
                UdpTarget source;
                if(reply.size()<4||reply[0]||reply[1]||reply[2]||!parseUdpAddress(reply,3,source))continue;
                VmBytes packet=preserveSource?std::move(reply):VmBytes(reply.begin()+3+source.headerSize,reply.end());
                if(packet.size()>(preserveSource&&internalOwner?UDP_MAX_ENVELOPE:UDP_MAX_PACKET)||cancelled())continue;
                pending.fetch_add(1);ssize_t sent;
                do{sent=send(peer,packet.data(),packet.size(),UDP_SEND_FLAGS);}while(sent<0&&errno==EINTR);
                if(sent<0||static_cast<size_t>(sent)!=packet.size())pending.fetch_sub(1);
            }
            if(!ok)break;
        }
        done.store(true);
        // An uncounted wake follows all queued replies. Readers drain legitimate
        // zero-length datagrams before observing exhausted carrier state.
        const ssize_t ignored=send(peer,"",0,UDP_SEND_FLAGS);(void)ignored;
    }
    ~DialerDatagramBridge() {
        stopping.store(true);startWake.notify_all();
        if(peer>=0)shutdown(peer,SHUT_RDWR);
        if(upstream&&upstream->fd>=0)shutdown(upstream->fd,SHUT_RDWR);
        if(worker.joinable())worker.join();
        if(peer>=0)closeSocket(peer);
    }
};

bool dialerDatagramClosed(const std::shared_ptr<DialerDatagramBridge>& bridge,bool drained)
{
    return bridge&&bridge->done.load()&&(!drained||bridge->pending.load()==0);
}
void consumeDialerDatagram(const std::shared_ptr<DialerDatagramBridge>& bridge)
{
    if(bridge&&bridge->pending.load())bridge->pending.fetch_sub(1);
}
void activateDialerDatagram(const std::shared_ptr<DialerDatagramBridge>& bridge,bool internal)
{
    if(!bridge)return;
    {std::lock_guard<std::mutex> lock(g_state.sessionsMutex);const auto found=g_state.connections.find(bridge->client);if(found!=g_state.connections.end())bridge->ownerId=found->second.id;}
    {std::lock_guard<std::mutex> lock(bridge->startMutex);bridge->internalOwner=internal;bridge->ready=true;}
    bridge->startWake.notify_all();
}
int openDialerDatagramTransport(const ProxyNode& node,const std::string& host,int port,bool preserveSource,
    std::shared_ptr<DialerDatagramBridge>& output,size_t& limit,std::string& error)
{
    auto bridge=std::make_shared<DialerDatagramBridge>();
    if(!bridge->slot.held){error="Proxy chain worker limit reached";return -1;}
    const auto address=shadowsocksAddress(host,port);
    if(address.empty()){error="Invalid UDP chain destination";return -1;}
    bridge->target.host=host;bridge->target.port=port;bridge->target.headerSize=address.size();bridge->preserveSource=preserveSource;
    bridge->upstream=openUdpFlow(-1,bridge->target,node,true);
    if(!bridge->upstream){error="Cannot open UDP dialer-proxy route";return -1;}
    limit=std::min<size_t>(UDP_MAX_PACKET,bridge->upstream->payloadLimit());
    int pair[2];if(socketpair(AF_UNIX,SOCK_DGRAM,0,pair)!=0){error="Cannot create UDP chain transport";return -1;}
    bridge->peer=pair[1];bridge->client=pair[0];
    for(int fd:pair){int size=512*1024;setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&size,sizeof(size));setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size));prepareUdpSocket(fd);}
    try{auto* state=bridge.get();bridge->worker=std::thread([state](){try{state->run();}catch(...){state->done.store(true);const ssize_t ignored=send(state->peer,"",0,UDP_SEND_FLAGS);(void)ignored;}});}
    catch(...){closeSocket(pair[0]);error="Cannot start UDP chain transport";return -1;}
    output=std::move(bridge);return pair[0];
}
