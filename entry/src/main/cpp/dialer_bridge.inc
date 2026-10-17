// Socket pairs preserve the byte-stream contract of every existing outbound
// codec, including TLS, WebSocket, partial records and TCP half-close.
std::atomic<unsigned> g_dialerWorkers{0};
struct DialerWorkerSlot {
    bool held=false;
    DialerWorkerSlot() {
        unsigned count=g_dialerWorkers.load();
        while(count<128)if(g_dialerWorkers.compare_exchange_weak(count,count+1)){held=true;g_state.workers.fetch_add(1);break;}
    }
    ~DialerWorkerSlot(){if(held){g_dialerWorkers.fetch_sub(1);g_state.workers.fetch_sub(1);g_state.workersDone.notify_all();}}
};

struct DialerBridge {
    DialerWorkerSlot slot;
    int peer=-1;
    std::unique_ptr<ProxyStream> upstream;
    std::thread worker;
    ~DialerBridge() {
        if(peer>=0)shutdown(peer,SHUT_RDWR);
        if(upstream&&upstream->fd>=0)shutdown(upstream->fd,SHUT_RDWR);
        if(worker.joinable())worker.join();
        if(peer>=0)closeSocket(peer);
    }
};

int openDialerTransport(const ProxyNode& node,const std::string& host,int port,int timeout,
    std::shared_ptr<DialerBridge>& output,std::string& error)
{
    auto bridge=std::make_shared<DialerBridge>();
    if(!bridge->slot.held){error="Proxy chain worker limit reached";return -1;}
    bridge->upstream=std::make_unique<ProxyStream>();
    if(!openProxyStream(node,host,port,*bridge->upstream,error,timeout)) {
        error="dialer-proxy connection failed: "+error;return -1;
    }
    int pair[2];if(socketpair(AF_UNIX,SOCK_STREAM,0,pair)!=0){error="Cannot create proxy-chain transport";return -1;}
    bridge->peer=pair[1];trackSocket(pair[0]);trackSocket(pair[1]);
    if(g_currentClient>=0)attachUpstream(g_currentClient,pair[0]);
    try {
        auto* state=bridge.get();
        bridge->worker=std::thread([state]() {
            try { relayStream(state->peer,*state->upstream); }
            catch(...) { coreLog("warning","Proxy-chain transport stopped unexpectedly"); }
            shutdown(state->peer,SHUT_RDWR);
        });
    } catch(...) {closeSocket(pair[0]);error="Cannot start proxy-chain transport";return -1;}
    output=std::move(bridge);return pair[0];
}
