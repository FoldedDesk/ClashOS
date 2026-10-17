std::atomic<unsigned> g_dnsWireWorkers{0};
void dnsListenerLoop(DnsListener*);
void DnsListener::activate(const std::shared_ptr<DnsConfig>& next)
{
    {std::lock_guard<std::mutex> lock(mutex);config=next;started=true;active.store(true);}wake.notify_all();
}
void DnsListener::stop()
{
    {std::lock_guard<std::mutex> lock(mutex);retired=true;active.store(false);for(int fd:sockets)shutdown(fd,SHUT_RDWR);}wake.notify_all();
    if(thread.joinable())thread.join();
    {std::lock_guard<std::mutex> lock(mutex);if(tcp>=0){close(tcp);tcp=-1;}if(udp>=0){close(udp);udp=-1;}}
}
DnsListener::~DnsListener()
{
    stop();
}
std::shared_ptr<DnsListener> bindDnsListener(const std::string& host,int port,std::string& error)
{
    auto listener=std::make_shared<DnsListener>();listener->host=host;
    sockaddr_storage address{};socklen_t length=0;
    if(inet_pton(AF_INET,host.c_str(),&reinterpret_cast<sockaddr_in*>(&address)->sin_addr)==1) {
        auto* a=reinterpret_cast<sockaddr_in*>(&address);a->sin_family=AF_INET;a->sin_port=htons(port);length=sizeof(*a);
    } else if(inet_pton(AF_INET6,host.c_str(),&reinterpret_cast<sockaddr_in6*>(&address)->sin6_addr)==1) {
        auto* a=reinterpret_cast<sockaddr_in6*>(&address);a->sin6_family=AF_INET6;a->sin6_port=htons(port);length=sizeof(*a);
    } else {error="Invalid DNS listen address";return nullptr;}
    listener->tcp=socket(address.ss_family,SOCK_STREAM,0);
    if(listener->tcp<0){error="Cannot create DNS TCP listener";return nullptr;}
    int reuse=1;setsockopt(listener->tcp,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
    if(address.ss_family==AF_INET6){int dual=0;setsockopt(listener->tcp,IPPROTO_IPV6,IPV6_V6ONLY,&dual,sizeof(dual));}
    if(bind(listener->tcp,reinterpret_cast<sockaddr*>(&address),length)!=0||listen(listener->tcp,16)!=0||getsockname(listener->tcp,reinterpret_cast<sockaddr*>(&address),&length)!=0) {
        error="Cannot bind DNS TCP listener: "+std::string(std::strerror(errno));return nullptr;
    }
    listener->port=address.ss_family==AF_INET?ntohs(reinterpret_cast<sockaddr_in*>(&address)->sin_port):ntohs(reinterpret_cast<sockaddr_in6*>(&address)->sin6_port);
    listener->address=(host.find(':')==std::string::npos?host:"["+host+"]")+":"+std::to_string(listener->port);
    listener->udp=socket(address.ss_family,SOCK_DGRAM,0);
    if(listener->udp<0){error="Cannot create DNS UDP listener";return nullptr;}
    if(address.ss_family==AF_INET6){int dual=0;setsockopt(listener->udp,IPPROTO_IPV6,IPV6_V6ONLY,&dual,sizeof(dual));}
    // UDP has no TIME_WAIT. Keep its port exclusive rather than allowing overlapping binds.
    if(bind(listener->udp,reinterpret_cast<sockaddr*>(&address),length)!=0){error="Cannot bind DNS UDP listener: "+std::string(std::strerror(errno));return nullptr;}
    for(int fd:{listener->tcp,listener->udp})fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0)|O_NONBLOCK);
    try{listener->thread=std::thread(dnsListenerLoop,listener.get());}
    catch(...){error="Cannot start DNS listener worker";return nullptr;}
    return listener;
}
bool prepareDnsListener(const std::shared_ptr<DnsConfig>& config,std::shared_ptr<DnsListener>& next,std::string& error)
{
    next.reset();if(!config->enabled||config->listen.empty())return true;
    if(g_state.dnsListener&&g_state.dnsListener->active.load()&&g_state.dnsListener->host==config->listenHost&&g_state.dnsListener->port==config->listenPort) {next=g_state.dnsListener;return true;}
    next=bindDnsListener(config->listenHost,config->listenPort,error);
    if(!next)error+="; current DNS/configuration has been preserved";
    return next!=nullptr;
}
void replaceDnsListenerLocked(const std::shared_ptr<DnsListener>& next)
{
    if(g_state.dnsListener!=next&&g_state.dnsListener)g_state.dnsListener->stop();
    g_state.dnsListener=next;if(next)next->activate(g_state.dns);
}
bool dnsStartWorker(const std::function<void()>& work)
{
    if(g_state.workers.load()>=128)return false;
    if(g_dnsWireWorkers.fetch_add(1)>=16){g_dnsWireWorkers.fetch_sub(1);return false;}
    g_state.workers.fetch_add(1);
    try {
        std::thread([work]() {
            try{work();}catch(...){coreLog("warning","DNS client request failed");}
            g_dnsWireWorkers.fetch_sub(1);{std::lock_guard<std::mutex> lock(g_state.sessionsMutex);g_state.workers.fetch_sub(1);}g_state.workersDone.notify_all();
        }).detach();
    } catch(...) {g_dnsWireWorkers.fetch_sub(1);{std::lock_guard<std::mutex> lock(g_state.sessionsMutex);g_state.workers.fetch_sub(1);}g_state.workersDone.notify_all();return false;}
    return true;
}
void dnsTcpClient(const std::shared_ptr<DnsListener>& listener,int fd)
{
    struct Close{int fd;std::shared_ptr<DnsListener> listener;~Close(){std::lock_guard<std::mutex> lock(listener->mutex);listener->sockets.erase(fd);closeSocket(fd);}}close{fd,listener};
    socketTimeout(fd,10000);
    for(int count=0;count<64&&listener->active.load()&&g_state.running.load();++count) {
        std::array<char,2> size{};if(!readExact(fd,size.data(),2))break;
        const size_t length=(static_cast<unsigned char>(size[0])<<8)|static_cast<unsigned char>(size[1]);
        if(length<12)break;
        std::vector<unsigned char> question(length);if(!readExact(fd,reinterpret_cast<char*>(question.data()),length))break;
        ++listener->queries;
        std::shared_ptr<DnsConfig> config;{std::lock_guard<std::mutex> lock(listener->mutex);config=listener->config;}
        auto reply=dnsAnswerPacket(question,true,config);if(!listener->active.load())break;
        if(reply.empty())continue;
        std::vector<unsigned char> prefix;dnsPut16(prefix,reply.size());
        if(!sendAll(fd,prefix)||!sendAll(fd,reply))break;
    }
}
void dnsListenerLoop(DnsListener* raw)
{
    {std::unique_lock<std::mutex> lock(raw->mutex);raw->wake.wait(lock,[&]{return raw->started||raw->retired;});if(raw->retired)return;}
    while(raw->active.load()) {
        pollfd descriptors[2]={{raw->udp,POLLIN,0},{raw->tcp,POLLIN,0}};
        const int ready=poll(descriptors,2,100);if(ready<0&&errno==EINTR)continue;if(ready<0)break;
        if(!raw->active.load())break;
        auto listener=raw->shared_from_this();std::shared_ptr<DnsConfig> config;
        {std::lock_guard<std::mutex> lock(raw->mutex);config=raw->config;}
        if(descriptors[0].revents&POLLIN) {
            std::vector<unsigned char> question(65536);sockaddr_storage peer{};socklen_t length=sizeof(peer);
            const auto size=recvfrom(raw->udp,question.data(),question.size(),0,reinterpret_cast<sockaddr*>(&peer),&length);
            if(size>0) {
                question.resize(size);++raw->queries;
                if(!dnsStartWorker([listener,config,question,peer,length]() {
                    const auto reply=dnsAnswerPacket(question,false,config);
                    std::lock_guard<std::mutex> lock(listener->mutex);
                    if(listener->active.load()&&listener->udp>=0&&!reply.empty())sendto(listener->udp,reply.data(),reply.size(),UDP_SEND_FLAGS,reinterpret_cast<const sockaddr*>(&peer),length);
                })) {
                    ++raw->rejected;const auto request=dnsReadQuestion(question);
                    if(!(request.flags&0x8000)){const auto reply=dnsMinimalReply(request,2);sendto(raw->udp,reply.data(),reply.size(),UDP_SEND_FLAGS,reinterpret_cast<sockaddr*>(&peer),length);}
                }
            }
        }
        if(descriptors[1].revents&POLLIN) {
            const int fd=accept(raw->tcp,nullptr,nullptr);if(fd<0)continue;
            fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0)&~O_NONBLOCK);
            trackSocket(fd);
            {std::lock_guard<std::mutex> lock(raw->mutex);raw->sockets.insert(fd);}
            if(!dnsStartWorker([listener,fd](){dnsTcpClient(listener,fd);})) {++raw->rejected;{std::lock_guard<std::mutex> lock(raw->mutex);raw->sockets.erase(fd);}closeSocket(fd);}
        }
    }
}
