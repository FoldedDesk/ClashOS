// HTTP(S) probes run through the selected production outbound, including nested TLS.
struct TestTarget {
    std::string host;
    int port = 80;
    std::string path;
    bool tls = false;
};
bool splitHostPort(const std::string& authority, std::string& host, int& port, int defaultPort);
bool parseTestUrl(const std::string& url, TestTarget& target)
{
    target={};
    const bool secure=url.rfind("https://",0)==0;
    if (!secure && url.rfind("http://",0)!=0) return false;
    if (std::any_of(url.begin(),url.end(),[](unsigned char byte){return byte<=32 || byte==127;})) return false;
    const size_t start=secure ? 8 : 7;
    const size_t end=url.find_first_of("/?#",start);
    const std::string authority=url.substr(start,end==std::string::npos ? std::string::npos : end-start);
    if (!splitHostPort(authority,target.host,target.port,secure ? 443 : 80)) return false;
    target.tls=secure;target.path=end==std::string::npos ? "/" : url.substr(end);
    const size_t fragment=target.path.find('#');if(fragment!=std::string::npos)target.path.resize(fragment);
    if(target.path.empty() || target.path.front()!='/')target.path="/"+target.path;
    return true;
}
bool validProbeUrl(const std::string& url) { TestTarget target;return parseTestUrl(url,target); }
using ProbeStatusRanges=std::vector<std::pair<int,int>>;
bool parseProbeStatus(const std::string& text, ProbeStatusRanges& ranges)
{
    ranges.clear();
    if (text.empty() || text=="*") {ranges={{100,599}};return true;}
    std::istringstream input(text);std::string token;
    auto number=[](const std::string& raw,int& value) {
        if(raw.size()!=3 || !std::all_of(raw.begin(),raw.end(),[](unsigned char byte){return std::isdigit(byte);}))return false;
        value=std::atoi(raw.c_str());return value>=100 && value<=599;
    };
    if(text.back()=='/')return false;
    while(std::getline(input,token,'/')) {
        const size_t dash=token.find('-');int first=0,last=0;
        if(!number(token.substr(0,dash),first))return false;
        if(dash==std::string::npos)last=first;
        else if(!number(token.substr(dash+1),last) || last<first)return false;
        ranges.emplace_back(first,last);
    }
    return !ranges.empty();
}
bool validProbeStatus(const std::string& text) { ProbeStatusRanges ranges;return parseProbeStatus(text,ranges); }
struct ProbeDeadlineScope {
    std::chrono::steady_clock::time_point previous=g_probeDeadline;
    explicit ProbeDeadlineScope(int milliseconds) { g_probeDeadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(milliseconds); }
    ~ProbeDeadlineScope(){g_probeDeadline=previous;}
};
struct HttpTunnel {
    ProxyStream& stream;
    std::vector<unsigned char> pending;size_t cursor=0;
    TlsChannel tls;
    explicit HttpTunnel(ProxyStream& source):stream(source),tls(source.fd) {
        tls.writeTransport=[this](const unsigned char* data,size_t size)->ssize_t {
            return streamWrite(stream,reinterpret_cast<const char*>(data),size)?static_cast<ssize_t>(size):-1;
        };
        tls.readTransport=[this](unsigned char* data,size_t size)->ssize_t {return plainRead(data,size);};
    }
    ssize_t plainRead(unsigned char* data,size_t size) {
        if(!prepareSocketIo(stream.fd))return -1;
        if(cursor==pending.size()){if(!streamRead(stream,pending))return errno==0?0:-1;cursor=0;}
        const size_t count=std::min(size,pending.size()-cursor);std::copy_n(pending.data()+cursor,count,data);cursor+=count;return static_cast<ssize_t>(count);
    }
    bool startTls(const std::string& host,std::string& error) {
        const char* roots=nullptr;
#ifdef CLAHSOS_HOST_TEST
        roots=g_testVmessTrust;
#endif
        return tls.start(host,false,error,roots);
    }
    bool write(const std::string& data){return tls.enabled?tls.writeBytes(reinterpret_cast<const unsigned char*>(data.data()),data.size()):streamWrite(stream,data.data(),data.size());}
    ssize_t read(unsigned char* data,size_t size){return tls.enabled?tls.readBytes(data,size):plainRead(data,size);}
};
bool testHttpResponse(ProxyStream& stream,const TestTarget& target,std::string& error,const std::string& expected="200-399")
{
    ProbeStatusRanges ranges;if(!parseProbeStatus(expected,ranges)){error="Invalid expected HTTP status";return false;}
    HttpTunnel tunnel(stream);
    // Website certificate checks are independent of outbound node TLS settings.
    if(target.tls&&!tunnel.startTls(target.host,error))return false;
    const std::string authority=target.host.find(':')==std::string::npos ? target.host : "["+target.host+"]";
    const std::string request="GET "+target.path+" HTTP/1.1\r\nHost: "+authority+":"+std::to_string(target.port)+
        "\r\nUser-Agent: ClashOS/1.0\r\nConnection: close\r\n\r\n";
    const bool written=tunnel.write(request);
    if(!written){error="Cannot write probe request";return false;}
    std::string headers;size_t consumed=0,total=0;int interim=0;
    while(total<65536) {
        const size_t end=headers.find("\r\n\r\n",consumed);
        if(end!=std::string::npos) {
            const size_t lineEnd=headers.find("\r\n",consumed);
            std::istringstream status(headers.substr(consumed,lineEnd-consumed));std::string version,codeText;
            status>>version>>codeText;
            if((version!="HTTP/1.1"&&version!="HTTP/1.0") || codeText.size()!=3 ||
               !std::all_of(codeText.begin(),codeText.end(),[](unsigned char c){return std::isdigit(c);}))break;
            const int code=std::atoi(codeText.c_str());
            if(code>=100&&code<200&&code!=101&&++interim<=5){consumed=end+4;continue;}
            if(code>=200&&code<=599&&std::any_of(ranges.begin(),ranges.end(),[&](const auto& range){return code>=range.first&&code<=range.second;}))return true;
            error="Probe returned HTTP "+codeText+" outside expected status "+expected;return false;
        }
        std::vector<unsigned char> chunk;
        if(target.tls) {
            chunk.resize(4096);const ssize_t count=tunnel.read(chunk.data(),chunk.size());
            if(count<=0){error="HTTPS probe response interrupted or timed out";return false;}chunk.resize(static_cast<size_t>(count));
        } else if(!streamRead(stream,chunk)){error="HTTP probe response interrupted or timed out";return false;}
        total+=chunk.size();headers.append(chunk.begin(),chunk.end());
    }
    error="Invalid or oversized HTTP probe response";return false;
}
int probeNode(const ProxyNode& node,const TestTarget& target,int timeout,const std::string& expected,std::string& error)
{
    ProbeDeadlineScope deadline(timeout);
    const auto start=std::chrono::steady_clock::now();ProxyStream stream;
    if(!openProxyStream(node,target.host,target.port,stream,error,timeout)||!testHttpResponse(stream,target,error,expected))return 0;
    return std::max(1,static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count()));
}
std::string delayResponse(const std::string& path)
{
    const size_t suffix=path.find("/delay?");if(suffix==std::string::npos)return "{\"error\":\"Invalid delay request\"}";
    const std::string name=urlDecode(path.substr(9,suffix-9));TestTarget target;
    if(!parseTestUrl(queryValue(path,"url"),target))return "{\"error\":\"A valid HTTP or HTTPS probe URL is required\"}";
    const std::string rawExpected=queryValue(path,"expected");const std::string expected=rawExpected.empty() ? "200-399":rawExpected;
    if(!validProbeStatus(expected))return "{\"error\":\"Invalid expected HTTP status\"}";
    int timeout=std::atoi(queryValue(path,"timeout").c_str());timeout=std::clamp(timeout<=0 ? 5000:timeout,100,60000);
    ProxyNode node;uint64_t revision;
    {std::lock_guard<std::mutex> guard(g_state.mutex);const RouteContext context{target.host,"probe","tcp"};node=resolveProxyLocked(name,&context);revision=g_state.configRevision;}
    std::string error;const int delay=probeNode(node,target,timeout,expected,error);
    {std::lock_guard<std::mutex> guard(g_state.mutex);if(g_state.configRevision==revision && resolveProxyLocked(name).name==node.name)g_state.delays[name]=delay;}
    if(delay==0){coreLog("warning","Latency test failed for "+name+": "+error);return "{\"error\":\""+jsonEscape(error)+"\"}";}
    return "{\"delay\":"+std::to_string(delay)+"}";
}
