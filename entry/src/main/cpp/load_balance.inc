// Request-based distribution. Callers hold g_state.mutex; inspection never advances policy state.
static const char* const publicSuffixRules[] = {
#include "third_party/public_suffix_list/rules.inc"
};

std::string balanceDestinationKey(std::string host)
{
    host=lower(host);
    if(!host.empty()&&host.back()=='.')host.pop_back();
    unsigned char address[16]{};char canonical[INET6_ADDRSTRLEN]{};
    for(int family:{AF_INET,AF_INET6})if(inet_pton(family,host.c_str(),address)==1) {
        if(inet_ntop(family,address,canonical,sizeof(canonical)))return canonical;
    }
    if(host.empty()||host.size()>253)return host;
    std::vector<size_t> labels{0};
    for(size_t i=0;i<host.size();++i)if(host[i]=='.')labels.push_back(i+1);
    auto has=[](const std::string& rule) {
        return std::binary_search(std::begin(publicSuffixRules),std::end(publicSuffixRules),rule);
    };
    size_t suffix=1;
    for(size_t i=0;i<labels.size();++i) {
        const std::string value=host.substr(labels[i]);
        if(has("!"+value)){suffix=labels.size()-i-1;break;}
        if(has(value))suffix=std::max(suffix,labels.size()-i);
        if(i>0&&has("*."+value))suffix=std::max(suffix,labels.size()-i+1);
    }
    return labels.size()>suffix?host.substr(labels[labels.size()-suffix-1]):host;
}

uint64_t balanceHash(const std::string& key)
{
    uint64_t result=14695981039346656037ULL;
    for(unsigned char ch:key){result^=ch;result*=1099511628211ULL;}
    result^=result>>33;result*=0xff51afd7ed558ccdULL;
    result^=result>>33;result*=0xc4ceb9fe1a85ec53ULL;
    return result^(result>>33);
}

bool balancedMemberAvailableLocked(const ProxyGroup& group,const std::string& member,const RouteContext& context)
{
    RouteContext peek=context;peek.advance=false;
    const ProxyNode node=resolveProxyLocked(member,&peek);
    if(node.type=="reject")return false;
    const auto sample=group.health.find(member);
    if(sample!=group.health.end()&&matchesProxyHealth(node,sample->second)&&sample->second.delay==0)return false;
    if(context.network=="udp") {
        if(group.disableUdp||!supportsUdp(node))return false;
    }
    return true;
}

std::string chooseBalancedMemberLocked(ProxyGroup& group,const RouteContext& context)
{
    std::vector<std::string> available;
    for(const std::string& member:group.proxies)if(balancedMemberAvailableLocked(group,member,context))available.push_back(member);
    if(available.empty()){if(context.advance)group.lastSelected.clear();return "";}
    std::string selected;
    const std::string destination=balanceDestinationKey(context.host);
    // A UDP-capable subset does not reset the cursor or consume a candidate on inspection.
    if(group.strategy=="round-robin") {
        const size_t start=group.roundRobin%group.proxies.size();
        for(size_t offset=0;offset<group.proxies.size();++offset) {
            const size_t index=(start+offset)%group.proxies.size();
            if(std::find(available.begin(),available.end(),group.proxies[index])!=available.end()) {
                selected=group.proxies[index];if(context.advance)group.roundRobin=(index+1)%group.proxies.size();break;
            }
        }
    } else if(group.strategy=="sticky-sessions") {
        const std::string key=context.source+'\0'+destination;
        auto session=group.sessions.find(key);
        const bool valid=session!=group.sessions.end()&&context.now<session->second.expires&&
            std::find(available.begin(),available.end(),session->second.member)!=available.end();
        if(valid){selected=session->second.member;if(context.advance)session->second.used=context.now;}
        else {
            const uint64_t entropy=balanceHash(key+std::to_string(context.now.time_since_epoch().count())+std::to_string(group.sessionSerial+1));
            selected=available[entropy%available.size()];
            if(context.advance) {
                if(session!=group.sessions.end())group.sessions.erase(session);
                for(auto item=group.sessions.begin();item!=group.sessions.end();) {
                    if(context.now>=item->second.expires)item=group.sessions.erase(item);else ++item;
                }
                if(group.sessions.size()>=1000) {
                    const auto oldest=std::min_element(group.sessions.begin(),group.sessions.end(),[](const auto& a,const auto& b){return a.second.used<b.second.used;});
                    group.sessions.erase(oldest);
                }
                ++group.sessionSerial;
                group.sessions[key]={selected,context.now+std::chrono::minutes(10),context.now};
            }
        }
    } else {
        // Rendezvous hashing depends on member identity, so provider reordering does not move sessions.
        uint64_t best=0;bool first=true;
        for(const std::string& member:available) {
            const uint64_t score=balanceHash(destination+'\0'+member);
            if(first||score>best||(score==best&&member<selected)){first=false;best=score;selected=member;}
        }
    }
    if(context.advance)group.lastSelected=selected;
    return selected;
}

std::string clientSourceAddress(int fd)
{
    sockaddr_storage address{};socklen_t size=sizeof(address);char host[INET6_ADDRSTRLEN]{};
    if(getpeername(fd,reinterpret_cast<sockaddr*>(&address),&size)!=0)return "";
    if(address.ss_family==AF_INET)inet_ntop(AF_INET,&reinterpret_cast<sockaddr_in*>(&address)->sin_addr,host,sizeof(host));
    else if(address.ss_family==AF_INET6) {
        const auto& ip=reinterpret_cast<sockaddr_in6*>(&address)->sin6_addr;
        if(IN6_IS_ADDR_V4MAPPED(&ip))inet_ntop(AF_INET,&ip.s6_addr[12],host,sizeof(host));
        else inet_ntop(AF_INET6,&ip,host,sizeof(host));
    }
    return host;
}
