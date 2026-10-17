// DNS server framing and replies. Preserve original packets when possible, including unknown RRs.
void dnsSet16(std::vector<unsigned char>& bytes,size_t at,uint16_t value){bytes[at]=value>>8;bytes[at+1]=value&255;}
void dnsPut32(std::vector<unsigned char>& bytes,uint32_t value){dnsPut16(bytes,value>>16);dnsPut16(bytes,value&65535);}
void dnsSet32(std::vector<unsigned char>& bytes,size_t at,uint32_t value){dnsSet16(bytes,at,value>>16);dnsSet16(bytes,at+2,value&65535);}
bool dnsWriteName(std::vector<unsigned char>& out,std::string name)
{
    std::string normalized;if(!dnsNormalizeName(name,normalized))return false;
    if(name=="."){out.push_back(0);return true;}if(name.back()=='.')name.pop_back();size_t start=0;
    for(;;){const size_t end=name.find('.',start),length=(end==std::string::npos?name.size():end)-start;out.push_back(length);out.insert(out.end(),name.begin()+start,name.begin()+start+length);if(end==std::string::npos)break;start=end+1;}
    out.push_back(0);return true;
}
struct DnsWireQuestion {
    uint16_t id=0,flags=0,type=1;
    std::string name;
    std::vector<unsigned char> question;
    DnsQueryOptions options;
    int error=0;
};
DnsWireQuestion dnsReadQuestion(const std::vector<unsigned char>& packet)
{
    DnsWireQuestion request;
    if(packet.size()>=2)request.id=dnsRead16(packet,0);
    if(packet.size()>=4)request.flags=dnsRead16(packet,2);
    auto fail=[&](int code){request.error=code;return request;};
    if(packet.size()<12||packet.size()>65535||dnsRead16(packet,4)!=1||dnsRead16(packet,6)||dnsRead16(packet,8))return fail(1);
    if(request.flags&0x7800)return fail(4);
    size_t at=12,plain=12;
    while(plain<packet.size()&&packet[plain]){const size_t length=packet[plain++];if(length>63||length>packet.size()-plain)return fail(1);plain+=length;}
    if(!dnsReadName(packet,at,request.name)||at>packet.size()-4)return fail(1);
    request.type=dnsRead16(packet,at);const auto klass=dnsRead16(packet,at+2);at+=4;
    request.question.assign(packet.begin()+12,packet.begin()+at);
    if(klass!=1||request.type==0||request.type==251||request.type==252)return fail(5);
    const size_t additional=dnsRead16(packet,10);if(additional>16)return fail(1);
    for(size_t n=0;n<additional;++n) {
        std::string name;if(!dnsReadName(packet,at,name)||at>packet.size()-10)return fail(1);
        const uint16_t type=dnsRead16(packet,at),size=dnsRead16(packet,at+2);const uint32_t ttl=dnsRead32(packet,at+4);const size_t length=dnsRead16(packet,at+8);at+=10;
        if(length>packet.size()-at)return fail(1);
        if(type!=41)return fail(type==250||type==24?5:4);
        if(request.options.edns||name!=".")return fail(1);
        request.options.edns=true;request.options.udpSize=std::clamp<uint16_t>(size,512,1232);request.options.dnssecOk=(ttl&0x8000)!=0;
        if((ttl>>16)&255)request.error=16;
        const size_t end=at+length;
        while(at<end){if(end-at<4)return fail(1);const size_t bytes=dnsRead16(packet,at+2);at+=4;if(bytes>end-at)return fail(1);at+=bytes;}
    }
    if(at!=packet.size())return fail(1);
    request.options.checkingDisabled=(request.flags&0x0010)!=0;request.options.cacheOnly=(request.flags&0x0100)==0;
    return request;
}
void dnsAppendOpt(std::vector<unsigned char>& packet,const DnsWireQuestion& request,int code)
{
    packet.push_back(0);dnsPut16(packet,41);dnsPut16(packet,1232);
    dnsPut32(packet,(static_cast<uint32_t>(code>>4)<<24)|(request.options.dnssecOk?0x8000:0));dnsPut16(packet,0);
}
std::vector<unsigned char> dnsMinimalReply(const DnsWireQuestion& request,int code,bool truncated=false)
{
    std::vector<unsigned char> packet;dnsPut16(packet,request.id);dnsPut16(packet,0x8080|(request.flags&0x0110)|(code&15)|(truncated?0x0200:0));
    dnsPut16(packet,request.question.empty()?0:1);dnsPut16(packet,0);dnsPut16(packet,0);dnsPut16(packet,request.options.edns?1:0);
    packet.insert(packet.end(),request.question.begin(),request.question.end());if(request.options.edns)dnsAppendOpt(packet,request,code);return packet;
}
bool dnsRecordWire(const DnsRecord& record,std::vector<unsigned char>& packet)
{
    std::vector<unsigned char> data;
    if(record.type==1||record.type==28) {
        data.resize(record.type==1?4:16);if(inet_pton(record.type==1?AF_INET:AF_INET6,record.data.c_str(),data.data())!=1)return false;
    } else if(record.type==2||record.type==5||record.type==12) {if(!dnsWriteName(data,record.data))return false;}
    else if(record.type==15||record.type==33||record.type==6) {
        std::istringstream fields(record.data);std::string name,mailbox;uint64_t value=0;
        if(record.type==6) {
            if(!(fields>>name>>mailbox)||!dnsWriteName(data,name)||!dnsWriteName(data,mailbox))return false;
            for(int i=0;i<5;++i){if(!(fields>>value)||value>0xffffffffU)return false;dnsPut32(data,value);}
        } else {
            for(int i=0;i<(record.type==15?1:3);++i){if(!(fields>>value)||value>65535)return false;dnsPut16(data,value);}
            if(!(fields>>name)||!dnsWriteName(data,name))return false;
        }
    } else {
        // These RDATA layouts forbid compressed names or consist only of opaque bytes.
        const std::set<uint16_t> safe{10,11,13,16,20,22,25,27,28,29,37,40,42,43,44,46,47,48,50,51,52,53,59,60,61,62,63,64,65,99,256,257};
        if(!safe.count(record.type))return false;data=record.raw;
    }
    if(data.size()>65535||!dnsWriteName(packet,record.name))return false;
    dnsPut16(packet,record.type);dnsPut16(packet,1);dnsPut32(packet,record.ttl);dnsPut16(packet,data.size());packet.insert(packet.end(),data.begin(),data.end());return true;
}
std::vector<unsigned char> dnsEncodeAnswer(const DnsWireQuestion& request,const DnsAnswer& answer)
{
    if(answer.wireComplete&&!answer.wire.empty()) {
        auto packet=answer.wire;size_t at=12;std::string name;
        if(dnsReadName(packet,at,name)&&at+4==12+request.question.size()) {
            at+=4;const size_t count=static_cast<size_t>(dnsRead16(packet,6))+dnsRead16(packet,8)+dnsRead16(packet,10);bool valid=true;
            for(size_t i=0;i<count;++i) {
                if(!dnsReadName(packet,at,name)||at>packet.size()-10){valid=false;break;}
                const uint16_t type=dnsRead16(packet,at),length=dnsRead16(packet,at+8);
                if(length>packet.size()-at-10){valid=false;break;}
                if(type!=41){auto ttl=dnsRead32(packet,at+4);
                    const bool negative=answer.rcode==3||std::none_of(answer.records.begin(),answer.records.end(),[&](const auto& record){return record.section==0&&record.type==answer.type;});
                    if(type==6&&length>=4&&negative)ttl=std::min(ttl,std::min<uint32_t>(300,dnsRead32(packet,at+10+length-4)));
                    dnsSet32(packet,at+4,ttl>answer.wireAge?ttl-answer.wireAge:0);}
                at+=10;if(length>packet.size()-at){valid=false;break;}at+=length;
            }
            if(valid&&at==packet.size()) {
                uint16_t flags=(dnsRead16(packet,2)&0x042f)|0x8080|(request.flags&0x0110);
                if(answer.cached)flags&=~0x0400;
                if(!request.options.dnssecOk&&!(request.flags&0x0020))flags&=~0x0020;
                dnsSet16(packet,0,request.id);dnsSet16(packet,2,flags);
                std::copy(request.question.begin(),request.question.end(),packet.begin()+12);return packet;
            }
        }
    }
    auto packet=dnsMinimalReply(request,answer.rcode);packet.resize(12+request.question.size());
    std::array<uint16_t,3> counts{};
    for(int section=0;section<3;++section)for(const auto& record:answer.records)if(record.section==section) {
        if(!dnsRecordWire(record,packet)||packet.size()>65535)return dnsMinimalReply(request,2);++counts[section];
    }
    for(size_t i=0;i<3;++i)dnsSet16(packet,6+i*2,counts[i]);
    if(request.options.edns){dnsAppendOpt(packet,request,answer.rcode);dnsSet16(packet,10,counts[2]+1);}
    return packet;
}
std::vector<unsigned char> dnsAnswerPacket(const std::vector<unsigned char>& query,bool tcp,const std::shared_ptr<DnsConfig>& config)
{
    if(query.size()<2)return {};
    const auto request=dnsReadQuestion(query);if(request.flags&0x8000)return {};
    std::vector<unsigned char> reply;
    if(request.error)reply=dnsMinimalReply(request,request.error);
    else {
        const auto answer=queryDns(request.name,request.type,DnsPurpose::General,HealthClock::now()+std::chrono::milliseconds(5000),config,&request.options);
        if(!answer.error.empty())reply=dnsMinimalReply(request,answer.error=="DNS recursion was not requested"?5:2);
        else reply=dnsEncodeAnswer(request,answer);
    }
    const size_t maximum=tcp?65535:request.options.edns?request.options.udpSize:512;
    if(reply.size()>maximum)reply=dnsMinimalReply(request,dnsRead16(reply,2)&15,true);
    return reply;
}
