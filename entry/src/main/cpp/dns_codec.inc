// Bounded DNS wire reader: RFC 1035 names/RRs, RFC 3596 AAAA, RFC 8484 wire messages.
uint16_t dnsRead16(const std::vector<unsigned char>& bytes,size_t at)
{
    return (static_cast<uint16_t>(bytes[at])<<8)|bytes[at+1];
}
uint32_t dnsRead32(const std::vector<unsigned char>& bytes,size_t at)
{
    return (static_cast<uint32_t>(dnsRead16(bytes,at))<<16)|dnsRead16(bytes,at+2);
}
void dnsPut16(std::vector<unsigned char>& bytes,uint16_t value)
{
    bytes.push_back(value>>8);bytes.push_back(value&255);
}
bool dnsNormalizeName(std::string input,std::string& output)
{
    output.clear();if(input=="."){output=".";return true;}if(!input.empty()&&input.back()=='.')input.pop_back();
    if(input.empty()||input.size()>253)return false;
    size_t length=0;
    for(unsigned char c:input) {
        if(c=='.'){if(!length||length>63)return false;length=0;}
        else {if(c<=32||c>=127||c=='/'||c=='\\'||c==':'||c=='@'||c=='?'||c=='#'||c==','||c=='*'||c=='+')return false;++length;}
    }
    if(!length||length>63)return false;output=lower(input);return true;
}
bool dnsReadName(const std::vector<unsigned char>& packet,size_t& cursor,std::string& output)
{
    output.clear();size_t at=cursor;bool jumped=false;std::set<size_t> visited;
    for(size_t labels=0;labels<128;++labels) {
        if(at>=packet.size()||!visited.insert(at).second)return false;
        const unsigned char length=packet[at++];
        if((length&0xc0)==0xc0) {
            if(at>=packet.size())return false;const size_t target=((length&63)<<8)|packet[at++];
            if(target<12||target>=at-2)return false;
            if(!jumped)cursor=at;jumped=true;at=target;continue;
        }
        if(length&0xc0||length>63||length>packet.size()-at)return false;
        if(length==0){if(!jumped)cursor=at;if(output.empty())output=".";return output.size()<=253;}
        if(!output.empty())output+='.';
        for(size_t i=0;i<length;++i) {
            const unsigned char c=packet[at+i];if(c<=32||c>=127||c=='.'||c=='\\')return false;output+=static_cast<char>(std::tolower(c));
        }
        if(output.size()>253)return false;at+=length;
        if(!jumped)cursor=at;
    }
    return false;
}
bool dnsBuildQuestion(const std::string& name,uint16_t type,uint16_t id,std::vector<unsigned char>& packet,const DnsQueryOptions* options=nullptr)
{
    std::string host;if(!dnsNormalizeName(name,host)||type==0||type==252||type==251)return false;
    packet.clear();dnsPut16(packet,id);dnsPut16(packet,0x0100|(options&&options->checkingDisabled?0x0010:0));dnsPut16(packet,1);
    dnsPut16(packet,0);dnsPut16(packet,0);dnsPut16(packet,options&&options->edns?1:0);
    size_t start=0;
    while(host!=".") {
        const size_t end=host.find('.',start),length=(end==std::string::npos?host.size():end)-start;
        packet.push_back(length);packet.insert(packet.end(),host.begin()+start,host.begin()+start+length);
        if(end==std::string::npos)break;start=end+1;
    }
    packet.push_back(0);dnsPut16(packet,type);dnsPut16(packet,1);
    if(options&&options->edns){packet.push_back(0);dnsPut16(packet,41);dnsPut16(packet,options->udpSize);dnsPut16(packet,0);dnsPut16(packet,options->dnssecOk?0x8000:0);dnsPut16(packet,0);}return true;
}
bool dnsParseResponse(const std::vector<unsigned char>& packet,const std::string& name,uint16_t type,uint16_t id,DnsAnswer& answer)
{
    answer={};answer.name=name;answer.type=type;
    auto fail=[&](const std::string& error){answer.records.clear();answer.error=error;return false;};
    if(packet.size()<12||packet.size()>65535||dnsRead16(packet,0)!=id)return fail("DNS response transaction does not match");
    const uint16_t flags=dnsRead16(packet,2);
    if(!(flags&0x8000)||(flags&0x7800)||dnsRead16(packet,4)!=1)return fail("Invalid DNS response header");
    answer.rcode=flags&15;answer.truncated=(flags&0x0200)!=0;
    size_t cursor=12;std::string question;
    if(!dnsReadName(packet,cursor,question)||cursor>packet.size()-4||question!=name||dnsRead16(packet,cursor)!=type||dnsRead16(packet,cursor+2)!=1)
        return fail("DNS response question does not match");
    cursor+=4;
    if(answer.truncated)return true;
    const size_t total=static_cast<size_t>(dnsRead16(packet,6))+dnsRead16(packet,8)+dnsRead16(packet,10);
    if(total>2048)return fail("DNS response has too many records");
    bool opt=false;
    for(size_t i=0;i<total;++i) {
        DnsRecord record;record.section=i<dnsRead16(packet,6)?0:i<static_cast<size_t>(dnsRead16(packet,6))+dnsRead16(packet,8)?1:2;
        if(!dnsReadName(packet,cursor,record.name)||cursor>packet.size()-10)return fail("Invalid DNS record name or length");
        record.type=dnsRead16(packet,cursor);const uint16_t klass=dnsRead16(packet,cursor+2);record.ttl=dnsRead32(packet,cursor+4);
        const size_t length=dnsRead16(packet,cursor+8),first=cursor+10;
        if(length>packet.size()-first)return fail("Truncated DNS record data");cursor=first+length;
        if(record.type==41) {
            if(opt||record.section!=2||record.name!=".")return fail("Invalid DNS OPT record");
            opt=true;answer.rcode|=static_cast<int>(record.ttl>>24)<<4;
            if((record.ttl>>16)&255)return fail("Unsupported DNS response EDNS version");
            size_t at=first;
            while(at<cursor){if(cursor-at<4)return fail("Invalid DNS EDNS option");const size_t bytes=dnsRead16(packet,at+2);at+=4;if(bytes>cursor-at)return fail("Invalid DNS EDNS option length");at+=bytes;}
            continue;
        }
        if(klass!=1)continue;
        record.raw.assign(packet.begin()+first,packet.begin()+cursor);
        if(record.type==1||record.type==28) {
            const size_t expected=record.type==1?4:16;char address[INET6_ADDRSTRLEN]{};
            if(length!=expected||!inet_ntop(record.type==1?AF_INET:AF_INET6,packet.data()+first,address,sizeof(address)))return fail("Invalid DNS address record");
            record.data=address;
        } else if(record.type==2||record.type==5||record.type==12) {
            size_t at=first;if(!dnsReadName(packet,at,record.data)||at!=cursor)return fail("Invalid DNS name record");
        } else if(record.type==15||record.type==33) {
            const size_t prefix=record.type==15?2:6;if(length<=prefix)return fail("Invalid DNS MX/SRV record");
            size_t at=first+prefix;std::string target;
            if(!dnsReadName(packet,at,target)||at!=cursor)return fail("Invalid DNS MX/SRV target");
            for(size_t offset=0;offset<prefix;offset+=2)record.data+=std::to_string(dnsRead16(packet,first+offset))+" ";record.data+=target;
        } else if(record.type==6) {
            size_t at=first;std::string primary,mailbox;
            if(!dnsReadName(packet,at,primary)||!dnsReadName(packet,at,mailbox)||at>cursor||cursor-at!=20)return fail("Invalid DNS SOA record");
            record.data=primary+" "+mailbox;for(size_t offset=0;offset<20;offset+=4)record.data+=" "+std::to_string(dnsRead32(packet,at+offset));
        } else if(record.type==16) {
            size_t at=first;
            while(at<cursor) {
                const size_t bytes=packet[at++];if(bytes>cursor-at)return fail("Invalid DNS TXT record");
                if(!record.data.empty())record.data+=' ';record.data+='"';
                for(size_t n=0;n<bytes;++n){const unsigned char c=packet[at++];if(c=='"'||c=='\\')record.data+='\\';if(c>=32&&c<127)record.data+=static_cast<char>(c);else record.data+='?';}record.data+='"';
            }
        } else {
            const char* digits="0123456789abcdef";record.data="\\# "+std::to_string(length)+" ";
            for(size_t at=first;at<cursor&&at<first+1024;++at){record.data+=digits[packet[at]>>4];record.data+=digits[packet[at]&15];}
        }
        answer.records.push_back(std::move(record));
    }
    if(cursor!=packet.size())return fail("Trailing DNS message data");
    answer.wire=packet;return true;
}
std::vector<std::string> dnsAnswerAddresses(const DnsAnswer& answer)
{
    std::vector<std::string> result;std::set<std::string> owners{answer.name};
    for(size_t step=0;step<16;++step) {
        const size_t before=owners.size();
        for(const auto& record:answer.records)if(record.section==0&&record.type==5&&owners.count(record.name))owners.insert(record.data);
        if(owners.size()==before)break;
    }
    for(const auto& record:answer.records)if(record.section==0&&(record.type==1||record.type==28)&&record.type==answer.type&&owners.count(record.name)&&result.size()<32&&
        std::find(result.begin(),result.end(),record.data)==result.end())result.push_back(record.data);
    return result;
}
