// HTTP/1 message boundaries are independent of TCP reads. Never treat a
// following proxy request as the current origin's body (RFC 9112 section 6.3).
namespace HttpIngress {
constexpr size_t headerLimit=65536, chunkLineLimit=8192;
bool tokenChar(unsigned char c) {
    return (c>='0'&&c<='9')||(c>='A'&&c<='Z')||(c>='a'&&c<='z')||
        c!=0&&std::strchr("!#$%&'*+-.^_`|~",c)!=nullptr;
}
bool token(const std::string& text) {return !text.empty()&&std::all_of(text.begin(),text.end(),[](unsigned char c){return tokenChar(c);});}
std::string ows(const std::string& value) {
    const auto first=value.find_first_not_of(" \t");if(first==std::string::npos)return {};
    return value.substr(first,value.find_last_not_of(" \t")-first+1);
}
struct Field {std::string name,value;};
struct Head {
    std::string first;std::vector<Field> fields;std::set<std::string> connection;
    std::vector<std::string> values(const std::string& name) const {std::vector<std::string> out;for(const auto& f:fields)if(lower(f.name)==name)out.push_back(f.value);return out;}
    std::string joined(const std::string& name) const {std::string out;for(const auto& v:values(name)){if(!out.empty())out+=", ";out+=v;}return out;}
};
bool list(const std::string& value,std::vector<std::string>& result) {
    size_t start=0;
    for(;;){const auto comma=value.find(',',start);const auto item=ows(value.substr(start,comma==std::string::npos?comma:comma-start));if(item.empty())return false;result.push_back(item);if(comma==std::string::npos)return true;start=comma+1;}
}
bool parseHead(const std::string& wire,Head& head) {
    if(wire.size()>headerLimit||wire.size()<4||wire.compare(wire.size()-4,4,"\r\n\r\n")!=0)return false;
    const auto first=wire.find("\r\n");if(!first||first==std::string::npos)return false;head={};head.first=wire.substr(0,first);
    for(unsigned char c:head.first)if(c<32||c==127)return false;
    for(size_t at=first+2;at<wire.size()-2;){
        const auto end=wire.find("\r\n",at);if(end==std::string::npos)return false;
        const auto line=wire.substr(at,end-at);const auto colon=line.find(':');if(colon==std::string::npos||!token(line.substr(0,colon)))return false;
        const auto value=ows(line.substr(colon+1));for(unsigned char c:value)if((c<32&&c!='\t')||c==127)return false;
        if(head.fields.size()>=1024)return false;head.fields.push_back({line.substr(0,colon),value});at=end+2;
    }
    for(const auto& name:{"connection","proxy-connection"})for(const auto& v:head.values(name)){
        if(ows(v).empty())continue;std::vector<std::string> items;if(!list(v,items))return false;for(const auto& item:items){if(!token(item))return false;head.connection.insert(lower(item));}
    }
    return true;
}
bool decimal(const std::string& value,uint64_t& result,unsigned base=10) {
    if(value.empty())return false;result=0;
    for(unsigned char c:value){unsigned digit=c>='0'&&c<='9'?c-'0':base==16&&c>='a'&&c<='f'?c-'a'+10:base==16&&c>='A'&&c<='F'?c-'A'+10:base;
        if(digit>=base||result>(UINT64_MAX-digit)/base)return false;result=result*base+digit;}
    return true;
}
enum class BodyKind {None,Length,Chunked,Eof};
struct Framing {BodyKind kind=BodyKind::None;uint64_t length=0;bool hasLength=false;std::string transfer;};
bool framing(const Head& head,bool request,bool noBody,Framing& out) {
    out={};
    for(const auto& value:head.values("content-length")){
        std::vector<std::string> values;if(!list(value,values))return false;
        for(const auto& item:values){uint64_t size;if(!decimal(item,size)||out.hasLength&&out.length!=size)return false;out.hasLength=true;out.length=size;}
    }
    const auto encodings=head.values("transfer-encoding");
    if(!encodings.empty()){
        std::vector<std::string> values;
        out.transfer=head.joined("transfer-encoding");if(!list(out.transfer,values))return false;
        unsigned chunked=0;bool lastChunked=false;
        for(size_t i=0;i<values.size();++i){
            const auto semi=values[i].find(';');const auto name=lower(ows(values[i].substr(0,semi)));if(!token(name))return false;
            if(name=="chunked"){if(++chunked>1||semi!=std::string::npos||i+1!=values.size())return false;lastChunked=true;}
        }
        if(request&&(out.hasLength||!lastChunked))return false;
        out.kind=lastChunked?BodyKind::Chunked:BodyKind::Eof;
    }else out.kind=out.hasLength?BodyKind::Length:request?BodyKind::None:BodyKind::Eof;
    if(noBody)out.kind=BodyKind::None;
    return true;
}
bool chunkExtensions(const std::string& line,size_t at) {
    auto space=[&]{while(at<line.size()&&(line[at]==' '||line[at]=='\t'))++at;};
    while(at<line.size()){
        space();if(at==line.size())return true;if(line[at++]!=';')return false;space();
        const auto begin=at;while(at<line.size()&&tokenChar(line[at]))++at;if(begin==at)return false;space();
        if(at<line.size()&&line[at]=='='){
            ++at;space();if(at==line.size())return false;
            if(line[at]=='"'){
                ++at;bool closed=false;
                while(at<line.size()){unsigned char c=line[at++];if(c=='"'){closed=true;break;}if(c=='\\'){if(at==line.size())return false;c=line[at++];}if((c<32&&c!='\t')||c==127)return false;}
                if(!closed)return false;
            }else{const auto begin=at;while(at<line.size()&&tokenChar(line[at]))++at;if(begin==at)return false;}
        }
        space();if(at<line.size()&&line[at]!=';')return false;
    }
    return true;
}
bool forbiddenTrailer(const std::string& name) {
    static const std::set<std::string> names={"host","content-length","transfer-encoding","trailer","connection","proxy-connection","keep-alive","upgrade","te","authorization","proxy-authorization","proxy-authenticate"};
    return names.count(name)!=0;
}
struct Body {
    Framing framing;uint64_t remaining=0;enum Stage {Size,Data,DataEnd,Trailers,Done} stage=Done;
    std::set<std::string> hop;bool dechunk=false;
    Body()=default;
    Body(Framing value,const std::set<std::string>& options={}):framing(std::move(value)),remaining(framing.length),hop(options) {if(framing.kind==BodyKind::Chunked)stage=Size;}
    bool done() const {return framing.kind==BodyKind::None||framing.kind==BodyKind::Length&&remaining==0||framing.kind==BodyKind::Chunked&&stage==Done;}
    bool consume(std::string& input,std::string& output) {
        output.clear();size_t used=0;
        auto emit=[&](size_t size,bool payload=true){if(!dechunk||payload)output.append(input,used,size);used+=size;};
        if(framing.kind==BodyKind::Length){const auto count=static_cast<size_t>(std::min<uint64_t>(remaining,input.size()));emit(count);remaining-=count;}
        else if(framing.kind==BodyKind::Eof)emit(input.size());
        else if(framing.kind==BodyKind::Chunked)while(used<input.size()&&stage!=Done){
            if(stage==Size){
                const auto end=input.find("\r\n",used);if(end==std::string::npos){if(input.size()-used>chunkLineLimit)return false;break;}
                if(end-used>chunkLineLimit)return false;const auto line=input.substr(used,end-used);
                const auto numberEnd=line.find_first_not_of("0123456789abcdefABCDEF");const auto value=line.substr(0,numberEnd);
                if(!decimal(value,remaining,16)||!chunkExtensions(line,numberEnd==std::string::npos?line.size():numberEnd))return false;
                emit(end+2-used,false);stage=remaining?Data:Trailers;
            }else if(stage==Data){const auto count=static_cast<size_t>(std::min<uint64_t>(remaining,input.size()-used));emit(count);remaining-=count;if(!remaining)stage=DataEnd;}
            else if(stage==DataEnd){if(input.size()-used<2)break;if(input.compare(used,2,"\r\n")!=0)return false;emit(2,false);stage=Size;}
            else if(stage==Trailers){
                if(input.size()-used>=2&&input.compare(used,2,"\r\n")==0){emit(2,false);stage=Done;continue;}
                const auto end=input.find("\r\n\r\n",used);if(end==std::string::npos){if(input.size()-used>headerLimit)return false;break;}
                if(end+4-used>headerLimit)return false;Head fields;if(!parseHead("trailers\r\n"+input.substr(used,end+4-used),fields))return false;
                std::string cleaned;
                for(const auto& field:fields.fields){const auto name=lower(field.name);if(forbiddenTrailer(name))return false;if(!hop.count(name))cleaned+=field.name+": "+field.value+"\r\n";}
                if(!dechunk)output+=cleaned+"\r\n";used=end+4;stage=Done;
            }
        }
        input.erase(0,used);return true;
    }
};
struct Request {
    Head head;Framing body;std::string method,target,version,host,path;int port=80;bool tunnel=false,persistent=false,upgrade=false;
};
bool protocols(const std::string& value,std::set<std::string>& out) {
    std::vector<std::string> values;if(!list(value,values))return false;
    for(const auto& value:values){const auto slash=value.find('/');if(!token(value.substr(0,slash))||slash!=std::string::npos&&!token(value.substr(slash+1)))return false;out.insert(lower(value));}return true;
}
bool request(const Head& head,Request& out) {
    out={};out.head=head;const auto a=head.first.find(' '),b=a==std::string::npos?a:head.first.find(' ',a+1);
    if(a==std::string::npos||b==std::string::npos||head.first.find(' ',b+1)!=std::string::npos)return false;
    out.method=head.first.substr(0,a);out.target=head.first.substr(a+1,b-a-1);out.version=head.first.substr(b+1);
    if(!token(out.method)||out.target.empty()||(out.version!="HTTP/1.1"&&out.version!="HTTP/1.0"))return false;
    out.tunnel=out.method=="CONNECT";out.port=out.tunnel?443:80;
    const auto hosts=head.values("host");if(hosts.size()>1||head.values("proxy-authorization").size()>1)return false;
    if(out.version=="HTTP/1.1"&&hosts.empty()&&!out.tunnel)return false;
    if(!hosts.empty()){std::string ignored;int port;if(!splitHostPort(hosts[0],ignored,port,out.port)||std::any_of(ignored.begin(),ignored.end(),[](unsigned char c){return c<=32||c==127;}))return false;}
    if(out.tunnel){if(!splitHostPort(out.target,out.host,out.port,443))return false;}
    else if(out.target.rfind("http://",0)==0){TestTarget target;if(!parseTestUrl(out.target,target))return false;out.host=target.host;out.port=target.port;out.path=target.path;}
    else{if(hosts.empty()||!splitHostPort(hosts[0],out.host,out.port,80)||(out.target[0]!='/'&&out.target!="*"))return false;out.path=out.target;}
    if(!framing(head,true,false,out.body)||out.version=="HTTP/1.0"&&!out.body.transfer.empty())return false;
    if(out.tunnel&&(out.body.kind==BodyKind::Chunked||out.body.length))return false;
    out.persistent=out.version=="HTTP/1.1"&&!head.connection.count("close");
    out.upgrade=head.connection.count("upgrade")&&!head.values("upgrade").empty();
    if(out.upgrade){std::set<std::string> offers;if(out.version!="HTTP/1.1"||!protocols(head.joined("upgrade"),offers))return false;}
    return true;
}
bool skipField(const std::string& name,const Head& head) {
    return head.connection.count(name)||name=="connection"||name=="proxy-connection"||name=="proxy-authorization"||name=="proxy-authenticate"||
        name=="keep-alive"||name=="te"||name=="upgrade"||name=="content-length"||name=="transfer-encoding";
}
std::string authority(const Request& req) {
    const auto host=req.host.find(':')!=std::string::npos?"["+req.host+"]":req.host;
    return host+(req.port==80?"":":"+std::to_string(req.port));
}
std::string renderFields(const Head& head,const Framing& framing) {
    std::string output;for(const auto& field:head.fields)if(!skipField(lower(field.name),head))output+=field.name+": "+field.value+"\r\n";
    if(!framing.transfer.empty())output+="Transfer-Encoding: "+framing.transfer+"\r\n";
    else if(framing.hasLength)output+="Content-Length: "+std::to_string(framing.length)+"\r\n";
    return output;
}
std::string forwarded(const Request& req) {
    Head head=req.head;head.fields.erase(std::remove_if(head.fields.begin(),head.fields.end(),[](const auto& field){return lower(field.name)=="host";}),head.fields.end());
    std::string output=req.method+" "+req.path+" "+req.version+"\r\nHost: "+authority(req)+"\r\n"+renderFields(head,req.body);
    if(req.upgrade)output+="Connection: Upgrade\r\nUpgrade: "+req.head.joined("upgrade")+"\r\n";
    else output+="Connection: close\r\n";
    return output+"\r\n";
}
struct Response {Head head;Framing body;int status=0;bool interim=false,upgrade=false;std::string reason;};
bool response(const Head& head,const Request& req,Response& out) {
    out={};out.head=head;
    if(head.first.size()<12||(head.first.substr(0,9)!="HTTP/1.1 "&&head.first.substr(0,9)!="HTTP/1.0 ")||head.first.size()>12&&head.first[12]!=' ')return false;
    uint64_t status;if(!decimal(head.first.substr(9,3),status)||status<100||status>599)return false;out.status=static_cast<int>(status);out.reason=head.first.substr(9);
    out.interim=status>=100&&status<200&&status!=101;out.upgrade=status==101;
    if(!framing(head,false,req.method=="HEAD"||status<200||status==204||status==304,out.body))return false;
    if(head.first.substr(0,8)=="HTTP/1.0"&&!out.body.transfer.empty())return false;
    if(req.version=="HTTP/1.0"&&out.body.kind!=BodyKind::None&&!out.body.transfer.empty()&&lower(ows(out.body.transfer))!="chunked")return false;
    if(out.upgrade){
        std::set<std::string> offers,selected;if(!req.upgrade||!head.connection.count("upgrade")||!protocols(req.head.joined("upgrade"),offers)||!protocols(head.joined("upgrade"),selected)||selected.empty())return false;
        for(const auto& item:selected)if(!offers.count(item))return false;
    }
    return true;
}
std::string rendered(const Response& reply,const Request& req,bool close) {
    auto body=reply.body;auto head=reply.head;
    if(req.version=="HTTP/1.0"&&!body.transfer.empty()){
        body.transfer.clear();body.hasLength=false;
        head.fields.erase(std::remove_if(head.fields.begin(),head.fields.end(),[](const auto& field){return lower(field.name)=="trailer";}),head.fields.end());
    }
    if(reply.status<200||reply.status==204){body.transfer.clear();body.hasLength=false;}
    std::string out=req.version+" "+reply.reason+"\r\n"+renderFields(head,body);
    if(reply.upgrade)out+="Connection: Upgrade\r\nUpgrade: "+reply.head.joined("upgrade")+"\r\n";
    else if(!reply.interim)out+=close?"Connection: close\r\n":"Connection: keep-alive\r\n";
    return out+"\r\n";
}
} // namespace HttpIngress
