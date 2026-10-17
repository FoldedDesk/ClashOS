// Bounded HTTP(S) provider downloads with strict framing and origin-aware redirects.
struct ProviderHttpReader {
    HttpTunnel& tunnel;std::string buffer;size_t offset=0,controlBytes=0;
    explicit ProviderHttpReader(HttpTunnel& connection):tunnel(connection){}
    bool fill(std::string& error) {
        std::array<unsigned char,8192> bytes{};const ssize_t count=tunnel.read(bytes.data(),bytes.size());
        if(count<=0){error=count==0?"Provider response was truncated":"Provider response was interrupted or timed out";return false;}
        if(offset>0){buffer.erase(0,offset);offset=0;}buffer.append(reinterpret_cast<const char*>(bytes.data()),static_cast<size_t>(count));return true;
    }
    bool line(std::string& output,std::string& error) {
        for(;;) {
            const size_t end=buffer.find("\r\n",offset);
            if(end!=std::string::npos) {
                const size_t length=end-offset+2;if(length>65536-controlBytes){error="Provider HTTP headers exceed 64 KB";return false;}
                controlBytes+=length;output=buffer.substr(offset,end-offset);offset=end+2;return true;
            }
            if(buffer.size()-offset>65536-controlBytes){error="Provider HTTP headers exceed 64 KB";return false;}
            if(!fill(error))return false;
        }
    }
    bool bytes(size_t count,std::string& output,std::string& error) {
        while(count>0) {
            if(offset==buffer.size()&&!fill(error))return false;
            const size_t length=std::min(count,buffer.size()-offset);output.append(buffer,offset,length);offset+=length;count-=length;
        }
        return true;
    }
};
bool providerDecimal(const std::string& text,size_t maximum,size_t& result)
{
    if(text.empty())return false;result=0;
    for(unsigned char byte:text){if(!std::isdigit(byte)||result>(maximum-static_cast<size_t>(byte-'0'))/10)return false;result=result*10+byte-'0';if(result>maximum)return false;}
    return true;
}
bool providerInflate(const std::string& input,size_t limit,std::string& output,std::string& error)
{
    z_stream stream{};if(inflateInit2(&stream,15+32)!=Z_OK){error="Cannot initialize provider decompressor";return false;}
    stream.next_in=reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));stream.avail_in=static_cast<uInt>(input.size());
    output.clear();int status=Z_OK;std::array<char,8192> buffer{};
    while(status==Z_OK) {
        stream.next_out=reinterpret_cast<Bytef*>(buffer.data());stream.avail_out=buffer.size();status=inflate(&stream,Z_NO_FLUSH);
        const size_t count=buffer.size()-stream.avail_out;
        if(count>limit-output.size()){error="Decompressed provider exceeds its size limit";status=Z_MEM_ERROR;break;}
        output.append(buffer.data(),count);
    }
    const bool valid=status==Z_STREAM_END&&stream.avail_in==0;inflateEnd(&stream);
    if(!valid){if(error.empty())error="Invalid compressed provider response";output.clear();}return valid;
}
std::string providerOrigin(const TestTarget& target){return std::string(target.tls?"https://":"http://")+(target.host.find(':')==std::string::npos?target.host:"["+target.host+"]")+":"+std::to_string(target.port);}
std::string providerRedirect(const TestTarget& source,const std::string& location)
{
    if(location.rfind("http://",0)==0||location.rfind("https://",0)==0)return location;
    if(location.rfind("//",0)==0)return std::string(source.tls?"https:":"http:")+location;
    if(location.empty())return {};
    const std::string origin=providerOrigin(source);
    if(location.front()=='/')return origin+location;
    std::string path=source.path.substr(0,source.path.find('?'));
    if(location.front()=='?')return origin+path+location;
    path.resize(path.find_last_of('/')+1);return origin+path+location;
}
bool providerHttpDownload(const ProxyProvider& provider,const ProxyNode& route,std::string& body,std::map<std::string,std::string>& responseHeaders,std::string& error)
{
    error.clear();body.clear();responseHeaders.clear();
    ProbeDeadlineScope deadline(provider.timeout);std::string url=provider.url;std::map<std::string,std::string> custom=provider.headers;
    for(int redirects=0;redirects<=5;++redirects) {
        TestTarget target;if(!parseTestUrl(url,target)){error="Invalid provider URL or redirect";return false;}
        ProxyStream stream;if(!openProxyStream(route,target.host,target.port,stream,error,provider.timeout))return false;
        HttpTunnel tunnel(stream);if(target.tls&&!tunnel.startTls(target.host,error))return false;
        std::map<std::string,std::string> headers={{"user-agent","Clash.Meta/ClashOS"},{"accept","application/yaml, application/json, text/plain, */*"},{"accept-encoding","gzip, deflate"}};
        for(const auto& item:custom) {
            const std::string key=lower(item.first);
            if(key!="host"&&key!="content-length"&&key!="transfer-encoding"&&key!="connection")headers[key]=item.second;
        }
        const std::string host=(target.host.find(':')==std::string::npos?target.host:"["+target.host+"]")+":"+std::to_string(target.port);
        std::string request="GET "+target.path+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n";
        for(const auto& header:headers)request+=header.first+": "+header.second+"\r\n";request+="\r\n";
        if(!tunnel.write(request)){error="Cannot write provider request";return false;}
        ProviderHttpReader reader(tunnel);int status=0;
        for(int interim=0;interim<6;++interim) {
            std::string line;if(!reader.line(line,error))return false;
            std::istringstream first(line);std::string version,code;first>>version>>code;
            if((version!="HTTP/1.1"&&version!="HTTP/1.0")||code.size()!=3||!std::all_of(code.begin(),code.end(),[](unsigned char c){return std::isdigit(c);})) {error="Invalid provider HTTP status";return false;}
            status=std::atoi(code.c_str());responseHeaders.clear();
            while(reader.line(line,error)&&!line.empty()) {
                const size_t colon=line.find(':');if(colon==std::string::npos||colon==0){error="Invalid provider HTTP header";return false;}
                const std::string key=lower(line.substr(0,colon)),value=trim(line.substr(colon+1));
                if(key.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~")!=std::string::npos||
                    std::any_of(value.begin(),value.end(),[](unsigned char byte){return (byte<32&&byte!='\t')||byte==127;})){error="Invalid provider HTTP header";return false;}
                const auto existing=responseHeaders.find(key);
                if(existing!=responseHeaders.end()) {
                    if(key=="transfer-encoding"||key=="content-encoding"){error="Ambiguous provider HTTP header";return false;}
                    if((key=="content-length"||key=="location"||key=="transfer-encoding"||key=="content-encoding")&&existing->second!=value){error="Ambiguous provider HTTP header";return false;}
                    if(existing->second==value)continue;
                    existing->second+=", "+value;
                }else responseHeaders[key]=value;
            }
            if(!error.empty())return false;
            if(status>=200||status==101)break;
        }
        if(status==301||status==302||status==303||status==307||status==308) {
            const std::string next=providerRedirect(target,responseHeaders["location"]);TestTarget destination;
            if(redirects==5||!parseTestUrl(next,destination)||(target.tls&&!destination.tls)){error="Unsafe or excessive provider redirect";return false;}
            if(providerOrigin(target)!=providerOrigin(destination))custom.clear();
            url=next;continue;
        }
        if(status!=200){error="Provider returned HTTP "+std::to_string(status);return false;}
        const std::string encoding=lower(responseHeaders["content-encoding"]),transfer=lower(responseHeaders["transfer-encoding"]);
        if(!encoding.empty()&&encoding!="identity"&&encoding!="gzip"&&encoding!="deflate"){error="Unsupported provider content encoding";return false;}
        if(!transfer.empty()&&(transfer!="chunked"||responseHeaders.count("content-length"))){error="Unsupported or ambiguous provider transfer encoding";return false;}
        body.clear();
        if(transfer=="chunked") {
            for(;;) {
                std::string line;if(!reader.line(line,error))return false;
                const std::string number=line.substr(0,line.find(';'));size_t length=0;
                if(number.empty()||number.size()>16){error="Invalid provider chunk size";return false;}
                for(unsigned char digit:number) {
                    const int value=std::isdigit(digit)?digit-'0':digit>='a'&&digit<='f'?digit-'a'+10:digit>='A'&&digit<='F'?digit-'A'+10:-1;
                    if(value<0||length>(provider.sizeLimit-static_cast<size_t>(value))/16){error="Provider chunk exceeds its size limit";return false;}
                    length=length*16+value;
                }
                if(length==0){do{if(!reader.line(line,error))return false;}while(!line.empty());break;}
                if(length>provider.sizeLimit-body.size()){error="Provider response exceeds its size limit";return false;}
                if(!reader.bytes(length,body,error))return false;
                std::string ending;if(!reader.bytes(2,ending,error)||ending!="\r\n"){error="Invalid provider chunk terminator";return false;}
            }
        } else if(responseHeaders.count("content-length")) {
            size_t length=0;if(!providerDecimal(responseHeaders["content-length"],provider.sizeLimit,length)){error="Invalid or oversized provider content-length";return false;}
            if(!reader.bytes(length,body,error))return false;
        } else {
            body=reader.buffer.substr(reader.offset);
            std::array<unsigned char,8192> bytes{};
            if(body.size()>provider.sizeLimit){error="Provider response exceeds its size limit";return false;}
            for(;;) {
                const ssize_t count=tunnel.read(bytes.data(),bytes.size());if(count==0)break;
                if(count<0){error="Provider response interrupted or timed out";return false;}
                if(static_cast<size_t>(count)>provider.sizeLimit-body.size()){error="Provider response exceeds its size limit";return false;}
                body.append(reinterpret_cast<const char*>(bytes.data()),static_cast<size_t>(count));
            }
            if(target.tls&&!tunnel.tls.cleanEof){error="EOF-delimited HTTPS provider ended without TLS close_notify";return false;}
        }
        if(encoding=="gzip"||encoding=="deflate") {
            std::string decoded;if(!providerInflate(body,provider.sizeLimit,decoded,error))return false;body=std::move(decoded);
        }
        return true;
    }
    error="Provider redirect limit reached";return false;
}
