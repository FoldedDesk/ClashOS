// XUDP is a framed UDP session inside an authenticated VMess/VLESS stream.
// Wire references: XTLS/Xray-core common/xudp/xudp.go and MetaCubeX/sing-vmess
// xudp.go. This connection owns mux session 0; other session IDs are rejected.
struct XudpSession {
    static constexpr size_t MaxPayload = 65507, MaxMetadata = 4096;
    std::function<bool(const unsigned char*,size_t)> send;
    std::function<bool(VmBytes&,bool)> receive;
    std::function<bool()> upstreamPending;
    std::string destination, fallback;
    int port = 0, failure = 0;
    VmBytes globalId, input;
    size_t offset = 0;
    bool sent = false, ended = false;

    XudpSession(std::string host,int targetPort,std::string replyHost,VmBytes id,
        std::function<bool(const unsigned char*,size_t)> writer,
        std::function<bool(VmBytes&,bool)> reader,std::function<bool()> pending)
        :send(std::move(writer)),receive(std::move(reader)),upstreamPending(std::move(pending)),
         destination(std::move(host)),fallback(std::move(replyHost)),port(targetPort),globalId(std::move(id)) {}
    static VmBytes address(const std::string& host,int port) {
        if(host.empty()||host.size()>255||port<1||port>65535||
            std::any_of(host.begin(),host.end(),[](unsigned char c){return c<=32||c==127;}))return {};
        VmBytes out;vmUint(out,port,2);unsigned char bytes[16];
        if(inet_pton(AF_INET,host.c_str(),bytes)==1){out.push_back(1);out.insert(out.end(),bytes,bytes+4);}
        else if(inet_pton(AF_INET6,host.c_str(),bytes)==1){out.push_back(3);out.insert(out.end(),bytes,bytes+16);}
        else {out.push_back(2);out.push_back(static_cast<unsigned char>(host.size()));vmAppend(out,vmBytes(host));}
        return out;
    }
    static bool source(const unsigned char* bytes,size_t length,VmBytes& socks) {
        if(length<3)return false;
        const int port=(bytes[0]<<8)|bytes[1];const unsigned char kind=bytes[2];
        std::string host;char text[INET6_ADDRSTRLEN]{};
        if(kind==1||kind==3) {
            const size_t size=kind==1?4:16;
            if(length<3+size||!inet_ntop(kind==1?AF_INET:AF_INET6,bytes+3,text,sizeof(text)))return false;
            host=text;
        } else if(kind==2) {
            if(length<4||!bytes[3]||length<4+static_cast<size_t>(bytes[3]))return false;
            host.assign(reinterpret_cast<const char*>(bytes+4),bytes[3]);
        } else return false;
        if(address(host,port).empty())return false;
        socks=shadowsocksAddress(host,port);return !socks.empty();
    }
    bool fail(int error) {failure=error?error:EIO;errno=failure;return false;}
    size_t available() const {return input.size()-offset;}
    bool fill(size_t length,bool nonblocking) {
        while(available()<length) {
            VmBytes part;
            if(!receive(part,nonblocking)) {
                if(errno==EAGAIN||errno==EWOULDBLOCK)return false;
                if(errno)return fail(errno);
                if(available())return fail(EPROTO);
                ended=true;return false;
            }
            if(part.empty()||available()+part.size()>MaxPayload+MaxMetadata+16392)return fail(EPROTO);
            if(offset){input.erase(input.begin(),input.begin()+offset);offset=0;}
            vmAppend(input,part);
        }
        return true;
    }
    bool writeDatagram(const VmBytes& payload) {
        if(failure||ended){errno=failure?failure:EPIPE;return false;}
        if(payload.size()>MaxPayload){errno=EMSGSIZE;return false;}
        const auto target=address(destination,port);
        if(target.empty()||(!globalId.empty()&&globalId.size()!=8)){errno=EINVAL;return false;}
        VmBytes metadata{0,0,static_cast<unsigned char>(sent?2:1),1,2};vmAppend(metadata,target);
        if(!sent&&!globalId.empty())vmAppend(metadata,globalId);
        VmBytes packet;vmUint(packet,metadata.size(),2);vmAppend(packet,metadata);vmUint(packet,payload.size(),2);vmAppend(packet,payload);
        if(!send(packet.data(),packet.size()))return fail(errno);
        sent=true;return true;
    }
    bool readDatagram(VmBytes& output,bool nonblocking=false) {
        output.clear();errno=0;if(failure){errno=failure;return false;}if(ended)return false;
        for(unsigned control=0;control<32;++control) {
            if(!fill(2,nonblocking))return false;
            const size_t length=(static_cast<size_t>(input[offset])<<8)|input[offset+1];
            if(length<4||length>MaxMetadata)return fail(EPROTO);
            if(!fill(2+length,nonblocking))return false;
            const auto* metadata=input.data()+offset+2;
            const unsigned status=metadata[2],options=metadata[3];
            if(metadata[0]||metadata[1]||(options&~3u)||status<2||status>4)return fail(EPROTO);
            if(options&2)return fail(ECONNRESET);
            if(status==3){ended=true;return false;}
            VmBytes reply;
            if(status==2) {
                if(length==4)reply=shadowsocksAddress(fallback.empty()?destination:fallback,port);
                else if(metadata[4]!=2||!source(metadata+5,length-5,reply))return fail(EPROTO);
                if(reply.empty())return fail(EPROTO);
            }
            size_t total=2+length,size=0;
            if(options&1) {
                if(!fill(total+2,nonblocking))return false;
                size=(static_cast<size_t>(input[offset+total])<<8)|input[offset+total+1];total+=2;
                if(size>MaxPayload)return fail(EMSGSIZE);
                if(!fill(total+size,nonblocking))return false;
            }
            if(status==2&&(options&1)) {
                output=std::move(reply);output.insert(output.end(),input.begin()+offset+total,input.begin()+offset+total+size);
                offset+=total+size;return true; // An empty datagram remains a packet.
            }
            offset+=total+size;
        }
        errno=EAGAIN;return false; // Bound control-only bursts without recursive reads.
    }
    bool pending() const {
        if(failure||ended)return false;
        const size_t size=available();
        if(size>=2) {
            const size_t metadata=(static_cast<size_t>(input[offset])<<8)|input[offset+1];
            if(metadata<4||metadata>MaxMetadata)return true;
            if(size>=2+metadata) {
                const auto* header=input.data()+offset+2;
                if(header[0]||header[1]||header[2]<2||header[2]>4||(header[3]&~1u))return true;
                if(input[offset+4]==3||!(input[offset+5]&1))return true;
                if(size>=4+metadata) {
                    const size_t payload=(static_cast<size_t>(input[offset+2+metadata])<<8)|input[offset+3+metadata];
                    if(payload>MaxPayload||size>=4+metadata+payload)return true;
                }
            }
        }
        return upstreamPending();
    }
};
