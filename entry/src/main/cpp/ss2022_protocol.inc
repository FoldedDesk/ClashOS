// SIP022/SIP023 client: distinct from legacy AEAD framing and key derivation.
SsBytes ss2022Hash(const SsBytes& material,size_t size,const char* context=nullptr)
{
    SsBytes result(size);blake3_hasher hash;
    if(context)blake3_hasher_init_derive_key(&hash,context);else blake3_hasher_init(&hash);
    blake3_hasher_update(&hash,material.data(),material.size());blake3_hasher_finalize(&hash,result.data(),result.size());
    return result;
}
SsBytes ss2022Subkey(const SsBytes& key,const SsBytes& salt,const char* context="shadowsocks 2022 session subkey")
{
    SsBytes material=key;material.insert(material.end(),salt.begin(),salt.end());return ss2022Hash(material,key.size(),context);
}
void ss2022Append(SsBytes& target,const SsBytes& value) { target.insert(target.end(),value.begin(),value.end()); }
void ss2022Put(SsBytes& out,uint64_t value,size_t size) { for(size_t i=0;i<size;++i)out.push_back(static_cast<unsigned char>(value>>(8*(size-1-i)))); }
uint64_t ss2022Get(const unsigned char* value,size_t size) { uint64_t out=0;for(size_t i=0;i<size;++i)out=(out<<8)|value[i];return out; }
bool ss2022Timestamp(uint64_t value) { const uint64_t now=static_cast<uint64_t>(std::time(nullptr));return value>now?value-now<=30:now-value<=30; }
bool ss2022Block(bool encrypt,const SsBytes& key,const SsBytes& input,SsBytes& output)
{
    output.clear();if((key.size()!=16&&key.size()!=32)||input.size()!=16)return false;
    mbedtls_aes_context aes;mbedtls_aes_init(&aes);output.resize(16);
    int rc=encrypt?mbedtls_aes_setkey_enc(&aes,key.data(),key.size()*8):mbedtls_aes_setkey_dec(&aes,key.data(),key.size()*8);
    if(!rc)rc=mbedtls_aes_crypt_ecb(&aes,encrypt?MBEDTLS_AES_ENCRYPT:MBEDTLS_AES_DECRYPT,input.data(),output.data());
    mbedtls_aes_free(&aes);if(rc)output.clear();return rc==0;
}
bool ss2022Seal(SsCipher method,const SsBytes& key,SsBytes& nonce,const SsBytes& plain,SsBytes& output)
{
    SsBytes cipher,tag(16);if(!validShadowsocksNonce(nonce)||!shadowsocksAead(true,method,key,nonce,plain,cipher,tag))return false;
    incrementNonce(nonce);ss2022Append(output,cipher);ss2022Append(output,tag);return true;
}
bool ss2022Open(SsCipher method,const SsBytes& key,SsBytes& nonce,const SsBytes& packet,SsBytes& plain)
{
    plain.clear();if(packet.size()<16||!validShadowsocksNonce(nonce))return false;
    SsBytes cipher(packet.begin(),packet.end()-16),tag(packet.end()-16,packet.end());
    if(!shadowsocksAead(false,method,key,nonce,cipher,plain,tag))return false;
    incrementNonce(nonce);return true;
}
size_t ss2022AddressSize(const SsBytes& bytes,size_t offset)
{
    if(offset>=bytes.size())return 0;size_t size=0;
    if(bytes[offset]==1)size=7;else if(bytes[offset]==4)size=19;
    else if(bytes[offset]==3&&offset+1<bytes.size()&&bytes[offset+1]) {
        size=4+bytes[offset+1];if(size<=bytes.size()-offset&&std::find(bytes.begin()+offset+2,bytes.begin()+offset+size-2,0)!=bytes.begin()+offset+size-2)return 0;
    }
    if(!size||size>bytes.size()-offset||!ss2022Get(bytes.data()+offset+size-2,2))return 0;return size;
}

// XChaCha20 uses the standard HChaCha20 subkey and a 96-bit nonce whose first
// four bytes are zero. AES methods use a separately encrypted 16-byte header.
SsBytes ss2022HChaCha(const SsBytes& key,const SsBytes& nonce)
{
    if(key.size()!=32||nonce.size()!=24)return {};
    auto word=[](const unsigned char* p){return uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);};
    uint32_t x[16]={0x61707865,0x3320646e,0x79622d32,0x6b206574};
    for(int i=0;i<8;++i)x[4+i]=word(key.data()+4*i);for(int i=0;i<4;++i)x[12+i]=word(nonce.data()+4*i);
    auto rotate=[](uint32_t v,unsigned bits){return (v<<bits)|(v>>(32-bits));};
    auto quarter=[&](int a,int b,int c,int d){x[a]+=x[b];x[d]=rotate(x[d]^x[a],16);x[c]+=x[d];x[b]=rotate(x[b]^x[c],12);x[a]+=x[b];x[d]=rotate(x[d]^x[a],8);x[c]+=x[d];x[b]=rotate(x[b]^x[c],7);};
    for(int i=0;i<10;++i){quarter(0,4,8,12);quarter(1,5,9,13);quarter(2,6,10,14);quarter(3,7,11,15);quarter(0,5,10,15);quarter(1,6,11,12);quarter(2,7,8,13);quarter(3,4,9,14);}
    SsBytes out;for(int i:{0,1,2,3,12,13,14,15})for(int j=0;j<4;++j)out.push_back(static_cast<unsigned char>(x[i]>>(8*j)));return out;
}
bool ss2022XChaCha(bool encrypt,const SsBytes& key,const SsBytes& nonce,const SsBytes& input,SsBytes& output)
{
    output.clear();const auto subkey=ss2022HChaCha(key,nonce);if(subkey.empty()||(!encrypt&&input.size()<16))return false;
    SsBytes shortNonce(4,0);shortNonce.insert(shortNonce.end(),nonce.begin()+16,nonce.end());SsBytes tag(16),body=input;
    if(!encrypt){tag.assign(body.end()-16,body.end());body.resize(body.size()-16);}
    if(!shadowsocksAead(encrypt,SsCipher::ChaCha2022,subkey,shortNonce,body,output,tag))return false;
    if(encrypt)ss2022Append(output,tag);return true;
}

struct Ss2022Session {
    int fd,failure=0;SsCipher method;SsKeys keys;SsBytes requestSalt,sendKey,sendNonce=SsBytes(12,0),receiveKey,receiveNonce=SsBytes(12,0),packet;
    enum class Stage { Salt,Header,Length,Payload };Stage stage=Stage::Salt;size_t received=0,payloadLength=0;bool eof=false;
    Ss2022Session(int socket,SsCipher cipher,SsKeys psk):fd(socket),method(cipher),keys(std::move(psk)),packet(shadowsocksKeySize(cipher)){}
    bool fail(int value){failure=value?value:EIO;errno=failure;return false;}
    void next(Stage value,size_t size){stage=value;received=0;packet.resize(size);}
    bool start(const std::string& host,int port) {
        if(keys.empty())return fail(EINVAL);const auto address=shadowsocksAddress(host,port);if(address.empty())return fail(EINVAL);
        requestSalt.resize(keys.back().size());SsBytes randomness(2);if(!randomBytes(requestSalt)||!randomBytes(randomness))return fail(EIO);
        sendKey=ss2022Subkey(keys.back(),requestSalt);SsBytes wire=requestSalt;
        for(size_t i=0;i+1<keys.size();++i) {
            SsBytes encrypted;if(!ss2022Block(true,ss2022Subkey(keys[i],requestSalt,"shadowsocks 2022 identity subkey"),ss2022Hash(keys[i+1],16),encrypted))return fail(EIO);ss2022Append(wire,encrypted);
        }
        const size_t paddingSize=1+ss2022Get(randomness.data(),2)%900;SsBytes padding(paddingSize);if(!randomBytes(padding))return fail(EIO);
        SsBytes variable=address;ss2022Put(variable,padding.size(),2);ss2022Append(variable,padding);
        SsBytes fixed{0};ss2022Put(fixed,static_cast<uint64_t>(std::time(nullptr)),8);ss2022Put(fixed,variable.size(),2);
        if(!ss2022Seal(method,sendKey,sendNonce,fixed,wire)||!ss2022Seal(method,sendKey,sendNonce,variable,wire)||!sendAll(fd,wire))return fail(errno);
        return true;
    }
    bool write(const char* data,size_t size) {
        if(sendKey.empty())return fail(EINVAL);
        for(size_t offset=0;offset<size;){const size_t length=std::min<size_t>(65535,size-offset);SsBytes plain(data+offset,data+offset+length),lengthBytes,wire;ss2022Put(lengthBytes,length,2);
            if(!ss2022Seal(method,sendKey,sendNonce,lengthBytes,wire)||!ss2022Seal(method,sendKey,sendNonce,plain,wire)||!sendAll(fd,wire))return fail(errno);offset+=length;}
        return true;
    }
    bool read(SsBytes& output,bool nonblocking) {
        output.clear();errno=0;if(failure){errno=failure;return false;}if(eof)return false;if(keys.empty()||requestSalt.empty())return fail(EINVAL);
        unsigned emptyFrames=0;
        for(;;) {
            if(stage!=Stage::Salt&&!validShadowsocksNonce(receiveNonce))return fail(errno);
            while(received<packet.size()) {
                if(!prepareSocketIo(fd))return fail(errno);const auto count=recv(fd,packet.data()+received,packet.size()-received,nonblocking?MSG_DONTWAIT:0);
                if(count<0){if(errno==EINTR)continue;if(nonblocking&&(errno==EAGAIN||errno==EWOULDBLOCK)){errno=EAGAIN;return false;}return fail((errno==EAGAIN||errno==EWOULDBLOCK)?ETIMEDOUT:errno);}
                if(!count){if(received||stage==Stage::Payload||stage==Stage::Header)return fail(ECONNRESET);eof=true;return false;}received+=static_cast<size_t>(count);
            }
            if(stage==Stage::Salt){receiveKey=ss2022Subkey(keys.back(),packet);next(Stage::Header,11+requestSalt.size()+16);continue;}
            SsBytes plain;if(!ss2022Open(method,receiveKey,receiveNonce,packet,plain))return fail(EBADMSG);
            if(stage==Stage::Header) {
                if(plain.size()!=11+requestSalt.size()||plain[0]!=1||!ss2022Timestamp(ss2022Get(plain.data()+1,8))||!std::equal(requestSalt.begin(),requestSalt.end(),plain.begin()+9))return fail(EBADMSG);
                payloadLength=ss2022Get(plain.data()+plain.size()-2,2);next(Stage::Payload,payloadLength+16);
            } else if(stage==Stage::Length) {
                if(plain.size()!=2)return fail(EPROTO);payloadLength=ss2022Get(plain.data(),2);next(Stage::Payload,payloadLength+16);
            } else {
                if(plain.size()!=payloadLength)return fail(EPROTO);output=std::move(plain);next(Stage::Length,18);
                if(!output.empty())return true;if(nonblocking&&++emptyFrames>=32){errno=EAGAIN;return false;}
            }
        }
    }
};

struct Ss2022ReplayWindow {
    bool initialized=false;uint64_t highest=0;std::bitset<1024> seen;
    bool accepts(uint64_t id)const{return !initialized||id>highest||(highest-id<seen.size()&&!seen[static_cast<size_t>(highest-id)]);}
    void add(uint64_t id){if(!initialized){initialized=true;highest=id;seen.reset();seen[0]=true;}else if(id>highest){const uint64_t shift=id-highest;if(shift>=seen.size())seen.reset();else seen<<=static_cast<size_t>(shift);highest=id;seen[0]=true;}else seen[static_cast<size_t>(highest-id)]=true;}
};

struct Ss2022Datagram {
    SsCipher method;SsKeys keys;SsBytes clientId,sendKey;uint64_t counter=0;bool exhausted=false;
    struct Server { Ss2022ReplayWindow window;HealthClock::time_point last; };
    std::map<std::string,Server> servers;
    Ss2022Datagram(SsCipher cipher,SsKeys psk):method(cipher),keys(std::move(psk)),clientId(8){if(!randomBytes(clientId))clientId.clear();if(!keys.empty()&&!clientId.empty())sendKey=ss2022Subkey(keys.back(),clientId);}
    size_t overhead()const{return method==SsCipher::ChaCha2022?67:43+(keys.empty()?0:16*(keys.size()-1));}
    bool encode(const SsBytes& plain,SsBytes& packet) {
        packet.clear();if(exhausted){errno=EOVERFLOW;return false;}if(keys.empty()||clientId.empty()||!ss2022AddressSize(plain,0)){errno=EINVAL;return false;}if(plain.size()>65507-overhead()){errno=EMSGSIZE;return false;}
        SsBytes separate=clientId;ss2022Put(separate,counter,8);SsBytes body{0};ss2022Put(body,static_cast<uint64_t>(std::time(nullptr)),8);ss2022Put(body,0,2);ss2022Append(body,plain);
        // Consume each packet ID before encryption/send; a failed send must never
        // reuse a nonce with a different payload on the next attempt.
        if(counter==UINT64_MAX)exhausted=true;else ++counter;
        if(method==SsCipher::ChaCha2022) {
            SsBytes nonce(24),combined=separate,cipher;ss2022Append(combined,body);if(!randomBytes(nonce)||!ss2022XChaCha(true,keys.back(),nonce,combined,cipher))return false;packet=nonce;ss2022Append(packet,cipher);
        } else {
            if(!ss2022Block(true,keys.front(),separate,packet))return false;
            for(size_t i=0;i+1<keys.size();++i){SsBytes hash=ss2022Hash(keys[i+1],16),encrypted;for(size_t j=0;j<16;++j)hash[j]^=separate[j];if(!ss2022Block(true,keys[i],hash,encrypted))return false;ss2022Append(packet,encrypted);}
            SsBytes nonce(separate.begin()+4,separate.end()),cipher,tag(16);if(!shadowsocksAead(true,method,sendKey,nonce,body,cipher,tag))return false;ss2022Append(packet,cipher);ss2022Append(packet,tag);
        }
        return true;
    }
    bool decode(const SsBytes& packet,SsBytes& plain) {
        plain.clear();errno=EBADMSG;if(keys.empty()||clientId.empty()||packet.size()>65507||packet.size()<16+16+19+7)return false;
        SsBytes separate,body;
        if(method==SsCipher::ChaCha2022) {
            if(packet.size()<24+16+16+19+7)return false;SsBytes nonce(packet.begin(),packet.begin()+24),cipher(packet.begin()+24,packet.end()),combined;
            if(!ss2022XChaCha(false,keys.back(),nonce,cipher,combined)||combined.size()<16+19+7)return false;
            separate.assign(combined.begin(),combined.begin()+16);body.assign(combined.begin()+16,combined.end());
        } else {
            if(!ss2022Block(false,keys.back(),SsBytes(packet.begin(),packet.begin()+16),separate))return false;
            const SsBytes id(separate.begin(),separate.begin()+8),key=ss2022Subkey(keys.back(),id),nonce(separate.begin()+4,separate.end()),cipher(packet.begin()+16,packet.end()-16);SsBytes tag(packet.end()-16,packet.end());
            if(!shadowsocksAead(false,method,key,nonce,cipher,body,tag))return false;
        }
        if(body.size()<19||body[0]!=1||!ss2022Timestamp(ss2022Get(body.data()+1,8))||!std::equal(clientId.begin(),clientId.end(),body.begin()+9)){errno=EBADMSG;return false;}
        const size_t padding=ss2022Get(body.data()+17,2);if(padding>body.size()-19||!ss2022AddressSize(body,19+padding)){errno=EBADMSG;return false;}
        const std::string serverId(separate.begin(),separate.begin()+8);const uint64_t id=ss2022Get(separate.data()+8,8);const auto now=HealthClock::now();auto found=servers.find(serverId);
        if(std::equal(clientId.begin(),clientId.end(),separate.begin()))return false;
        if(found!=servers.end()&&!found->second.window.accepts(id)){errno=EALREADY;return false;}
        if(found==servers.end()) {
            for(auto i=servers.begin();i!=servers.end();)if(now-i->second.last>=std::chrono::seconds(60))i=servers.erase(i);else ++i;
            if(servers.size()>=32){errno=EBADMSG;return false;}found=servers.emplace(serverId,Server{}).first;
        }
        // Authenticate and validate every field before committing replay state.
        found->second.window.add(id);found->second.last=now;plain.assign(body.begin()+19+padding,body.end());errno=0;return true;
    }
};

size_t ss2022UdpOverhead(const ProxyNode& node)
{
    const auto method=shadowsocksCipher(node.cipher);if(!isSs2022(method))return shadowsocksKeySize(method)+16;
    if(method==SsCipher::ChaCha2022)return 67;const auto keys=ss2022Keys(method,node.password);return 43+(keys.empty()?0:16*(keys.size()-1));
}

bool ss2022CryptoSelfTest()
{
    SsBytes key16(16),key32(32);for(size_t i=0;i<32;++i){key32[i]=static_cast<unsigned char>(i);if(i<16)key16[i]=static_cast<unsigned char>(i);}
    return ss2022Hash({},32)==decodeHex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")&&
        ss2022Subkey(key16,key16)==decodeHex("c9f0ab099fbde35a9cda88caa0369328")&&
        ss2022Subkey(key32,key32)==decodeHex("f13347c4d2bfa7841392e196863bc95caf554d8a793628e45ea8bbb1e24fcae1")&&
        ss2022HChaCha(key32,decodeHex("000000090000004a00000000314159270000000000000000"))==decodeHex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
}
