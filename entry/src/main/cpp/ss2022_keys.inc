// SIP022 keys are decoded directly, never passed through EVP_BytesToKey.
using SsBytes = std::vector<unsigned char>;
using SsKeys = std::vector<SsBytes>;
SsKeys ss2022Keys(SsCipher method,const std::string& text)
{
    if(!isSs2022(method)||text.empty()||text.size()>512)return {};
    SsKeys keys;size_t begin=0;
    do {
        const size_t end=text.find(':',begin);std::string part=text.substr(begin,end==std::string::npos?end:end-begin);
        if(part.empty()||part.size()>44||std::any_of(part.begin(),part.end(),[](unsigned char c){return !(std::isalnum(c)||c=='+'||c=='/'||c=='=');}))return {};
        while(part.size()%4)part+='=';
        SsBytes key(48);size_t size=0;
        if(mbedtls_base64_decode(key.data(),key.size(),&size,reinterpret_cast<const unsigned char*>(part.data()),part.size())||size!=shadowsocksKeySize(method))return {};
        key.resize(size);unsigned char canonical[65]={};size_t length=0;
        if(mbedtls_base64_encode(canonical,sizeof(canonical),&length,key.data(),key.size())||part!=std::string(reinterpret_cast<char*>(canonical),length))return {};
        keys.push_back(std::move(key));if(keys.size()>9||(method==SsCipher::ChaCha2022&&keys.size()>1))return {};
        if(end==std::string::npos)break;begin=end+1;
    }while(begin<=text.size());
    return keys;
}
