// Independent bounded readers for YAML/text rules and the published MRS v1 wire layout.
// Wire references: mihomo rules/provider/mrs_reader.go, component/{trie,cidr}/*_bin.go.
constexpr size_t RULE_MAX_COUNT = 1000000, RULE_MAX_NODES = 4 * 1024 * 1024;
constexpr size_t RULE_DECODE_LIMIT = 64 * 1024 * 1024;

bool ruleReverse(const std::string& input, std::string& output)
{
    std::vector<std::pair<size_t,size_t>> runes;
    for (size_t i=0; i<input.size();) {
        const unsigned char lead=input[i]; size_t length=lead<128?1:lead>=0xc2&&lead<=0xdf?2:lead>=0xe0&&lead<=0xef?3:lead>=0xf0&&lead<=0xf4?4:0;
        if(length==0||length>input.size()-i)return false;
        uint32_t rune=lead & (length==1?0x7f:length==2?0x1f:length==3?0x0f:7);
        for(size_t j=1;j<length;++j){const unsigned char byte=input[i+j];if((byte&0xc0)!=0x80)return false;rune=(rune<<6)|(byte&63);}
        if((length==2&&rune<128)||(length==3&&rune<2048)||(length==4&&rune<65536)||rune>0x10ffff||(rune>=0xd800&&rune<=0xdfff))return false;
        runes.push_back({i,length});i+=length;
    }
    output.clear();output.reserve(input.size());
    for(auto it=runes.rbegin();it!=runes.rend();++it)output.append(input,it->first,it->second);
    return true;
}
bool ruleDomainKeys(std::string domain,std::vector<std::string>& keys)
{
    domain=lower(trim(domain));if(domain.empty()||domain.size()>1024)return false;
    if(domain.back()=='.')domain.pop_back();
    bool inclusive=domain.rfind("+.",0)==0, suffix=domain.front()=='.';
    if(inclusive)domain.erase(0,2);else if(suffix)domain.erase(0,1);
    if(domain.empty())return false;
    std::istringstream input(domain);std::string label;
    if(domain.back()=='.')return false;
    while(std::getline(input,label,'.')) {
        if(label.empty()||label.size()>255)return false;
        if(label!="*"&&std::any_of(label.begin(),label.end(),[](unsigned char c){return c<=32||c==127||c=='*'||c=='+'||c=='/'||c=='\\'||c==','||c==':'||c=='#'||c=='?'||c=='@';}))return false;
    }
    std::string reversed;if(!ruleReverse(domain,reversed))return false;
    if(!suffix)keys.push_back(reversed);
    if(suffix||inclusive)keys.push_back(reversed+".+");
    return true;
}
bool buildRuleDomains(const std::vector<std::string>& payload,RuleDomainIndex& index,std::string& error)
{
    std::vector<std::string> keys;
    for(const auto& pattern:payload)if(!ruleDomainKeys(pattern,keys)){error="Invalid domain rule in provider";return false;}
    std::sort(keys.begin(),keys.end());keys.erase(std::unique(keys.begin(),keys.end()),keys.end());
    index={};
    struct Span{size_t first,last,depth;};std::vector<Span> queue{{0,keys.size(),0}},next;
    size_t node=0;
    while(!queue.empty()) {
        for(auto span:queue) {
            if(node>=RULE_MAX_NODES){error="Domain rule trie exceeds its node limit";return false;}
            index.edges.push_back(static_cast<uint32_t>(index.labels.size()));
            if(index.leaves.size()<=node/64)index.leaves.push_back(0);
            if(span.first<span.last&&keys[span.first].size()==span.depth){index.leaves[node/64]|=uint64_t(1)<<(node%64);++span.first;}
            for(size_t first=span.first;first<span.last;) {
                const auto byte=static_cast<unsigned char>(keys[first][span.depth]);size_t last=first+1;
                while(last<span.last&&keys[last][span.depth]==keys[first][span.depth])++last;
                index.labels.push_back(byte);next.push_back({first,last,span.depth+1});first=last;
            }
            ++node;
        }
        queue.swap(next);next.clear();
    }
    index.edges.push_back(static_cast<uint32_t>(index.labels.size()));return true;
}
bool RuleDomainIndex::matches(const std::string& host) const
{
    if(edges.size()<2||host.empty()||host.size()>1024)return false;
    std::string normalized=lower(host);if(normalized.back()=='.')normalized.pop_back();
    if(normalized.empty()||normalized.front()=='.'||normalized.back()=='.'||normalized.find("..")!=std::string::npos)return false;
    std::string key;if(!ruleReverse(normalized,key))return false;
    struct Cursor{uint32_t node;size_t offset;};std::vector<Cursor> stack{{0,0}};
    while(!stack.empty()) {
        const auto state=stack.back();stack.pop_back();
        if(state.offset==key.size()) {
            if((leaves[state.node/64]>>(state.node%64))&1)return true;
            continue;
        }
        for(uint32_t edge=edges[state.node];edge<edges[state.node+1];++edge) {
            const unsigned char label=labels[edge];
            if(label=='+')return true;
            if(label=='*') {
                size_t end=key.find('.',state.offset);if(end==std::string::npos)end=key.size();
                if(end>state.offset)stack.push_back({edge+1,end});
            } else if(label==static_cast<unsigned char>(key[state.offset]))stack.push_back({edge+1,state.offset+1});
        }
    }
    return false;
}
std::vector<std::string> RuleDomainIndex::preview(size_t limit) const
{
    std::vector<std::string> result;if(edges.size()<2)return result;
    struct Cursor{uint32_t node;std::string key;};std::vector<Cursor> stack{{0,""}};
    while(!stack.empty()&&result.size()<limit) {
        auto state=std::move(stack.back());stack.pop_back();
        if((leaves[state.node/64]>>(state.node%64))&1) {
            std::string value=state.key;if(!value.empty()&&value.back()=='+')value.pop_back();
            std::string reversed;if(ruleReverse(value,reversed))result.push_back(std::move(reversed));
        }
        for(uint32_t edge=edges[state.node+1];edge>edges[state.node];) {
            --edge;stack.push_back({edge+1,state.key+static_cast<char>(labels[edge])});
        }
    }
    return result;
}
bool ruleIpAddress(const std::string& text,int& family,std::array<unsigned char,16>& output)
{
    output={};in_addr ipv4{};in6_addr ipv6{};
    if(inet_pton(AF_INET,text.c_str(),&ipv4)==1){family=4;output[10]=output[11]=255;std::memcpy(output.data()+12,&ipv4,4);return true;}
    if(inet_pton(AF_INET6,text.c_str(),&ipv6)!=1)return false;
    std::memcpy(output.data(),&ipv6,16);family=6;
    if(std::all_of(output.begin(),output.begin()+10,[](unsigned char b){return b==0;})&&output[10]==255&&output[11]==255)family=4;
    return true;
}
bool parseRuleCidr(const std::string& text,RuleIpRange& range)
{
    const size_t slash=text.find('/');if(slash==std::string::npos)return false;
    int family=0;std::array<unsigned char,16> address{};
    if(!ruleIpAddress(text.substr(0,slash),family,address))return false;
    const std::string raw=text.substr(slash+1);if(raw.empty()||raw.size()>3||!std::all_of(raw.begin(),raw.end(),[](unsigned char b){return std::isdigit(b);}))return false;
    int prefix=std::atoi(raw.c_str());const bool ipv4=text.substr(0,slash).find(':')==std::string::npos;
    if(prefix>(ipv4?32:128))return false;if(ipv4)prefix+=96;
    range.family=family;range.first=range.last=address;
    for(int bit=prefix;bit<128;++bit){const unsigned char mask=1<<(7-bit%8);range.first[bit/8]&=~mask;range.last[bit/8]|=mask;}
    if(!ipv4&&family==4&&prefix<96)return false;
    return true;
}
void mergeRuleRanges(std::vector<RuleIpRange>& ranges)
{
    std::sort(ranges.begin(),ranges.end(),[](const auto& a,const auto& b){return std::tie(a.family,a.first,a.last)<std::tie(b.family,b.first,b.last);});
    std::vector<RuleIpRange> merged;
    for(const auto& range:ranges) {
        if(!merged.empty()&&merged.back().family==range.family&&range.first<=merged.back().last)merged.back().last=std::max(merged.back().last,range.last);
        else merged.push_back(range);
    }
    ranges=std::move(merged);
}
bool ruleRangesMatch(const std::vector<RuleIpRange>& ranges,const std::string& host)
{
    RuleIpRange query;if(!ruleIpAddress(host,query.family,query.first))return false;
    auto found=std::upper_bound(ranges.begin(),ranges.end(),query,[](const auto& a,const auto& b){return std::tie(a.family,a.first)<std::tie(b.family,b.first);});
    if(found==ranges.begin())return false;--found;
    return found->family==query.family&&query.first>=found->first&&query.first<=found->last;
}
std::vector<std::string> splitRuleFields(const std::string& text)
{
    std::vector<std::string> fields;size_t start=0;int depth=0;
    for(size_t i=0;i<text.size();++i) {
        if(text[i]=='('){if(++depth>32)return {};}
        else if(text[i]==')'){if(--depth<0)return {};}
        else if(text[i]==','&&depth==0){fields.push_back(trim(text.substr(start,i-start)));start=i+1;}
    }
    if(depth!=0)return {};fields.push_back(trim(text.substr(start)));return fields;
}
bool rulePortPattern(const std::string& value,int port,bool validateOnly=false)
{
    std::istringstream input(value);std::string token;bool matched=false;int count=0;
    if(value.empty()||value.back()=='/')return false;
    while(std::getline(input,token,'/')) {
        if(++count>64)return false;const size_t dash=token.find('-');
        auto number=[](const std::string& raw,int& result){if(raw.empty()||raw.size()>5||!std::all_of(raw.begin(),raw.end(),[](unsigned char b){return std::isdigit(b);}))return false;result=std::atoi(raw.c_str());return result>0&&result<=65535;};
        int first=0,last=0;if(!number(token.substr(0,dash),first))return false;
        if(dash==std::string::npos)last=first;else if(!number(token.substr(dash+1),last)||last<first)return false;
        if(port>=first&&port<=last)matched=true;
    }
    return validateOnly||matched;
}
bool parseRuleExpression(const std::string& text,ProxyRule& rule,bool classical,std::string& error,size_t depth=0)
{
    if(depth>32||text.empty()||text.size()>16384){error="Routing expression exceeds its size/depth limit";return false;}
    auto fields=splitRuleFields(text);if(fields.empty()){error="Unbalanced routing expression";return false;}
    rule={};rule.kind=lower(fields[0]);if(rule.kind=="final")rule.kind="match";
    const bool logical=rule.kind=="and"||rule.kind=="or"||rule.kind=="not";
    const size_t arguments=rule.kind=="match"?1:2,expected=arguments+(classical?0:1);
    if(fields.size()!=expected&&!(fields.size()==expected+1&&lower(fields.back())=="no-resolve")){error="Invalid routing rule fields";return false;}
    rule.noResolve=fields.size()>expected;
    if(!classical)rule.target=fields[arguments];
    if(arguments==2)rule.value=fields[1];
    if(logical) {
        if(rule.value.size()<2||rule.value.front()!='('||rule.value.back()!=')'){error="Logical rule requires a parenthesized condition list";return false;}
        const auto children=splitRuleFields(rule.value.substr(1,rule.value.size()-2));
        if(children.empty()||children.size()>128||(rule.kind=="not"&&children.size()!=1)){error="Invalid logical rule conditions";return false;}
        for(const auto& child:children) {
            if(child.size()<2||child.front()!='('||child.back()!=')'){error="Logical conditions must be parenthesized";return false;}
            ProxyRule condition;if(!parseRuleExpression(child.substr(1,child.size()-2),condition,true,error,depth+1))return false;
            rule.conditions.push_back(std::move(condition));
        }
        return true;
    }
    if(rule.kind=="domain"||rule.kind=="domain-suffix"||rule.kind=="domain-keyword"||rule.kind=="rule-set") {
        if(rule.value.empty()||rule.value.find('\0')!=std::string::npos){error="Routing rule requires a non-empty pattern";return false;}return true;
    }
    if(rule.kind=="domain-wildcard") {rule.domainPattern=std::make_shared<RuleDomainIndex>();return buildRuleDomains({rule.value},*rule.domainPattern,error);}
    if(rule.kind=="domain-regex") {rule.pattern=std::make_shared<ProviderPattern>(rule.value);if(!rule.pattern->valid){error="Invalid domain regex";return false;}return true;}
    if(rule.kind=="ip-cidr"||rule.kind=="ip-cidr6"||rule.kind=="src-ip-cidr"||rule.kind=="src-ip-cidr6") {
        RuleIpRange range;if(!parseRuleCidr(rule.value,range)){error="Invalid routing CIDR";return false;}return true;
    }
    if(rule.kind=="dst-port"){if(!rulePortPattern(rule.value,0,true)){error="Invalid destination port rule";return false;}return true;}
    if(rule.kind=="network"){const auto network=lower(rule.value);if(network!="tcp"&&network!="udp"){error="Invalid network rule";return false;}return true;}
    if(rule.kind=="match")return true;
    if(rule.kind=="geoip"||rule.kind=="src-geoip"||rule.kind=="geosite") {
        if(!geoTag(rule.value)){error="Invalid GeoData category";return false;}return true;
    }
    if(rule.kind=="ip-asn"||rule.kind=="src-ip-asn") {
        if(rule.value.empty()||rule.value.size()>10||!std::all_of(rule.value.begin(),rule.value.end(),[](unsigned char c){return std::isdigit(c);})||std::strtoull(rule.value.c_str(),nullptr,10)>0xffffffffULL){error="Invalid IP ASN number";return false;}return true;
    }
    error="Unsupported classical rule type: "+rule.kind;return false;
}
struct RuleBinaryReader {
    const std::string& data;size_t offset=0;
    bool bytes(size_t count,std::string& output){if(count>data.size()-offset)return false;output.assign(data,offset,count);offset+=count;return true;}
    bool number(size_t count,uint64_t& value){if(count>data.size()-offset)return false;value=0;for(size_t i=0;i<count;++i)value=(value<<8)|static_cast<unsigned char>(data[offset++]);return true;}
    bool words(std::vector<uint64_t>& output,size_t maximum){uint64_t length;if(!number(8,length)||length<1||length>maximum||length>(data.size()-offset)/8)return false;output.resize(length);for(auto& word:output)if(!number(8,word))return false;return true;}
};
bool decodeRuleZstd(const std::string& input,std::string& output,std::string& error)
{
    ZSTD_DCtx* context=ZSTD_createDCtx();if(context==nullptr){error="Cannot allocate MRS decompressor";return false;}
    size_t status=ZSTD_DCtx_setParameter(context,ZSTD_d_windowLogMax,26);
    ZSTD_inBuffer source{input.data(),input.size(),0};std::array<char,65536> bytes{};output.clear();
    while(!ZSTD_isError(status)) {
        ZSTD_outBuffer target{bytes.data(),bytes.size(),0};status=ZSTD_decompressStream(context,&target,&source);
        if(target.pos>RULE_DECODE_LIMIT-output.size()){error="Decoded MRS exceeds 64 MB";break;}
        output.append(bytes.data(),target.pos);
        if(status==0||ZSTD_isError(status))break;
        if(source.pos==source.size&&target.pos==0){error="Truncated MRS compression frame";break;}
    }
    const bool ok=error.empty()&&!ZSTD_isError(status)&&status==0&&source.pos==source.size;
    ZSTD_freeDCtx(context);if(!ok){output.clear();if(error.empty())error="Invalid MRS compression or trailing frame";}return ok;
}
bool decodeRuleMrs(const RuleProvider& provider,const std::string& input,RuleData& output,std::string& error)
{
    std::string decoded;if(!decodeRuleZstd(input,decoded,error))return false;
    RuleBinaryReader reader{decoded};std::string magic;uint64_t behavior,count,extra,version;
    if(!reader.bytes(4,magic)||magic!=std::string("MRS\1",4)||!reader.number(1,behavior)||behavior!=(provider.behavior=="domain"?0:1)||
        !reader.number(8,count)||count==0||count>RULE_MAX_COUNT||!reader.number(8,extra)||extra>decoded.size()-reader.offset){error="Invalid MRS header, behavior or rule count";return false;}
    reader.offset+=extra;if(!reader.number(1,version)||version!=1){error="Unsupported MRS strategy version";return false;}
    output.count=count;
    if(provider.behavior=="domain") {
        auto& index=output.domains;std::vector<uint64_t> bitmap;uint64_t labelCount;
        if(!reader.words(index.leaves,(RULE_MAX_NODES+63)/64)||!reader.words(bitmap,(2*RULE_MAX_NODES+63)/64)||
            !reader.number(8,labelCount)||labelCount<1||labelCount>=RULE_MAX_NODES||labelCount>decoded.size()-reader.offset){error="Invalid MRS domain arrays";return false;}
        index.labels.assign(decoded.begin()+reader.offset,decoded.begin()+reader.offset+labelCount);reader.offset+=labelCount;
        const size_t nodes=labelCount+1,bits=2*nodes-1;
        if(index.leaves.size()!=(nodes+63)/64||bitmap.size()!=(bits+63)/64){error="Inconsistent MRS domain bitmap lengths";return false;}
        if((nodes%64&&index.leaves.back()>>(nodes%64))||(bits%64&&bitmap.back()>>(bits%64))){error="Invalid MRS domain padding";return false;}
        if(index.leaves[0]&1){error="MRS domain trie contains an empty pattern";return false;}
        size_t node=0,edge=0;std::vector<uint16_t> depths(nodes,0);std::vector<unsigned char> utf8(nodes,0);
        for(size_t bit=0;bit<bits;++bit) {
            if(node>=nodes){error="Invalid MRS domain node count";return false;}
            if(index.edges.size()==node)index.edges.push_back(edge);
            if((bitmap[bit/64]>>(bit%64))&1) {
                if(((index.leaves[node/64]>>(node%64))&1)&&utf8[node]!=0){error="Truncated UTF-8 in MRS domain pattern";return false;}
                if(edge==index.edges[node]&&((index.leaves[node/64]>>(node%64))&1)==0){error="MRS domain contains a dead branch";return false;}
                ++node;
            } else {
                if(edge>=labelCount||edge+1<=node){error="Invalid MRS domain topology";return false;}
                const unsigned char label=index.labels[edge];
                if(label<=32||label==127||label=='/'||label=='\\'||label==','||label==':'||label=='#'||label=='?'||label=='@'||
                    (edge>index.edges[node]&&index.labels[edge-1]>=label)){error="Invalid or unsorted MRS domain edge";return false;}
                if((label=='+'&&(node==0||index.labels[node-1]!='.'))||(label=='*'&&node>0&&index.labels[node-1]!='.')||
                    (node>0&&(index.labels[node-1]=='+'||(index.labels[node-1]=='*'&&label!='.')))){error="Invalid MRS domain wildcard";return false;}
                const unsigned char previous=utf8[node];int next=-1;
                if(previous==0) {
                    if(label<128)next=0;else if(label>=0xc2&&label<=0xdf)next=1;
                    else if(label==0xe0)next=4;else if(label==0xed)next=5;else if(label>=0xe1&&label<=0xef)next=2;
                    else if(label==0xf0)next=6;else if(label==0xf4)next=7;else if(label>=0xf1&&label<=0xf3)next=3;
                } else {
                    const unsigned char minimum=previous==4?0xa0:previous==6?0x90:0x80,maximum=previous==5?0x9f:previous==7?0x8f:0xbf;
                    if(label>=minimum&&label<=maximum)next=previous<=3?previous-1:previous<=5?1:2;
                }
                if(next<0){error="Invalid UTF-8 in MRS domain trie";return false;}utf8[edge+1]=static_cast<unsigned char>(next);
                depths[edge+1]=depths[node]+1;if(depths[edge+1]>1024){error="MRS domain path is too long";return false;}
                ++edge;
            }
        }
        if(node!=nodes||edge!=labelCount){error="Incomplete MRS domain tree";return false;}index.edges.push_back(edge);
    } else {
        uint64_t length;if(!reader.number(8,length)||length<1||length>RULE_MAX_COUNT||length>(decoded.size()-reader.offset)/32){error="Invalid MRS IP range count";return false;}
        for(uint64_t i=0;i<length;++i) {
            RuleIpRange range;std::string bytes;if(!reader.bytes(32,bytes))return false;
            std::copy_n(reinterpret_cast<const unsigned char*>(bytes.data()),16,range.first.begin());std::copy_n(reinterpret_cast<const unsigned char*>(bytes.data()+16),16,range.last.begin());
            auto family=[](const auto& a){return std::all_of(a.begin(),a.begin()+10,[](unsigned char b){return b==0;})&&a[10]==255&&a[11]==255?4:6;};
            range.family=family(range.first);
            if(range.family!=family(range.last)||range.first>range.last){error="Invalid MRS IP range";return false;}output.ranges.push_back(range);
        }
        mergeRuleRanges(output.ranges);
    }
    if(reader.offset!=decoded.size()){error="Trailing MRS strategy data";return false;}return true;
}
bool compileRulePayload(const RuleProvider& provider,const std::vector<std::string>& payload,std::shared_ptr<const RuleData>& result,std::string& error)
{
    if(payload.size()>RULE_MAX_COUNT){error="Rule provider exceeds one million entries";return false;}
    auto data=std::make_shared<RuleData>();data->count=payload.size();
    if(provider.behavior=="domain") {if(!buildRuleDomains(payload,data->domains,error))return false;}
    else if(provider.behavior=="ipcidr") {
        for(const auto& value:payload){RuleIpRange range;if(!parseRuleCidr(trim(value),range)){error="Invalid CIDR in rule provider";return false;}data->ranges.push_back(range);}
        mergeRuleRanges(data->ranges);
    } else for(const auto& value:payload) {ProxyRule rule;if(!parseRuleExpression(trim(value),rule,true,error))return false;data->classical.push_back(std::move(rule));}
    result=std::move(data);return true;
}
bool parseRuleContent(const RuleProvider& provider,const std::string& body,std::shared_ptr<const RuleData>& result,std::string& error)
{
    error.clear();if(body.empty()||body.size()>provider.sizeLimit){error="Rule provider content is empty or exceeds its size limit";return false;}
    if(provider.format=="mrs") {auto data=std::make_shared<RuleData>();if(!decodeRuleMrs(provider,body,*data,error))return false;result=std::move(data);return true;}
    std::vector<std::string> payload;
    if(provider.format=="text") {
        std::istringstream input(body);std::string line;
        while(std::getline(input,line)){line=trim(line);if(line.empty()||line[0]=='#'||line.rfind("//",0)==0)continue;payload.push_back(line);if(payload.size()>RULE_MAX_COUNT){error="Too many rule provider entries";return false;}}
    } else {
        yaml_parser_t parser;if(!yaml_parser_initialize(&parser)){error="Cannot allocate rule YAML parser";return false;}
        yaml_parser_set_input_string(&parser,reinterpret_cast<const unsigned char*>(body.data()),body.size());yaml_document_t document;
        if(!yaml_parser_load(&parser,&document)){yaml_parser_delete(&parser);error="Invalid rule provider YAML";return false;}
        auto* root=yaml_document_get_root_node(&document);auto* list=yamlValue(document,root,"payload");if(list==nullptr)list=yamlValue(document,root,"rules");
        bool ok=list!=nullptr&&list->type==YAML_SEQUENCE_NODE;
        if(ok)for(auto* item=list->data.sequence.items.start;item<list->data.sequence.items.top;++item) {
            auto* entry=yaml_document_get_node(&document,*item);if(entry->type!=YAML_SCALAR_NODE||payload.size()>=RULE_MAX_COUNT){ok=false;break;}payload.push_back(yamlText(entry));
        }
        yaml_document_delete(&document);
        if(ok){yaml_document_t extra;if(!yaml_parser_load(&parser,&extra))ok=false;else{if(yaml_document_get_root_node(&extra)!=nullptr)ok=false;yaml_document_delete(&extra);}}
        yaml_parser_delete(&parser);if(!ok){error="Rule provider requires one YAML document with a payload/rules list";return false;}
    }
    return compileRulePayload(provider,payload,result,error);
}
