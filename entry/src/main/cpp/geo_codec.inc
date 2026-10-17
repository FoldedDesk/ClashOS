// The .dat wire schema is v2ray routercommon.{GeoIPList,GeoSiteList} protobuf.
// The bounded reader skips unknown protobuf fields and never casts a file into native structs.
struct GeoProto {
    std::string_view input;size_t at=0;bool valid=true;
    bool number(uint64_t& value) {
        value=0;
        for(unsigned shift=0;shift<64;shift+=7) {
            if(at>=input.size()){valid=false;return false;}
            const auto byte=static_cast<unsigned char>(input[at++]);
            if(shift==63&&byte>1){valid=false;return false;}
            value|=static_cast<uint64_t>(byte&127)<<shift;if(!(byte&128))return true;
        }
        valid=false;return false;
    }
    bool field(unsigned& key,unsigned& wire,uint64_t& value,std::string_view& bytes) {
        bytes={};value=0;if(at==input.size())return false;
        uint64_t tag=0;if(!number(tag)||tag>0xffffffffU||!(tag>>3)){valid=false;return false;}
        key=tag>>3;wire=tag&7;
        if(wire==0)return number(value);
        size_t length=0;
        if(wire==2){uint64_t size=0;if(!number(size)||size>input.size()-at){valid=false;return false;}length=size;}
        else if(wire==1)length=8;else if(wire==5)length=4;else {valid=false;return false;}
        if(length>input.size()-at){valid=false;return false;}bytes=input.substr(at,length);at+=length;return true;
    }
};
bool geoTag(const std::string& value) {
    return !value.empty()&&value.size()<=256&&std::all_of(value.begin(),value.end(),[](unsigned char c){return std::isalnum(c)||c=='-'||c=='_'||c=='!'||c=='.'||c=='@';});
}
bool geoReadCidr(std::string_view bytes,RuleIpRange& range)
{
    GeoProto reader{bytes};std::string_view ip;uint64_t prefix=0,value=0;unsigned key=0,wire=0;std::string_view data;
    while(reader.field(key,wire,value,data)) {
        if(key==1){if(wire!=2)return false;ip=data;}
        else if(key==2){if(wire!=0||value>128)return false;prefix=value;}
    }
    if(!reader.valid||(ip.size()!=4&&ip.size()!=16)||prefix>ip.size()*8)return false;
    range={};range.family=ip.size()==4?4:6;
    const size_t offset=ip.size()==4?12:0;
    if(offset){range.first[10]=range.first[11]=255;prefix+=96;}
    std::memcpy(range.first.data()+offset,ip.data(),ip.size());range.last=range.first;
    for(unsigned bit=prefix;bit<128;++bit){const unsigned char mask=1<<(7-bit%8);range.first[bit/8]&=~mask;range.last[bit/8]|=mask;}
    return true;
}
bool geoReadDomain(std::string_view bytes,GeoDomain& domain)
{
    GeoProto reader{bytes};uint64_t value=0;unsigned key=0,wire=0;std::string_view data;
    while(reader.field(key,wire,value,data)) {
        if(key==1){if(wire!=0||value>3)return false;domain.type=value;}
        else if(key==2){if(wire!=2||data.empty()||data.size()>2048||data.find('\0')!=std::string_view::npos)return false;domain.value=std::string(data);}
        else if(key==3) {
            if(wire!=2||domain.attributes.size()>=64)return false;
            GeoProto attribute{data};std::string name;uint64_t number=0;unsigned field=0,type=0;std::string_view text;
            while(attribute.field(field,type,number,text))if(field==1){if(type!=2)return false;name=lower(std::string(text));}
            if(!attribute.valid||!geoTag(name))return false;domain.attributes.insert(std::move(name));
        }
    }
    if(!reader.valid||domain.value.empty())return false;
    if(domain.type!=1)domain.value=lower(domain.value);return true;
}
bool geoReadDat(const std::string& kind,const std::string& content,std::shared_ptr<const GeoDatabase>& result,std::string& error)
{
    error.clear();
    auto database=std::make_shared<GeoDatabase>();database->kind=kind;database->bytes=content.size();
    if(content.empty()||content.size()>GEO_MAX_BYTES){error="GeoData file is empty or exceeds 64 MB";return false;}
    GeoProto list{content};uint64_t value=0;unsigned key=0,wire=0;std::string_view bytes;size_t entries=0;
    auto fail=[&](const char* reason){error=reason;return false;};
    while(list.field(key,wire,value,bytes)) {
        if(key!=1)continue;if(wire!=2||++entries>8192)return fail("Invalid GeoData entry list");
        GeoProto entry{bytes};unsigned field=0,type=0;uint64_t number=0;std::string_view data;
        std::string code;GeoIpSet ipset;std::vector<GeoDomain> domains;
        while(entry.field(field,type,number,data)) {
            if(field==1){if(type!=2)return fail("Invalid GeoData category");code=lower(std::string(data));}
            else if(field==2) {
                if(type!=2||++database->count>2000000)return fail("GeoData has too many entries");
                if(kind=="geoip"){RuleIpRange range;if(!geoReadCidr(data,range))return fail("Invalid GeoIP CIDR");ipset.ranges.push_back(range);}
                else {GeoDomain domain;if(!geoReadDomain(data,domain))return fail("Invalid GeoSite domain");domains.push_back(std::move(domain));}
            } else if(kind=="geoip"&&field==3){if(type!=0||number>1)return fail("Invalid GeoIP inverse flag");ipset.inverse=number!=0;}
        }
        if(!entry.valid||!geoTag(code))return fail("Invalid GeoData protobuf category");
        if(kind=="geoip") {
            if(database->ips.count(code))return fail("Duplicate GeoIP category");mergeRuleRanges(ipset.ranges);database->ips.emplace(std::move(code),std::move(ipset));
        } else {
            if(database->sites.count(code))return fail("Duplicate GeoSite category");database->sites.emplace(std::move(code),std::move(domains));
        }
    }
    if(!list.valid||!entries)return fail("Invalid or truncated GeoData protobuf");result=std::move(database);return true;
}
bool geoValidateMmdb(GeoDatabase& database,std::string& error)
{
    const size_t count=database.mmdb.metadata.node_count;
    if(count==0||count>8*1024*1024){error="MMDB search tree exceeds its node limit";return false;}
    std::vector<std::array<uint32_t,2>> children(count,{UINT32_MAX,UINT32_MAX});std::set<uint32_t> entries;size_t decoded=0;
    for(uint32_t i=0;i<count;++i) {
        MMDB_search_node_s node{};
        if(MMDB_read_node(&database.mmdb,i,&node)!=MMDB_SUCCESS){error="Invalid MMDB search tree";return false;}
        for(unsigned side=0;side<2;++side) {
            const auto type=side?node.right_record_type:node.left_record_type;
            const auto record=side?node.right_record:node.left_record;
            auto entry=side?node.right_record_entry:node.left_record_entry;
            if(type==MMDB_RECORD_TYPE_SEARCH_NODE) {
                if(record>=count){error="Invalid MMDB child node";return false;}children[i][side]=record;
            } else if(type==MMDB_RECORD_TYPE_DATA&&entries.insert(entry.offset).second) {
                MMDB_entry_data_list_s* list=nullptr;
                const int status=MMDB_get_entry_data_list(&entry,&list);
                bool valid=status==MMDB_SUCCESS&&list;
                if(valid)valid=database.kind=="asn"?list->entry_data.type==MMDB_DATA_TYPE_MAP:
                    list->entry_data.type==MMDB_DATA_TYPE_MAP||list->entry_data.type==MMDB_DATA_TYPE_ARRAY||list->entry_data.type==MMDB_DATA_TYPE_UTF8_STRING;
                for(auto* value=list;valid&&value;value=value->next)if(++decoded>8*1024*1024)valid=false;
                if(list)MMDB_free_entry_data_list(list);
                if(!valid){error="Invalid or excessively nested MMDB record data";return false;}
            } else if(type==MMDB_RECORD_TYPE_INVALID){error="Invalid MMDB data pointer";return false;}
        }
    }
    std::vector<unsigned char> color(count,0);
    struct Frame{uint32_t index;unsigned stage;};std::vector<Frame> stack;
    for(uint32_t root=0;root<count;++root) {
        if(color[root])continue;stack.push_back({root,0});
        while(!stack.empty()) {
            auto& frame=stack.back();if(frame.stage==0)color[frame.index]=1;
            if(frame.stage==2){color[frame.index]=2;stack.pop_back();continue;}
            const auto child=children[frame.index][frame.stage++];if(child==UINT32_MAX)continue;
            if(color[child]==1){error="Cyclic MMDB search tree";return false;}
            if(color[child]==0)stack.push_back({child,0});
        }
    }
    return true;
}
bool geoReadFile(const std::string& kind,const std::string& path,std::shared_ptr<const GeoDatabase>& result,std::string& error)
{
    error.clear();
    struct stat info{};if(stat(path.c_str(),&info)!=0||!S_ISREG(info.st_mode)||info.st_size<=0||info.st_size>static_cast<off_t>(GEO_MAX_BYTES)){error="GeoData file is unavailable, empty, or exceeds 64 MB";return false;}
    if(kind=="geoip"||kind=="geosite") {std::string content;if(!readProviderFile(path,GEO_MAX_BYTES,content,error))return false;return geoReadDat(kind,content,result,error);}
    auto database=std::make_shared<GeoDatabase>();database->kind=kind;database->bytes=info.st_size;
    const int status=MMDB_open(path.c_str(),MMDB_MODE_MMAP,&database->mmdb);
    if(status!=MMDB_SUCCESS){error="Invalid MMDB database: "+std::string(MMDB_strerror(status));return false;}
    database->opened=true;
    const std::string type=lower(database->mmdb.metadata.database_type?database->mmdb.metadata.database_type:"");
    if((kind=="asn"&&type.find("asn")==std::string::npos)||(kind=="mmdb"&&type.find("asn")!=std::string::npos)){error="MMDB database type does not match the selected resource";return false;}
    if(!geoValidateMmdb(*database,error))return false;
    database->count=database->mmdb.metadata.node_count;result=std::move(database);return true;
}
bool geoMmdbEntry(const GeoDatabase& database,const std::string& ip,MMDB_lookup_result_s& result)
{
    sockaddr_storage address{};int family=0;std::array<unsigned char,16> bytes{};
    if(!database.opened||!ruleIpAddress(ip,family,bytes))return false;
    if(family==4){auto* a=reinterpret_cast<sockaddr_in*>(&address);a->sin_family=AF_INET;std::memcpy(&a->sin_addr,bytes.data()+12,4);}
    else {auto* a=reinterpret_cast<sockaddr_in6*>(&address);a->sin6_family=AF_INET6;std::memcpy(&a->sin6_addr,bytes.data(),16);}
    int error=0;result=MMDB_lookup_sockaddr(&database.mmdb,reinterpret_cast<sockaddr*>(&address),&error);return error==MMDB_SUCCESS&&result.found_entry;
}
std::vector<std::string> geoMmdbCountries(const GeoDatabase& database,const std::string& ip)
{
    MMDB_lookup_result_s result{};if(!geoMmdbEntry(database,ip,result))return {};
    MMDB_entry_data_s value{};std::vector<std::string> countries;
    auto append=[&](){if(value.has_data&&value.type==MMDB_DATA_TYPE_UTF8_STRING&&value.data_size<=256)countries.push_back(lower(std::string(value.utf8_string,value.data_size)));};
    if(MMDB_get_value(&result.entry,&value,nullptr)==MMDB_SUCCESS) {
        if(value.type==MMDB_DATA_TYPE_UTF8_STRING)append();
        else if(value.type==MMDB_DATA_TYPE_ARRAY)for(unsigned i=0,count=std::min<uint32_t>(value.data_size,64);i<count;++i) {
            const auto index=std::to_string(i);if(MMDB_get_value(&result.entry,&value,index.c_str(),nullptr)==MMDB_SUCCESS)append();
        }
    }
    if(countries.empty())for(const char* field:{"country","registered_country"}) {
        if(MMDB_get_value(&result.entry,&value,field,"iso_code",nullptr)==MMDB_SUCCESS)append();if(!countries.empty())break;
    }
    return countries;
}
bool geoIpMatch(const GeoDatabase& database,const std::string& category,const std::string& ip)
{
    const auto key=lower(category);
    if(database.kind=="geoip") {const auto found=database.ips.find(key);return found!=database.ips.end()&&(ruleRangesMatch(found->second.ranges,ip)!=found->second.inverse);}
    const auto countries=geoMmdbCountries(database,ip);return std::find(countries.begin(),countries.end(),key)!=countries.end();
}
std::shared_ptr<const GeoSiteMatcher> geoSiteMatcher(const GeoDatabase& database,const std::string& expression)
{
    const auto key=lower(expression);std::lock_guard<std::mutex> lock(database.matcherMutex);
    const auto cached=database.matchers.find(key);if(cached!=database.matchers.end())return cached->second;
    auto matcher=std::make_shared<GeoSiteMatcher>();
    auto found=database.sites.find(key);std::vector<std::pair<std::string,bool>> filters;
    if(found==database.sites.end()) {
        const auto split=key.find('@');found=database.sites.find(key.substr(0,split));
        if(split!=std::string::npos) {
            std::istringstream input(key.substr(split+1));std::string attribute;
            while(std::getline(input,attribute,'@')) {
                const bool inverse=!attribute.empty()&&attribute.front()=='!';if(inverse)attribute.erase(0,1);
                if(!geoTag(attribute)){matcher->error="Invalid GeoSite attribute";break;}filters.push_back({attribute,inverse});
            }
        }
    }
    if(found==database.sites.end())matcher->error="GeoSite category is unavailable: "+key;
    if(matcher->error.empty()) {
        std::vector<std::string> domains;
        for(const auto& domain:found->second) {
            if(std::any_of(filters.begin(),filters.end(),[&](const auto& filter){return (domain.attributes.count(filter.first)>0)==filter.second;}))continue;
            if(domain.type==0)matcher->keywords.push_back(domain.value);
            else if(domain.type==1) {
                auto pattern=std::make_shared<ProviderPattern>(domain.value);
                if(!pattern->valid){matcher->error="Unsupported or invalid GeoSite regex in "+key;break;}matcher->patterns.push_back(std::move(pattern));
            } else domains.push_back((domain.type==2?"+.":"")+domain.value);
        }
        if(matcher->error.empty())buildRuleDomains(domains,matcher->domains,matcher->error);
    }
    if(database.matchers.size()>=256)database.matchers.erase(database.matchers.begin());database.matchers[key]=matcher;return matcher;
}
bool geoSiteMatch(const GeoSiteMatcher& matcher,const std::string& input)
{
    const auto host=lower(input);if(matcher.domains.matches(host))return true;
    for(const auto& keyword:matcher.keywords)if(host.find(keyword)!=std::string::npos)return true;
    for(const auto& pattern:matcher.patterns)if(pattern->matches(host))return true;return false;
}
