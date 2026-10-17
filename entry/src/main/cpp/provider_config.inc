// Provider schema and node filtering. No network I/O is performed while parsing a profile.
struct ProviderPattern {
    std::unique_ptr<re2::RE2> expression;bool compiled=false,valid=true;
    explicit ProviderPattern(std::string pattern) {
        if(pattern.empty())return;
        if(pattern.size()>2048){valid=false;return;}
        size_t separator;while((separator=pattern.find("```"))!=std::string::npos)pattern.replace(separator,3,"|");
        re2::RE2::Options options;options.set_log_errors(false);options.set_max_mem(2*1024*1024);
        expression=std::make_unique<re2::RE2>(pattern,options);valid=expression->ok();compiled=valid;
    }
    bool matches(const std::string& value) const {return valid&&(!expression||re2::RE2::PartialMatch(value,*expression));}
    ProviderPattern(const ProviderPattern&)=delete;
};
bool validProviderPattern(const std::string& pattern){return ProviderPattern(pattern).valid;}
bool applyProviderOptions(const ProxyProvider& provider,std::vector<ProxyNode>& nodes,std::string& error)
{
    ProviderPattern include(provider.filter),exclude(provider.excludeFilter);
    if(!include.valid||!exclude.valid){error="Invalid provider filter";return false;}
    std::set<std::string> excluded;std::istringstream types(lower(provider.excludeType));std::string type;
    while(std::getline(types,type,'|')){if(type=="shadowsocks")type="ss";excluded.insert(trim(type));}
    std::vector<ProxyNode> selected;std::set<std::string> names={"DIRECT","REJECT"};
    for(ProxyNode& node:nodes) {
        if(node.name.size()>4096){error="Provider proxy name exceeds 4096 bytes";return false;}
        if(!include.matches(node.name)||(!provider.excludeFilter.empty()&&exclude.matches(node.name))||excluded.count(node.type))continue;
        node.name=provider.prefix+node.name+provider.suffix;node.provider=provider.name;
        if(provider.overrideUdp>=0){node.udp=provider.overrideUdp!=0;node.udpConfigured=true;}
        if(provider.overrideSkipVerify>=0)node.skipCertVerify=provider.overrideSkipVerify!=0;
        if(node.name.empty()||!names.insert(node.name).second){error="Provider overrides produced duplicate/reserved proxy names";return false;}
        selected.push_back(std::move(node));
    }
    nodes=std::move(selected);return true;
}
bool parseProviderDefinitions(yaml_document_t& document,yaml_node_t* root,std::vector<ProxyProvider>& providers,std::string& error)
{
    yaml_node_t* map=yamlValue(document,root,"proxy-providers");if(map==nullptr)return true;
    if(map->type!=YAML_MAPPING_NODE){error="proxy-providers must be a mapping";return false;}
    auto text=[&](yaml_node_t* value,const char* key){return yamlText(yamlValue(document,value,key));};
    auto number=[&](yaml_node_t* source,const char* key,int& output,int low,int high) {
        const std::string value=text(source,key);if(value.empty())return true;
        char* end=nullptr;const long parsed=std::strtol(value.c_str(),&end,10);
        if(end==value.c_str()||*end!='\0'||parsed<low||parsed>high)return false;output=static_cast<int>(parsed);return true;
    };
    std::set<std::string> names;
    for(yaml_node_pair_t* pair=map->data.mapping.pairs.start;pair<map->data.mapping.pairs.top;++pair) {
        ProxyProvider provider;provider.name=yamlText(yaml_document_get_node(&document,pair->key));
        yaml_node_t* source=yaml_document_get_node(&document,pair->value);
        if(provider.name.empty()||provider.name.size()>256||!names.insert(provider.name).second||source->type!=YAML_MAPPING_NODE){error="Provider names must be unique and values must be mappings";return false;}
        provider.type=lower(text(source,"type"));provider.url=text(source,"url");provider.path=text(source,"path");
        if(provider.type!="http"&&provider.type!="file"&&provider.type!="inline"){error="Provider type must be http, file or inline";return false;}
        if(provider.type=="http"&&!validProbeUrl(provider.url)){error="HTTP provider requires a valid HTTP(S) URL";return false;}
        if(provider.type=="file"&&provider.path.empty()){error="File provider requires path";return false;}
        const std::string route=text(source,"proxy");if(!route.empty())provider.downloadProxy=route;
        if(!number(source,"interval",provider.interval,0,604800)||!number(source,"timeout",provider.timeout,100,60000)){error="Invalid provider update interval or timeout";return false;}
        int size=0;if(!number(source,"size-limit",size,0,8*1024*1024)){error="Provider size-limit must be between 0 and 8 MB";return false;}if(size>0)provider.sizeLimit=static_cast<size_t>(size);
        provider.filter=text(source,"filter");provider.excludeFilter=text(source,"exclude-filter");provider.excludeType=text(source,"exclude-type");
        if(!validProviderPattern(provider.filter)||!validProviderPattern(provider.excludeFilter)){error="Invalid provider filter";return false;}
        if(!text(source,"age-secret-key").empty()){error="Encrypted age provider payloads are not supported yet";return false;}
        yaml_node_t* headers=yamlValue(document,source,"header");
        if(headers!=nullptr) {
            if(headers->type!=YAML_MAPPING_NODE){error="Provider header must be a mapping";return false;}
            size_t total=0;
            for(yaml_node_pair_t* header=headers->data.mapping.pairs.start;header<headers->data.mapping.pairs.top;++header) {
                const std::string key=yamlText(yaml_document_get_node(&document,header->key));std::string value;
                yaml_node_t* values=yaml_document_get_node(&document,header->value);
                if(values->type==YAML_SEQUENCE_NODE)for(yaml_node_item_t* item=values->data.sequence.items.start;item<values->data.sequence.items.top;++item) {
                    if(!value.empty())value+=", ";value+=yamlText(yaml_document_get_node(&document,*item));
                } else value=yamlText(values);
                total+=key.size()+value.size();
                if(total>65536||key.empty()||key.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`|~")!=std::string::npos||
                    value.find('\0')!=std::string::npos||value.find_first_of("\r\n")!=std::string::npos){error="Invalid provider HTTP header";return false;}
                provider.headers[key]=value;
            }
        }
        yaml_node_t* override=yamlValue(document,source,"override");
        if(override!=nullptr) {
            if(override->type!=YAML_MAPPING_NODE){error="Provider override must be a mapping";return false;}
            if(yamlValue(document,override,"override-expr")!=nullptr||yamlValue(document,override,"proxy-name")!=nullptr){error="Provider override expressions/renaming rules are not supported yet";return false;}
            provider.prefix=text(override,"additional-prefix");provider.suffix=text(override,"additional-suffix");
            if(yamlValue(document,override,"udp")!=nullptr)provider.overrideUdp=lower(text(override,"udp"))=="true"?1:0;
            if(yamlValue(document,override,"skip-cert-verify")!=nullptr)provider.overrideSkipVerify=lower(text(override,"skip-cert-verify"))=="true"?1:0;
        }
        provider.health.name=provider.name;provider.health.type="Provider";
        yaml_node_t* health=yamlValue(document,source,"health-check");
        if(health!=nullptr) {
            if(health->type!=YAML_MAPPING_NODE){error="Provider health-check must be a mapping";return false;}
            provider.healthEnabled=lower(text(health,"enable"))=="true";
            const std::string url=text(health,"url"),expected=text(health,"expected-status");
            if(!url.empty())provider.health.url=url;if(!expected.empty())provider.health.expectedStatus=expected;
            provider.health.lazy=lower(text(health,"lazy"))!="false";
            if(!number(health,"interval",provider.health.interval,0,604800)||!number(health,"timeout",provider.health.timeout,100,60000)||
                !validProbeUrl(provider.health.url)||!validProbeStatus(provider.health.expectedStatus)){error="Invalid provider health-check settings";return false;}
        }
        yaml_node_t* payload=yamlValue(document,source,"payload");
        if(payload!=nullptr) {
            if(!parseProxySequence(document,payload,provider.nodes,error)||!applyProviderOptions(provider,provider.nodes,error))return false;
        } else if(provider.type=="inline"){error="Inline provider requires a payload list";return false;}
        providers.push_back(std::move(provider));
    }
    return true;
}
bool parseProviderContent(const ProxyProvider& provider,const std::string& text,std::vector<ProxyNode>& nodes,std::string& error)
{
    error.clear();
    if(text.empty()||text.size()>provider.sizeLimit){error="Provider content is empty or exceeds its size limit";return false;}
    yaml_parser_t parser;if(!yaml_parser_initialize(&parser)){error="Cannot allocate provider YAML parser";return false;}
    yaml_parser_set_input_string(&parser,reinterpret_cast<const unsigned char*>(text.data()),text.size());yaml_document_t document;
    if(!yaml_parser_load(&parser,&document)){yaml_parser_delete(&parser);error="Invalid provider YAML/JSON";return false;}
    yaml_node_t* root=yaml_document_get_root_node(&document);
    bool ok=root!=nullptr&&root->type==YAML_MAPPING_NODE&&resolveYamlMerges(document,text,error)&&parseProxySequence(document,yamlValue(document,root,"proxies"),nodes,error);
    yaml_document_delete(&document);
    if(ok) {
        yaml_document_t extra;
        if(!yaml_parser_load(&parser,&extra)){ok=false;error="Invalid trailing provider YAML";}
        else {if(yaml_document_get_root_node(&extra)!=nullptr){ok=false;error="Provider must contain one YAML document";}yaml_document_delete(&extra);}
    }
    yaml_parser_delete(&parser);
    if(!ok){if(error.empty())error="Provider must contain a proxies list";return false;}
    if(nodes.empty()){error="Provider returned no proxies";return false;}
    return applyProviderOptions(provider,nodes,error);
}
std::string providerHash(const std::string& input)
{
    unsigned char output[32];const mbedtls_md_info_t* info=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if(info==nullptr||mbedtls_md(info,reinterpret_cast<const unsigned char*>(input.data()),input.size(),output)!=0)return {};
    std::ostringstream text;text<<std::hex<<std::setfill('0');for(unsigned char byte:output)text<<std::setw(2)<<static_cast<unsigned int>(byte);return text.str();
}
std::string providerIdentity(const ProxyProvider& provider)
{
    std::string source=provider.type+'\0'+provider.url+'\0'+provider.path;
    for(const auto& header:provider.headers)source+='\0'+header.first+'\0'+header.second;
    return providerHash(source);
}
std::string providerCachePath(const std::string& profile,const ProxyProvider& provider){return profile+".provider-"+providerHash(provider.name).substr(0,16)+".cache";}
bool readProviderFile(const std::string& path,size_t limit,std::string& content,std::string& error)
{
    error.clear();
    std::ifstream file(path,std::ios::binary);if(!file){error="Provider file is unavailable";return false;}
    content.clear();std::array<char,8192> buffer{};
    while(file){file.read(buffer.data(),buffer.size());const size_t count=static_cast<size_t>(file.gcount());if(count>limit-content.size()){error="Provider file exceeds its size limit";content.clear();return false;}content.append(buffer.data(),count);}
    return true;
}
std::string resolveProviderFile(const std::string& profile,const std::string& path)
{
    const size_t slash=profile.find_last_of('/');if(slash==std::string::npos)return {};
    const std::string base=profile.substr(0,slash);char realBase[PATH_MAX],realFile[PATH_MAX];
    const std::string requested=path.empty()?"":path.front()=='/'?path:base+"/"+path;
    if(realpath(base.c_str(),realBase)==nullptr||realpath(requested.c_str(),realFile)==nullptr)return {};
    const std::string root=std::string(realBase)+"/",file=realFile;
    return file.rfind(root,0)==0?file:std::string{};
}
bool providerNamesAvailableLocked(const std::string& name,const std::vector<ProxyNode>& nodes,std::string& error)
{
    std::set<std::string> occupied={"DIRECT","REJECT"};
    for(const ProxyNode& node:g_state.localNodes)occupied.insert(node.name);
    for(const ProxyGroup& group:g_state.groups)occupied.insert(group.name);
    for(const ProxyProvider& provider:g_state.providers)if(provider.name!=name)for(const ProxyNode& node:provider.nodes)occupied.insert(node.name);
    for(const ProxyNode& node:nodes)if(!occupied.insert(node.name).second){error="Provider proxy name conflicts with another proxy or group";return false;}
    return true;
}
void rebuildProviderNodesLocked()
{
    g_state.nodes=g_state.localNodes;
    for(ProxyProvider& provider:g_state.providers) {
        provider.health.proxies.clear();
        for(const ProxyNode& node:provider.nodes){g_state.nodes.push_back(node);provider.health.proxies.push_back(node.name);}
    }
    g_state.proxyNames.clear();for(const ProxyNode& node:g_state.nodes)g_state.proxyNames.push_back(node.name);
    for(ProxyGroup& group:g_state.groups) {
        const std::string selected=group.now;std::vector<std::string> members=group.configuredProxies;std::set<std::string> seen(members.begin(),members.end());
        ProviderPattern include(group.filter),exclude(group.excludeFilter);
        auto add=[&](const ProxyNode& node){if(include.matches(node.name)&&(group.excludeFilter.empty()||!exclude.matches(node.name))&&seen.insert(node.name).second)members.push_back(node.name);};
        if(group.includeAllProxies) {
            std::vector<ProxyNode> ordered=g_state.localNodes;std::sort(ordered.begin(),ordered.end(),[](const ProxyNode& a,const ProxyNode& b){return a.name<b.name;});
            for(const ProxyNode& node:ordered)add(node);
        }
        for(const ProxyProvider& provider:g_state.providers)if(group.includeAllProviders||std::find(group.providers.begin(),group.providers.end(),provider.name)!=group.providers.end())for(const ProxyNode& node:provider.nodes)add(node);
        if(!group.excludeFilter.empty())members.erase(std::remove_if(members.begin(),members.end(),[&](const std::string& name){return exclude.matches(name);}),members.end());
        group.proxies=std::move(members);
        if(group.type=="LoadBalance") {
            group.now.clear();group.pendingSelection.clear();group.manual.clear();
            if(std::find(group.proxies.begin(),group.proxies.end(),group.lastSelected)==group.proxies.end())group.lastSelected.clear();
            for(auto session=group.sessions.begin();session!=group.sessions.end();) {
                if(std::find(group.proxies.begin(),group.proxies.end(),session->second.member)==group.proxies.end())session=group.sessions.erase(session);
                else ++session;
            }
        } else {
        if(std::find(group.proxies.begin(),group.proxies.end(),selected)==group.proxies.end())group.now=group.proxies.empty()?"":group.proxies.front();
        if(!group.pendingSelection.empty()&&std::find(group.proxies.begin(),group.proxies.end(),group.pendingSelection)!=group.proxies.end()) {
            group.now=group.pendingSelection;if(group.pendingManual&&(group.type=="URLTest"||group.type=="Fallback"))group.manual=group.pendingSelection;group.pendingSelection.clear();
        }
        if(std::find(group.proxies.begin(),group.proxies.end(),group.manual)==group.proxies.end())group.manual.clear();
        }
        group.health.clear();group.checking=false;++group.checkGeneration;group.nextCheck={};
    }
    wakeHealthChecks();
}
bool readManagedProviderCache(const std::string& profile,const ProxyProvider& provider,std::string& content,std::string& error,std::string& path)
{
    path=providerCachePath(profile,provider);
    if(!readProviderFile(path,provider.sizeLimit+256,content,error))return false;
    const std::string prefix="# ClahsOS provider source: "+providerIdentity(provider)+"\n";
    if(content.rfind(prefix,0)!=0){error="Provider cache belongs to a different source";return false;}
    content.erase(0,prefix.size());return true;
}
std::string providerFileTime(const std::string& path)
{
    struct stat info{};if(stat(path.c_str(),&info)!=0)return {};
    std::tm value{};gmtime_r(&info.st_mtime,&value);char text[32]{};std::strftime(text,sizeof(text),"%Y-%m-%dT%H:%M:%SZ",&value);return text;
}
void initializeProvidersLocked()
{
    for(ProxyProvider& provider:g_state.providers) {
        if(provider.type=="inline")continue;
        std::string content,error,path;std::vector<ProxyNode> nodes;bool read=false;
        read=readManagedProviderCache(g_state.configPath,provider,content,error,path);
        if(!read&&provider.type=="file") {
            path=resolveProviderFile(g_state.configPath,provider.path);
            read=!path.empty()&&readProviderFile(path,provider.sizeLimit,content,error);
        }
        if(read&&parseProviderContent(provider,content,nodes,error)&&providerNamesAvailableLocked(provider.name,nodes,error)) {
            provider.nodes=std::move(nodes);provider.updatedAt=providerFileTime(path);
        } else if(provider.type=="file")provider.lastError=error.empty()?"Provider file must be inside the configuration directory":error;
    }
}
