bool validateRuleGraph(const std::vector<RuleProvider>& providers,const std::string& replacement,
    const std::shared_ptr<const RuleData>& data,std::string& error)
{
    std::map<std::string,const RuleProvider*> map;for(const auto& provider:providers)map[provider.name]=&provider;
    std::map<std::string,int> visited;
    std::function<bool(const std::string&,size_t)> visit;
    std::function<bool(const ProxyRule&,size_t)> check=[&](const ProxyRule& rule,size_t depth) {
        if(rule.kind=="rule-set"&&!visit(rule.value,depth+1))return false;
        for(const auto& child:rule.conditions)if(!check(child,depth+1))return false;
        return true;
    };
    visit=[&](const std::string& name,size_t depth) {
        if(depth>32||visited[name]==1){error="Cyclic or excessively nested rule providers";return false;}
        if(visited[name]==2)return true;
        const auto found=map.find(name);if(found==map.end()){error="Unknown rule provider: "+name;return false;}
        visited[name]=1;const auto snapshot=name==replacement?data:found->second->data;
        if(snapshot)for(const auto& rule:snapshot->classical)if(!check(rule,depth))return false;
        visited[name]=2;return true;
    };
    for(const auto& provider:providers)if(!visit(provider.name,0))return false;return true;
}
bool parseRuleDefinitions(yaml_document_t& document,yaml_node_t* root,std::vector<RuleProvider>& providers,std::string& error)
{
    auto* map=yamlValue(document,root,"rule-providers");if(map==nullptr)return true;
    if(map->type!=YAML_MAPPING_NODE||map->data.mapping.pairs.top-map->data.mapping.pairs.start>128){error="rule-providers must be a mapping of at most 128 resources";return false;}
    auto text=[&](yaml_node_t* source,const char* key){return yamlText(yamlValue(document,source,key));};
    auto number=[&](yaml_node_t* source,const char* key,int& output,int minimum,int maximum) {
        const auto raw=text(source,key);if(raw.empty())return true;char* end=nullptr;const long value=std::strtol(raw.c_str(),&end,10);
        if(end==raw.c_str()||*end!='\0'||value<minimum||value>maximum)return false;output=static_cast<int>(value);return true;
    };
    std::set<std::string> names;
    for(auto* pair=map->data.mapping.pairs.start;pair<map->data.mapping.pairs.top;++pair) {
        RuleProvider provider;provider.name=yamlText(yaml_document_get_node(&document,pair->key));provider.interval=86400;
        auto* source=yaml_document_get_node(&document,pair->value);
        if(source->type!=YAML_MAPPING_NODE||provider.name.empty()||provider.name.size()>256||!names.insert(provider.name).second){error="Rule provider names must be non-empty and unique, with mapping definitions";return false;}
        provider.type=lower(text(source,"type"));provider.behavior=lower(text(source,"behavior"));
        const auto format=lower(text(source,"format"));if(!format.empty())provider.format=format;
        provider.url=text(source,"url");provider.path=text(source,"path");const auto route=text(source,"proxy");if(!route.empty())provider.downloadProxy=route;
        if(provider.type!="http"&&provider.type!="file"&&provider.type!="inline"){error="Rule provider type must be http, file or inline";return false;}
        if(provider.behavior!="domain"&&provider.behavior!="ipcidr"&&provider.behavior!="classical"){error="Rule provider behavior must be domain, ipcidr or classical";return false;}
        if((provider.format!="yaml"&&provider.format!="text"&&provider.format!="mrs")||(provider.format=="mrs"&&provider.behavior=="classical")){error="Rule provider format must be yaml/text, or mrs with domain/ipcidr behavior";return false;}
        if(provider.type=="http"&&!validProbeUrl(provider.url)){error="HTTP rule provider requires a valid HTTP(S) URL";return false;}
        if(provider.type=="file"&&provider.path.empty()){error="File rule provider requires a path";return false;}
        int size=0;if(!number(source,"interval",provider.interval,0,604800)||!number(source,"timeout",provider.timeout,100,60000)||!number(source,"size-limit",size,0,8*1024*1024)){error="Invalid rule provider update interval, timeout or size-limit";return false;}
        if(size>0)provider.sizeLimit=size;
        auto* headers=yamlValue(document,source,"header");
        if(headers) {
            if(headers->type!=YAML_MAPPING_NODE){error="Rule provider headers must be a mapping";return false;}size_t total=0;
            for(auto* header=headers->data.mapping.pairs.start;header<headers->data.mapping.pairs.top;++header) {
                const auto key=yamlText(yaml_document_get_node(&document,header->key));auto* values=yaml_document_get_node(&document,header->value);std::string value;
                if(values->type==YAML_SEQUENCE_NODE)for(auto* item=values->data.sequence.items.start;item<values->data.sequence.items.top;++item){if(!value.empty())value+=", ";value+=yamlText(yaml_document_get_node(&document,*item));}
                else value=yamlText(values);
                total+=key.size()+value.size();
                if(total>65536||key.empty()||key.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`|~")!=std::string::npos||
                    value.find('\0')!=std::string::npos||value.find_first_of("\r\n")!=std::string::npos){error="Invalid rule provider HTTP header";return false;}provider.headers[key]=value;
            }
        }
        auto* payload=yamlValue(document,source,"payload");
        if(payload) {
            if(payload->type!=YAML_SEQUENCE_NODE){error="Inline/fallback rule provider payload must be a list";return false;}
            std::vector<std::string> entries;
            for(auto* item=payload->data.sequence.items.start;item<payload->data.sequence.items.top;++item) {
                auto* entry=yaml_document_get_node(&document,*item);if(entry->type!=YAML_SCALAR_NODE||entries.size()>=RULE_MAX_COUNT){error="Invalid inline rule provider entry";return false;}entries.push_back(yamlText(entry));
            }
            if(!compileRulePayload(provider,entries,provider.data,error))return false;
        } else if(provider.type=="inline"){error="Inline rule provider requires a payload list";return false;}
        providers.push_back(std::move(provider));
    }
    return validateRuleGraph(providers,"",nullptr,error);
}
std::string ruleProviderIdentity(const RuleProvider& provider)
{
    return providerHash(providerIdentity(provider)+'\0'+provider.behavior+'\0'+provider.format);
}
std::string ruleProviderCachePath(const std::string& profile,const RuleProvider& provider)
{
    return profile+".rule-provider-"+providerHash(provider.name).substr(0,16)+".cache";
}
bool readRuleCache(const std::string& profile,const RuleProvider& provider,std::string& content,std::string& error,std::string& path)
{
    path=ruleProviderCachePath(profile,provider);
    if(!readProviderFile(path,provider.sizeLimit+256,content,error))return false;
    const std::string prefix="# ClahsOS rule source: "+ruleProviderIdentity(provider)+"\n";
    if(content.rfind(prefix,0)!=0){error="Rule cache belongs to a different source/behavior/format";return false;}
    content.erase(0,prefix.size());return true;
}
void initializeRuleProvidersLocked()
{
    for(auto& provider:g_state.ruleProviders) {
        if(provider.type=="inline")continue;
        std::string content,error,path;bool read=readRuleCache(g_state.configPath,provider,content,error,path);
        if(!read&&provider.type=="file") {path=resolveProviderFile(g_state.configPath,provider.path);read=!path.empty()&&readProviderFile(path,provider.sizeLimit,content,error);}
        std::shared_ptr<const RuleData> data;
        if(read&&parseRuleContent(provider,content,data,error)&&validateRuleGraph(g_state.ruleProviders,provider.name,data,error)) {
            provider.data=std::move(data);provider.updatedAt=providerFileTime(path);
        } else if(provider.type=="file")provider.lastError=error.empty()?"Rule provider file is not available inside the profile directory":error;
        if(!provider.data&&provider.lastError.empty())provider.lastError="Rule provider is waiting for its first successful download";
    }
}
