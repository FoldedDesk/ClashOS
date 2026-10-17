bool splitHostPort(const std::string&,std::string&,int&,int);
bool parseDnsEndpoint(std::string raw,DnsEndpoint& endpoint,std::string& error)
{
    endpoint={};raw=trim(raw);
    if(raw.empty()||raw.size()>2048) {error="Invalid DNS server address";return false;}
    const size_t fragment=raw.find('#');
    if(fragment!=std::string::npos) {
        endpoint.routeExplicit=true;
        endpoint.route=urlDecode(raw.substr(fragment+1));raw.resize(fragment);
        if(endpoint.route.empty()||endpoint.route.find('&')!=std::string::npos||endpoint.route.find('=')!=std::string::npos) {error="Unsupported DNS server option; use an outbound name or RULES";return false;}
        if(std::any_of(endpoint.route.begin(),endpoint.route.end(),[](unsigned char c){return c<32||c==127;})){error="Invalid DNS outbound name";return false;}
    }
    if(std::any_of(raw.begin(),raw.end(),[](unsigned char c){return c<=32||c==127;})){error="Invalid DNS server address";return false;}
    if(raw=="system"||raw=="system://") {endpoint.transport="system";endpoint.host="system";return true;}
    const size_t scheme=raw.find("://");
    if(scheme!=std::string::npos){endpoint.transport=lower(raw.substr(0,scheme));raw.erase(0,scheme+3);}
    if(endpoint.transport!="udp"&&endpoint.transport!="tcp"&&endpoint.transport!="tls"&&endpoint.transport!="https") {error="Unsupported DNS transport: "+endpoint.transport;return false;}
    const size_t slash=raw.find_first_of("/?");const std::string authority=raw.substr(0,slash);
    endpoint.port=endpoint.transport=="https"?443:endpoint.transport=="tls"?853:53;
    if(!splitHostPort(authority,endpoint.host,endpoint.port,endpoint.port)||endpoint.host.find('@')!=std::string::npos) {error="Invalid DNS server host or port";return false;}
    int family=0;std::array<unsigned char,16> address{};std::string normalized;
    if(!ruleIpAddress(endpoint.host,family,address)&&(!dnsNormalizeName(endpoint.host,normalized)||normalized==".")){error="Invalid DNS server hostname";return false;}
    if(slash!=std::string::npos) {
        endpoint.path=raw.substr(slash);if(endpoint.path.front()=='?')endpoint.path="/"+endpoint.path;
        if(endpoint.transport!="https"&&endpoint.path!="/"){error="Only HTTPS DNS accepts a request path";return false;}
    }
    return true;
}
bool parseDnsConfig(yaml_document_t& document,yaml_node_t* root,DnsConfig& config,std::string& error)
{
    auto* source=yamlValue(document,root,"dns");
    if(source&&source->type!=YAML_MAPPING_NODE){error="dns must be a mapping";return false;}
    auto flag=[&](const char* key,bool& value) {
        auto* node=yamlValue(document,source,key);if(!node)return true;
        const auto raw=lower(yamlText(node));if(raw!="true"&&raw!="false"){error=std::string("dns.")+key+" must be true or false";return false;}
        value=raw=="true";return true;
    };
    if(!flag("enable",config.enabled)||!flag("ipv6",config.ipv6)||!flag("use-hosts",config.useHosts)||!flag("respect-rules",config.respectRules)||!flag("direct-nameserver-follow-policy",config.directFollowPolicy))return false;
    config.listen=yamlText(yamlValue(document,source,"listen"));
    if(!config.listen.empty()) {
        const std::string address=config.listen.front()==':'&&config.listen.find(':',1)==std::string::npos?"0.0.0.0"+config.listen:config.listen;
        int family=0;std::array<unsigned char,16> ip{};
        if(!splitHostPort(address,config.listenHost,config.listenPort,0)||!ruleIpAddress(config.listenHost,family,ip)){error="dns.listen must contain an IPv4/IPv6 address and port";return false;}
    }
    const auto mode=yamlText(yamlValue(document,source,"enhanced-mode"));
    if(!mode.empty()&&mode!="redir-host"&&mode!="fake-ip"){error="dns.enhanced-mode must be redir-host or fake-ip";return false;}
    if(!mode.empty())config.enhancedMode=mode;
    auto endpoints=[&](yaml_node_t* node,std::vector<DnsEndpoint>& values) {
        if(!node)return true;
        std::vector<std::string> raw;
        if(node->type==YAML_SCALAR_NODE)raw.push_back(yamlText(node));
        else if(node->type==YAML_SEQUENCE_NODE) {
            if(node->data.sequence.items.top-node->data.sequence.items.start>32){error="DNS server list exceeds 32 entries";return false;}
            for(auto* item=node->data.sequence.items.start;item<node->data.sequence.items.top;++item) {
                auto* scalar=yaml_document_get_node(&document,*item);if(!scalar||scalar->type!=YAML_SCALAR_NODE){error="DNS server list entries must be strings";return false;}raw.push_back(yamlText(scalar));
            }
        } else {error="DNS server list must contain strings";return false;}
        for(auto& item:raw){DnsEndpoint endpoint;if(!parseDnsEndpoint(item,endpoint,error))return false;values.push_back(std::move(endpoint));}return true;
    };
    for(const auto& entry:std::vector<std::pair<const char*,std::vector<DnsEndpoint>*>>{{"nameserver",&config.servers},{"default-nameserver",&config.bootstrap},{"proxy-server-nameserver",&config.proxy},{"direct-nameserver",&config.direct},{"fallback",&config.fallback}})
        if(!endpoints(yamlValue(document,source,entry.first),*entry.second))return false;
    for(const auto& endpoint:config.bootstrap) {
        int family=0;std::array<unsigned char,16> address{};
        if(endpoint.transport!="system"&&!ruleIpAddress(endpoint.host,family,address)){error="default-nameserver must use IP addresses";return false;}
        if(endpoint.route!="DIRECT"){error="default-nameserver cannot depend on an outbound proxy";return false;}
    }
    auto pattern=[&](const std::string& expression,std::shared_ptr<RuleDomainIndex>& index) {
        index=std::make_shared<RuleDomainIndex>();return buildRuleDomains({expression},*index,error);
    };
    auto policies=[&](const char* key,std::vector<DnsPolicy>& result) {
        auto* map=yamlValue(document,source,key);if(!map)return true;
        if(map->type!=YAML_MAPPING_NODE||map->data.mapping.pairs.top-map->data.mapping.pairs.start>256){error="DNS policies must be a mapping of at most 256 entries";return false;}
        for(auto* pair=map->data.mapping.pairs.start;pair<map->data.mapping.pairs.top;++pair) {
            DnsPolicy policy;policy.expression=yamlText(yaml_document_get_node(&document,pair->key));
            if(!endpoints(yaml_document_get_node(&document,pair->value),policy.servers)||policy.servers.empty()){if(error.empty())error="DNS policy requires a server";return false;}
            if(policy.expression.rfind("geosite:",0)==0) {
                std::istringstream names(policy.expression.substr(8));std::string name;bool any=false;
                while(std::getline(names,name,',')){if(!geoTag(trim(name))){error="Invalid DNS GeoSite category";return false;}any=true;}
                if(!any){error="DNS GeoSite policy requires a category";return false;}
            } else if(policy.expression.rfind("rule-set:",0)!=0&&!pattern(policy.expression,policy.pattern))return false;
            result.push_back(std::move(policy));
        }
        return true;
    };
    if(!policies("nameserver-policy",config.policies)||!policies("proxy-server-nameserver-policy",config.proxyPolicies))return false;
    auto* hosts=yamlValue(document,root,"hosts");
    if(hosts) {
        if(hosts->type!=YAML_MAPPING_NODE||hosts->data.mapping.pairs.top-hosts->data.mapping.pairs.start>4096){error="hosts must be a mapping with at most 4096 entries";return false;}
        for(auto* pair=hosts->data.mapping.pairs.start;pair<hosts->data.mapping.pairs.top;++pair) {
            DnsHost host;host.expression=yamlText(yaml_document_get_node(&document,pair->key));if(!pattern(host.expression,host.pattern))return false;
            auto* value=yaml_document_get_node(&document,pair->value);
            if(value->type==YAML_SCALAR_NODE)host.addresses.push_back(yamlText(value));
            else if(value->type==YAML_SEQUENCE_NODE&&value->data.sequence.items.top-value->data.sequence.items.start<=32)
                for(auto* item=value->data.sequence.items.start;item<value->data.sequence.items.top;++item)host.addresses.push_back(yamlText(yaml_document_get_node(&document,*item)));
            else {error="hosts values must be an address/alias or a list";return false;}
            for(const auto& value:host.addresses){int family=0;std::array<unsigned char,16> address{};std::string name;if(!ruleIpAddress(value,family,address)&&!dnsNormalizeName(value,name)){error="Invalid hosts address/alias";return false;}}
            config.hosts.push_back(std::move(host));
        }
    }
    auto* filter=yamlValue(document,source,"fallback-filter");
    if(filter) {
        if(filter->type!=YAML_MAPPING_NODE){error="fallback-filter must be a mapping";return false;}
        const auto geoip=lower(yamlText(yamlValue(document,filter,"geoip")));
        if(!geoip.empty()&&geoip!="true"&&geoip!="false"){error="fallback-filter.geoip must be true or false";return false;}
        config.geoipFallback=geoip!="false"&&!config.fallback.empty();
        const auto code=lower(yamlText(yamlValue(document,filter,"geoip-code")));if(!code.empty()){if(!geoTag(code)){error="Invalid DNS fallback GeoIP code";return false;}config.geoipCode=code;}
        for(const char* key:{"domain","ipcidr"}) {
            auto* list=yamlValue(document,filter,key);if(!list)continue;
            if(list->type!=YAML_SEQUENCE_NODE||list->data.sequence.items.top-list->data.sequence.items.start>4096){error="DNS fallback filter must be a list of at most 4096 items";return false;}
            for(auto* item=list->data.sequence.items.start;item<list->data.sequence.items.top;++item) {
                const std::string value=yamlText(yaml_document_get_node(&document,*item));
                if(std::string(key)=="domain"){std::shared_ptr<RuleDomainIndex> index;if(!pattern(value,index))return false;config.fallbackDomains.push_back(std::move(index));}
                else {RuleIpRange range;if(!parseRuleCidr(value,range)){error="Invalid DNS fallback CIDR";return false;}config.fallbackRanges.push_back(range);}
            }
        }
    } else if(!config.fallback.empty())config.geoipFallback=true;
    if(config.respectRules&&config.proxy.empty()){error="dns.respect-rules requires proxy-server-nameserver to avoid resolution loops";return false;}
    if(config.enabled&&config.servers.empty()){error="Enabled DNS requires at least one nameserver";return false;}
    if(config.enabled&&config.listenPort>0) {
        auto self=[&](const DnsEndpoint& server) {
            if((server.transport!="udp"&&server.transport!="tcp")||server.port!=config.listenPort||server.route!="DIRECT")return false;
            return server.host==config.listenHost||(config.listenHost=="0.0.0.0"&&server.host.rfind("127.",0)==0)||(config.listenHost=="::"&&(server.host=="::1"||server.host.rfind("127.",0)==0));
        };
        for(const auto* servers:{&config.servers,&config.bootstrap,&config.proxy,&config.direct,&config.fallback})for(const auto& server:*servers)
            if(self(server)){error="DNS upstream cannot point at its own listener";return false;}
        for(const auto* policies:{&config.policies,&config.proxyPolicies})for(const auto& policy:*policies)for(const auto& server:policy.servers)
            if(self(server)){error="DNS policy cannot point at its own listener";return false;}
    }
    if(lower(yamlText(yamlValue(document,source,"prefer-h3")))=="true")config.warnings.push_back("DNS HTTP/3 preference is unavailable; HTTPS DNS uses verified HTTP/1.1 TLS");
    if(config.enabled&&!config.listen.empty()&&config.enhancedMode=="fake-ip")config.warnings.push_back("The configured DNS listener returns real IP addresses; fake-ip is currently limited to the TUN mapping engine");
    if(yamlValue(document,source,"fake-ip-filter"))config.warnings.push_back("Custom fake-ip filters are not yet connected to the TUN mapping engine");
    return true;
}
