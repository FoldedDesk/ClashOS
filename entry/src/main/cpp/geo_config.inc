bool parseGeoConfig(yaml_document_t& document,yaml_node_t* root,GeoConfig& config,std::string& error)
{
    auto flag=[&](const char* name,bool& value) {
        auto* node=yamlValue(document,root,name);if(!node)return true;
        const auto text=lower(yamlText(node));if(text!="true"&&text!="false"){error=std::string(name)+" must be true or false";return false;}
        value=text=="true";return true;
    };
    if(!flag("geodata-mode",config.dat)||!flag("geo-auto-update",config.autoUpdate))return false;
    if(auto* node=yamlValue(document,root,"geo-update-interval")) {
        const auto text=yamlText(node);size_t hours=0;
        if(text.empty()||text.size()>4||!std::all_of(text.begin(),text.end(),[](unsigned char c){return std::isdigit(c);})||(hours=std::strtoul(text.c_str(),nullptr,10))<1||hours>8760){error="geo-update-interval must be 1 to 8760 hours";return false;}
        config.interval=hours;
    }
    auto* urls=yamlValue(document,root,"geox-url");if(!urls)return true;
    if(urls->type!=YAML_MAPPING_NODE){error="geox-url must be a mapping";return false;}
    for(auto* pair=urls->data.mapping.pairs.start;pair<urls->data.mapping.pairs.top;++pair) {
        const auto key=lower(yamlText(yaml_document_get_node(&document,pair->key)));
        const auto url=yamlText(yaml_document_get_node(&document,pair->value));
        auto found=std::find_if(config.resources.begin(),config.resources.end(),[&](const auto& resource){return resource.kind==key;});
        if(found==config.resources.end()||!validProbeUrl(url)){error="geox-url requires a known GeoData kind and an HTTP(S) URL";return false;}found->url=url;
    }
    return true;
}
