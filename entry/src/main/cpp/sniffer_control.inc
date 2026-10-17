std::string snifferConfigJson(const SnifferConfig& config)
{
    std::string protocols = "{";
    for (const auto& entry : config.protocols) {
        std::vector<std::string> ports;
        for (const auto& range : entry.second.ports) ports.push_back(std::to_string(range.first) + (range.first == range.second ? "" : "-" + std::to_string(range.second)));
        if (protocols.size() > 1) protocols += ",";
        protocols += "\"" + entry.first + "\":{\"ports\":" + inboundStringsJson(ports) + ",\"override-destination\":" + (entry.second.overrideDestination ? "true" : "false") + "}";
    }
    return std::string("{\"enable\":") + (config.enabled ? "true" : "false") + ",\"force-dns-mapping\":" + (config.forceDnsMapping ? "true" : "false") +
        ",\"parse-pure-ip\":" + (config.parsePureIp ? "true" : "false") + ",\"override-destination\":" + (config.overrideDestination ? "true" : "false") +
        ",\"sniff\":" + protocols + "},\"force-domain\":" + inboundStringsJson(config.forceDomain) + ",\"skip-domain\":" + inboundStringsJson(config.skipDomain) +
        ",\"skip-src-address\":" + inboundStringsJson(config.skipSource) + ",\"skip-dst-address\":" + inboundStringsJson(config.skipDestination) + "}";
}

bool snifferJsonTypes(JSContext* context, JSValue object, std::string& error)
{
    const auto boolean = [&](JSValue root, const char* name) {
        JSValue value = JS_GetPropertyStr(context, root, name);
        const bool valid = JS_IsUndefined(value) || JS_IsBool(value); JS_FreeValue(context, value);
        if (!valid) error = std::string("sniffer.") + name + " must be a boolean";
        return valid;
    };
    const auto list = [&](JSValue root, const char* name, bool numeric) {
        JSValue value = JS_GetPropertyStr(context, root, name);
        if (JS_IsUndefined(value)) { JS_FreeValue(context, value); return true; }
        bool valid = JS_IsArray(context, value) == 1; uint32_t count = 0;
        JSValue length = JS_GetPropertyStr(context, value, "length");
        valid = valid && JS_ToUint32(context, &count, length) == 0 && count <= 256; JS_FreeValue(context, length);
        for (uint32_t i = 0; valid && i < count; ++i) {
            JSValue item = JS_GetPropertyUint32(context, value, i);
            valid = JS_IsString(item) || (numeric && JS_IsNumber(item));
            JS_FreeValue(context, item);
        }
        JS_FreeValue(context, value);
        if (!valid) error = std::string("sniffer.") + name + (numeric ? " must contain port numbers or ranges" : " must contain strings");
        return valid;
    };
    for (const char* key : {"enable", "force-dns-mapping", "parse-pure-ip", "override-destination"}) if (!boolean(object, key)) return false;
    for (const char* key : {"force-domain", "skip-domain", "skip-src-address", "skip-dst-address", "sniffing"}) if (!list(object, key, false)) return false;
    if (!list(object, "port-whitelist", true)) return false;
    JSValue protocols = JS_GetPropertyStr(context, object, "sniff");
    if (JS_IsUndefined(protocols)) { JS_FreeValue(context, protocols); return true; }
    if (!JS_IsObject(protocols) || JS_IsArray(context, protocols) != 0) { JS_FreeValue(context, protocols); error = "sniffer.sniff must be an object"; return false; }
    JSPropertyEnum* keys = nullptr; uint32_t count = 0;
    bool valid = JS_GetOwnPropertyNames(context, &keys, &count, protocols, JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0;
    for (uint32_t i = 0; i < count; ++i) {
        JSValue value = JS_GetProperty(context, protocols, keys[i].atom);
        if (valid) valid = JS_IsObject(value) && JS_IsArray(context, value) == 0 && boolean(value, "override-destination") && list(value, "ports", true);
        JS_FreeValue(context, value); JS_FreeAtom(context, keys[i].atom);
    }
    if (keys) js_free(context, keys); JS_FreeValue(context, protocols);
    if (!valid && error.empty()) error = "Invalid sniffer protocol object";
    return valid;
}

bool snifferJsonPatch(ControllerConfigJson& json, SnifferConfig& config, std::string& error)
{
    JSValue value = JS_GetPropertyStr(json.context, json.root, "sniffer");
    if (!JS_IsUndefined(value) && !JS_IsNull(value)) {
        if (!JS_IsObject(value) || JS_IsArray(json.context, value) != 0) { JS_FreeValue(json.context, value); error = "sniffer must be an object"; return false; }
        if (!snifferJsonTypes(json.context, value, error)) { JS_FreeValue(json.context, value); return false; }
        JSValue serialized = JS_JSONStringify(json.context, value, JS_UNDEFINED, JS_UNDEFINED);
        size_t size = 0; const char* bytes = JS_ToCStringLen(json.context, &size, serialized);
        bool valid = bytes && size <= 128 * 1024; yaml_parser_t parser; yaml_document_t document;
        if (valid) {
            valid = yaml_parser_initialize(&parser) != 0;
            if (valid) {
                yaml_parser_set_input_string(&parser, reinterpret_cast<const unsigned char*>(bytes), size);
                valid = yaml_parser_load(&parser, &document) != 0;
                if (valid) {
                    SnifferConfig next; valid = parseSnifferConfig(document, yaml_document_get_root_node(&document), next, error);
                    yaml_document_delete(&document); if (valid) config = std::move(next);
                }
                yaml_parser_delete(&parser);
            }
        }
        if (bytes) JS_FreeCString(json.context, bytes); JS_FreeValue(json.context, serialized); JS_FreeValue(json.context, value);
        if (!valid) { if (error.empty()) error = "Invalid sniffer configuration"; return false; }
    } else JS_FreeValue(json.context, value);
    JSValue toggle = JS_GetPropertyStr(json.context, json.root, "sniffing");
    const bool enableAction = JS_IsBool(toggle) && JS_ToBool(json.context, toggle) == 1; JS_FreeValue(json.context, toggle);
    if (!json.boolean("sniffing", config.enabled, error)) return false;
    // A runtime enable action is useful on profiles without a sniffer section.
    if (enableAction && config.protocols.empty()) {
        config.protocols["HTTP"] = {{{80,80},{8080,8880}}, config.overrideDestination};
        config.protocols["TLS"] = {{{443,443},{8443,8443}}, config.overrideDestination};
        config.protocols["QUIC"] = config.protocols["TLS"];
    }
    return normalizeSnifferConfig(config, error);
}

std::string snifferDraftError(const std::string& text)
{
    if (text.empty() || text.size() > 128 * 1024) return "Sniffer JSON must be between 1 byte and 128 KiB";
    ControllerConfigJson json; std::string error;
    if (!json.parse(text, error) || !json.keys({"sniffer"}, error)) return error;
    JSValue value = JS_GetPropertyStr(json.context, json.root, "sniffer");
    const bool object = JS_IsObject(value) && JS_IsArray(json.context, value) == 0;
    JS_FreeValue(json.context, value);
    if (!object) return "Expected a JSON object containing a sniffer object";
    SnifferConfig config;
    snifferJsonPatch(json, config, error);
    return error;
}
