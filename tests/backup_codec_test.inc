void backupCodecTests(const std::string& directory) {
    std::string output, error;
    require(backupYamlText("items:\n- {uid: public, type: local, updated: 123}\nflag: false\nname: 'PUBLIC 😀'\n", output, error), "Backup YAML reader rejected public index");
    require(output.find("\"updated\":123") != std::string::npos && output.find("\"flag\":false") != std::string::npos && output.find("PUBLIC 😀") != std::string::npos, "Backup YAML reader lost scalar types or Unicode");
    error.clear(); require(!backupYamlText("items: 1\nitems: 2\n", output, error), "Duplicate archive index keys accepted");
    error.clear(); require(!backupYamlText("a: &x {b: *x}", output, error), "Cyclic archive YAML accepted");
    error.clear(); require(!backupYamlText("a: 1\n---\nb: 2", output, error), "Multiple archive YAML documents accepted");
    std::vector<unsigned char> decoded; const auto compressed = hex("0b0875f2f1745688f20c50f8307f46031700");
    require(backupInflate(compressed.data(), compressed.size(), 16, decoded) && text(decoded) == "PUBLIC ZIP 😀\n", "Raw ZIP deflate differs from independent Python zlib vector");
    require(!backupInflate(compressed.data(), compressed.size(), 15, decoded), "Incorrect ZIP decompressed length accepted");
    auto trailing = compressed; trailing.push_back(0); require(!backupInflate(trailing.data(), trailing.size(), 16, decoded), "Trailing compressed ZIP bytes accepted");
    require(!backupInflate(compressed.data(), compressed.size() - 1, 16, decoded), "Truncated compressed ZIP data accepted");
    require(!backupInflate(compressed.data(), compressed.size(), BACKUP_BYTES_LIMIT + 1, decoded), "Oversized ZIP expansion accepted");
    ConfigMerges merges; merges.sequence = R"({"rules":{"prepend":["DOMAIN,public.invalid,DIRECT"],"append":[],"delete":[]},"proxies":{"prepend":[{"name":"Public added","type":"direct"}],"append":[],"delete":["Public old"]},"groups":{"prepend":[],"append":[],"delete":[]}})";
    const std::string source = "proxies:\n- {name: Public old, type: direct}\nproxy-groups:\n- {name: Public group, type: select, proxies: [Public old, DIRECT]}\nrules: [MATCH,DIRECT]\n";
    // Use a valid terminal rule, encoded as one scalar.
    const std::string validSource = source.substr(0, source.rfind("rules:")) + "rules: ['MATCH,DIRECT']\n";
    ParsedConfig parsed; error.clear(); require(parseConfigText(validSource, parsed, error, nullptr, nullptr, &merges), "Migrated sequence configuration rejected");
    require(parsed.nodes.size() == 1 && parsed.nodes[0].name == "Public added", "Migrated sequence did not delete/add nodes");
    require(parsed.groups.size() == 1 && parsed.groups[0].proxies.size() == 2 && parsed.groups[0].proxies[0] == "Public added" && parsed.groups[0].proxies[1] == "DIRECT", "Migrated sequence did not update first selector or remove old references");
    require(parsed.sourceRules.front() == "DOMAIN,public.invalid,DIRECT", "Migrated prepended rule missing");
    merges.globalScript = "function main(config) { if (config.proxies[0].name !== 'Public added') throw Error('wrong sequence order'); config.rules = ['MATCH,REJECT']; return config; }";
    error.clear(); ParsedConfig ordered; require(parseConfigText(validSource, ordered, error, nullptr, nullptr, &merges) && ordered.sourceRules == std::vector<std::string>{"MATCH,REJECT"}, "Migrated sequences must run before global scripts");
    const std::string settings = "{\"version\":3,\"global\":\"\",\"profile\":\"\",\"globalScript\":\"\",\"profileScript\":\"\",\"profileName\":\"PUBLIC\",\"sequence\":\"" + jsonEscape(merges.sequence) + "\"}";
    ConfigMerges roundtrip; error.clear(); require(parseConfigMerges(settings, roundtrip, error) && roundtrip.sequence == merges.sequence, "Migrated sequence settings v3 roundtrip failed");
    const std::string path = directory + "/public-archive.yaml";
    { std::ofstream f(path); f << validSource; } { std::ofstream f(path + ".verge-seq.json"); f << merges.sequence; }
    ConfigMerges disk; error.clear(); require(readConfigMerges(path, disk, error) && disk.sequence == merges.sequence, "Native reload omitted migrated subscription sequence");
}
