void configScriptTests(const std::string& directory)
{
    const std::string source = R"(port: 7890
socks-port: 7891
proxies: [{name: base, type: direct}]
proxy-groups: [{name: Policy, type: select, proxies: [base]}]
rules: ['MATCH,Policy']
values: {flag: true, text: "true", integer: 7890, quoted: "00123", nothing: null, textNull: "null", explicit: !!str 12345, hex: 0x10, octal: 0o10, number: 1e2}
shared: &shared {keep: yes}
first: *shared
second: *shared
)";
    auto settings = [](const ConfigMerges& input) {
        return "{\"version\":2,\"global\":\"" + jsonEscape(input.global) + "\",\"profile\":\"" + jsonEscape(input.profile) +
            "\",\"globalScript\":\"" + jsonEscape(input.globalScript) + "\",\"profileScript\":\"" + jsonEscape(input.profileScript) + "\",\"profileName\":\"" + jsonEscape(input.profileName) + "\"}";
    };
    auto result = [&](const ConfigMerges& input, const std::string& config = "") { return ruleEditorJson(config.empty() ? source : config, "", true, "", settings(input)); };
    ConfigMerges extensions;
    extensions.global = "custom: {stage: 1}\n"; extensions.profile = "custom: {stage: 3}\n"; extensions.profileName = "公开配置 A";
    extensions.globalScript = R"(function main(config, profileName) {
      if(config.custom.stage !== 1 || profileName !== '公开配置 A') throw new Error('wrong global input');
      const v=config.values;
      if(v.flag!==true || v.text!=='true' || v.integer!==7890 || v.quoted!=='00123' || v.nothing!==null || v.textNull!=='null' || v.explicit!=='12345' || v.hex!==16 || v.octal!==8 || v.number!==100) throw new Error('scalar types lost');
      config.first.keep='changed'; if(config.second.keep!=='yes') throw new Error('alias branch mutated');
      config.custom.stage=2; console.info('global',profileName); return config;
    })";
    extensions.profileScript = R"(const main = (config, name) => {
      if(config.custom.stage!==3) throw new Error('profile merge order');
      config.rules.unshift('DST-PORT,18088,DIRECT'); config.hosts={'script.fixture.test':'192.0.2.30'};
      config.proxies.push({name:'脚本节点',type:'direct'});
      config['proxy-groups'].push({name:'脚本组',type:'select',proxies:['脚本节点','REJECT']});
      console.warn('profile',name); return config;
    })";
    ConfigMerges decoded; std::string error; require(parseConfigMerges(settings(extensions), decoded, error), "Version 2 extension settings must preserve both script stages");
    const std::string combined = result(extensions);
    require(combined.find("\"error\":\"\"") != std::string::npos, ("Extension pipeline failed: " + combined).c_str());
    EditorYaml response; require(response.parse(combined, 8 * 1024 * 1024, error), "Script preview response must remain valid JSON");
    auto* root = yaml_document_get_root_node(&response.document); const std::string generated = yamlText(yamlValue(response.document, root, "content"));
    require(!generated.empty() && generated.front() != '{' && generated.find("!!int") == std::string::npos && generated.find("!!bool") == std::string::npos,
        "Script export must use readable block YAML without redundant primitive tags");
    ParsedConfig parsed; require(parseConfigText(generated, parsed, error) && parsed.nodes.size() == 2 && parsed.groups.size() == 2 && parsed.rules.front().target == "DIRECT", "Exported script output must load without any script or merge settings");
    auto* logs = yamlValue(response.document, root, "scriptLogs"); require(logs && logs->type == YAML_SEQUENCE_NODE && logs->data.sequence.items.top - logs->data.sequence.items.start == 2, "Each stage console output must be captured exactly once during export");
    require(combined.find("global 公开配置 A") != std::string::npos && combined.find("profile 公开配置 A") != std::string::npos, "Console messages must include actual profileName and levels");
    ConfigMerges random; random.profileScript = R"(function main(c){const n='node-'+Math.random();c.proxies=[{name:n,type:'direct'}];c['proxy-groups']=[];c.rules=['MATCH,'+n];return c;})";
    const std::string randomResult = result(random); EditorYaml randomDocument;
    require(randomDocument.parse(randomResult, 8 * 1024 * 1024, error), "Randomized preview must return readable JSON");
    const std::string randomContent = yamlText(yamlValue(randomDocument.document, yaml_document_get_root_node(&randomDocument.document), "content"));
    ParsedConfig randomConfig; require(parseConfigText(randomContent, randomConfig, error), "Validation and export must reuse one script execution, including randomized names");
    require(objectEditorJson(source, "", "", true, settings(random)).find("\"error\":\"\"") != std::string::npos, "Node editor snapshot must compose script-generated nodes without a second validation run");
    ConfigMerges async; async.profileScript = "async function main(c){await Promise.resolve();c.rules=['MATCH,REJECT'];return c;}";
    require(result(async).find("\"error\":\"\"") != std::string::npos, "Promise-based scripts can finish through bounded local microtasks");
    const std::vector<std::string> invalid = {
        "let value=1;", "function main( {", "function main(c){throw new Error('public script error');}",
        "function main(c){return null;}", "function main(c){return [];}", "function main(c){return 'not a config';}",
        "function main(c){c.rules=['MATCH,missing-policy'];return c;}",
        "function main(c){c['proxy-groups']=[{name:'loop',type:'select',proxies:['loop']}];return c;}",
        "function main(c){return new Promise(()=>{});}", "async function main(c){throw new Error('public rejection');}",
        "function main(c){c.self=c;return c;}", "function main(c){return {toJSON(){return []}};}",
        "function main(c){new ArrayBuffer(128*1024*1024);return c;}",
        "function main(c){c.extra=Array(100001).fill(0);return c;}"
    };
    for (const auto& script : invalid) { ConfigMerges bad; bad.profileScript = script; require(result(bad).find("\"error\":\"\"") == std::string::npos, "Invalid, failing or unsupported script results must not pass configuration validation"); }
    ConfigMerges sandbox; sandbox.profileScript = R"(async function main(c){
      for(const name of ['std','os','process','require','fetch','XMLHttpRequest','setTimeout','loadFile']) if(typeof globalThis[name]!=='undefined') throw new Error('unexpected host API');
      let denied=false;try{await import('std');}catch(e){denied=true;}if(!denied)throw new Error('module loader exposed');
      let blocked=false;try{Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0);}catch(e){blocked=true;}if(!blocked)throw new Error('blocking atomics exposed');
      if([...new Set([1,2,2])].length!==2||new Map([['x',1]]).get('x')!==1||!/节点/u.test('节点'))throw new Error('standard JS missing');return c;})";
    require(result(sandbox).find("\"error\":\"\"") != std::string::npos, "Standard JS works while filesystem, network, modules, timers and blocking atomics are unavailable");
    ConfigMerges bounded; bounded.profileScript = "function main(c){while(true){}return c;}"; const auto began = std::chrono::steady_clock::now();
    require(result(bounded).find("500 ms") != std::string::npos && std::chrono::steady_clock::now() - began < std::chrono::seconds(3), "Infinite loops must stop at the execution deadline");
    bounded.profileScript = "function main(c){/^(a+)+$/.test('a'.repeat(10000)+'!');return c;}"; const auto regexpBegan = std::chrono::steady_clock::now();
    require(result(bounded).find("\"error\":\"\"") == std::string::npos && std::chrono::steady_clock::now() - regexpBegan < std::chrono::seconds(3), "Expensive native regular expressions must obey the same interruption budget");
    ConfigMerges console; console.profileScript = "function main(c){console.log('界'.repeat(10000));return c;}";
    const std::string truncated = result(console); EditorYaml consoleDocument;
    require(consoleDocument.parse(truncated, 8 * 1024 * 1024, error) && truncated.find("output truncated") != std::string::npos, "Large Unicode console output must be bounded without invalid UTF-8");
    ConfigMerges identity; identity.profileScript = "function main(c){return c;}";
    require(result(identity, "extra: &x [*x]\nrules: ['MATCH,DIRECT']\n").find("cyclic") != std::string::npos, "Cyclic YAML aliases must fail at the JS boundary");
    require(result(identity, "extra: 9007199254740993\nrules: ['MATCH,DIRECT']\n").find("safe range") != std::string::npos, "Unsafe integer conversion must not silently change source data");
    identity.profileScript = std::string(256 * 1024 + 1, ' '); require(result(identity).find("size limits") != std::string::npos, "Script source byte caps apply before execution");
    const std::string profile = directory + "/script-device.yaml", globalFile = directory + "/.global-script.js";
    unlink(globalFile.c_str()); { std::ofstream out(profile); out << source; }
    { std::ofstream out(directory + "/script-device.meta.json"); out << "{\"name\":\"公开配置 A\"}"; }
    { std::ofstream out(globalFile); out << "function main(c,n){if(n!=='公开配置 A')throw new Error('wrong name');c.rules=['MATCH,REJECT'];return c;}"; }
    stopCore(); require(loadConfigLocked(profile, error) && activeProxyNode("fixture.test", 443).type == "reject", "Runtime global scripts must receive the saved profile display name");
    { std::ofstream out(profile + ".script.js"); out << "function main(c){c.rules=['MATCH,DIRECT'];return c;}"; }
    require(loadConfigLocked(profile, error) && activeProxyNode("fixture.test", 443).type == "direct", "Runtime profile scripts must override the global stage");
    { std::ofstream out(profile + ".script.js"); out << "function main(){throw new Error('failure');}"; }
    require(!loadConfigLocked(profile, error) && activeProxyNode("fixture.test", 443).type == "direct", "A script failure must retain the current native route");
    unlink(globalFile.c_str()); unlink((profile + ".script.js").c_str());
    require(loadConfigLocked(profile, error) && readTestFile(profile) == source, "Removing script layers restores source configuration without rewriting it");
}
