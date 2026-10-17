import test from 'node:test';
import assert from 'node:assert/strict';
import {EditorState} from '@codemirror/state';
import {yaml} from '@codemirror/lang-yaml';
import {json} from '@codemirror/lang-json';
import {CompletionContext} from '@codemirror/autocomplete';
import {history,undo} from '@codemirror/commands';
import {clashCompletions} from './completion.mjs';
import {serializeDocument} from './document.mjs';

function fixture(source,language='yaml') {
  const marker=source.indexOf('¦');assert(marker>=0);const pos=source.slice(0,marker).replace(/\r\n?/g,'\n').length,text=source.replace('¦','');
  let state=EditorState.create({doc:text,extensions:[language==='json'?json():yaml(),history()]});const baseline=state.doc;
  const result=clashCompletions(language)(new CompletionContext(state,pos,true));
  const view={get state(){return state;},dispatch(spec){state=state.update(spec).state;},focus(){}};
  return {result,labels:result?.options.map(x=>x.label)||[],apply(label){const option=result?.options.find(x=>x.label===label);assert(option,'Missing '+label);option.apply(view);return state.doc.toString();},undo(){assert(undo(view));return serializeDocument(state.doc,baseline,text);},text};
}
const nodes='proxies:\n  - {name: Public, type: ss}\n  - {name: "🇯🇵 日本 #1", type: trojan}\n';
for(const language of ['yaml','json'])test('Dialer references preserve exact Unicode names and support undo: '+language,()=>{
  const f=fixture(language==='yaml'?nodes+'proxy-groups: [{name: Gateway, proxies: [Public]}]\nproxy-providers: {P: {type: inline, payload: [{name: Exit, type: ss, dialer-proxy: ¦}]}}':JSON.stringify({proxies:[{name:'Public',type:'ss'},{name:'🇯🇵 日本 #1',type:'trojan'},{name:'Exit',type:'ss','dialer-proxy':'¦'}],'proxy-groups':[{name:'Gateway',proxies:['Public']}]}),language);
  for(const label of ['Public','🇯🇵 日本 #1','Gateway','DIRECT'])assert(f.labels.includes(label),label);
  assert(!f.labels.includes('Exit'));const changed=f.apply('🇯🇵 日本 #1');
  if(language==='json')assert.equal(JSON.parse(changed).proxies[2]['dialer-proxy'],'🇯🇵 日本 #1');else assert(changed.includes('dialer-proxy: "🇯🇵 日本 #1"'));
  assert.equal(f.undo(),f.text);
});
test('Dialer candidates exclude direct and indirect cycles through nodes and groups',()=>{
  const f=fixture('proxies: [{name: Exit, type: ss, dialer-proxy: ¦}, {name: Back, type: ss, dialer-proxy: Exit}, {name: Public, type: ss}]\nproxy-groups: [{name: Unsafe, proxies: [Back]}, {name: All, include-all-proxies: true}, {name: Safe, proxies: [Public]}]');
  for(const name of ['Exit','Back','Unsafe','All'])assert(!f.labels.includes(name),name);for(const name of ['Public','Safe','DIRECT'])assert(f.labels.includes(name),name);
});
test('Provider dialer override excludes groups consuming that provider, including dynamic resources',()=>{
  for(const type of ['inline','http']){
    const f=fixture('proxies: [{name: Public, type: ss}]\nproxy-providers: {P: {type: '+type+', override: {dialer-proxy: ¦}, payload: [{name: Exit, type: ss}]}}\nproxy-groups: [{name: Unsafe, use: [P]}, {name: All, include-all-providers: true}, {name: Safe, proxies: [Public]}]');
    assert(!f.labels.includes('Unsafe'));assert(!f.labels.includes('All'));assert(f.labels.includes('Safe'));
  }
});
test('Adding a provider or node to a group cannot introduce a dialer cycle',()=>{
  const source='proxies: [{name: Back, type: ss, dialer-proxy: Main}, {name: Public, type: ss}]\nproxy-providers: {P: {type: http, override: {dialer-proxy: Main}}, Safe: {type: http}}\n';
  const members=fixture(source+'proxy-groups: [{name: Main, proxies: [¦]}]');assert(!members.labels.includes('Back'));assert(members.labels.includes('Public'));
  const providers=fixture(source+'proxy-groups: [{name: Main, use: [¦]}]');assert.deepEqual(providers.labels,['Safe']);
});
test('Dialer fields are offered on nodes and provider overrides',()=>{
  for(const source of ['proxies: [{name: Exit, dial¦}]','proxy-providers: {P: {override: {dial¦}}}','proxy-providers: {P: {payload: [{name: Exit, dial¦}]}}'])assert(fixture(source).labels.includes('dialer-proxy'));
});
for(const protocol of ['http','socks5'])for(const language of ['yaml','json']) {
  test('Forward proxy network completion follows native TCP support: '+protocol+' '+language,()=>{
    const source=language==='yaml'?`proxies: [{name: Public, type: ${protocol}, network: ¦}]`:`{"proxies":[{"name":"Public","type":"${protocol}","network":¦}]}`;
    const f=fixture(source,language);assert.deepEqual(f.labels,['tcp']);const text=f.apply('tcp');
    if(language==='json')assert.equal(JSON.parse(text).proxies[0].network,'tcp');else assert(text.includes('network: tcp'));
    assert.equal(f.undo(),f.text);
  });
  test('Forward proxy completion never suggests unused SS/VMess ciphers: '+protocol+' '+language,()=>{
    const source=language==='yaml'?`proxies: [{type: ${protocol}, cipher: ¦}]`:`{"proxies":[{"type":"${protocol}","cipher":¦}]}`;
    assert.deepEqual(fixture(source,language).labels,[]);
  });
}
for(const tail of ['[¦]','[Pu¦]','["Pu¦blic"]','\n      - ¦','\n      - Pu¦'])test('YAML member references in block/flow/quoted drafts: '+tail,()=>{
  const f=fixture(nodes+'proxy-groups:\n  - name: Main\n    proxies: '+tail+'\n');assert(f.labels.includes('Public'));assert(!f.labels.includes('Main'));
  const text=f.apply('Public');assert(text.includes('"Public"'));assert.equal(f.undo(),f.text);
});
for(const tail of ['[¦]','["Pu¦"]','["Pu¦blic"]','["DIRECT",¦]'])test('JSON member references preserve surrounding structure: '+tail,()=>{
  const f=fixture('{"proxies":[{"name":"Public","type":"ss"}],"proxy-groups":[{"name":"Main","proxies":'+tail+'}]}','json');
  assert(f.labels.includes('Public'));assert(!f.labels.includes('Main'));assert(JSON.parse(f.apply('Public'))['proxy-groups'][0].proxies.includes('Public'));assert.equal(f.undo(),f.text);
});
test('Unicode and YAML metacharacters are a single quoted member and do not alter comments',()=>{
  const f=fixture(nodes+'proxy-groups:\n  - name: Main\n    proxies:\n      - 🇯🇵 日¦ # PUBLIC COMMENT\n');
  assert(f.labels.includes('🇯🇵 日本 #1'));assert(f.apply('🇯🇵 日本 #1').endsWith('      - "🇯🇵 日本 #1" # PUBLIC COMMENT\n'));
});
test('JSON-escaped identifiers decode before matching and are quoted once on insertion',()=>{
  const name='Public "quoted" \\ path 😀',f=fixture(JSON.stringify({proxies:[{name}], 'proxy-groups':[{name:'Main',proxies:['Pu¦']}]}),'json');
  assert.deepEqual(JSON.parse(f.apply(name))['proxy-groups'][0].proxies,[name]);
});
test('Single-quoted YAML names and values preserve literal apostrophes',()=>{
  const f=fixture("proxies: [{name: 'Public''s node'}]\nproxy-groups: [{name: Main, proxies: ['Pu¦blic']}]");
  assert(f.labels.includes("Public's node"));assert(f.apply("Public's node").includes('["Public\'s node"]'));
});
test('A YAML prefix ending in an escaped apostrophe still matches its decoded node name',()=>{
  const f=fixture("proxies: [{name: 'Public''s node'}]\nproxy-groups: [{name: Main, proxies: ['Public''¦s node']}]");
  assert.deepEqual(f.labels,["Public's node"]);assert(f.apply("Public's node").includes('["Public\'s node"]'));assert.equal(f.undo(),f.text);
});
test('A JSON prefix ending in an escaped quote still matches its decoded node name',()=>{
  const name='Public "quoted"',source=JSON.stringify({proxies:[{name}],'proxy-groups':[{name:'Main',proxies:['Public "¦quoted"']}]});
  const f=fixture(source,'json');assert.deepEqual(f.labels,[name]);assert.deepEqual(JSON.parse(f.apply(name))['proxy-groups'][0].proxies,[name]);assert.equal(f.undo(),f.text);
});
test('Member candidates omit duplicates, self references and groups that create indirect cycles',()=>{
  const f=fixture(nodes+'proxy-groups:\n  - name: Main\n    proxies: [Public, ¦]\n  - name: Parent\n    proxies: [Bridge]\n  - name: Bridge\n    proxies: [Main]\n  - name: Independent\n    proxies: [DIRECT]\n');
  for(const name of ['Main','Parent','Bridge','Public'])assert(!f.labels.includes(name),name);assert(f.labels.includes('Independent'));assert(f.labels.includes('DIRECT'));
});
test('Editing the existing member may retain that member',()=>{
  const f=fixture(nodes+'proxy-groups: [{name: Main, proxies: [Pu¦blic]}]');assert(f.labels.includes('Public'));
});
const providers='proxy-providers:\n  type: {type: inline, payload: [{name: Pool node}], override: {additional-prefix: "[P] ", additional-suffix: " #1"}}\n  dns: {type: http, url: "https://example.com/nodes.yaml"}\nrule-providers:\n  PublicRules: {type: inline, behavior: domain, payload: [example.com]}\n';
test('Group use references only proxy providers and omits existing entries',()=>{
  const f=fixture(providers+'proxy-groups: [{name: Main, use: [type, ¦]}]');assert.deepEqual(f.labels,['dns']);assert(f.apply('dns').includes('[type, "dns"]'));
});
test('Inline provider node references use their actual prefix and suffix',()=>{
  const f=fixture(providers+'proxy-groups: [{name: Main, proxies: [¦]}]');assert(f.labels.includes('[P] Pool node #1'));assert(!f.labels.includes('Pool node'));assert(!f.labels.includes('type'));assert(!f.labels.includes('dns'));
});
test('Dynamic or filtered providers do not fabricate node candidates',()=>{
  for(const settings of ['type: http','type: inline, filter: Public','type: inline, exclude-filter: Public','type: inline, exclude-type: ss']){
    const f=fixture('proxy-providers: {P: {'+settings+', payload: [{name: Public}]}}\nproxy-groups: [{name: Main, proxies: [Pu¦]}]');assert(!f.labels.includes('Public'));
  }
});
for(const section of ['proxy-providers','rule-providers'])test('Provider download route references nodes, groups and built-ins: '+section,()=>{
  const f=fixture(nodes+'proxy-groups: [{name: Main, proxies: [Public]}]\n'+section+': {P: {proxy: ¦}}');for(const name of ['Public','Main','DIRECT','REJECT'])assert(f.labels.includes(name),name);
});
test('Default selection offers configured members and used inline-provider nodes',()=>{
  const f=fixture(nodes+providers+'proxy-groups: [{name: Main, proxies: [Public], use: [type], default-selected: ¦}]');
  assert.deepEqual(new Set(f.labels),new Set(['Public','[P] Pool node #1']));
});
test('Include-all flags add static and inline-provider default candidates',()=>{
  const f=fixture(nodes+providers+'proxy-groups: [{name: Main, include-all: true, default-selected: ¦}]');
  assert(f.labels.includes('Public'));assert(f.labels.includes('🇯🇵 日本 #1'));assert(f.labels.includes('[P] Pool node #1'));assert(!f.labels.includes('Main'));
});
for(const [rule,label] of [['DOMAIN,example.com,Pu¦','Public'],['MATCH,DI¦','DIRECT'],['RULE-SET,Pub¦,DIRECT','PublicRules'],['RULE-SET,PublicRules,Pu¦','Public'],['IP-CIDR,192.0.2.0/24,Pu¦,no-resolve','Public'],['AND,((DOMAIN,example.com),(NETWORK,tcp)),Pu¦','Public'],['DO¦','DOMAIN']])
  for(const language of ['yaml','json'])test('Routing completion keeps rule expression and other fields: '+language+' '+rule,()=>{
    const source=language==='yaml'?nodes+providers+'rules:\n  - '+JSON.stringify(rule)+' # PUBLIC\n':JSON.stringify({proxies:[{name:'Public'}],'rule-providers':{PublicRules:{}},rules:[rule]});
    const f=fixture(source,language);assert(f.labels.includes(label));const output=f.apply(label);
    if(language==='json'){const result=JSON.parse(output).rules[0];assert(!result.includes('¦'));assert(result.includes(label));if(rule.includes('no-resolve'))assert(result.endsWith(',no-resolve'));}
    else assert(output.endsWith(' # PUBLIC\n'));assert.equal(f.undo(),f.text);
  });
test('Replacing the middle of an existing rule target replaces its complete token',()=>{
  const f=fixture(nodes+'proxy-groups: [{name: Main, proxies: [Public]}]\nrules: ["IP-CIDR,192.0.2.0/24,Ma¦in,no-resolve"]');
  assert(f.apply('Main').endsWith('rules: ["IP-CIDR,192.0.2.0/24,Main,no-resolve"]'));
});
test('Rule CSV targets exclude commas and parentheses; group member references remain available',()=>{
  const definitions='proxies: [{name: "Public, comma"}, {name: "Public (paren)"}]\n';
  assert.deepEqual(fixture(definitions+'rules: ["MATCH,Pu¦"]').labels,[]);assert.equal(fixture(definitions+'proxy-groups: [{name: Main, proxies: [Pu¦]}]').labels.length,2);
});
for(const tail of ['DOMAIN,exam¦ple.com,DIRECT','AND,((DOMAIN,exam¦ple.com),(NETWORK,tcp)),DIRECT','IP-CIDR,192.0.2.0/24,DIRECT,no-res¦olve'])test('Rule operands and flags are not proxy target positions: '+tail,()=>{
  assert.equal(fixture(nodes+'rules: ['+JSON.stringify(tail)+']').result,null);
});
for(const source of [nodes+'# proxy-groups: [Pu¦]',nodes+'custom: {proxies: [Pu¦]}',nodes+'proxies: [{name: Another, password: Pu¦}]',nodes+'note: |\n  proxy-groups: [{proxies: [Pu¦]}]\n',nodes+'proxy-providers: {P: {payload: [{name: Another, password: Pu¦}]}}'])test('References never derive candidates from comments, secrets or unrelated data: '+source.slice(-55),()=>assert.equal(fixture(source).result,null));
test('Name extraction is scoped to configuration definitions, not embedded objects or scalar text',()=>{
  const f=fixture('note: {proxies: [{name: SecretLike}], password: PasswordLike}\n# proxies: [{name: CommentLike}]\nproxy-groups: [{name: Main, proxies: [¦]}]');assert.deepEqual(f.labels,['DIRECT','REJECT']);
});
test('Separate YAML documents never share reference candidates',()=>{
  const f=fixture(nodes+'---\nproxies: [{name: Second}]\nproxy-groups: [{name: Main, proxies: [¦]}]');assert(f.labels.includes('Second'));assert(!f.labels.includes('Public'));
});
test('Reference cache follows new editor documents after names change',()=>{
  let state=EditorState.create({doc:nodes+'proxy-groups: [{name: Main, proxies: []}]',extensions:[yaml()]});
  const labels=()=>clashCompletions('yaml')(new CompletionContext(state,state.doc.length-3,true))?.options.map(x=>x.label)||[];
  assert(labels().includes('Public'));const from=state.doc.toString().indexOf('Public');state=state.update({changes:{from,to:from+6,insert:'Renamed'}}).state;assert(labels().includes('Renamed'));assert(!labels().includes('Public'));
});
test('Reference insertion and undo preserve exact CRLF bytes',()=>{
  const f=fixture((nodes+'proxy-groups: [{name: Main, proxies: [Pu¦]}]\n').replaceAll('\n','\r\n'));f.apply('Public');assert.equal(f.undo(),f.text);
});
test('Large documents still resolve definitions after the initial parser budget',async()=>{
  const source='# PUBLIC\n'.repeat(20000)+nodes+'proxy-groups: [{name: Main, proxies: [Pu¦]}]',pos=source.indexOf('¦'),state=EditorState.create({doc:source.replace('¦',''),extensions:[yaml()]});
  const result=await clashCompletions('yaml')(new CompletionContext(state,pos,true));assert(result.options.some(x=>x.label==='Public'));
});
test('An aborted large-document query stops without publishing stale names',async()=>{
  const text='# PUBLIC\n'.repeat(150000)+nodes+'proxy-groups: [{name: Main, proxies: []}]',state=EditorState.create({doc:text,extensions:[yaml()]});
  let aborted=false,listener;const context={state,pos:state.doc.length-3,explicit:true,get aborted(){return aborted;},addEventListener(type,callback,options){assert.equal(type,'abort');assert(options.onDocChange);listener=callback;}};
  const result=clashCompletions('yaml')(context);assert(result instanceof Promise);aborted=true;listener();assert.equal(await result,null);
});
test('A retained completion cannot overwrite a newer document or a readonly/composing editor',()=>{
  const text=nodes+'proxy-groups: [{name: Main, proxies: [Pu]}]',state=EditorState.create({doc:text,extensions:[yaml()]}),pos=text.length-3,result=clashCompletions('yaml')(new CompletionContext(state,pos,true)),option=result.options.find(x=>x.label==='Public');assert(option);
  for(const [changed,readonly,composing] of [[true,false,false],[false,true,false],[false,false,true]]){
    let current=EditorState.create({doc:text+(changed?'\n# newer':''),extensions:[yaml(),EditorState.readOnly.of(readonly)]});const before=current.doc.toString();
    option.apply({get state(){return current;},composing,dispatch(spec){current=current.update(spec).state;},focus(){}});assert.equal(current.doc.toString(),before);
  }
});
for(const tail of ['proxy-groups: [{name: Main, proxies: Pu¦}]','proxy-groups: [{name: Main, use: ¦}]','rules: "MATCH,Pu¦"','proxy-providers: {P: {proxy: [Pu¦]}}'])test('References respect scalar/list schema shapes: '+tail,()=>assert.equal(fixture(nodes+tail).result,null));
for(const [source,expected] of [
  ['allow-l¦','allow-lan'],['lan-dis¦','lan-disallowed-ips'],['auth¦','authentication'],['snif¦','sniffer'],
  ['dns:\n  direct-n¦','direct-nameserver'],['dns:\n  proxy-server-nameserver-p¦','proxy-server-nameserver-policy'],
  ['proxy-groups: [{include-all-pr¦}]','include-all-proxies'],['proxy-groups: [{hi¦}]','hidden'],['proxy-groups: [{ic¦}]','icon'],
  ['proxy-providers: {dns: {ov¦}}','override'],['proxy-providers: {dns: {override: {add¦}}}','additional-prefix'],
  ['sniffer:\n  force-d¦','force-dns-mapping'],['sniffer: {sniff: {QU¦}}','QUIC'],['sniffer: {sniff: {TLS: {po¦}}}','ports'],
  ['sniffer: {sniff: {http: {override-d¦}}}','override-destination'],['proxies: [{al¦}]','alpn'],
  ['proxy-providers: {P: {payload: [{ws-opts: {pa¦}}]}}','path']
  ,['proxy-providers:\n  "🇯🇵 Public: #1":\n    he¦','health-check']
  ,["proxy-providers:\n  'Public''s nodes':\n    ty¦",'type']
  ,['proxy-providers:\n  Public nodes:\n    ov¦','override']
])test('Native schema fields are contextual: '+source,()=>assert(fixture(source).labels.includes(expected)));
test('VMess cipher values follow the actual protocol instead of Shadowsocks',()=>{
  const f=fixture('proxies: [{name: Public, type: vmess, cipher: ¦}]');assert(f.labels.includes('auto'));assert(f.labels.includes('chacha20-poly1305'));assert(!f.labels.includes('aes-256-gcm'));
});
for(const source of ['custom: {enable: tr¦}','custom: {sniffer: {en¦}}','proxy-providers: {P: {header: {en¦}}}','proxy-providers: {P: {unknown: {ty¦}}}','proxy-groups: [{extra: {en¦}}]'])test('Unknown and arbitrary mappings do not inherit native schema fields: '+source,()=>assert.equal(fixture(source).result,null));
