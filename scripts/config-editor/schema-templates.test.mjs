import test from 'node:test';
import assert from 'node:assert/strict';
import {EditorState} from '@codemirror/state';
import {yaml} from '@codemirror/lang-yaml';
import {CompletionContext} from '@codemirror/autocomplete';
import {history,undo} from '@codemirror/commands';
import {parse} from 'yaml';
import {clashCompletions} from './completion.mjs';
import {serializeDocument} from './document.mjs';

function fixture(source) {
  const marker=source.indexOf('¦');assert(marker>=0);
  const pos=source.slice(0,marker).replace(/\r\n?/g,'\n').length,text=source.replace('¦','');
  let state=EditorState.create({doc:text,extensions:[yaml(),history()]});const baseline=state.doc;
  const result=clashCompletions('yaml')(new CompletionContext(state,pos,true));assert(!(result instanceof Promise));
  const view={get state(){return state;},dispatch(spec){state=state.update(spec).state;},focus(){}};
  return {labels:result?.options.map(x=>x.label)||[],apply(label){const option=result?.options.find(x=>x.label===label);assert(option,'Missing '+label);option.apply(view);return state.doc.toString();},undo(){assert(undo(view));return serializeDocument(state.doc,baseline,text);},text};
}
for(const [definition,consumer,field] of [
  ['shared: &base {net¦}','proxies: [{<<: *base, name: Public, type: http}]','network'],
  ['shared: &base\n  net¦','proxies: [{<<: *base, name: Public, type: http}]','network'],
  ['shared: &base {ti¦}','proxy-groups: [{<<: *base, name: Main}]','timeout'],
  ['shared: &base {he¦}','proxy-providers: {P: *base}','health-check'],
  ['shared: &base {be¦}','rule-providers: {P: *base}','behavior'],
  ['shared: &base {mo¦}','<<: *base','mode'],
  ['shared: &base {en¦}','dns: *base','enable'],
  ['shared: &base {additional-pr¦}','proxy-providers: {P: {override: *base}}','additional-prefix'],
  ['shared: &base {pa¦}','proxies: [{name: Public, type: vmess, ws-opts: *base}]','path'],
  ['shared: &base {po¦}','sniffer: {sniff: {tls: *base}}','ports'],
  ['shared: &base {ge¦}','dns: {fallback-filter: *base}','geoip'],
])test('Template fields follow their effective schema: '+consumer,()=>{
  const f=fixture(definition+'\n'+consumer+'\n');
  assert(f.labels.includes(field),field+': '+f.labels);
});
test('A blank indented line retains the shared template mapping context',()=>{
  const f=fixture('shared: &base\n  type: http\n  ¦\nproxies: [{<<: *base, name: Public}]\n');assert(f.labels.includes('network'));assert(!f.labels.includes('mode'));
});
test('The first partial block key inserts one colon and undoes to the exact untouched draft',()=>{
  const f=fixture('shared: &base\r\n  net¦\r\nproxies: [{<<: *base, name: Public, type: http}]\r\n');
  const result=f.apply('network');assert(result.includes('  network: "tcp"'));assert.equal(parse(result,{merge:true}).proxies[0].network,'tcp');assert.equal(f.undo(),f.text);
});
test('Nested shared maps inherit a schema through more than one merge layer',()=>{
  const f=fixture('headers: &headers {pa¦}\nbase: &base {ws-opts: *headers}\nnext: &next {<<: *base}\nproxies: [{<<: *next, type: vmess, name: Public}]');assert.deepEqual(f.labels,['path']);
});
test('A map used by both group and health-check contexts offers their common fields',()=>{
  const source='shared: &base {¦}\nproxy-groups: [{<<: *base, name: Main}]\nproxy-providers: {P: {health-check: *base}}';
  const f=fixture(source);for(const key of ['url','interval','timeout','expected-status','lazy'])assert(f.labels.includes(key),key);
  for(const key of ['name','enable','strategy','proxies'])assert(!f.labels.includes(key),key);
  assert.equal(parse(f.apply('timeout'),{merge:true})['proxy-groups'][0].timeout,5000);assert.equal(f.undo(),f.text);
});
test('A shared type has to be a valid node and provider type simultaneously',()=>{
  const f=fixture('shared: &base {type: ¦}\nproxies: [{<<: *base, name: Public}]\nproxy-providers: {P: *base}');assert.deepEqual(f.labels,['http']);
  const parsed=parse(f.apply('http'),{merge:true});assert.equal(parsed.proxies[0].type,'http');assert.equal(parsed['proxy-providers'].P.type,'http');
});
test('Incompatible shared type consumers do not suggest invalid values or defaults',()=>{
  const consumers='\nproxies: [{<<: *base, name: Public}]\nproxy-groups: [{<<: *base, name: Main}]';
  assert.deepEqual(fixture('shared: &base {type: ¦}'+consumers).labels,[]);
  assert.deepEqual(fixture('shared: &base {ty¦}'+consumers).labels,[]);
});
test('Effective protocol overrides intersect cipher values at their shared definition',()=>{
  const f=fixture('shared: &base {cipher: ¦}\nproxies: [{<<: *base, name: SS, type: ss}, {<<: *base, name: VM, type: vmess}]');assert.deepEqual(f.labels,['aes-128-gcm']);
});
test('An explicit field override removes that consumer from shared enum constraints',()=>{
  const f=fixture('shared: &base {network: ¦}\nproxies: [{<<: *base, name: Public, type: vmess}, {<<: *base, name: Detached, type: http, network: tcp}]');assert.deepEqual(f.labels,['tcp','ws']);
});
test('A source scalar alias receives the schema of its actual field consumers',()=>{
  const f=fixture('protocol: &protocol ht¦tp\nproxies: [{name: Public, type: *protocol}]');assert.deepEqual(f.labels,['http']);assert.equal(parse(f.apply('http')).proxies[0].type,'http');assert.equal(f.undo(),f.text);
});
test('Boolean scalar aliases retain filtering and exact insertion',()=>{
  const f=fixture('flag: &flag tr¦ue\ndns: {enable: *flag}\nproxies: [{name: Public, udp: *flag}]');assert.deepEqual(f.labels,['true']);assert.equal(parse(f.apply('true')).dns.enable,true);
});
test('Aliased enum values still have to satisfy every real consumer',()=>{
  const f=fixture('protocol: &protocol ¦http\nproxies: [{name: Public, type: *protocol}]\nproxy-providers: {P: {type: *protocol}}');assert.deepEqual(f.labels,['http']);assert.equal(parse(f.apply('http')).protocol,'http');assert.equal(f.undo(),f.text);
});
for(const source of [
  'unused: &unused {net¦}\nproxies: [{name: Public}]',
  'base: &base {dns: {en¦}}\n<<: *base\ndns: {enable: true}',
  'base: &base {ws-opts: {pa¦}}\nproxies: [{<<: *base, name: Public, ws-opts: {path: /explicit}}]',
  'custom: &custom {sniffer: {en¦}}\nproxies: [{name: Public}]',
  'base: &base {ty¦}\n---\nproxies: [{<<: *base, name: Public}]',
  'base: &same {ty¦}\nother: &same {type: http}\nproxies: [*same]',
  'base: &base {<<: *base, net¦}\nproxies: [{<<: *base, name: Public}]',
  'shared: &base {password: ht¦}\nproxies: [{<<: *base, name: Public, type: http}]',
  'flag: &flag ht¦tp\nproxies: [{name: Public, type: *flag, password: *flag}]',
  'future: *later\nbase: &later {net¦}\nproxies: [*future]',
])test('Unused, overridden, unrelated, secret or invalid template contexts remain silent: '+source.split('\n')[0],()=>assert.deepEqual(fixture(source).labels,[]));
for(const source of [
  'shared: &base {network: &tc¦p tcp}\nproxies: [{<<: *base, type: vmess}]',
  'network: &network tcp\nshared: &base {network: *net¦work}\nproxies: [{<<: *base, type: vmess}]',
  'shared: &base {tls: !!tr¦ue true}\nproxies: [{<<: *base, type: vmess}]',
])test('Schema completion never overwrites an alias, anchor or tag token',()=>assert.deepEqual(fixture(source).labels,[]));
test('Quoted template enum insertion preserves comments, anchors and CRLF undo bytes',()=>{
  const f=fixture(('shared: &base {network: \'w¦s\'} # PUBLIC\nproxies: [{<<: *base, name: Public, type: vmess}]\n').replaceAll('\n','\r\n'));
  const result=f.apply('ws');assert(result.includes('shared: &base {network: "ws"} # PUBLIC'));assert.equal(parse(result,{merge:true}).proxies[0].network,'ws');assert.equal(f.undo(),f.text);
});
test('Changing a consumer protocol invalidates inferred template enums and undo restores them',()=>{
  const text='shared: &base {network: }\nproxies: [{<<: *base, type: http}]';let state=EditorState.create({doc:text,extensions:[yaml(),history()]});
  const labels=()=>clashCompletions('yaml')(new CompletionContext(state,text.indexOf('network: ')+9,true))?.options.map(x=>x.label)||[];
  assert.deepEqual(labels(),['tcp']);const from=text.lastIndexOf('http');state=state.update({changes:{from,to:from+4,insert:'vmess'}}).state;assert.deepEqual(labels(),['tcp','ws']);
  assert(undo({get state(){return state;},dispatch(spec){state=state.update(spec).state;}}));assert.deepEqual(labels(),['tcp']);
});
test('Dense shared schema definitions remain bounded without expanding aliases',async()=>{
  const source='shared: &base {network: }\nproxies: ['+Array.from({length:1500},(_,i)=>'{<<: *base, name: Node-'+i+', type: vmess}').join(',')+']';
  const state=EditorState.create({doc:source,extensions:[yaml()]});const result=await clashCompletions('yaml')(new CompletionContext(state,source.indexOf('network: ')+9,true));assert.deepEqual(result?.options.map(x=>x.label),['tcp','ws']);
});
