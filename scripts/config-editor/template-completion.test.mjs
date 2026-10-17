import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {EditorState} from '@codemirror/state';
import {yaml} from '@codemirror/lang-yaml';
import {CompletionContext} from '@codemirror/autocomplete';
import {history,undo} from '@codemirror/commands';
import {parse} from 'yaml';
import {clashCompletions} from './completion.mjs';
import {serializeDocument} from './document.mjs';

function fixture(source) {
  const marker=source.indexOf('¦');assert(marker>=0);const pos=source.slice(0,marker).replace(/\r\n?/g,'\n').length,text=source.replace('¦','');
  let state=EditorState.create({doc:text,extensions:[yaml(),history()]});const baseline=state.doc;
  const result=clashCompletions('yaml')(new CompletionContext(state,pos,true));assert(!(result instanceof Promise),'Small fixture must complete synchronously');
  const view={get state(){return state;},dispatch(spec){state=state.update(spec).state;},focus(){}};
  return {labels:result?.options.map(x=>x.label)||[],apply(label){const option=result?.options.find(x=>x.label===label);assert(option,'Missing '+label);option.apply(view);return state.doc.toString();},undo(){assert(undo(view));return serializeDocument(state.doc,baseline,text);},text};
}
const nodes='proxies: [{name: Public, type: http}, {name: Other, type: http}]\n';
const publicFixture=fs.readFileSync(new URL('../../tests/fixtures/yaml/editor-templates.yaml',import.meta.url),'utf8');
test('Native compatibility fixture resolves root merges, scalar/sequence aliases and inline provider overrides',()=>{
  const f=fixture(publicFixture.replace('default-selected: *node-name','default-selected: ¦'));
  assert.deepEqual(new Set(f.labels),new Set(['Template HTTP','DIRECT','[T] Pool']));
  const changed=f.apply('[T] Pool');assert(changed.includes('!!merge <<: *defaults'));assert(changed.includes('proxies: *members'));
  assert.equal(parse(changed,{merge:true})['proxy-groups'][0]['default-selected'],'[T] Pool');assert.equal(f.undo(),f.text);
});
test('References inside an aliased rules template use effective nodes, groups and rule providers',()=>{
  const routes=fixture(publicFixture.replace('MATCH,Template-Main','MATCH,Template¦'));
  assert.deepEqual(new Set(routes.labels),new Set(['Template HTTP','Template-HTTPS','Template-Main']));
  const sets=fixture(publicFixture.replace('MATCH,Template-Main','RULE-SET,Fix¦,DIRECT'));assert.deepEqual(sets.labels,['FixtureRules']);
});
test('Shared member list completion excludes duplicates and every consuming group',()=>{
  const f=fixture(nodes+'members: &members [Public, ¦]\nproxy-groups: [{name: A, proxies: *members}, {name: B, proxies: *members}, {name: Parent, proxies: [B]}, {name: Safe, proxies: [DIRECT]}]');
  for(const name of ['Public','A','B','Parent'])assert(!f.labels.includes(name),name);
  for(const name of ['Other','DIRECT','Safe'])assert(f.labels.includes(name),name);
  assert(parse(f.apply('Other'))['proxy-groups'][0].proxies.includes('Other'));assert.equal(f.undo(),f.text);
});
test('Merged shared fields check every inheriting group, including explicit overrides',()=>{
  const f=fixture(nodes+'base: &base {proxies: [¦]}\nproxy-groups: [{<<: *base, name: A}, {<<: *base, name: B}, {<<: *base, name: Detached, proxies: [DIRECT]}]');
  assert(!f.labels.includes('A'));assert(!f.labels.includes('B'));assert(f.labels.includes('Detached'));
});
test('Aliases of complete mappings keep use-site names and actual inherited dialer edges',()=>{
  const f=fixture('base: &base {type: http, dialer-proxy: Main}\nnode: &node {<<: *base, name: Back}\nproxies: [*node, {name: Public, type: http}]\nproxy-groups: [{name: Main, proxies: [¦]}, {name: Parent, proxies: [Back]}]');
  assert(!f.labels.includes('Back'));assert(!f.labels.includes('Parent'));assert(f.labels.includes('Public'));
});
test('An inherited shared node dialer cannot create cycles in any consumer',()=>{
  const f=fixture('base: &base {type: http, dialer-proxy: ¦}\nproxies: [{<<: *base, name: A}, {<<: *base, name: B}, {name: Public}]\nproxy-groups: [{name: Parent, proxies: [B]}]');
  for(const name of ['A','B','Parent'])assert(!f.labels.includes(name),name);assert(f.labels.includes('Public'));
});
test('Provider template override uses the effective prefixed names for cycle checks',()=>{
  const f=fixture(nodes+'base: &base {type: inline, payload: [{name: Exit}], override: {additional-prefix: "[P] ", dialer-proxy: ¦}}\nproxy-providers: {P: *base}\nproxy-groups: [{name: Unsafe, use: [P]}, {name: All, include-all-providers: true}, {name: Safe, proxies: [Public]}]');
  for(const name of ['[P] Exit','Unsafe','All'])assert(!f.labels.includes(name),name);assert(f.labels.includes('Safe'));
});
for(const [key,header] of [['!!merge "<<"',''],['!m!merge \'<<\'','%TAG !m! tag:yaml.org,2002:\n---\n'],['!<tag:yaml.org,2002:merge> <<',''],['*merge','merge: &merge <<\n']])test('Native merge tag/key alias semantics: '+key,()=>{
  const f=fixture(header+'base: &base {proxies: [{name: Inherited}]}\n'+key+': *base\nproxy-groups: [{name: Main, proxies: [Inh¦]}]');assert.deepEqual(f.labels,['Inherited']);
});
for(const key of ['"<<"',"'<<'",'!!str <<','!!str "<<"','!<tag:yaml.org,2002:str> <<'])test('Literal merge-like keys do not fabricate effective definitions: '+key,()=>{
  const f=fixture('base: &base {proxies: [{name: Hidden}]}\n'+key+': *base\nproxy-groups: [{name: Main, proxies: [Hi¦]}]');assert.deepEqual(f.labels,[]);
});
for(const body of ['proxies: []\n<<: *base','<<: *base\nproxies: []'])test('Explicit empty definitions override inherited values regardless of order: '+body,()=>{
  assert.deepEqual(fixture('base: &base {proxies: [{name: Hidden}]}\n'+body+'\nproxy-groups: [{name: Main, proxies: [Hi¦]}]').labels,[]);
});
test('Earlier merge sources win and nested maps are replaced shallowly',()=>{
  const f=fixture('first: &first {override: {additional-prefix: "WRONG "}, payload: [{name: First}]}\nsecond: &second {payload: [{name: Wrong}]}\nproxy-providers: {P: {<<: [*first, *second], type: inline, override: {additional-suffix: " S"}}}\nproxy-groups: [{name: Main, proxies: [¦]}]');
  assert(f.labels.includes('First S'));assert(!f.labels.some(x=>x.includes('WRONG')||x.includes('Wrong')));
});
for(const type of ['http','socks5','vmess','vless'])test('Inherited/aliased protocol types constrain native enum completion: '+type,()=>{
  const f=fixture('protocol: &protocol '+type+'\nbase: &base {type: *protocol}\nproxies: [{<<: *base, name: Public, network: ¦}]');
  assert.deepEqual(f.labels,['http','socks5'].includes(type)?['tcp']:['tcp','ws']);
});
for(const anchor of ['&node','!!map &node','&node !!map'])test('Block anchors and tags retain field context: '+anchor,()=>{
  assert(fixture('proxies: '+anchor+'\n  - name: Public\n    net¦').labels.includes('network'));
});
test('YAML-specific escapes, folded/quoted names and plain numeric text match the core',()=>{
  const f=fixture('proxies:\n  - {name: "A\\x20B", type: http}\n  - {name: "Emoji \\U0001F600", type: http}\n  - {name: 0012, type: http}\n  - {name: !!int 0x12, type: http}\n  - name: >-\n      Folded\n      name\n    type: http\n  - name: "Quoted\n      name"\n    type: http\nproxy-groups: [{name: Main, proxies: [¦]}]');
  for(const name of ['A B','Emoji 😀','0012','0x12','Folded name','Quoted name'])assert(f.labels.includes(name),name);
  assert.equal(parse(f.apply('A B'))['proxy-groups'][0].proxies[0],'A B');
});
test('An aliased field key is read as its actual name',()=>{
  const f=fixture('key: &key name\nproxies: [{*key: Public}]\nproxy-groups: [{name: Main, proxies: [Pu¦]}]');assert.deepEqual(f.labels,['Public']);
});
test('Filtered inherited providers do not expose unverifiable nodes',()=>{
  const f=fixture('base: &base {type: inline, filter: Public, payload: [{name: Public}]}\nproxy-providers: {P: *base}\nproxy-groups: [{name: Main, proxies: [Pu¦]}]');assert.deepEqual(f.labels,[]);
});
for(const prefix of ['proxies: *future\nlater: &future [{name: Hidden}]\n','one: &same {name: Hidden}\ntwo: &same {name: Other}\nproxies: [*same]\n','base: &base {proxies: [{name: Hidden}]}\n---\n<<: *base\n'])test('Forward, duplicate and cross-document anchors never fabricate names: '+prefix.split('\n')[0],()=>{
  assert.deepEqual(fixture(prefix+'proxy-groups: [{name: Main, proxies: [Hi¦]}]').labels,[]);
});
for(const tail of ['proxies: *no¦des','proxies: &mem¦bers []','type: !!st¦r http'])test('Completing identifiers never overwrites YAML alias/anchor/tag tokens: '+tail,()=>{
  assert.deepEqual(fixture('nodes: &nodes [Public]\nproxy-groups: [{name: Main, '+tail+'}]').labels,[]);
});
for(const broken of ['base: &base {<<: *base}\n<<: *base','base: &base [*base]\nproxies: *base','<<: *undefined','<<: [{proxies: [{name: Hidden}]}, [wrong]]','<<: {proxies: [{name: Hidden}]}\n<<: {}'])test('Invalid merge drafts remain bounded and never leak unrelated names: '+broken.split('\n')[0],()=>{
  const start=performance.now();assert.deepEqual(fixture(broken+'\nproxy-groups: [{name: Main, proxies: [Hi¦]}]').labels,[]);assert(performance.now()-start<1000);
});
test('Exponential aliases stay a graph rather than expanding into candidate objects',()=>{
  let source='a0: &a0 [{name: Hidden}]\n';for(let i=1;i<=18;i++)source+='a'+i+': &a'+i+' ['+Array(10).fill('*a'+(i-1)).join(',')+']\n';
  const start=performance.now();const f=fixture(source+'proxies: *a18\nproxy-groups: [{name: Main, proxies: [Hi¦]}]');assert.deepEqual(f.labels,[]);assert(performance.now()-start<1000);
});
test('Shared template completion preserves CRLF, comments and exact undo bytes',()=>{
  const f=fixture((nodes+'members: &members [Pu¦] # PUBLIC COMMENT\nproxy-groups: [{name: Main, proxies: *members}]\n').replaceAll('\n','\r\n'));
  assert(f.apply('Public').includes('members: &members ["Public"] # PUBLIC COMMENT'));assert.equal(f.undo(),f.text);
});
test('Changing an anchor invalidates semantic caches and undo restores its references',()=>{
  const text='name: &name Public\nproxies: [{name: *name}]\nproxy-groups: [{name: Main, proxies: []}]';
  let state=EditorState.create({doc:text,extensions:[yaml(),history()]});
  const labels=()=>clashCompletions('yaml')(new CompletionContext(state,state.doc.length-3,true))?.options.map(x=>x.label)||[];
  assert(labels().includes('Public'));const from=text.indexOf('Public');state=state.update({changes:{from,to:from+6,insert:'Renamed'}}).state;
  assert(labels().includes('Renamed'));assert(!labels().includes('Public'));
  assert(undo({get state(){return state;},dispatch(spec){state=state.update(spec).state;}}));assert(labels().includes('Public'));
});
test('Explicit empty inherited member/use lists constrain defaults instead of borrowing template values',()=>{
  const f=fixture(nodes+'base: &base {proxies: [Public], use: [P]}\nproxy-providers: {P: {type: inline, payload: [{name: Pool}]}}\nproxy-groups: [{<<: *base, name: Main, proxies: [], use: [], default-selected: ¦}]');assert.deepEqual(f.labels,[]);
});
test('A dense valid template profile remains usable without expanding shared maps',async()=>{
  const source='base: &base {type: http, server: 127.0.0.1, port: 18097}\nproxies: ['+Array.from({length:1500},(_,i)=>'{<<: *base, name: Node-'+i+'}').join(',')+']\nproxy-groups: [{name: Main, proxies: [Node-149]}]';
  const state=EditorState.create({doc:source,extensions:[yaml()]});const result=await clashCompletions('yaml')(new CompletionContext(state,state.doc.length-3,true));
  assert(result?.options.some(x=>x.label==='Node-1499'));
});
