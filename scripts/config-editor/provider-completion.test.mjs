import test from 'node:test';
import assert from 'node:assert/strict';
import {EditorState} from '@codemirror/state';
import {yaml} from '@codemirror/lang-yaml';
import {json} from '@codemirror/lang-json';
import {CompletionContext} from '@codemirror/autocomplete';
import {history,undo} from '@codemirror/commands';
import {clashCompletions,completionContext} from './completion.mjs';
import {providerReferenceQuery} from './references.mjs';
import {ProviderCompletionClient} from './provider-bridge.mjs';
import {serializeDocument} from './document.mjs';

const prefix='proxy-providers: {P: {type: http, url: https://example.invalid/nodes}}\n';
const cached=(nodes,name='P')=>({providers:[{name,nodes:nodes.map(n=>typeof n==='string'?{name:n,type:'ss',dialer:''}:n)}]});
async function fixture(source,language='yaml',data=cached(['Cached 😀'])){
 const marker=source.indexOf('¦');assert(marker>=0);const pos=source.slice(0,marker).replace(/\r\n?/g,'\n').length,text=source.replace('¦','');
 let state=EditorState.create({doc:text,extensions:[language==='yaml'?yaml():json(),history()]});const original=state.doc,queries=[];
 const result=await clashCompletions(language,async query=>{queries.push(JSON.parse(query));return typeof data==='function'?data(query):data;})(new CompletionContext(state,pos,true));
 const view={get state(){return state;},dispatch(spec){state=state.update(spec).state;},focus(){}};
 return{result,queries,labels:result?.options.map(o=>o.label)||[],text,apply(label){const option=result?.options.find(o=>o.label===label);assert(option,'Missing '+label);option.apply(view);return serializeDocument(state.doc,original,text);},undo(){assert(undo(view));return serializeDocument(state.doc,original,text);}};
}
for(const language of ['yaml','json'])test('Downloaded provider names participate in members, exact insertion and undo: '+language,async()=>{
 const source=language==='yaml'?prefix+'proxy-groups: [{name: Main, use: [P], proxies: [Ca¦]}]':JSON.stringify({'proxy-providers':{P:{type:'http',url:'https://example.invalid/nodes'}},'proxy-groups':[{name:'Main',use:['P'],proxies:['Ca¦']}]}),f=await fixture(source,language);
 assert.deepEqual(f.labels,['Cached 😀']);assert.equal(f.queries.length,1);assert(f.apply('Cached 😀').includes('Cached 😀'));assert.equal(f.undo(),f.text);
});
test('Provider defaults include cached candidates only from used providers',async()=>{
 const f=await fixture(prefix+'proxy-groups: [{name: Main, use: [P], default-selected: Ca¦}]');assert.deepEqual(f.labels,['Cached 😀']);
 const other=await fixture(prefix+'proxy-groups: [{name: Main, proxies: [DIRECT], default-selected: Ca¦}]');assert.deepEqual(other.labels,[]);
});
test('Cached nodes take part in direct and indirect dialer cycle checks',async()=>{
 const data=cached([{name:'Back',type:'ss',dialer:'Main'},'Safe']);
 const f=await fixture(prefix+'proxy-groups: [{name: Main, proxies: [¦]}]','yaml',data);assert(!f.labels.includes('Back'));assert(f.labels.includes('Safe'));
 const use=await fixture(prefix+'proxy-groups: [{name: Main, use: [¦]}]','yaml',data);assert(!use.labels.includes('P'));
 const dialer=await fixture(prefix+'proxies: [{name: Main, type: ss, dialer-proxy: ¦}]','yaml',data);assert(!dialer.labels.includes('Back'));assert(dialer.labels.includes('Safe'));
});
test('Provider override templates exclude their own cached exits and consuming groups',async()=>{
 const f=await fixture('x-template: &route {dialer-proxy: ¦}\nproxy-providers: {P: {type: http, url: https://example.invalid/nodes, override: *route}}\nproxy-groups: [{name: Consumer, use: [P]}, {name: Safe, proxies: [DIRECT]}]');
 assert(!f.labels.includes('Consumer'));assert(!f.labels.includes('Cached 😀'));assert(f.labels.includes('Safe'));
});
test('Cached candidates exclude existing members and preserve CRLF comments on insertion',async()=>{
 const source=prefix.replaceAll('\n','\r\n')+'proxy-groups:\r\n  - name: Main\r\n    proxies: ["Cached 😀", Sa¦] # PUBLIC\r\n';
 const f=await fixture(source,'yaml',cached(['Cached 😀','Safe #1']));assert.deepEqual(f.labels,['Safe #1']);assert(f.apply('Safe #1').endsWith('["Cached 😀", "Safe #1"] # PUBLIC\r\n'));assert.equal(f.undo(),f.text);
});
test('Routing rules and provider download routes can use cached names',async()=>{
 const rules=await fixture(prefix+'rules: ["MATCH,Ca¦"]');assert.deepEqual(rules.labels,['Cached 😀']);assert(rules.apply('Cached 😀').includes('MATCH,Cached 😀'));
 const download=await fixture(prefix+'rule-providers: {R: {proxy: Ca¦}}');assert.deepEqual(download.labels,['Cached 😀']);
});
test('Native metadata replaces a downloaded provider fallback without applying its prefix twice',async()=>{
 const f=await fixture('proxy-providers: {P: {type: http, url: https://example.invalid/nodes, override: {additional-prefix: "[P] "}, payload: [{name: Old fallback, type: ss}]}}\nproxy-groups: [{name: Main, proxies: [¦]}]','yaml',cached(['[P] Native name']));
 assert(f.labels.includes('[P] Native name'));assert(!f.labels.includes('[P] [P] Native name'));assert(!f.labels.includes('[P] Old fallback'));
});
test('Effective YAML aliases and merges project provider definitions without unrelated or payload secrets',async()=>{
 const source='x-source: &source {type: http, url: "https://example.invalid/selected", header: {Authorization: ["PUBLIC-HEADER", "NEXT"]}}\nx-options: &options {additional-prefix: "[N] "}\nx-private: {password: UNRELATED-SECRET}\nproxy-providers: {P: {<<: *source, filter: "Japan```US", override: *options, payload: [{name: Fallback, password: PAYLOAD-SECRET}]}}\nproxy-groups: [{name: Main, proxies: [¦]}]';
 const f=await fixture(source),query=f.queries[0]['proxy-providers'].P;
 assert.equal(query.url,'https://example.invalid/selected');assert.deepEqual(query.header.Authorization,['PUBLIC-HEADER','NEXT']);assert.equal(query.override['additional-prefix'],'[N] ');
 assert(!JSON.stringify(f.queries).includes('UNRELATED-SECRET'));assert(!JSON.stringify(f.queries).includes('PAYLOAD-SECRET'));
});
test('Each changed source, filter and header is queried from its own draft',async()=>{
 for(const value of ['first','second']){
  const f=await fixture(`proxy-providers: {P: {type: file, path: ${value}.yaml, filter: ${value}, header: {X-Public: ${value}}}}\nproxy-groups: [{name: Main, proxies: [¦]}]`);
  const p=f.queries[0]['proxy-providers'].P;assert.equal(p.path,value+'.yaml');assert.equal(p.filter,value);assert.equal(p.header['X-Public'],value);
 }
});
test('Missing, rejected, malformed and unrelated cache responses retain document-local assistance',async()=>{
 for(const data of [{providers:[]},{providers:[{name:'Other',nodes:[{name:'Foreign',type:'ss',dialer:''}]}]},{providers:[{name:'P',nodes:[{name:42}]}]},()=>{throw Error('unavailable');}]){
  const f=await fixture(prefix+'proxies: [{name: Local, type: direct}]\nproxy-groups: [{name: Main, proxies: [¦]}]','yaml',data);assert(f.labels.includes('Local'));assert(!f.labels.includes('Foreign'));assert(!f.labels.includes('Cached 😀'));
 }
});
test('Cache transport is never requested for comments, secrets, schema keys or inline-only documents',async()=>{
 for(const source of [prefix+'# proxies: Ca¦',prefix+'password: Ca¦',prefix+'dns: {ena¦}',prefix+'proxies: [{type: s¦}]','proxy-providers: {P: {type: inline, payload: [{name: Local}]}}\nproxy-groups: [{name: Main, proxies: [¦]}]']){
  const f=await fixture(source);assert.equal(f.queries.length,0);
 }
});
test('Special provider keys remain inert and incomplete/recursive definitions issue no cache request',async()=>{
 const f=await fixture('proxy-providers: {"__proto__": {type: http, url: https://example.invalid/nodes}}\nproxy-groups: [{name: Main, proxies: [¦]}]','yaml',cached(['Cached 😀'],'__proto__'));
 assert(Object.hasOwn(f.queries[0]['proxy-providers'],'__proto__'));assert(f.labels.includes('Cached 😀'));assert.equal(Object.prototype.nodes,undefined);
 const source='x: &loop {header: *loop}\nproxy-providers: {P: {type: http, url: https://example.invalid/nodes, <<: *loop}}\nproxy-groups: [{name: Main, proxies: [¦]}]';
 assert.equal((await fixture(source)).queries.length,0);
});
test('An aborted asynchronous completion produces no late result',async()=>{
 const source=prefix+'proxy-groups: [{name: Main, proxies: [¦]}]',pos=source.indexOf('¦'),state=EditorState.create({doc:source.replace('¦',''),extensions:[yaml()]});
 let release;const pending=new Promise(r=>{release=r;});const context={state,pos,explicit:true,aborted:false};
 const work=clashCompletions('yaml',()=>pending)(context);await Promise.resolve();context.aborted=true;release(cached(['Cached 😀']));assert.equal(await work,null);
});
function context(){const handlers=[];return{aborted:false,addEventListener(name,fn){assert.equal(name,'abort');handlers.push(fn);},abort(){this.aborted=true;handlers.forEach(fn=>fn());}};}
test('Bridge accepts only the matching request/revision and queues only the latest lookup',async t=>{
 const sent=[],client=new ProviderCompletionClient(packet=>sent.push(JSON.parse(packet)));t.after(()=>client.dispose());
 const a=client.request('first',context(),1),b=client.request('second',context(),1),c=client.request('third',context(),2);
 assert.equal(await b,null);assert.equal(sent.length,1);assert.equal(client.receive(99,1,cached(['Wrong'])),false);assert.equal(client.receive(1,99,cached(['Wrong'])),false);
 client.receive(1,1,cached(['First']));assert.equal((await a).providers[0].nodes[0].name,'First');assert.equal(sent[1].query,'third');
 client.receive(sent[1].id,2,cached(['Third']));assert.equal((await c).providers[0].nodes[0].name,'Third');
});
test('Bridge discards aborted and changed-document results while releasing the next query',async t=>{
 let revision=1;const sent=[],client=new ProviderCompletionClient(packet=>sent.push(JSON.parse(packet)),(_context,r)=>r===revision);t.after(()=>client.dispose());
 const old=context(),a=client.request('first',old,1);old.abort();assert.equal(await a,null);revision=2;
 const b=client.request('second',context(),2);client.receive(1,1,cached(['Stale']));assert.equal(sent.length,2);client.receive(2,2,cached(['Current']));assert.equal((await b).providers[0].nodes[0].name,'Current');
 const c=client.request('third',context(),2);revision=3;client.receive(3,2,cached(['Wrong revision']));assert.equal(await c,null);
});
test('Bridge timeout, send failure and disposal settle every pending lookup',async()=>{
 const timed=new ProviderCompletionClient(()=>{},()=>true,5);assert.equal(await timed.request('first',context(),1),null);timed.dispose();
 const broken=new ProviderCompletionClient(()=>{throw Error('transport');});assert.equal(await broken.request('first',context(),1),null);broken.dispose();
 const client=new ProviderCompletionClient(()=>{}),a=client.request('first',context(),1),b=client.request('second',context(),1);client.dispose();
 assert.equal(await a,null);assert.equal(await b,null);assert.equal(await client.request('closed',context(),1),null);assert.equal(client.receive(1,1,{}),false);
});
