import test from 'node:test';
import assert from 'node:assert/strict';
import {EditorState} from '@codemirror/state';
import {yaml} from '@codemirror/lang-yaml';
import {json} from '@codemirror/lang-json';
import {javascript} from '@codemirror/lang-javascript';
import {CompletionContext} from '@codemirror/autocomplete';
import {syntaxTree} from '@codemirror/language';
import {highlightTree,classHighlighter} from '@lezer/highlight';
import {history,undo,redo} from '@codemirror/commands';
import {clashCompletions,completionContext,completionEdit} from './completion.mjs';
import {serializeDocument} from './document.mjs';
import {scriptCompletions} from './script-completion.mjs';
import {detectLanguage,nativeErrorLocation} from './language.mjs';

function fixture(source,language='yaml'){
 const pos=source.indexOf('¦'),text=source.replace('¦','');assert(pos>=0);
 const state=EditorState.create({doc:text,extensions:[language==='yaml'?yaml():json(),history()]});
 const info=completionContext(state,pos,language),result=clashCompletions(language)(new CompletionContext(state,pos,true));
 return {state,info,result,labels:result?.options.map(x=>x.label)||[]};
}
for(const [source,language,expected,absent]of [
 ['po¦','yaml','port','password'],['dns:\n  en¦','yaml','enable','port'],
 ['proxies:\n  - name: Public\n    ty¦','yaml','type','dns'],['proxy-groups:\n  - name: Main\n    type: se¦','yaml','select','ss'],
 ['proxies:\n  - name: Public\n    type: s¦','yaml','ss','select'],['dns:\n  enable: tr¦','yaml','true','port'],
 ['proxy-providers:\n  Public:\n    he¦','yaml','health-check','socks-port'],
 ['proxy-providers:\n  Public:\n    health-check:\n      la¦','yaml','lazy','path'],
 ['rule-providers:\n  Public:\n    be¦','yaml','behavior','cipher'],
 ['{"po¦":7890}','json','port','password'],['{"dns":{"en¦":true}}','json','enable','port'],
 ['{"proxy-groups":[{"type":"se¦"}]}','json','select','ss'],['{"proxies":[{"type":"s¦"}]}','json','ss','select'],
 ['proxies: [{name: Public, ty¦: ss}]','yaml','type','dns']
 ,['proxy-providers:\n  Public:\n    payload:\n      - na¦','yaml','name','interval']
 ,['proxy-providers:\n  Public:\n    payload:\n      - type: s¦','yaml','ss','select']
 ,['proxy-providers:\n  dns:\n    ty¦','yaml','type','enable']
])test('Contextual completion: '+source,()=>{const f=fixture(source,language);assert(f.labels.includes(expected),JSON.stringify(f));assert(!f.labels.includes(absent));});

for(const source of ['# port: po¦','proxies:\n  - password: se¦','note: |\n  po¦','note: >\n  por¦'])
 test('Do not invent completions in comments, secrets or scalar content: '+source,()=>assert.equal(fixture(source).result,null));
for(const source of ['proxy-groups:\n  - name: Main\n    proxies:\n      - na¦','proxy-providers:\n  ty¦','rule-providers:\n  Public:\n    payload:\n      - na¦','custom:\n  type: s¦'])
 test('Do not offer mapping fields for member names or unrelated values: '+source,()=>assert.equal(fixture(source).result,null));
test('Existing YAML values/comments survive replacing a key',()=>{
 const f=fixture('po¦: 7890 # PUBLIC'),opt=f.result.options.find(x=>x.label==='port'),e=completionEdit(f.state.doc,f.info,opt);
 assert.equal(f.state.update({changes:{from:e.from,to:e.to,insert:e.insert}}).state.doc.toString(),'port: 7890 # PUBLIC');
});
test('Existing JSON key quotes and value are preserved',()=>{
 const f=fixture('{"po¦":7890}','json'),opt=f.result.options.find(x=>x.label==='port'),e=completionEdit(f.state.doc,f.info,opt);
 assert.deepEqual(JSON.parse(f.state.update({changes:{from:e.from,to:e.to,insert:e.insert}}).state.doc.toString()),{port:7890});
});
test('New field inserts syntax and selects its editable value',()=>{
 const f=fixture('po¦'),e=completionEdit(f.state.doc,f.info,f.result.options.find(x=>x.label==='port'));
 assert.equal(e.insert,'port: 7890');assert.equal(e.insert.slice(e.anchor-e.from,e.head-e.from),'7890');
});
test('Quoted JSON enum replacement keeps valid JSON',()=>{
 const f=fixture('{"proxy-groups":[{"type":"se¦"}]}','json'),e=completionEdit(f.state.doc,f.info,f.result.options.find(x=>x.label==='select'));
 assert.equal(JSON.parse(f.state.update({changes:{from:e.from,to:e.to,insert:e.insert}}).state.doc.toString())['proxy-groups'][0].type,'select');
});
test('Real parser supplies syntax spans and foldable hierarchy',()=>{
 const state=EditorState.create({doc:'# PUBLIC\ndns:\n  enable: true\n  nameserver: ["tls://dns.example"]\n',extensions:[yaml()]});
 const spans=[];highlightTree(syntaxTree(state),classHighlighter,(from,to,classes)=>spans.push({text:state.doc.sliceString(from,to),classes}));
 assert(spans.some(x=>x.text==='# PUBLIC'&&/comment/.test(x.classes)));assert(spans.some(x=>x.text==='dns'&&/propertyName/.test(x.classes)));
 assert(spans.some(x=>x.text.includes('tls://dns.example')&&/string/.test(x.classes)));
 assert(syntaxTree(state).toString().includes('BlockMapping'));
});
for(const initial of ['port: 7890\n','# PUBLIC\r\nport: 7890\r\n','\uFEFF# PUBLIC\rport: 7890\r','# mixed\r\nport: 7890\n'])test('No-op and undo preserve exact original bytes '+JSON.stringify(initial),()=>{
 let state=EditorState.create({doc:initial,extensions:[yaml(),history()]}),baseline=state.doc;
 assert.equal(serializeDocument(state.doc,baseline,initial),initial);
 state=state.update({changes:{from:state.doc.length,insert:'new'}}).state;
 const holder={get state(){return state;},dispatch(tr){state=tr.state;}};
 assert(undo(holder));assert.equal(serializeDocument(state.doc,baseline,initial),initial);assert(redo(holder));assert(serializeDocument(state.doc,baseline,initial).endsWith('new'));
});
test('Edited CRLF configuration retains CRLF serialization with LF paste',()=>{
 const initial='port: 7890\r\n',state=EditorState.create({doc:initial}),changed=state.update({changes:{from:state.doc.length,insert:'mode: rule\n'}}).state;
 assert.equal(serializeDocument(changed.doc,state.doc,initial),'port: 7890\r\nmode: rule\r\n');
});
test('Unicode offsets and executable-looking text remain inert document data',()=>{
 const original='# PUBLIC 😀\npassword: "</script><img src=x onerror=alert(1)>"\n',state=EditorState.create({doc:original});
 assert.equal(serializeDocument(state.doc,state.doc,original),original);
 const source='# PUBLIC 😀\ndns:\n  en¦',f=fixture(source);assert(f.labels.includes('enable'));assert.equal(f.info.from,source.indexOf('en'));
});
test('Large document completion at the end remains contextual',()=>{
 const f=fixture('# public\n'.repeat(20000)+'dns:\n  en¦');assert(f.labels.includes('enable'));
});

function scriptFixture(source) {
 const pos=source.indexOf('¦'),state=EditorState.create({doc:source.replace('¦',''),extensions:[javascript(),history()]});
 const result=scriptCompletions(new CompletionContext(state,pos,true));
 return {state,result,labels:result?.options.map(x=>x.label)||[]};
}
for(const [source,expected] of [['ma¦','main'],['config.ru¦','rules'],['config["proxy-g¦"]','proxy-groups'],["config['socks-p¦']",'socks-port'],['console.wa¦','warn']])
 test('Extension script completion: '+source,()=>assert(scriptFixture(source).labels.includes(expected)));
for(const source of ['// config.ru¦','/* config.ru¦ */','"config.ru¦"', 'const text = "config[\'ru¦"','function main(config) { ma¦ }','"main¦"'])
 test('Script assistance excludes comments, strings and nested entry templates: '+source,()=>assert.equal(scriptFixture(source).result,null));
test('JavaScript dot completion excludes keys that need brackets',()=>assert(!scriptFixture('config.¦').labels.includes('proxy-groups')));
for(const source of ['config["ru¦les"]', "config['ru¦les']",'config.ru¦les'])test('Script completion replaces the full member without damaging quotes: '+source,()=>{
 const f=scriptFixture(source),r=f.result;
 const text=f.state.update({changes:{from:r.from,to:r.to,insert:'rules'}}).state.doc.toString();
 assert.equal(text,source.replace('ru¦les','rules'));
});
test('JavaScript mode stays fixed for empty scripts, object literals and script edits',()=>{
 for(const source of ['', '{ rules: [] }', '[1,2]', 'function main(config) { return config; }'])assert.equal(detectLanguage(source,'javascript'),'javascript');
 assert.equal(detectLanguage('{"rules":[]}'),'json');assert.equal(detectLanguage('dns:\n  enable: true'),'yaml');
});
test('Real JavaScript grammar highlights keywords and finds invalid syntax without evaluating it',()=>{
 const state=EditorState.create({doc:'function main(config) {\n  throw new Error("PUBLIC");\n  return config;\n}',extensions:[javascript()]});
 const spans=[];highlightTree(syntaxTree(state),classHighlighter,(from,to,classes)=>spans.push({text:state.doc.sliceString(from,to),classes}));
 assert(spans.some(x=>x.text==='function'&&/keyword/.test(x.classes)));assert(syntaxTree(state).toString().includes('Block'));
 const broken=EditorState.create({doc:'function main( {',extensions:[javascript()]});let errors=0;syntaxTree(broken).iterate({enter(n){if(n.type.isError)errors++;}});assert(errors>0);
});
test('Script native error locations refer only to the edited source, not another extension or generated YAML',()=>{
 assert.deepEqual(nativeErrorLocation('profile: SyntaxError\n at profile-script.js:4:8','javascript','profile'),{line:4,column:8});
 assert.deepEqual(nativeErrorLocation('global: Error\n at main (global-script.js:7)','javascript','global'),{line:7,column:1});
 assert.equal(nativeErrorLocation('global: Error\n at global-script.js:7','javascript','profile'),null);
 assert.equal(nativeErrorLocation('YAML line 8: invalid generated config','javascript','profile'),null);
 assert.deepEqual(nativeErrorLocation('YAML extension line 2, column 3: expected a value','yaml'),{line:2,column:3});
});
