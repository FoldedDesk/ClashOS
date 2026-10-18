// Production ArkTS ZIP/conversion code; native YAML uses the compiled production
// C++ reader. Python zipfile independently supplies and inspects archive bytes.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),vm=require('node:vm'),assert=require('node:assert/strict'),cp=require('node:child_process'),zlib=require('node:zlib');
const ts=require('./test_env.cjs')();
const root=path.resolve(__dirname,'../entry/src/main/ets/service'),work=fs.mkdtempSync(path.join(os.tmpdir(),'clashos-archive-'));
const native=process.env.CLASHOS_NATIVE_TESTS||path.resolve(__dirname,'../.host-build/native/native_tests');
let checks=0,readerIndex=0;const check=(x,label)=>{assert(x,label);checks++;},same=(a,b,label)=>{assert.deepEqual(JSON.parse(JSON.stringify(a)),JSON.parse(JSON.stringify(b)),label);checks++;};
class NativeReader {
 backupYaml(text){const f=path.join(work,`yaml-${readerIndex++}.yaml`);fs.writeFileSync(f,text);return cp.execFileSync(native,['archive-yaml',f],{encoding:'utf8',maxBuffer:32*1024*1024});}
 backupInflate(bytes,expected){const result=zlib.inflateRawSync(bytes,{maxOutputLength:expected+1});assert.equal(result.length,expected);return Uint8Array.from(result);}
}
const util={TextEncoder:class{encodeInto(s){return new TextEncoder().encode(s);}},TextDecoder:{create:(encoding,options)=>{const d=new TextDecoder(encoding,options);return{decodeToString:(b,o)=>d.decode(b,o)};}}};
const modules=new Map();function load(name){
 if(modules.has(name))return modules.get(name);const m={exports:{}};modules.set(name,m.exports);
 const source=fs.readFileSync(path.join(root,name+'.ets'),'utf8'),code=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2020}}).outputText;
 vm.runInNewContext(code,{module:m,exports:m.exports,require:p=>p==='@kit.ArkTS'?{util}:p==='@ohos.url'?{default:{URL}}:p==='./ClashNativeCore'?{ClashNativeCore:NativeReader}:load(p.slice(2)),Uint8Array,ArrayBuffer,DataView,TextEncoder,TextDecoder,Set},{filename:name});return m.exports;
}
(async()=>{try{
 cp.execFileSync('python3',[path.join(__dirname,'fixtures/verge-backup/make_archives.py'),work]);
 const {readZip,writeZip,zipCrc}=load('BackupZip'),{BackupArchiveCodec}=load('BackupArchiveCodec'),codec=new BackupArchiveCodec(new NativeReader()),inflater=new NativeReader();
 const first=JSON.parse(codec.decode(fs.readFileSync(path.join(work,'public-verge-stored.zip'))));
 check(first.profiles.length===2,'Actual upstream-shaped archive retains both local and remote profiles');
 const p=first.profiles[0],remote=first.profiles[1];
 check(p.content===fs.readFileSync(path.join(__dirname,'fixtures/verge-backup/profiles/public.yaml'),'utf8'),'Original profile bytes and Unicode preserved');
 check(p.script===fs.readFileSync(path.join(__dirname,'fixtures/verge-backup/profiles/public-script.js'),'utf8'),'Per-profile script retained exactly');
 check(first.globals.script.includes('PUBLIC sequence order')&&first.globals.merge.includes('public-global.invalid'),'Global extensions retained');
 check(remote.sourceUrl==='https://example.invalid/public-subscription'&&remote.updateInterval===60,'Remote metadata retains address and interval');
 same(JSON.parse(p.sequence).proxies.delete,['Public old'],'Deletion references retained separately from the downloaded source');
 check(p.selections==='"Public group" "Public added"\n','Native selection records use compatible quoted names');
 check(!JSON.stringify(first).includes('PUBLIC-IGNORED'),'Desktop controller and WebDAV credentials are excluded from conversion');
 check(first.appearance.mode==='dark'&&first.migrationNotes.length>0,'Appearance and material migration scope are available to preview');
 for(const label of ['deflated','descriptor']){const d=JSON.parse(codec.decode(fs.readFileSync(path.join(work,`public-verge-${label}.zip`))));same(d.profiles,first.profiles,`Python ${label} ZIP produces the same profiles`);}
 check(zipCrc(new TextEncoder().encode('123456789'))===0xcbf43926,'ZIP CRC matches standard check vector');
 const encoded=codec.encode(first),entries=readZip(encoded,inflater),exported=path.join(work,'export.zip');fs.writeFileSync(exported,encoded);
 same(JSON.parse(codec.decode(encoded)),first,'ClashOS sidecar preserves a lossless native ZIP roundtrip');
 const cached=JSON.parse(JSON.stringify(first));cached.profiles[0].resources=[{suffix:'.provider-0011223344556677.cache',data:Buffer.from([0,128,255,10]).toString('base64')}];cached.profiles[0].pinned=true;
 same(JSON.parse(codec.decode(codec.encode(cached))),cached,'Native ZIP roundtrip retains opaque cache bytes and metadata independently of Verge members');
 cached.groupIcons={version:1,entries:[{name:'public icon',source:'local:icon-AbC123/icon.png'}],assets:[{name:'icon-AbC123/icon.png',data:Buffer.from('public PNG bytes').toString('base64')}]};
 same(JSON.parse(codec.decode(codec.encode(cached))).groupIcons,cached.groupIcons,'ZIP sidecar preserves icon preferences and image resources without inventing desktop settings');
 cached.network={version:1,ports:{http:18890,socks:18891,mixed:0},inbound:{'allow-lan':false,'bind-address':'127.0.0.1',authentication:['public-backup:PUBLIC-p@ss'],'skip-auth-prefixes':[],'lan-allowed-ips':['127.0.0.0/8'],'lan-disallowed-ips':[]}};
 const networkZip=readZip(codec.encode(cached),inflater);
 same(JSON.parse(codec.decode(codec.encode(cached))).network,cached.network,'The native ZIP sidecar preserves selected network overrides and proxy authentication losslessly');
 check(!networkZip.filter(e=>e.name!=='clashos-backup.json').some(e=>new TextDecoder().decode(e.bytes).includes('PUBLIC-p@ss')),'Native network preferences are not silently applied through desktop-compatible ZIP members');
 cached.desktop={trayEnabled:false,closeToTray:true};
 same(JSON.parse(codec.decode(codec.encode(cached))).desktop,cached.desktop,'Native ZIP sidecar preserves an independent tray toggle and latent close preference');
 check(JSON.parse(new TextDecoder().decode(readZip(codec.encode(cached),inflater).find(e=>e.name==='verge.yaml').bytes)).trayEnabled===undefined,'ClashOS desktop fields are not invented as upstream preferences');
 const noSidecar=writeZip(entries.filter(e=>e.name!=='clashos-backup.json')),vergeRoundtrip=JSON.parse(codec.decode(noSidecar));
 same(vergeRoundtrip.profiles.map(x=>[x.name,x.content,x.script,x.sourceUrl,x.sequence]),first.profiles.map(x=>[x.name,x.content,x.script,x.sourceUrl,x.sequence]),'Verge-compatible members work without relying on the native sidecar');
 cp.execFileSync('python3',['-c',`import zipfile,json,sys
with zipfile.ZipFile(sys.argv[1]) as z:
 assert z.testzip() is None
 index=json.loads(z.read('profiles.yaml')); assert len([x for x in index['items'] if x['type'] in ('local','remote')])==2
 assert json.loads(z.read('clashos-backup.json'))['profiles'][0]['name']=='clashos-zip-public-local'
 assert 'PUBLIC-IGNORED' not in z.read('verge.yaml').decode()
`,exported]);checks++;
 const bom='\ufeff# PUBLIC 😀\r\n',bomZip=writeZip([{name:'public.yaml',bytes:new TextEncoder().encode(bom)}]);check(new TextDecoder('utf-8',{ignoreBOM:true}).decode(readZip(bomZip,inflater)[0].bytes)===bom,'ZIP entries retain BOM and CRLF bytes');
 const raw=fs.readFileSync(path.join(work,'public-verge-stored.zip')),baseEntries=readZip(raw,inflater);
 const rewrite=(change)=>{const a=baseEntries.map(x=>({name:x.name,bytes:x.bytes}));change(a);return writeZip(a);};
 const replaceIndex=fn=>rewrite(a=>{const i=a.findIndex(x=>x.name==='profiles.yaml');const d=JSON.parse(new NativeReader().backupYaml(new TextDecoder().decode(a[i].bytes)));fn(d);a[i].bytes=new TextEncoder().encode(JSON.stringify(d));});
 for(const [label,bytes]of [
  ['duplicate uid',replaceIndex(d=>d.items.push(d.items[0]))],
  ['missing extension',replaceIndex(d=>d.items.find(x=>x.type==='local').option.script='missing')],
  ['wrong extension type',replaceIndex(d=>d.items.find(x=>x.type==='local').option.script='public-rules')],
  ['traversal reference',replaceIndex(d=>d.items.find(x=>x.type==='local').file='../escape.yaml')],
  ['unsupported profile kind',replaceIndex(d=>d.items[0].type='unknown')],
  ['invalid auto update interval',replaceIndex(d=>d.items.find(x=>x.type==='remote').option.update_interval=-1)],
  ['missing remote URL',replaceIndex(d=>delete d.items.find(x=>x.type==='remote').url)],
  ['missing original file',rewrite(a=>a.splice(a.findIndex(x=>x.name==='profiles/public.yaml'),1))],
 ]){assert.throws(()=>codec.decode(bytes),undefined,label);checks++;}
 for(const name of ['../escape','/absolute','profiles/../escape','profiles\\escape','profiles//escape','file:escape']){assert.throws(()=>writeZip([{name,bytes:new Uint8Array()}]),undefined,name);checks++;}
 assert.throws(()=>writeZip([{name:'same',bytes:new Uint8Array()},{name:'same',bytes:new Uint8Array()}]));checks++;
 const simple=writeZip([{name:'public',bytes:new Uint8Array([1,2,3])}]);
 const central=30+'public'.length+3;
 for(const mutate of [
  b=>b[30+'public'.length]^=1,
  b=>b.writeUInt16LE(1,6),b=>b.writeUInt16LE(99,central+10),
  b=>b.writeUInt32LE(0xa0000000,central+38),
  b=>b.writeUInt32LE(0xffffffff,central+24),
  b=>b.writeUInt32LE(0xffffffff,central+42),
  b=>b[central+46]=0x2f,
 ]){const b=Buffer.from(simple);mutate(b);assert.throws(()=>readZip(b,inflater));checks++;}
 assert.throws(()=>readZip(simple.slice(0,-1),inflater));checks++;
 const marker=JSON.parse(JSON.stringify(first));marker.profiles[0].script='function main(config) { config.ipv6 = true; return config; }';
 marker.profiles[0].ruleEdits=JSON.stringify({version:1,prepend:['DOMAIN,native-public.invalid,REJECT'],append:[],remove:['MATCH,DIRECT']});
 marker.profiles[0].objectEdits=JSON.stringify({version:1,proxies:{prepend:[{name:'Native added',content:'{name: Native added, type: direct}'}],append:[],remove:['Public kept']},groups:{prepend:[],append:[],remove:[]}});
 const bridgeFiles=readZip(codec.encode(marker),inflater),bridgeIndex=JSON.parse(new TextDecoder().decode(bridgeFiles.find(x=>x.name==='profiles.yaml').bytes)),main=bridgeIndex.items.find(x=>x.type==='local'),scriptItem=bridgeIndex.items.find(x=>x.uid===main.option.script);
 const bridge=new TextDecoder().decode(bridgeFiles.find(x=>x.name==='profiles/'+scriptItem.file).bytes),ctx=vm.createContext({});vm.runInContext(bridge,ctx);
 const result=ctx.main({proxies:[{name:'Public kept',type:'direct'}],rules:['MATCH,DIRECT']},'PUBLIC');
 check(!result.then,'A synchronous original script remains synchronous for upstream Boa');
 same(result.proxies.map(x=>x.name),['Native added'],'Export bridge preserves native object edits after scripts');
 same(result.rules,['DOMAIN,native-public.invalid,REJECT'],'Export bridge preserves native rule edits after scripts');
 check(result.ipv6===true,'Export bridge actually executes the original extension');
 marker.profiles[0].script='const config = {publicMarker: true}; const profileName = "PUBLIC global"; function main(value) { value.marker = config.publicMarker; value.label = profileName; return value; }';
 const lexicalFiles=readZip(codec.encode(marker),inflater),lexicalScript=new TextDecoder().decode(lexicalFiles.find(x=>x.name==='profiles/clashos-0-script.js').bytes),lexical=vm.createContext({});vm.runInContext(lexicalScript,lexical);
 const scoped=lexical.main({proxies:[],rules:[]},'PUBLIC input');check(scoped.marker===true&&scoped.label==='PUBLIC global','Export wrapper does not collide with valid original top-level config/profileName declarations');
 console.log(`Backup archive scenarios passed: ${checks} (production ZIP/converter, production native YAML, independent Python ZIP fixtures/inspection)`);
}finally{fs.rmSync(work,{recursive:true,force:true});}})().catch(e=>{console.error(e);process.exitCode=1;});
