// Production icon settings/assets and picker pipeline with real temporary files.
// Harmony picker/URI and ImageKit are modeled; actual image decoding is a device check.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),vm=require('node:vm'),assert=require('node:assert/strict');
const ts=require('./test_env.cjs')(),root=path.resolve(__dirname,'../entry/src/main/ets');
const directory=fs.mkdtempSync(path.join(os.tmpdir(),'clashos-group-icons-')),descriptors=new Map(),cache=new Map();
let checks=0,maxWrite=Infinity,failWrite=false,failSync=false,failRename=false,failProtect=false,race;
let selected=[],failDecode=false,failPack=false,imageSize={width:128,height:64},sources=0,pixels=0,packers=0,decodedSize;
const png=Buffer.from([137,80,78,71,13,10,26,10,1,2,3,4]);
const check=(v,t)=>{assert(v,t);checks++;};
const flags={CREATE:64,READ_WRITE:2,TRUNC:512,EXCL:128,READ_ONLY:0};
const fileIo={OpenMode:flags,accessSync:p=>fs.existsSync(p),statSync:p=>typeof p==='number'?fs.fstatSync(p):fs.statSync(p),readTextSync:p=>fs.readFileSync(p,'utf8'),
 openSync:(p,f)=>{if(p.startsWith('file://'))throw Error('URI adapter fallback');const native=(f&flags.READ_WRITE?fs.constants.O_RDWR:fs.constants.O_RDONLY)|(f&flags.CREATE?fs.constants.O_CREAT:0)|(f&flags.TRUNC?fs.constants.O_TRUNC:0);const fd=fs.openSync(p,native);descriptors.set(fd,p);return{fd};},
 closeSync:f=>{fs.closeSync(f.fd);descriptors.delete(f.fd);},mkdirSync:p=>fs.mkdirSync(p),
 mkdtempSync:p=>{assert(p.endsWith('XXXXXX'),'Harmony mkdtemp requires a six-X template');return fs.mkdtempSync(p.slice(0,-6));},rmdirSync:p=>fs.rmdirSync(p),
 readSync:(fd,b)=>fs.readSync(fd,Buffer.from(b),0,b.byteLength,null),
 writeSync:(fd,b)=>{if(failWrite)throw Error('write failure');if(race&&descriptors.get(fd).endsWith('.tmp')){const fn=race;race=undefined;fn();}return fs.writeSync(fd,Buffer.from(b).subarray(0,maxWrite));},
 fsyncSync:fd=>{if(failSync)throw Error('sync failure');fs.fsyncSync(fd);},
 renameSync:(a,b)=>{if(failRename)throw Error('rename failure');fs.renameSync(a,b);},unlinkSync:p=>fs.unlinkSync(p)};
const image={createImageSource:()=>{sources++;return{getImageInfo:async()=>{if(failDecode)throw Error('decode failure');return{size:imageSize};},
 createPixelMap:async options=>{decodedSize=options.desiredSize;pixels++;return{release:async()=>{pixels--;}};},release:async()=>{sources--;}};},
 createImagePacker:()=>{packers++;return{packing:async()=>{if(failPack)throw Error('pack failure');return Uint8Array.from(png).buffer;},release:async()=>{packers--;}};}};
function load(name){const filename=path.join(root,name);if(cache.has(filename))return cache.get(filename).exports;const m={exports:{}};cache.set(filename,m);
 const requireShim=specifier=>{if(specifier==='@kit.CoreFileKit')return{fileIo,fileUri:{FileUri:class{constructor(uri){this.path=uri.replace('file://','');}}},picker:{DocumentSelectOptions:class{},DocumentViewPicker:class{async select(){return selected;}}}};
  if(specifier==='@kit.ImageKit')return{image};if(specifier==='@kit.AbilityKit')return{};
  if(specifier==='@kit.ArkTS')return{util:{TextEncoder:class{encodeInto(t){return new TextEncoder().encode(t);}}}};
  if(specifier.startsWith('.'))return load(path.relative(root,path.resolve(path.dirname(filename),specifier+'.ets')));throw Error('Unexpected import '+specifier);};
 const code=ts.transpileModule(fs.readFileSync(filename,'utf8'),{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2020}}).outputText;
 vm.runInNewContext(code,{module:m,exports:m.exports,require:requireShim,Uint8Array,ArrayBuffer,Set,JSON,Math:Object.assign(Object.create(Math),{random:()=>.5}),Date:{now:()=>1792225000000}});return m.exports;}
const protect=fd=>{if(failProtect)throw Error('protect failure');fs.fchmodSync(fd,0o600);};
(async()=>{try{
 const {GroupIconStore}=load('service/GroupIconStore.ets'),{iconImageUrl,groupIconSource,parseGroupIcons}=load('service/GroupIconTypes.ets');
 const {pickGroupIcon}=load('service/GroupIconPicker.ets'),store=new GroupIconStore(directory,protect),index=path.join(directory,'group-icons.json');
 for(const url of ['https://icons.example.test/icon.svg?a=1&b=%20','http://127.0.0.1:18095/icon.png','https://[::1]:9443/a.png'])check(iconImageUrl(url)===url,'Valid HTTP(S) and loopback IPv6 image URL');
 for(const bad of ['file:///private/config.yaml','data:image/svg+xml,svg','javascript:alert(1)','https://user:public@example.test/icon.png','https://a.test:0/a','https://a.test:65536/a','https://a.test/a\nb','https://a.test\\other'])check(iconImageUrl(bad)==='','Unsupported or ambiguous image source rejected');
 for(const value of ['local:../settings.json','local:icon-1-0-abcd1234.png/../a','builtin:unknown',42,null]){assert.throws(()=>groupIconSource(value));checks++;}
 check(store.load().length===0,'Fresh install follows configuration icons');
 const original=store.snapshot('组😀');maxWrite=3;store.save(original,'builtin:shield');maxWrite=Infinity;
 check(store.load()[0].source==='builtin:shield'&&(fs.statSync(index).mode&0o777)===0o600,'Complete Unicode preference survives partial writes and has private permissions');
 assert.throws(()=>store.save(original,'builtin:home'),/已变化/);checks++;
 store.save(store.snapshot('__proto__'),'builtin:proxies');check(store.load().some(e=>e.name==='__proto__'),'Group names cannot mutate object prototypes');
 const before=fs.readFileSync(index,'utf8');
 for(const kind of ['write','sync','rename','protect','zero']){
  failWrite=kind==='write';failSync=kind==='sync';failRename=kind==='rename';failProtect=kind==='protect';maxWrite=kind==='zero'?0:Infinity;
  assert.throws(()=>store.save(store.snapshot('组😀'),'builtin:home'));checks++;
  check(fs.readFileSync(index,'utf8')===before&&!fs.existsSync(index+'.tmp')&&descriptors.size===0,'Failed preference transaction preserves all groups and closes files: '+kind);
  failWrite=failSync=failRename=failProtect=false;maxWrite=Infinity;
 }
 const external=JSON.stringify({version:1,entries:[{name:'other',source:'builtin:home'}]});
 race=()=>fs.writeFileSync(index,external);assert.throws(()=>store.save(store.snapshot('组😀'),'builtin:balance'),/已变化/);checks++;
 check(fs.readFileSync(index,'utf8')===external&&!fs.existsSync(index+'.tmp'),'An update during writing cannot be overwritten by a stale dialog');
 fs.writeFileSync(index,before);
 const source=store.stageImage(Uint8Array.from(png).buffer),asset=store.displaySource(source).replace('file://','');
 check(fs.existsSync(asset)&&(fs.statSync(asset).mode&0o777)===0o600,'Imported normalized PNG stored privately without retaining picker permissions');
 const simultaneous=new GroupIconStore(directory,protect),secondImage=simultaneous.stageImage(Uint8Array.from(png).buffer);
 check(secondImage!==source&&fs.readFileSync(asset).equals(png),'Separate importers atomically allocate distinct assets without touching another image');simultaneous.releaseImage(secondImage);
 store.save(store.snapshot('组😀'),source);store.save(store.snapshot('shared'),source);store.releaseImage(source);
 check(fs.existsSync(asset),'Closing an editor keeps committed and shared images');
 failRename=true;assert.throws(()=>store.save(store.snapshot('组😀'),''));failRename=false;checks++;
 check(fs.existsSync(asset)&&store.load().find(e=>e.name==='组😀').source===source,'Failed reset preserves the old local image and preference');
 store.save(store.snapshot('组😀'),'');check(fs.existsSync(asset),'Reset retains images referenced by another group');
 store.save(store.snapshot('shared'),'');check(!fs.existsSync(asset),'Last successful reset releases the unreferenced local image');
 const draft=store.stageImage(Uint8Array.from(png).buffer),draftPath=store.displaySource(draft).replace('file://','');store.releaseImage(draft);
 check(!fs.existsSync(draftPath),'Canceled local import cleans its draft image');
 fs.writeFileSync(path.join(directory,'settings.json'),'unrelated');store.releaseImage('local:../settings.json');check(fs.readFileSync(path.join(directory,'settings.json'),'utf8')==='unrelated','Cleanup cannot target another application file');
 for(const text of ['null','[]','{"version":2,"entries":[]}','{"version":1,"entries":[null]}',JSON.stringify({version:1,entries:[{name:'g',source:'builtin:home'},{name:'g',source:'builtin:shield'}]}),'x'.repeat(512*1024+1)]){assert.throws(()=>parseGroupIcons(text));checks++;}
 fs.writeFileSync(index,'{broken');const corrupt=store.snapshot('repair');check(corrupt.error&&fs.readFileSync(index,'utf8')==='{broken','Corrupt preferences are exposed to the editor without silently replacing them');
 store.save(corrupt,'');check(store.load().length===0,'Explicit restore repairs corrupt preference syntax');
 selected=[];check(await pickGroupIcon({},store)===undefined&&descriptors.size===0,'Canceled picker creates no files or preference');
 const input=path.join(directory,'input.png');fs.writeFileSync(input,png);selected=['file://'+input];
 imageSize={width:1024,height:512};const picked=await pickGroupIcon({},store);
 check(picked&&decodedSize.width===256&&decodedSize.height===128,'Picker URI fallback reads the real file and normalizes icon size with aspect ratio');
 check(sources===0&&pixels===0&&packers===0&&descriptors.size===0,'Success releases all image and file resources');store.releaseImage(picked);
 for(const kind of ['decode','pack','oversize']){
  failDecode=kind==='decode';failPack=kind==='pack';imageSize=kind==='oversize'?{width:4097,height:16}:{width:32,height:32};
  await assert.rejects(()=>pickGroupIcon({},store));checks++;check(sources===0&&pixels===0&&packers===0&&descriptors.size===0,'Picker failure releases native resources: '+kind);
  failDecode=failPack=false;
 }
 fs.writeFileSync(input,Buffer.alloc(2*1024*1024+1));await assert.rejects(()=>pickGroupIcon({},store),/2 MB/);checks++;
 check(descriptors.size===0,'Large input rejected before decode without leaking the picker descriptor');
 console.log(`Group icon scenarios passed: ${checks} (production stores/picker; OS/image codecs modeled, temporary filesystem real)`);
}finally{fs.rmSync(directory,{recursive:true,force:true});}})().catch(e=>{console.error(e);process.exitCode=1;});
