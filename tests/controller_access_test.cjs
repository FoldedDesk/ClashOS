// Production credential store/controller/API/native wrapper, real temp files;
// Harmony filesystem adapters, native module and HTTP transport are shims.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),vm=require('node:vm'),assert=require('node:assert/strict');
const ts=require('./test_env.cjs')();
const root=path.resolve(__dirname,'../entry/src/main/ets'),directory=fs.mkdtempSync(path.join(os.tmpdir(),'clashos-controller-access-'));
let checks=0,maxWrite=Infinity,failWrite=false,failRename=false,failProtect=false,created=0,destroyed=0,connectionMemory=64*1024*1024;
const descriptors=new Set(),requests=[];
let configValues={mode:'Rule',port:7890,'socks-port':7891,'log-level':'warning',ipv6:true,sniffing:true,
 sniffer:{enable:true,sniff:{TLS:{ports:[443],'override-destination':false}}},path:'/public/profiles/配置 😀.yaml',temporary:false,revision:7};
const check=(value,message)=>{assert(value,message);checks++;};
const fileIo={OpenMode:{CREATE:1,READ_WRITE:2,TRUNC:4},accessSync:p=>fs.existsSync(p),statSync:p=>fs.statSync(p),readTextSync:p=>fs.readFileSync(p,'utf8'),
 openSync:p=>{const fd=fs.openSync(p,'w+');descriptors.add(fd);return{fd};},closeSync:v=>{const fd=typeof v==='number'?v:v.fd;fs.closeSync(fd);descriptors.delete(fd);},
 writeSync:(fd,b)=>{if(failWrite)throw Error('injected write failure');return fs.writeSync(fd,Buffer.from(b).subarray(0,maxWrite));},
 fsyncSync:fd=>fs.fsyncSync(fd),renameSync:(a,b)=>{if(failRename)throw Error('injected rename failure');fs.renameSync(a,b);},unlinkSync:p=>fs.unlinkSync(p)};
const http={RequestMethod:{GET:'GET',PUT:'PUT',DELETE:'DELETE'},createHttp:()=>{created++;return{destroy:()=>destroyed++,request:async(url,options)=>{
 requests.push({url,header:{...options.header},usingProxy:options.usingProxy,method:options.method,body:options.extraData});let value={};const endpoint=new URL(url).pathname;
 if(endpoint==='/version')value={version:'ClashOS Core 0.23 native',instance:'public-test'};
 if(endpoint==='/proxies')value={proxies:{}};if(endpoint==='/configs'){value=configValues;if(options.method==='PUT'||options.method==='PATCH')return{responseCode:204,result:''};}
 if(endpoint==='/connections')value={connections:[],memory:connectionMemory};if(endpoint==='/rules')value={rules:[]};
 return{responseCode:200,result:JSON.stringify(value)};
 }}}};
function nativeModule(){return{configureRuntimeDirectory:()=>true,secret:'',sets:0,starts:0,fail:0,mutateBeforeFail:false,
 info:()=>JSON.stringify({running:true,instance:'public-test',configPath:'public.yaml',mode:'Rule',controllerPort:9090,httpPort:7890,socksPort:7891}),
 controllerSecret(){return this.secret;},setControllerSecret(value){this.sets++;if(this.fail){this.fail--;if(this.mutateBeforeFail)this.secret=value;return false;}this.secret=value;return true;},
 startAsync:async function(){this.starts++;this.startedWith=this.secret;return true;},start:function(){this.starts++;this.startedWith=this.secret;return true;},
 protectFile:fd=>{if(failProtect)return false;fs.fchmodSync(fd,0o600);return true;}};}
function loader(native){const modules=new Map();function load(name){const filename=path.join(root,name);if(modules.has(filename))return modules.get(filename).exports;const m={exports:{}};modules.set(filename,m);
 const requireShim=p=>{if(p==='@kit.CoreFileKit')return{fileIo};if(p==='@kit.ArkTS')return{util:{TextEncoder:class{encodeInto(t){return new TextEncoder().encode(t);}}}};if(p==='@kit.NetworkKit')return{http};if(p==='libclash_core.so')return native;if(p.startsWith('.'))return load(path.relative(root,path.resolve(path.dirname(filename),p+'.ets')));throw Error('Unexpected import '+p);};
 const code=ts.transpileModule(fs.readFileSync(filename,'utf8'),{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2020,esModuleInterop:true}}).outputText;
 vm.runInNewContext(code,{module:m,exports:m.exports,require:requireShim,Uint8Array,ArrayBuffer});return m.exports;
 }return load;}
(async()=>{try{
 const native=nativeModule(),load=loader(native),{ControllerAccessStore,validateControllerSecret}=load('service/ControllerAccessStore.ets');
 const {ControllerAccessController,localControllerCredential}=load('service/ControllerAccessController.ets');
 const Core=load('service/ClashNativeCore.ets').ClashNativeCore,Api=load('service/ClashApi.ets').ClashApi;
 const core=new Core();core.configureControllerStore(directory);const store=new ControllerAccessStore(directory,fd=>core.protectFile(fd)),controller=new ControllerAccessController(store,core);
 const filename=path.join(directory,'controller-access.json'),initial=store.snapshot(),first='public-token+/%?A',second='public-token-B';
 check(initial.secret===''&&initial.revision===undefined&&!initial.error,'Missing settings default to optional authentication disabled');
 for(const invalid of ['with space','line\nfeed','中文','x'.repeat(257)]){assert.throws(()=>validateControllerSecret(invalid));checks++;}
 controller.save(initial,first);check(store.credential()===first&&native.secret===first&&(fs.statSync(filename).mode&0o777)===0o600,'Apply saves private settings and updates the actual native host');
 let previous=store.snapshot();maxWrite=3;controller.save(previous,second);maxWrite=Infinity;check(store.credential()===second,'Partial writes preserve complete credential bytes');
 assert.throws(()=>controller.save(previous,'stale'),/已变化/);checks++;check(store.credential()===second&&native.secret===second,'Stale dialogs cannot replace a newer key');
 for(const kind of ['write','rename','protect']){
  previous=store.snapshot();const sets=native.sets;failWrite=kind==='write';failRename=kind==='rename';failProtect=kind==='protect';
  assert.throws(()=>controller.save(previous,first));checks++;failWrite=failRename=failProtect=false;
  check(store.credential()===second&&native.secret===second&&native.sets===sets,'Storage failure must never change native authentication: '+kind);
  check(descriptors.size===0&&!fs.existsSync(filename+'.tmp'),'Failed settings writes release files: '+kind);
 }
 previous=store.snapshot();native.fail=1;native.mutateBeforeFail=true;assert.throws(()=>controller.save(previous,first),/原设置已保留/);checks++;
 check(store.credential()===second&&native.secret===second,'A native failure, including lost acknowledgement, restores both disk and live key');
 previous=store.snapshot();native.fail=2;assert.throws(()=>controller.save(previous,first),/运行密钥未能恢复/);checks++;native.fail=0;native.mutateBeforeFail=false;native.secret=second;
 check(store.credential()===second,'Incomplete native rollback must still preserve the previous file and report the incomplete step');
 const live=core.info(),stopped={...live,running:false},background={state:'running',core:{...live,controllerPort:9091}};
 check(localControllerCredential('http://127.0.0.1:9090',store,live)===second&&localControllerCredential('http://localhost:9090',store,live)===second,'Only the owned foreground loopback controller receives its managed key');
 for(const endpoint of ['http://remote.invalid:9090','http://127.0.0.1:9091','https://127.0.0.1:9090','http://127.0.0.1:9090/other'])check(localControllerCredential(endpoint,store,live)===undefined,'Never leak a local key to a foreign endpoint');
 check(localControllerCredential('http://127.0.0.1:9091',store,stopped,background)===second,'Owned background core uses the same private credential');
 check(localControllerCredential('http://127.0.0.1:9091',store,stopped,{...background,state:'error'})===undefined,'Stale or failed background state must not grant credential ownership');
 await core.startAsync('public.yaml',9090);check(native.startedWith===second,'Foreground restart loads the saved key before exposing the controller');
 const backgroundNative=nativeModule(),BackgroundCore=loader(backgroundNative)('service/ClashNativeCore.ets').ClashNativeCore,bg=new BackgroundCore();bg.configureControllerStore(directory);await bg.startAsync('public.yaml',9090);
 check(backgroundNative.startedWith===second,'Independent VPN/native process reads the same private settings before startup');
 const api=new Api();api.setLocalCredentialProvider(endpoint=>localControllerCredential(endpoint,store,core.info()));
 const memorySnapshot=await api.readSnapshot();check(memorySnapshot.memoryBytes===64*1024*1024,'Dashboard snapshot carries the controller process RSS');
 check(requests.length>0&&requests.every(r=>r.header.Authorization==='Bearer '+second),'All requests to the owned controller authenticate automatically');
 check(requests.every(r=>r.usingProxy===false),'Managed loopback credentials must never be routed through the system proxy');
 const config=await api.runtimeConfig();check(config.mode==='Rule'&&config.logLevel==='warning'&&config.ipv6&&config.path===configValues.path&&config.revision===7&&!config.temporary,'Runtime config maps real controller fields without exposing payload YAML');
 check(config.sniffing&&(await api.readSnapshot()).sniffing,'Runtime editor and dashboard read the same actual sniffer toggle');
 const snifferDraft=await api.snifferDraft();check(Object.keys(JSON.parse(snifferDraft)).join(',')==='sniffer'&&JSON.parse(snifferDraft).sniffer.sniff.TLS['override-destination']===false,'Sniffer editor preserves nested protocol options without copying unrelated controller fields');
 await api.saveSnifferDraft(config,snifferDraft);let snifferRequest=requests.at(-1),snifferRoute=new URL(snifferRequest.url);
 check(snifferRequest.method==='PATCH'&&snifferRequest.body===snifferDraft&&snifferRoute.searchParams.get('profile')===config.path&&snifferRoute.searchParams.get('revision')==='7','Sniffer apply carries the captured Unicode profile and revision with the exact validated draft');
 await api.saveRuntimeConfig(config,{...config,sniffing:false});check(JSON.parse(requests.at(-1).body).sniffing===false,'Disabling sniffing sends explicit false rather than omitting the change');
 await api.saveRuntimeConfig(config,{...config,mode:'Direct',logLevel:'error',ipv6:false});
 let mutation=requests.at(-1),route=new URL(mutation.url),patch=JSON.parse(mutation.body);
 check(mutation.method==='PATCH'&&route.searchParams.get('profile')===config.path&&route.searchParams.get('revision')==='7'&&patch.mode==='Direct'&&patch['log-level']==='error'&&patch.ipv6===false,'Runtime edit sends the original path/revision and typed values, accepting standard empty 204');
 await api.loadConfig('/public/配置 😀.yaml');mutation=requests.at(-1);route=new URL(mutation.url);
 check(mutation.method==='PUT'&&route.searchParams.get('force')==='true'&&JSON.parse(mutation.body).path==='/public/配置 😀.yaml','Profile selection puts force in the query accepted by actual Clash controllers');
 await api.loadConfig('');check(JSON.parse(requests.at(-1).body).path==='','Reload requests actual current source parsing rather than omitting a controller request');
 await api.loadConfig('',config);route=new URL(requests.at(-1).url);check(route.searchParams.get('profile')===config.path&&route.searchParams.get('revision')==='7','Reload carries the dialog snapshot to native validation atomically, rather than relying on a separate preflight read');
 configValues={...configValues,temporary:true,path:'/public/.clashos-runtime/controller.json'};
 check((await api.readSnapshot()).temporaryConfig===true&&(await api.runtimeConfig()).temporary,'Both dashboard snapshot and runtime dialog identify temporary payloads');
 configValues={...configValues,temporary:false};

 for(const invalid of [undefined,-1,'not-memory',Infinity]){connectionMemory=invalid;const value=await api.readSnapshot();check(value.connected&&value.memoryBytes===0,'Missing or invalid optional memory cannot show a bogus value or disconnect a compatible core');}connectionMemory=64*1024*1024;
 requests.length=0;api.setConfig('http://remote.invalid:9090','external-only-token');await api.readSnapshot();check(requests.every(r=>r.header.Authorization==='Bearer external-only-token'),'External cores retain their separate user-supplied credential');
 check(requests.every(r=>r.usingProxy===undefined),'External controller proxy routing keeps the previous transport default');
 controller.save(store.snapshot(),'');requests.length=0;api.setConfig('http://127.0.0.1:9090','external-only-token');await api.readSnapshot();check(requests.every(r=>!('Authorization' in r.header)),'Disabled local authentication must not fall back to an unrelated external credential');
 for(const raw of ['', '{broken', 'null', '[]', JSON.stringify({version:2,secret:first}),JSON.stringify({version:1,secret:'has space'})]){
  fs.writeFileSync(filename,raw);const snapshot=store.snapshot();check(snapshot.error&&snapshot.secret==='','Corrupt settings provide an explicit repair state without exposing raw data');
  assert.throws(()=>store.credential(),/设置无效/);checks++;const starts=native.starts;await assert.rejects(()=>core.startAsync('public.yaml',9090));checks++;check(native.starts===starts,'Corrupt credential files must fail before the native listener starts');
  controller.save(snapshot,second);check(store.credential()===second&&native.secret===second,'An explicit save repairs corrupt settings');
 }
 fs.writeFileSync(filename,'{broken');requests.length=0;const disconnected=await api.readSnapshot();check(!disconnected.connected&&requests.length===0,'Unreadable local credentials must not issue an unauthenticated HTTP request');
 check(created===destroyed,'HTTP transports are released even when the credential provider rejects the request');
 controller.save(store.snapshot(),'');check(store.credential()===''&&native.secret==='','Authentication can be disabled without affecting external settings');
 check(descriptors.size===0,'All credential descriptors are released');
 console.log(`Controller access scenarios passed: ${checks} (production services; OS/native/HTTP shims, real temporary files)`);
}finally{fs.rmSync(directory,{recursive:true,force:true});}})().catch(error=>{console.error(error);process.exitCode=1;});
