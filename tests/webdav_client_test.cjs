// Production WebDAV client, independent XML parser and controllable RCP boundary.
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict'),cp=require('node:child_process');
const ts=require('./test_env.cjs')();
const root=path.resolve(__dirname,'../entry/src/main/ets/service');
let checks=0,responses=[],requests=[],sessionConfigs=[],sessions=[];
const check=(value,label)=>{assert(value,label);checks++;};
const util={TextEncoder:class{encodeInto(value){return value.length===0?undefined:new TextEncoder().encode(value);}},TextDecoder:{create:(enc,options)=>({decodeToString:value=>new TextDecoder(enc,options).decode(value)})},
 Base64Helper:class{encodeToStringSync(value){return Buffer.from(value).toString('base64');}}};
const xml={EventType:{START_TAG:1,END_TAG:2,TEXT:3,CDSECT:4,ENTITY_REFERENCE:5},XmlPullParser:class{
 constructor(buffer){this.text=Buffer.from(buffer).toString('utf8');}
 parse(options){
  const python=`import sys,json,xml.etree.ElementTree as E
r=[]
def text_events(ns,name,text):
 for part in text.split('"')[:-1]:
  if part:r.append([3,ns,name,part])
  r.append([5,ns,'quot','"'])
 last=text.split('"')[-1]
 if last:r.append([3,ns,name,last])
def walk(n):
 tag=n.tag; ns,name=(tag[1:].split('}',1) if tag.startswith('{') else ['',tag])
 r.append([1,ns,name,''])
 if n.text:text_events(ns,name,n.text)
 for c in n:
  walk(c)
  if c.tail:text_events(ns,name,c.tail)
 r.append([2,ns,name,''])
walk(E.fromstring(sys.stdin.read()));print(json.dumps(r))`;
  const result=cp.spawnSync('python3',['-c',python],{input:this.text,encoding:'utf8'});
  if(result.status)throw new Error('Independent XML parse failed');
  for(const [event,ns,name,text] of JSON.parse(result.stdout))options.tokenValueCallbackFunction(event,{getName:()=>name,getNamespace:()=>ns,getText:()=>text});
 }
}};
const rcp={Request:class{constructor(url,method,headers,content){Object.assign(this,{url,method,headers,content});}},createSession(config){
 sessionConfigs.push(config);const session={closed:false,cancelled:false,
  async fetch(req){requests.push(req);const response=responses.shift();if(!response)throw new Error('Missing fixture response');
   if(response.pending)return new Promise((resolve,reject)=>session.reject=reject);
   if(response.error)throw new Error(response.error);
   const bytes=response.bytes||Buffer.from(response.text||'');
   for(let i=0;i<bytes.length;i+=response.chunk||8192){const chunk=bytes.subarray(i,i+(response.chunk||8192));req.destination(Uint8Array.from(chunk).buffer);if(session.cancelled)throw new Error('cancelled');}
   return{statusCode:response.status};
  },cancel(){session.cancelled=true;session.reject?.(new Error('cancelled'));},close(){session.closed=true;}
 };sessions.push(session);return session;
}};
const modules=new Map();function load(file){if(modules.has(file))return modules.get(file);const m={exports:{}};const code=ts.transpileModule(fs.readFileSync(path.join(root,file),'utf8'),{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2020}}).outputText;
 const requireShim=name=>name==='@kit.ArkTS'?{util}:name==='@kit.RemoteCommunicationKit'?{rcp}:name==='@ohos.url'?{default:{URL}}:name==='@ohos.xml'?{default:xml}:name==='./BackupTypes'?load('BackupTypes.ets'):name==='./TextCodec'?load('TextCodec.ets'):(()=>{throw new Error('Unexpected import '+name)})();
 vm.runInNewContext(code,{require:requireShim,module:m,exports:m.exports,URL,Uint8Array,ArrayBuffer,TextEncoder,TextDecoder,Error,Number,Date,JSON,Map,Set},{filename:file});modules.set(file,m.exports);return m.exports;
}
const {WebDavClient,webDavCollection,parseDavListing}=load('WebDavClient.ets');
const settings={url:'https://dav.example.invalid/dav/',username:'测试',password:'public:密码'};
const name='clashos-backup-1792190000000-0123456789abcdef0123456789abcdef.json';
const entry={name,bytes:10,updatedAt:'',remote:true,etag:'"v1"'};
const prop=(href,extra='',status='200 OK')=>`<d:response><d:href>${href}</d:href><d:propstat><d:prop><d:resourcetype/>${extra}</d:prop><d:status>HTTP/1.1 ${status}</d:status></d:propstat></d:response>`;
const listing=rows=>`<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">${rows}</d:multistatus>`;
(async()=>{
 check(webDavCollection(settings)==='https://dav.example.invalid/dav/ClashOS/','Dedicated collection is derived from normalized user directory');
 for(const address of ['file:///tmp/dav','https://u:p@dav.example.invalid/','https://dav.example.invalid/?key=secret','https://dav.example.invalid/#x','https://dav.example.invalid/a%2fb/']){assert.throws(()=>webDavCollection({...settings,url:address}));checks++;}
 assert.throws(()=>webDavCollection({...settings,username:'bad:name'}));checks++;
 const xmlText=listing(prop('/dav/ClashOS/'+name,'<d:getcontentlength>123</d:getcontentlength><d:getetag>&quot;v1&quot;</d:getetag><d:getlastmodified>Sat, 17 Oct 2026 00:00:00 GMT</d:getlastmodified>')+
 prop('https://outside.example.invalid/dav/ClashOS/'+name)+prop('/elsewhere/'+name)+prop('/dav/ClashOS/sub/'+name)+prop('/dav/ClashOS/'+name,'','404 Not Found'));
 const rows=parseDavListing(xmlText,webDavCollection(settings));check(rows.length===1&&rows[0].etag==='"v1"'&&rows[0].bytes===123,'DAV namespaces, HTTP status and exact collection containment are enforced');
 check(parseDavListing(listing(prop(name)),webDavCollection(settings)).length===1,'Relative direct-child href is supported');
 const folder=listing(`<d:response><d:href>/dav/ClashOS/${name}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`);
 check(parseDavListing(folder,webDavCollection(settings)).length===0,'Backup-like collections cannot be deleted as files');
 const weak=parseDavListing(listing(prop(name,'<d:getetag>W/&quot;weak&quot;</d:getetag>')),webDavCollection(settings));check(weak[0].etag==='','Weak ETags are never used for strong preconditions');
 for(const invalid of ['<broken>','<multistatus xmlns="wrong"/>','<!DOCTYPE x [<!ENTITY a "b">]><x/>']){assert.throws(()=>parseDavListing(invalid,webDavCollection(settings)));checks++;}
 const client=new WebDavClient(settings);responses=[{status:404}];check((await client.list()).length===0,'A missing dedicated collection is an empty initial list');
 responses=[{status:207,text:xmlText,chunk:3}];check((await client.list()).length===1,'Chunked UTF-8 data is assembled before XML parsing');
 check(requests.at(-1).method==='PROPFIND'&&requests.at(-1).headers.Depth==='1','Listings use actual PROPFIND Depth 1');
 check(requests.at(-1).headers.Authorization==='Basic '+Buffer.from(settings.username+':'+settings.password).toString('base64'),'Basic authentication preserves UTF-8 and colons in the password');
 responses=[{status:201},{status:201},{status:200,text:'备份🙂',chunk:1}];await client.upload({...entry,remote:false},'备份🙂');checks++;
 check(requests.at(-2).method==='PUT'&&requests.at(-2).headers['If-None-Match']==='*'&&requests.at(-1).method==='GET','Uploads are create-only and verified by an independent read-back request');
 responses=[{status:405},{status:201},{status:200,text:'changed'}];await assert.rejects(()=>client.upload(entry,'original'),/上传后校验失败/);checks++;
 responses=[{status:405},{status:412}];await assert.rejects(()=>client.upload(entry,'original'),/同名/);checks++;
 responses=[{status:200,text:'payload'}];check(await client.download(entry)==='payload'&&requests.at(-1).headers['If-Match']==='"v1"','Downloads retain the listed strong ETag precondition');
 responses=[{status:412}];await assert.rejects(()=>client.remove(entry),/备份已变化/);checks++;
 responses=[{status:204}];await client.remove(entry);check(requests.at(-1).method==='DELETE'&&requests.at(-1).headers['If-Match']==='"v1"','Remote deletion is scoped and conditional');
 responses=[{status:204}];await client.remove({...entry,etag:'',updatedAt:'2026-10-17T00:00:00.000Z'});check(requests.at(-1).headers['If-Unmodified-Since']==='Sat, 17 Oct 2026 00:00:00 GMT','Servers without strong ETags use the listed modification timestamp');
 await assert.rejects(()=>client.remove({...entry,etag:'',updatedAt:''}),/无法安全删除/);checks++;
 for(const code of [401,403,409,500]){responses=[{status:code}];await assert.rejects(()=>client.download(entry),/WebDAV/);checks++;}
 responses=[{status:302,text:'redirect'}];await assert.rejects(()=>client.download(entry),/重定向/);checks++;
 check(sessionConfigs.every(c=>c.requestConfiguration.transfer.autoRedirect===false),'Credentials are never automatically redirected');
 responses=[{error:'https://secret-user:secret-password@example.invalid/private?token=secret'}];await assert.rejects(()=>client.download(entry),e=>!e.message.includes('secret')&&!e.message.includes('example.invalid'));checks++;
 responses=[{status:200,bytes:Buffer.alloc(32*1024*1024+1),chunk:1024*1024}];await assert.rejects(()=>client.download(entry),/32 MB/);checks++;
 check(sessions.at(-1).cancelled&&sessions.at(-1).closed,'Oversized downloads are cancelled and sessions closed');
 responses=[{pending:true}];const pending=client.download(entry);client.close();await assert.rejects(()=>pending,/已取消/);checks++;
 await assert.rejects(()=>client.list(),/已取消/);checks++;
 check(sessions.every(s=>s.closed),'Every success, error and cancellation closes its RCP session');
 process.stdout.write(`WebDAV client scenarios passed: ${checks} (production ArkTS; independent XML parser; RCP transport shim)\n`);
})().catch(error=>{process.stderr.write(error.stack+'\n');process.exitCode=1;});
