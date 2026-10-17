// Production backup/profile/appearance coordinators; native validators and OS APIs are shims.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),vm=require('node:vm'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const ts=require('./test_env.cjs')();
const root=path.resolve(__dirname,'../entry/src/main/ets'),directory=fs.mkdtempSync(path.join(os.tmpdir(),'clashos-backup-v2-'));
const descriptors=new Map(),modules=new Map(),storage=new Map();
let checks=0,maxWrite=Infinity,failGlobalScript=false,failAppearanceWrite=false,failResource=false,failTokens=false,failPublishOnce=false,callback,appliedMode=-1,picked=[],lastBundle;
const check=(value,label)=>{assert(value,label);checks++;};
const fileIo={OpenMode:{READ_ONLY:0,CREATE:64,READ_WRITE:2,TRUNC:512},accessSync:p=>fs.existsSync(p),statSync:p=>typeof p==='number'?fs.fstatSync(p):fs.statSync(p),
 mkdirSync:(p,recursive)=>fs.mkdirSync(p,{recursive}),listFileSync:p=>fs.readdirSync(p),readTextSync:p=>fs.readFileSync(p,'utf8'),
 openSync:(p,flags)=>{const fd=fs.openSync(p,(flags&64)?'w+':'r');descriptors.set(fd,p);return{fd};},closeSync:f=>{const fd=typeof f==='number'?f:f.fd;fs.closeSync(fd);descriptors.delete(fd);},
 readSync:(fd,buffer)=>fs.readSync(fd,new Uint8Array(buffer),0,Math.min(buffer.byteLength,7),null),
 writeSync:(fd,buffer)=>{const p=descriptors.get(fd);if(failGlobalScript&&p.endsWith('/.global-script.js.tmp')||failAppearanceWrite&&p.endsWith('/appearance.json.tmp')||failResource&&p.includes('.provider-'))throw Error('injected file failure');return fs.writeSync(fd,Buffer.from(buffer).subarray(0,maxWrite));},
 fsyncSync:fd=>fs.fsyncSync(fd),renameSync:(a,b)=>fs.renameSync(a,b),unlinkSync:p=>fs.unlinkSync(p)};
class Validator{
 protectFile(fd){fs.fchmodSync(fd,0o600);}
 validate(content){if(content.includes('INVALID_CONFIG'))throw Error('invalid config');}
 ruleEditor(content,rules,render,objects='',text=''){
  this.validate(content);const b=text?JSON.parse(text):{};lastBundle=b;
  if(text.includes('INVALID_MERGE')||text.includes('INVALID_SCRIPT'))throw Error('invalid extension');
  if(content.includes('REQUIRES_ARCHIVE_GLOBAL')&&!(b.global||'').includes('ARCHIVE_GLOBAL'))throw Error('requires archive global');
  if((b.globalScript||'').includes('REQUIRES_PORTABLE_CONTEXT')&&!(b.profileName||'').startsWith('portable'))throw Error('requires portable profile');
  if((b.profileScript||'').includes('ASSERT_RESTORE_NAME')&&!(b.profileName||'').includes('（恢复'))throw Error('wrong restore name');
  return{error:'',content:render?content:undefined,rules:[],effective:[],policies:['DIRECT','REJECT'],providers:[]};
 }
}
const util={TextEncoder:class{encodeInto(text){return new TextEncoder().encode(text);}},TextDecoder:{create:()=>{const d=new TextDecoder('utf-8',{fatal:true});return{decodeToString:(b,o)=>d.decode(b,o)};}},generateRandomUUID:()=>crypto.randomUUID(),Base64Helper:class{encodeToStringSync(b){return Buffer.from(b).toString('base64');}decodeSync(s){return Uint8Array.from(Buffer.from(s,'base64'));}}};
const app={on:(type,cb)=>{callback=cb;return 1;},off:async()=>{callback=undefined;},setColorMode:mode=>{appliedMode=mode;callback?.onConfigurationUpdated({colorMode:mode<0?1:mode});}};
const context={filesDir:directory,config:{colorMode:1},getApplicationContext:()=>app};
function load(name){
 const file=path.join(root,name);if(modules.has(file))return modules.get(file).exports;const m={exports:{}};modules.set(file,m);
 const requireShim=p=>{
  if(p==='@kit.CoreFileKit')return{fileIo,picker:{DocumentSelectOptions:class{},DocumentViewPicker:class{async select(){return picked;}}},fileUri:{FileUri:class{constructor(p){this.path=p;}}}};
  if(p==='@kit.ArkTS')return{util};if(p==='@kit.NetworkKit')return{};
  if(p==='@kit.AbilityKit')return{ConfigurationConstant:{ColorMode:{COLOR_MODE_NOT_SET:-1,COLOR_MODE_DARK:0,COLOR_MODE_LIGHT:1}}};
  if(p==='@kit.ArkUI')return{ThemeControl:{setDefaultTheme:()=>{if(failTokens)throw Error('injected native theme failure');}}};
  if(p==='./ClashNativeCore')return{ClashNativeCore:Validator};
  if(p.startsWith('.'))return load(path.relative(root,path.resolve(path.dirname(file),p+'.ets')));
  throw Error('Unexpected import '+p);
 };
 const code=ts.transpileModule(fs.readFileSync(file,'utf8'),{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2020,experimentalDecorators:true}}).outputText;
 vm.runInNewContext(code,{module:m,exports:m.exports,require:requireShim,Observed:t=>t,TextEncoder,TextDecoder,Uint8Array,ArrayBuffer,
  AppStorage:{setOrCreate:(k,v)=>{if(failPublishOnce){failPublishOnce=false;throw Error('injected publish failure');}storage.set(k,v);},get:k=>storage.get(k)}});
 return m.exports;
}
const same=(a,b)=>a.merge===b.merge&&a.script===b.script;
(async()=>{let appearance;try{
 const {ProfileStore}=load('service/ProfileStore.ets'),{BackupStore}=load('service/BackupStore.ets'),{AppearanceController}=load('service/AppearanceController.ets'),{BackupRestoreCoordinator}=load('service/BackupRestoreCoordinator.ets');
 const profiles=new ProfileStore(context),backups=new BackupStore(context,profiles),protector=new Validator();
 const active=profiles.create('active','rules: [MATCH,DIRECT]\n'),portable=profiles.create('portable','rules: [MATCH,DIRECT]\n');
 const excluded=profiles.create('excluded','rules: [MATCH,DIRECT]\n','https://example.invalid/private?token=SYNTHETIC-EXCLUDED');
 const current={merge:'# CURRENT\nrules: [MATCH,DIRECT]\n',script:'function main(c){return c;} // current'},archived={merge:'# ARCHIVE_GLOBAL\nrules: [MATCH,REJECT]\n',script:'function main(c){return c;} // archived'};
 profiles.replaceBackupGlobals(profiles.backupGlobals(),archived);
 appearance=new AppearanceController(context,fd=>protector.protectFile(fd));appearance.save('dark','#8B5CF6');
 fs.writeFileSync(path.join(directory,'controller-access.json'),JSON.stringify({version:1,secret:'SYNTHETIC-CONTROLLER-EXCLUDED'}));
 const text=profiles.createBackup({profileIds:[portable.id],includeGlobals:true,includeAppearance:true}),archive=JSON.parse(text);
 check(archive.version===2&&archive.profiles.length===1&&archive.profiles[0].name==='portable','Explicit profile selection creates a v2 archive');
 check(!text.includes('SYNTHETIC-CONTROLLER-EXCLUDED'),'Application controller credentials are excluded from profile/settings backups');
 check(!text.includes(excluded.sourceUrl)&&!text.includes(excluded.name)&&!text.includes(directory),'Selective archives exclude unselected credentials and device paths');
 check(same(archive.globals,archived)&&archive.appearance.mode==='dark'&&archive.appearance.accent==='#8B5CF6','Globals, scripts and appearance are portable');
 const settingsOnly=profiles.createBackup({profileIds:[],includeGlobals:true,includeAppearance:true});check(profiles.inspectBackup(settingsOnly).rows.length===0,'Settings-only archives are supported');
 const profileOnly=JSON.parse(profiles.createBackup({profileIds:[portable.id],includeGlobals:false,includeAppearance:false}));check(profileOnly.version===2&&profileOnly.globals===undefined&&profileOnly.appearance===undefined,'Settings excluded by choice are not serialized');
 check(JSON.parse(profiles.createBackup()).version===1,'Legacy API remains compatible');
 for(const ids of [[portable.id,portable.id],['missing']]){assert.throws(()=>profiles.createBackup({profileIds:ids,includeGlobals:true,includeAppearance:false}));checks++;}
 assert.throws(()=>profiles.createBackup({profileIds:[],includeGlobals:false,includeAppearance:false}));checks++;
 const local=backups.importText(text);check(backups.read(local)===text&&(fs.statSync(path.join(directory,'backups',local.name)).mode&0o777)===0o600,'V2 archive storage is private and byte-exact');
 const corruptions=[a=>a.version=3,a=>{a.version=1;},a=>a.globals.merge=3,a=>a.globals.script='x'.repeat(262145),a=>a.appearance.mode='unknown',a=>a.appearance.accent='#GGGGGG',a=>{a.profiles=[];delete a.globals;delete a.appearance;},a=>a.globals=null];
 for(const mutate of corruptions){const a=JSON.parse(text);mutate(a);assert.throws(()=>profiles.inspectBackup(JSON.stringify(a)));checks++;}
 const old=JSON.parse(text);old.version=1;delete old.globals;delete old.appearance;check(profiles.inspectBackup(JSON.stringify(old)).rows[0].valid,'Old archives import without settings');
 assert.throws(()=>profiles.inspectBackup(JSON.stringify(old),true));checks++;
 profiles.replaceBackupGlobals(archived,current);appearance.save('light','#3478F6');
 const dependent=JSON.parse(text);dependent.profiles[0].content+='# REQUIRES_ARCHIVE_GLOBAL\n';
 check(!profiles.inspectBackup(JSON.stringify(dependent)).rows[0].valid&&profiles.inspectBackup(JSON.stringify(dependent),true).rows[0].valid,'Preview can validate against current or archived globals without committing them');
 check(same(profiles.backupGlobals(),current),'Preview does not change globals');
 const renamed=JSON.parse(text);renamed.profiles[0].script='ASSERT_RESTORE_NAME';const namePreview=profiles.inspectBackup(JSON.stringify(renamed),true);
 check(namePreview.rows[0].restoreName==='portable（恢复）'&&namePreview.rows[0].valid&&lastBundle.profileName==='portable（恢复）','Preview and script validation use the actual future copy name');
 const staged=profiles.restoreBackup(JSON.stringify(dependent),[0],true)[0];check(profiles.read(staged).includes('REQUIRES_ARCHIVE_GLOBAL')&&same(profiles.backupGlobals(),current),'Profile staging can use archive globals without changing live globals');profiles.remove(staged);
 const coordinator=new BackupRestoreCoordinator(profiles,appearance);
 const selection=(globals=true,looks=true)=>{const p=profiles.inspectBackup(text,globals);return{profiles:[0],globals,appearance:looks,expectedGlobals:p.currentGlobals,expectedAppearance:appearance.savedSettings(),expectedNames:p.namesSnapshot};};
 let calls=0,applied=current,failFirst=false,changeGlobal=false,changeAppearance=false;
 const runtime={validate:g=>profiles.validateBackupGlobals(active,g),reload:async()=>{calls++;applied=profiles.backupGlobals();if(calls===1&&changeGlobal)profiles.replaceBackupGlobals(applied,{merge:'# NEWER\n',script:''});if(calls===1&&changeAppearance)appearance.save('dark','#199A70');if(calls===1&&failFirst)throw Error('injected lost reload acknowledgement');}};
 const baseNames=profiles.backupNamesSnapshot();
 const cleanNew=()=>{for(const p of profiles.list())if(![active.id,portable.id,excluded.id].includes(p.id))profiles.remove(p);};
 let result=await coordinator.restore(text,selection(false,false),runtime);check(result.count===1&&!result.globals&&!result.appearance&&calls===0&&same(profiles.backupGlobals(),current),'Default restore creates copies without modifying global settings or runtime');cleanNew();
 const appearanceOnly=selection(false,true);appearanceOnly.profiles=[];result=await coordinator.restore(text,appearanceOnly,runtime);check(result.count===0&&result.appearance&&calls===0&&appearance.savedSettings().mode==='dark'&&same(profiles.backupGlobals(),current),'Appearance-only restores neither profiles nor globals');appearance.save('light','#3478F6');
 const globalsOnly=selection(true,false);globalsOnly.profiles=[];calls=0;result=await coordinator.restore(text,globalsOnly,runtime);check(result.count===0&&result.globals&&result.reloaded&&calls===1&&same(applied,archived),'Globals-only restore reloads the current runtime');profiles.replaceBackupGlobals(archived,current);
 calls=0;result=await coordinator.restore(text,selection(),runtime);check(result.count===1&&calls===1&&same(profiles.backupGlobals(),archived)&&appearance.savedSettings().mode==='dark','Full migration restores selected copies, globals, runtime and appearance');cleanNew();profiles.replaceBackupGlobals(archived,current);appearance.save('light','#3478F6');
 const stale=selection();profiles.replaceBackupGlobals(current,{merge:'# newer\n',script:''});await assert.rejects(()=>coordinator.restore(text,stale,runtime),/已变化/);checks++;profiles.replaceBackupGlobals(profiles.backupGlobals(),current);check(profiles.backupNamesSnapshot()===baseNames,'Stale global snapshots create no copies');
 const staleNames=selection(),newer=profiles.create('newer','rules: [MATCH,DIRECT]\n');await assert.rejects(()=>coordinator.restore(text,staleNames,runtime),/列表已变化/);checks++;profiles.remove(newer);
 const staleAppearance=selection();appearance.save('dark','#199A70');await assert.rejects(()=>coordinator.restore(text,staleAppearance,runtime),/外观设置已变化/);checks++;appearance.save('light','#3478F6');
 for(const kind of ['global-script','runtime','appearance-file','appearance-native','appearance-publish','resource']){
  calls=0;failGlobalScript=kind==='global-script';failFirst=kind==='runtime';failAppearanceWrite=kind==='appearance-file';failTokens=kind==='appearance-native';failPublishOnce=kind==='appearance-publish';failResource=kind==='resource';
  const chosen=selection();let failureText=text;
  if(kind==='resource'){const a=JSON.parse(text);a.profiles[0].resources=[{suffix:'.provider-0123456789abcdef.cache',data:Buffer.from('public').toString('base64')}];failureText=JSON.stringify(a);}
  await assert.rejects(()=>coordinator.restore(failureText,chosen,runtime));checks++;
  failGlobalScript=failFirst=failAppearanceWrite=failTokens=failPublishOnce=failResource=false;
  check(same(profiles.backupGlobals(),current)&&profiles.backupNamesSnapshot()===baseNames&&appearance.savedSettings().mode==='light','Failed migration rolls back globals, new profiles and persisted appearance: '+kind);
  if(['runtime','appearance-file','appearance-native','appearance-publish'].includes(kind))check(calls===2&&same(applied,current),'Runtime is reloaded again after rolling back files: '+kind);
  check(descriptors.size===0&&!fs.readdirSync(path.join(directory,'profiles')).some(n=>n.endsWith('.tmp')),'Failure releases files and staging resources: '+kind);
 }
 calls=0;changeAppearance=true;await assert.rejects(()=>coordinator.restore(text,selection(),runtime),/外观设置已变化/);checks++;changeAppearance=false;
 check(appearance.savedSettings().accent==='#199A70'&&same(profiles.backupGlobals(),current)&&profiles.backupNamesSnapshot()===baseNames,'An appearance changed during reload is preserved rather than overwritten');appearance.save('light','#3478F6');
 calls=0;changeGlobal=true;await assert.rejects(()=>coordinator.restore(text,selection(),runtime),/全局扩展/);checks++;changeGlobal=false;
 check(profiles.backupGlobals().merge==='# NEWER\n'&&profiles.backupNamesSnapshot()===baseNames,'Newer global files are preserved even when rollback cannot own them');profiles.replaceBackupGlobals(profiles.backupGlobals(),current);
 const reverse={script:current.script,merge:current.merge};profiles.replaceBackupGlobals(reverse,archived);profiles.replaceBackupGlobals({script:archived.script,merge:archived.merge},current);check(same(profiles.backupGlobals(),current),'Global ownership guards compare values rather than JSON property order');
 maxWrite=3;const partial=await coordinator.restore(text,selection(),runtime);maxWrite=Infinity;check(partial.count===1&&same(profiles.backupGlobals(),archived),'Full restore handles partial writes');cleanNew();profiles.replaceBackupGlobals(archived,current);appearance.save('light','#3478F6');
 const pickedPath=path.join(directory,'公开备份.json');fs.writeFileSync(pickedPath,text);picked=[pickedPath];check(await profiles.pickBackup()===text,'Backup JSON picker preserves Unicode and partial UTF-8 reads');picked=[];check(await profiles.pickBackup()===undefined,'Cancelling backup selection changes nothing');
 const freshProfiles=new ProfileStore({...context,filesDir:path.join(directory,'fresh')}),freshCoordinator=new BackupRestoreCoordinator(freshProfiles);
 for(const key of ['merge','script']){
  const bad=JSON.parse(settingsOnly);bad.globals[key]=key==='merge'?'INVALID_MERGE':'INVALID_SCRIPT';
  await assert.rejects(()=>freshCoordinator.restore(JSON.stringify(bad),{profiles:[],globals:true,appearance:false}),/invalid extension/);checks++;
  check(same(freshProfiles.backupGlobals(),{merge:'',script:''})&&freshProfiles.list().length===0,'Fresh settings-only restore validates before writing: '+key);
 }
 const freshResult=await freshCoordinator.restore(settingsOnly,{profiles:[],globals:true,appearance:false});
 check(freshResult.globals&&!freshResult.reloaded&&same(freshProfiles.backupGlobals(),archived)&&lastBundle.profileName==='默认配置','Valid settings-only archives restore on fresh installs using native default-profile validation');
 const contextual=JSON.parse(text);contextual.globals.script+=' // REQUIRES_PORTABLE_CONTEXT';
 const contextualResult=await freshCoordinator.restore(JSON.stringify(contextual),{profiles:[0],globals:true,appearance:false});
 check(contextualResult.count===1&&lastBundle.profileName==='portable','Fresh profile-plus-settings restore validates scripts in the selected profile context');
 const offlineCoordinator=new BackupRestoreCoordinator(profiles,appearance,active);
 const offlineResult=await offlineCoordinator.restore(settingsOnly,{profiles:[],globals:true,appearance:false});
 check(offlineResult.globals&&!offlineResult.reloaded&&lastBundle.profileName===active.name,'Offline restores validate against the selected profile rather than the default');
 profiles.replaceBackupGlobals(archived,current);
 const empty=JSON.parse(settingsOnly);empty.globals={merge:' \n',script:' \t'};const emptyText=JSON.stringify(empty);const emptyPlan=profiles.inspectBackup(emptyText,true);await coordinator.restore(emptyText,{profiles:[],globals:true,appearance:false,expectedGlobals:emptyPlan.currentGlobals,expectedNames:emptyPlan.namesSnapshot},runtime);check(profiles.globalMergeText()===''&&profiles.globalScriptText()==='','Explicitly restoring empty global settings clears previous overrides');
 check(profiles.read(active)==='rules: [MATCH,DIRECT]\n'&&profiles.read(excluded)==='rules: [MATCH,DIRECT]\n','Migration never rewrites existing configuration source');
 check(descriptors.size===0,'All migration descriptors are released');
 console.log(`Backup migration scenarios passed: ${checks} (production services; native/OS APIs shimmed, real temporary filesystem)`);
}finally{appearance?.dispose();fs.rmSync(directory,{recursive:true,force:true});}})().catch(e=>{console.error(e);process.exitCode=1;});
