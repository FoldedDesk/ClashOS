// Production palette, persistence and coordinator; native color APIs are shims.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),vm=require('node:vm'),assert=require('node:assert/strict');
const ts=require('./test_env.cjs')();
const root=path.resolve(__dirname,'../entry/src/main/ets');
const directory=fs.mkdtempSync(path.join(os.tmpdir(),'clashos-appearance-'));
const descriptors=new Set(),storage=new Map(),cache=new Map();
let checks=0,maxWrite=Infinity,failWrite=false,failRename=false,failSync=false,failProtect=false,failMode=false,failTokens=false;
let callback,id=0,offCount=0,systemDark=false,appliedMode=-1,lastTokens,tokenCalls=0,failTokenAt=0,failPublishOnce=false;
const check=(value,label)=>{assert(value,label);checks++;};
const fileIo={OpenMode:{CREATE:0x40,READ_WRITE:2,TRUNC:0x200},
  accessSync:p=>fs.existsSync(p),statSync:p=>fs.statSync(p),readTextSync:p=>fs.readFileSync(p,'utf8'),
  openSync:p=>{const fd=fs.openSync(p,'w+');descriptors.add(fd);return{fd};},
  closeSync:f=>{fs.closeSync(f.fd);descriptors.delete(f.fd);},
  writeSync:(fd,buffer)=>{if(failWrite)throw Error('write failure');return fs.writeSync(fd,Buffer.from(buffer).subarray(0,maxWrite));},
  fsyncSync:fd=>{if(failSync)throw Error('sync failure');fs.fsyncSync(fd);},
  renameSync:(from,to)=>{if(failRename)throw Error('rename failure');fs.renameSync(from,to);},unlinkSync:p=>fs.unlinkSync(p)
};
const app={on:(type,cb)=>{assert.equal(type,'environment');callback=cb;return++id;},
  off:async(type,key)=>{assert.equal(type,'environment');offCount++;callback=undefined;},
  setColorMode:mode=>{if(failMode)throw Error('native mode failure');appliedMode=mode;callback?.onConfigurationUpdated({colorMode:mode<0?(systemDark?0:1):mode});}
};
const context={filesDir:directory,config:{colorMode:1},getApplicationContext:()=>app};
const protect=fd=>{if(failProtect)throw Error('protect failure');fs.fchmodSync(fd,0o600);};
function load(name){
 const filename=path.join(root,name);
 if(cache.has(filename))return cache.get(filename).exports;
 const m={exports:{}};cache.set(filename,m);
 const requireShim=specifier=>{
  if(specifier==='@kit.CoreFileKit')return{fileIo};
  if(specifier==='@kit.ArkTS')return{util:{TextEncoder:class{encodeInto(value){return new TextEncoder().encode(value);}}}};
  if(specifier==='@kit.AbilityKit')return{UIAbility:class{},ConfigurationConstant:{ColorMode:{COLOR_MODE_NOT_SET:-1,COLOR_MODE_DARK:0,COLOR_MODE_LIGHT:1}}};
  if(specifier==='@kit.ArkUI')return{ThemeControl:{setDefaultTheme:theme=>{tokenCalls++;if(failTokens||tokenCalls===failTokenAt)throw Error('native tokens failure');lastTokens=theme;}}};
  if(specifier.startsWith('.'))return load(path.relative(root,path.resolve(path.dirname(filename),specifier+'.ets')));
  throw Error('Unexpected import '+specifier);
 };
 const code=ts.transpileModule(fs.readFileSync(filename,'utf8'),{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2020,experimentalDecorators:true}}).outputText;
 vm.runInNewContext(code,{module:m,exports:m.exports,require:requireShim,Observed:target=>target,
  AppStorage:{setOrCreate:(key,value)=>{if(failPublishOnce){failPublishOnce=false;throw Error('injected publish failure');}storage.set(key,value);},get:key=>storage.get(key)},TextEncoder,TextDecoder,Uint8Array,ArrayBuffer,Error,Set,Map,Number,JSON,Math});
 return m.exports;
}
// Independent sRGB contrast calculation, rather than verifying the production function against itself.
function ratio(a,b){const l=hex=>{const channels=[1,3,5].map(i=>parseInt(hex.slice(i,i+2),16)/255).map(n=>n<=.04045?n/12.92:((n+.055)/1.055)**2.4);return channels[0]*.2126+channels[1]*.7152+channels[2]*.0722;};const x=l(a),y=l(b);return(Math.max(x,y)+.05)/(Math.min(x,y)+.05);}
(async()=>{try{
 const {createPalette,appearanceSettings,DEFAULT_ACCENT}=load('theme/VergeTheme.ets');
 const {AppearanceStore}=load('service/AppearanceStore.ets'),{AppearanceController}=load('service/AppearanceController.ets');
 for(const dark of [false,true])for(const accent of ['#3478F6','#8B5CF6','#199A70','#D94C86','#D87724','#64748B','#FFFFFF','#000000','#808080','#FFFF00','#00FFFF','#FF00FF']){
  const p=createPalette(dark,accent);
  check(ratio(p.primary,p.surface)>=4.5&&ratio(p.primary,p.primarySoft)>=4.5&&ratio(p.onPrimary,p.primary)>=4.5,'Custom accents and primary buttons retain contrast');
  check(ratio(p.text,p.surface)>=4.5&&ratio(p.textSecondary,p.surface)>=4.5&&ratio(p.textMuted,p.surface)>=4.5,'Main, secondary and helper text remain readable');
  check(ratio(p.danger,p.surface)>=4.5&&ratio(p.success,p.surface)>=4.5&&ratio(p.warning,p.surface)>=4.5,'Status colors remain readable');
 }
 assert.throws(()=>appearanceSettings('other','#123456'));checks++;
 for(const accent of ['red','#abc','#12345g','#12345678','123456','']){assert.throws(()=>appearanceSettings('light',accent));checks++;}
 check(appearanceSettings('dark',' #abcDEF ').accent==='#ABCDEF','Valid hex input normalizes safely');
 const store=new AppearanceStore(directory,protect),savedPath=path.join(directory,'appearance.json');
 check(store.load().mode==='system'&&store.load().accent===DEFAULT_ACCENT,'New installs follow system');
 fs.writeFileSync(path.join(directory,'settings.json'),'private-existing-settings');
 maxWrite=2;store.save({mode:'dark',accent:'#8b5cf6'});maxWrite=Infinity;
 check(store.load().mode==='dark'&&store.load().accent==='#8B5CF6','Partial writes persist complete settings');
 check((fs.statSync(savedPath).mode&0o777)===0o600&&descriptors.size===0,'Settings are private and descriptors closed');
 const saved=fs.readFileSync(savedPath,'utf8');
 for(const kind of ['write','sync','rename','protect','zero']){
  failWrite=kind==='write';failSync=kind==='sync';failRename=kind==='rename';failProtect=kind==='protect';maxWrite=kind==='zero'?0:Infinity;
  assert.throws(()=>store.save({mode:'light',accent:'#199A70'}));checks++;
  check(fs.readFileSync(savedPath,'utf8')===saved&&!fs.existsSync(savedPath+'.tmp')&&descriptors.size===0,'Failed saves preserve settings and release resources');
  failWrite=failSync=failRename=failProtect=false;maxWrite=Infinity;
 }
 check(fs.readFileSync(path.join(directory,'settings.json'),'utf8')==='private-existing-settings','Appearance saves preserve existing app settings');
 for(const raw of ['{','null','{}','{"mode":"other","accent":"#123456"}','{"mode":"light","accent":3}','x'.repeat(4097)]){
  fs.writeFileSync(savedPath,raw);assert.throws(()=>store.load());checks++;
 }
 const fallback=new AppearanceController(context,protect);check(fallback.loadError&&fallback.settings.mode==='system'&&appliedMode===-1,'Corrupt preferences fall back without blocking app startup');fallback.dispose();
 fs.unlinkSync(savedPath);const c=new AppearanceController(context,protect);
 check(storage.get('clashosTheme').dark===false&&appliedMode===-1,'System light mode initializes native and custom widgets');
 callback.onConfigurationUpdated({colorMode:0});check(storage.get('clashosTheme').dark===true,'System dark updates the shared observed palette');
 c.save('light','#199A70');check(!storage.get('clashosTheme').dark&&appliedMode===1,'Explicit light overrides system dark');
 callback.onConfigurationUpdated({colorMode:0});check(!storage.get('clashosTheme').dark,'System callbacks cannot override an explicit choice');
 c.save('dark','#D94C86');check(storage.get('clashosTheme').dark&&lastTokens.colors.brand===storage.get('clashosTheme').primary,'Native tokens follow the selected accent');
 systemDark=true;c.save('system','#8B5CF6');check(storage.get('clashosTheme').dark&&appliedMode===-1,'Returning to system observes a synchronous native callback');
 systemDark=false;callback.onConfigurationUpdated({colorMode:1});check(!storage.get('clashosTheme').dark,'Following system supports the reverse transition');
 const previous=storage.get('clashosTheme'),before=fs.readFileSync(savedPath,'utf8');
 failWrite=true;assert.throws(()=>c.save('dark','#199A70'));failWrite=false;checks++;
 check(storage.get('clashosTheme')===previous&&c.settings.mode==='system'&&fs.readFileSync(savedPath,'utf8')===before&&appliedMode===-1,'Disk failures roll back native mode, palette and persisted choice');
 failMode=true;assert.throws(()=>c.save('dark','#199A70'));failMode=false;checks++;
 check(storage.get('clashosTheme')===previous&&fs.readFileSync(savedPath,'utf8')===before,'Native mode failures do not write preferences');
 failTokens=true;assert.throws(()=>c.save('dark','#199A70'));failTokens=false;checks++;
 check(storage.get('clashosTheme')===previous&&fs.readFileSync(savedPath,'utf8')===before,'Native theme failures do not write preferences');
 failTokenAt=tokenCalls+2;assert.throws(()=>c.save('dark','#199A70'));failTokenAt=0;checks++;
 check(storage.get('clashosTheme')===previous&&fs.readFileSync(savedPath,'utf8')===before,'A late native token failure still occurs before committing settings');
 failPublishOnce=true;assert.throws(()=>c.save('dark','#199A70'));checks++;
 check(storage.get('clashosTheme')===previous&&fs.readFileSync(savedPath,'utf8')===before&&c.settings.mode==='system','A shared-palette publication failure cannot leave newly committed preferences behind');
 const {nativeStyles,parseNativeStyles,sameNativeStyles}=load('theme/NativeStyles.ets'),{sameAppearance}=load('theme/AppearanceTypes.ets');
 const styles=nativeStyles();styles.fontFamily=' Noto Serif ';styles.fontScale=1.3;styles.cardRadius=24;styles.contentGap=24;
 styles.light={canvas:'#edf2f8',chrome:'#f4f7fc',surface:'#FFFFFF',field:'#F2F5FA',text:'#FFFFFF',textSecondary:'#FFFFFF',textMuted:'#FFFFFF'};
 styles.dark={canvas:'#151B27',chrome:'#192233',surface:'#202C40',field:'#26334B',text:'#000000',textSecondary:'#000000',textMuted:'#000000'};
 for(const dark of [false,true]){
  const p=createPalette(dark,'#FFFF00',styles),backgrounds=[p.surface,p.field,p.chrome,p.canvas];
  check(['text','textSecondary','textMuted','success','warning','danger','purple','primary'].every(k=>backgrounds.every(bg=>ratio(p[k],bg)>=4.5)),'Custom backgrounds and deliberately unreadable foregrounds are corrected across actual page surfaces');
  check(ratio(p.onPrimary,p.primary)>=4.5&&ratio(p.primary,p.primarySoft)>=4.5,'Custom style buttons and selected-node surfaces retain contrast');
  check(p.font(20)===26&&p.radius(8)===24&&p.radius(20)===32&&p.contentGap===24&&p.fontFamily==='Noto Serif','Native typography, corner bounds and page margins derive from the same validated style');
 }
 for(const mutate of [x=>x.version=2,x=>x.fontScale='1.1',x=>x.fontScale=NaN,x=>x.fontScale=Infinity,x=>x.fontScale=.84,x=>x.fontScale=1.31,
  x=>x.cardRadius=-1,x=>x.cardRadius=25,x=>x.cardRadius=1.5,x=>x.contentGap=7,x=>x.contentGap=25,x=>x.fontFamily='bad\nfont',x=>x.fontFamily='x'.repeat(121),
  x=>x.light=null,x=>x.dark=[],x=>x.light={surface:'red'},x=>x.light={text:17},x=>x.light={unknown:'#FFFFFF'},x=>x.css='body{}']){
  const bad=JSON.parse(JSON.stringify(styles));mutate(bad);assert.throws(()=>nativeStyles(bad));checks++;
 }
 for(const text of ['null','[]','{}','bad JSON','x'.repeat(8193)]){assert.throws(()=>parseNativeStyles(text));checks++;}
 const reordered={dark:styles.dark,light:styles.light,contentGap:24,cardRadius:24,fontScale:1.3,fontFamily:'Noto Serif',version:1};
 check(sameNativeStyles(styles,reordered)&&sameNativeStyles(undefined,nativeStyles()),'Style equality normalizes field order, case and absent default settings');
 c.save('system','#8B5CF6',styles);const styledSettings=c.savedSettings(),styledBefore=fs.readFileSync(savedPath,'utf8');
 styles.fontScale=.85;check(c.settings.styles.fontScale===1.3&&styledSettings.styles.fontScale===1.3,'Saved styles are independent of mutable caller drafts');
 c.save('dark','#199A70');check(c.settings.styles.fontScale===1.3&&storage.get('clashosTheme').dark,'Mode/accent edits retain custom style preferences');
 c.save('system','#8B5CF6');check(!storage.get('clashosTheme').dark&&c.settings.styles.fontScale===1.3,'System callbacks retain the saved typography and both color palettes');
 const changed=JSON.parse(JSON.stringify(c.savedSettings()));changed.styles.fontScale=1;check(!sameAppearance(c.savedSettings(),changed),'Appearance ownership guards detect style-only changes');
 for(const kind of ['write','sync','rename','protect','publish']){
  const baseline=fs.readFileSync(savedPath,'utf8'),palette=storage.get('clashosTheme');
  failWrite=kind==='write';failSync=kind==='sync';failRename=kind==='rename';failProtect=kind==='protect';failPublishOnce=kind==='publish';
  assert.throws(()=>c.save('light','#D94C86',nativeStyles()));checks++;
  failWrite=failSync=failRename=failProtect=failPublishOnce=false;
  check(fs.readFileSync(savedPath,'utf8')===baseline&&storage.get('clashosTheme')===palette&&c.settings.styles.fontScale===1.3,'Failed style application preserves native/shared/file state: '+kind);
 }
 const impossible=nativeStyles();impossible.light={surface:'#000000',field:'#FFFFFF',canvas:'#444444',chrome:'#BBBBBB'};
 assert.throws(()=>c.save('light','#3478F6',impossible),/背景/);checks++;
 check(fs.readFileSync(savedPath,'utf8')===styledBefore,'Unreadable style combinations fail before committing any state');
 c.save('system','#8B5CF6',null);check(c.settings.styles===undefined&&storage.get('clashosTheme').fontScale===1,'Explicit reset removes custom styles while preserving mode/accent');
 const oldCallback=callback,beforeDispose=storage.get('clashosTheme');c.dispose();oldCallback.onConfigurationUpdated({colorMode:0});check(storage.get('clashosTheme')===beforeDispose&&offCount===2,'Disposed windows unregister and ignore late callbacks');
 assert.throws(()=>c.save('light','#123456'));checks++;
 const reopened=new AppearanceController(context,protect);check(reopened.settings.mode==='system'&&reopened.settings.accent==='#8B5CF6','Reopened app restores saved appearance');reopened.dispose();
 store.save({mode:'dark',accent:'#8B5CF6',styles:impossible});const badTheme=new AppearanceController(context,protect);
 check(badTheme.loadError&&badTheme.settings.mode==='system'&&badTheme.settings.styles===undefined,'Semantically unreadable persisted colors fall back without disabling appearance recovery');badTheme.dispose();
 store.save({mode:'dark',accent:'#8B5CF6'});const Ability=load('entryability/EntryAbility.ets').default,ability=new Ability();ability.context=context;
 ability.onCreate({},{});check(appliedMode===0,'Saved dark mode is applied before the native window and widgets are created');
 let loaded=false;ability.onWindowStageCreate({loadContent:(page,done)=>{assert.equal(page,'pages/Index');assert.equal(appliedMode,0);loaded=true;done({code:0});}});check(loaded,'Window content loads after the appearance bootstrap');
 check(descriptors.size===0,'All filesystem descriptors released');
 console.log(`Appearance scenarios passed: ${checks} (production palette/store/controller; native APIs shimmed, temporary filesystem real)`);
}finally{fs.rmSync(directory,{recursive:true,force:true});}})().catch(e=>{console.error(e);process.exitCode=1;});
