// Production desktop lifecycle and private persistence. Device checks exercise
// actual OS registration, mouse menus, hiding, forwarding and process lifetime.
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), vm = require('node:vm');
const assert = require('node:assert/strict'), ts = require('./test_env.cjs')();
const root = path.resolve(__dirname, '../entry/src/main/ets');
let checks = 0;
const check = (v, label) => { assert(v, label); checks++; };
const same = (a, b, label) => { assert.deepEqual(JSON.parse(JSON.stringify(a)), JSON.parse(JSON.stringify(b)), label); checks++; };
function evaluate(source, context = {}) {
  const module = {exports: {}};
  vm.runInNewContext(ts.transpileModule(source, {compilerOptions: {module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020}}).outputText,
    {module, exports: module.exports, console, ...context});
  return module.exports;
}
const desktopModule = evaluate(fs.readFileSync(path.join(root, 'service/DesktopController.ets'), 'utf8'));
const {DesktopController: Controller} = desktopModule;
const deferred = () => { let resolve; const promise = new Promise(r => resolve = r); return {promise, resolve}; };
const tick = () => new Promise(setImmediate);
class Host {
  preferences = {trayEnabled: true, closeToTray: true};
  calls = []; fail = ''; supportedValue = true; pause;
  supported() { return this.supportedValue; }
  load() { this.calls.push('load'); if (this.fail === 'load') throw Error('load failed'); return {...this.preferences}; }
  save(p) { this.calls.push('save'); if (this.fail === 'save') throw Error('save failed'); this.preferences = {...p}; }
  async call(name) { this.calls.push(name); if (this.pause?.name === name) await this.pause.wait.promise; if (this.fail === name) throw Error(name + ' failed'); }
  addTray() { return this.call('add'); } removeTray() { return this.call('remove'); }
  startResident() { return this.call('attach'); } stopResident() { return this.call('detach'); }
  hide() { return this.call('hide'); } show() { return this.call('show'); } terminate() { return this.call('terminate'); }
}
const instance = () => { const host = new Host(); let notifications = 0; const controller = new Controller(host, () => notifications++); return {host, controller, notifications: () => notifications}; };
async function run() {
  let {host: h, controller: c} = instance();
  await c.initialize(); same(h.calls, ['load','add','attach'], 'A ready tray owns an actual resident attachment');
  check(c.snapshot().ready && !c.snapshot().busy, 'Readiness is committed after attachment');
  const copy = c.snapshot(); copy.ready = false; check(c.snapshot().ready, 'Published state is a snapshot');
  c.setCloseHook(true); check(c.snapshot().closeHook, 'Window-hook availability is distinct from icon readiness');
  check(await c.windowClose(), 'Close is intercepted'); check(h.calls.at(-1) === 'hide' && c.snapshot().ready, 'Close-to-tray hides without removing residency');
  c.enqueue('mode-Global'); c.enqueue('mode-Global'); c.enqueue('network-check'); c.enqueue('file:///SECRET');
  await tick();
  check(c.takeAction() === 'mode-Global', 'Allowlisted actions retain FIFO order');
  check(!c.takeAction(), 'An active action serializes following actions');
  c.enqueue('mode-Global'); c.finishAction('unrelated'); check(!c.takeAction(), 'Stale completion cannot release another action');
  c.finishAction('mode-Global'); check(c.takeAction() === 'network-check', 'Active duplicates never reappear behind a modal');
  c.finishAction('network-check'); check(!c.takeAction(), 'Untrusted commands never enter the queue');
  c.enqueue('show'); check(!c.hasActions() && h.calls.at(-1) === 'show', 'Left-click shows the existing window without navigation');
  c.enqueue('exit'); await tick(); check(c.takeAction() === 'exit', 'Exit is requested separately from actual termination');
  for (let i = 0; i < 20; i++) c.enqueue('exit');
  c.finishAction('exit'); check(!c.hasActions(), 'Repeated exit clicks do not reopen a cancelled confirmation');
  c.setCloseToTray(false); same(h.preferences, {trayEnabled:true, closeToTray:false}, 'Close behavior persists independently');
  await c.windowClose(); await tick(); check(c.takeAction() === 'exit' && !h.calls.includes('terminate'), 'Exit behavior waits for explicit confirmation'); c.finishAction('exit');
  await c.setEnabled(false); check(!c.snapshot().ready && !h.preferences.trayEnabled, 'Disable commits both runtime and preference');
  check(h.calls.lastIndexOf('detach') < h.calls.lastIndexOf('remove'), 'Resident stops before its icon is removed');
  await assert.rejects(c.hide(), /尚未就绪/); checks++; check(h.calls.at(-1) === 'save', 'Unavailable tray cannot hide the only window');
  assert.throws(() => c.setCloseToTray(true), /先启用/); checks++;
  await c.setEnabled(true); check(c.snapshot().ready && h.preferences.trayEnabled, 'Disabled tray can be enabled again');
  const before = {...h.preferences}; h.fail = 'save'; await assert.rejects(c.setEnabled(false), /save/); checks++;
  same(h.preferences, before, 'Failed preference write retains previous settings'); check(c.snapshot().ready, 'Failed disable persistence restores attached tray');
  assert.throws(() => c.setCloseToTray(true), /save/); checks++; check(!c.snapshot().closeToTray, 'Failed close-policy write cannot alter current behavior');
  h.fail = ''; await c.setEnabled(false); h.fail = 'save'; await assert.rejects(c.setEnabled(true), /save/); checks++;
  check(!c.snapshot().ready && !h.preferences.trayEnabled, 'Failed enable persistence removes the new resident and icon');
  h.fail = ''; await c.setEnabled(true); h.fail = 'hide'; c.setCloseToTray(true); await c.windowClose(); await tick();
  check(c.snapshot().error.includes('保持打开') && c.takeAction() === 'exit', 'Failed minimization keeps window and offers confirmation'); c.finishAction('exit');
  h.fail = ''; h.calls = []; await c.exit(); same(h.calls, ['detach','remove','terminate'], 'Confirmed exit releases residency before terminating main ability');
  check(c.snapshot().exiting && !c.takeAction(), 'Termination cannot dispatch queued mutations');

  ({host:h, controller:c} = instance()); h.fail = 'attach'; await c.initialize();
  check(!c.snapshot().ready && c.snapshot().error.includes('attach') && h.calls.includes('remove'), 'Failed resident attachment rolls back the tray');
  ({host:h, controller:c} = instance()); h.supportedValue = false; await c.initialize();
  check(!c.snapshot().ready && !h.calls.includes('add') && c.snapshot().error.includes('不支持'), 'Unsupported systems do not claim background protection');
  ({host:h, controller:c} = instance()); h.fail = 'load'; await c.initialize();
  check(!c.snapshot().ready && !h.calls.includes('add'), 'Unreadable settings remain visible without overwriting persisted data');
  ({host:h, controller:c} = instance()); h.pause = {name:'attach', wait:deferred()}; const starting = c.initialize();
  await Promise.resolve(); await Promise.resolve(); check(c.snapshot().busy && !c.snapshot().ready, 'Readiness is false while attachment is pending');
  await assert.rejects(c.setEnabled(false), /正在切换/); checks++; await c.initialize();
  h.pause.wait.resolve(); await starting; check(h.calls.filter(x => x === 'add').length === 1 && c.snapshot().ready, 'Duplicate initialization cannot create duplicate residents');
  c.residentLost(); check(!c.snapshot().ready && c.snapshot().error.includes('驻留已结束'), 'Lost resident revokes close-to-tray readiness and surfaces an error');
  await c.windowClose(); await tick(); check(c.takeAction() === 'exit', 'Resident loss keeps later close on a confirmation path'); c.finishAction('exit');
  await c.setEnabled(true); h.fail = 'terminate'; await assert.rejects(c.exit(), /terminate/); checks++;
  check(!c.snapshot().exiting && c.snapshot().ready, 'Failed termination restores tray and usable main-window state');

  ({host:h, controller:c} = instance()); await c.initialize(); h.pause={name:'show',wait:deferred()};
  c.enqueue('system-proxy'); await tick();
  check(!c.takeAction(),'Opening Settings must wait for actual foreground readiness, not only a launch request');
  c.enqueue('system-proxy');check(h.calls.filter(x=>x==='show').length===1,'Repeated pending actions coalesce foreground requests');
  h.pause.wait.resolve();await tick();check(c.takeAction()==='system-proxy','Foreground completion releases the queued Settings action');c.finishAction('system-proxy');
  h.pause=undefined;h.fail='show';c.enqueue('network-check');await tick();
  check(!c.takeAction() && c.snapshot().error.includes('显示主窗口'),'Failed foreground launch keeps queued actions from mutating an invisible window');
  c.foreground();check(c.takeAction()==='network-check' && !c.snapshot().error,'Manual taskbar restoration releases the original queued action');c.finishAction('network-check');

  // Whole-preference replacement coordinates one persisted commit with actual
  // registration, guarded snapshots and rollback of partial platform changes.
  ({host:h, controller:c} = instance()); await c.initialize(); c.setCloseHook(true);
  const originalDesktop = c.backupPreferences(); originalDesktop.closeToTray = false;
  check(c.backupPreferences().closeToTray, 'Backup snapshots cannot mutate controller or stored preferences');
  h.calls = []; await c.replacePreferences({trayEnabled:false,closeToTray:false}, c.backupPreferences());
  same(h.preferences, {trayEnabled:false,closeToTray:false}, 'Restore commits both desktop fields together');
  check(!c.snapshot().ready && h.calls.filter(x=>x==='save').length===1, 'Disabling through restore detaches the resident and writes once');
  await c.replacePreferences({trayEnabled:true,closeToTray:true}, c.backupPreferences());
  check(c.snapshot().ready && c.snapshot().closeToTray, 'Restore immediately reattaches tray before enabling close behavior');
  h.calls = []; await c.replacePreferences({trayEnabled:true,closeToTray:false}, c.backupPreferences());
  check(!h.calls.some(x=>['add','remove','attach','detach'].includes(x)), 'Close-policy-only restore does not recreate a working tray');
  await assert.rejects(c.replacePreferences({trayEnabled:false,closeToTray:false},{trayEnabled:true,closeToTray:true}),/已变化/); checks++;
  h.fail='save'; await assert.rejects(c.replacePreferences({trayEnabled:false,closeToTray:true},c.backupPreferences()),/save/); checks++;
  check(c.snapshot().ready && h.preferences.trayEnabled && !h.preferences.closeToTray, 'Failed whole-preference write restores residency and both old settings');
  h.fail=''; await c.setEnabled(false); h.fail='attach';
  await assert.rejects(c.replacePreferences({trayEnabled:true,closeToTray:false},c.backupPreferences()),/attach/); checks++;
  check(!c.snapshot().ready && !h.preferences.trayEnabled, 'Failed attachment leaves disabled persisted preferences and no usable-tray claim');
  h.fail=''; h.supportedValue=false; h.calls=[];
  await assert.rejects(c.replacePreferences({trayEnabled:true,closeToTray:false},c.backupPreferences()),/不支持/); checks++;
  check(!h.calls.some(x=>['add','attach','save'].includes(x)), 'Unsupported-device restore rejects before platform or preference mutations');
  h.supportedValue=true; c.setCloseHook(false);
  await assert.rejects(c.replacePreferences({trayEnabled:true,closeToTray:true},c.backupPreferences()),/不支持关闭/); checks++;
  c.setCloseHook(true); h.pause={name:'attach',wait:deferred()};
  const replacing=c.replacePreferences({trayEnabled:true,closeToTray:true},c.backupPreferences()); await tick();
  check(c.snapshot().busy && !c.snapshot().ready, 'Backup restoration owns pending registration');
  assert.throws(()=>c.backupPreferences(),/正在切换/); checks++;
  await assert.rejects(c.setEnabled(true),/正在切换/); checks++;
  h.preferences={trayEnabled:false,closeToTray:true}; h.pause.wait.resolve();
  await assert.rejects(replacing,/已变化/); checks++;
  same(h.preferences,{trayEnabled:false,closeToTray:true},'A newer file change during registration is never overwritten');
  check(!c.snapshot().ready && !c.snapshot().busy,'Stale asynchronous restore removes its new resident');
  assert.throws(()=>c.backupPreferences(),/已变化/); checks++;
  for(const invalid of [null,[],{}, {trayEnabled:1,closeToTray:false},{trayEnabled:false,closeToTray:'true'}]) {
    assert.throws(()=>desktopModule.desktopPreferences(invalid)); checks++;
  }
  same(desktopModule.desktopPreferences({trayEnabled:false,closeToTray:true,privateExtra:'excluded'}),{trayEnabled:false,closeToTray:true},'Only two allowlisted booleans enter a desktop snapshot');
  ({host:h, controller:c} = instance()); await c.initialize(); c.setCloseHook(true); h.fail='remove';
  await assert.rejects(c.replacePreferences({trayEnabled:false,closeToTray:false},c.backupPreferences()),/未能撤回/); checks++;
  check(!c.snapshot().ready && !c.snapshot().busy && h.preferences.trayEnabled, 'Failed platform rollback reports uncertainty and cannot hide the main window');
  ({host:h, controller:c} = instance()); h.preferences={trayEnabled:false,closeToTray:false};await c.initialize();c.setCloseHook(true);
  h.pause={name:'attach',wait:deferred()};const losingHook=c.replacePreferences({trayEnabled:true,closeToTray:true},c.backupPreferences());await tick();
  c.setCloseHook(false);h.pause.wait.resolve();await assert.rejects(losingHook,/不支持关闭/);checks++;
  check(!c.snapshot().ready&&!h.preferences.trayEnabled&&!h.preferences.closeToTray,'A close hook lost during asynchronous registration rejects before persistence and removes the new resident');

  // Real private-file writes, deliberately short writes and failing fsync/rename.
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'clashos-desktop-tests-')); fs.chmodSync(work, 0o700);
  let failure = '', short = false;
  const io = {OpenMode:{CREATE:1,READ_WRITE:2,TRUNC:4},accessSync:fs.existsSync,statSync:fs.statSync,readTextSync:p => fs.readFileSync(p,'utf8'),
    openSync:p => ({fd:fs.openSync(p,'w',0o600)}), closeSync:f => fs.closeSync(typeof f==='number'?f:f.fd), unlinkSync:fs.unlinkSync,
    writeSync:(fd,buffer) => { if(failure==='write') return 0; const b=Buffer.from(buffer);return fs.writeSync(fd,b,0,short ? Math.min(3,b.length) : b.length); },
    fsyncSync:fd => {if(failure==='sync')throw Error('sync');fs.fsyncSync(fd);},renameSync:(a,b) => {if(failure==='rename')throw Error('rename');fs.renameSync(a,b);}};
  const Store = evaluate(fs.readFileSync(path.join(root,'service/DesktopStore.ets'),'utf8'), {Uint8Array, require:name => {
    if(name==='@kit.CoreFileKit')return {fileIo:io};if(name==='./TextCodec')return {utf8Bytes:s=>new Uint8Array(Buffer.from(s))};if(name==='./DesktopController')return desktopModule;throw Error(name);
  }}).DesktopStore;
  const store = new Store(work, fd => {if(failure==='protect')throw Error('protect');fs.fchmodSync(fd,0o600);});
  const file = path.join(work,'desktop.json');
  try {
    same(store.load(),{trayEnabled:true,closeToTray:true},'Fresh installation has explicit desktop defaults');
    check(!fs.existsSync(file),'Reading defaults does not create a preference file');
    short = true; store.save({trayEnabled:false,closeToTray:false});
    same(store.load(),{trayEnabled:false,closeToTray:false},'Short writes persist complete independent preferences');
    check((fs.statSync(file).mode & 0o777)===0o600,'Persisted settings remain private');
    const original = fs.readFileSync(file,'utf8');
    for(const point of ['protect','write','sync','rename']) {
      failure = point; assert.throws(()=>store.save({trayEnabled:true,closeToTray:true}));checks++;
      check(fs.readFileSync(file,'utf8')===original,point+' failure retains original preferences');
      check(!fs.existsSync(file+'.tmp'),point+' failure cleans its temporary file');
    }
    failure='';
    for(const text of ['null','{}','{"trayEnabled":"yes","closeToTray":true}','{"trayEnabled":true,"closeToTray":0}','x'.repeat(1025)]) {
      fs.writeFileSync(file,text);assert.throws(()=>store.load());checks++;
    }
  } finally { fs.rmSync(work,{recursive:true,force:true}); }

  // Exercise the actual page dispatch methods with retained modal/draft state.
  const page = fs.readFileSync(path.join(root,'pages/Index.ets'),'utf8');
  const {DialogActivity} = evaluate(fs.readFileSync(path.join(root,'service/DialogActivity.ets'),'utf8'));
  const gate = new DialogActivity(), desktop = instance().controller; await desktop.initialize();
  const source = page.slice(page.indexOf('  private onDesktopChanged()'),page.indexOf('  private async exitDesktop()'));
  const Page = evaluate('export class Page {\n'+source+'\n}', {desktopSession:desktop,dialogActivity:gate,setTimeout:()=>0}).Page;
  const p = new Page(), modes=[], dialogs=[];
  Object.assign(p,{pageActive:true,initializingCore:false,updatingProfiles:[],theme:{danger:'#f00'},reviewNextImport(){},changeMode:async m=>modes.push(m),
    showMessageDialog:o=>dialogs.push(o),exitDesktop(){},openSystemNetworkCheck:async callback=>{p.networkDismiss=callback;return true;}});
  const lease=gate.enter();desktop.enqueue('mode-Global');p.reviewQueuedActions();check(!modes.length,'Tray actions preserve an open editor and its draft');
  gate.leave(lease);await tick();p.reviewQueuedActions();await tick();same(modes,['Global'],'Idle page calls the existing real mode-change path');
  desktop.enqueue('exit');await tick();p.reviewQueuedActions();await tick();check(dialogs.length===1 && p.desktopModalPending,'Exit confirmation reserves dispatch before the component appears');
  desktop.enqueue('exit');p.reviewQueuedActions();check(dialogs.length===1,'Repeated tray exit preserves the active confirmation');
  dialogs[0].onDismiss();check(!p.desktopModalPending && !desktop.hasActions(),'Cancelling confirmation releases exactly its own action');
  desktop.enqueue('network-check');await tick();p.reviewQueuedActions();await tick();
  check(p.desktopModalPending,'Network dialog retains action ownership until actual disappearance');
  p.networkDismiss();check(!p.desktopModalPending,'Network disappearance resumes queued work');
  p.showMessageDialog=()=>{throw Error('public dialog failure');};
  desktop.enqueue('exit');await tick();p.reviewQueuedActions();await tick();
  check(!p.desktopModalPending && !desktop.takeAction() && p.notice==='public dialog failure','A failed dialog open releases its reservation and active action');
  console.log('PASS '+checks+' desktop lifecycle, private-file and actual page-dispatch assertions');
}
run().catch(error=>{console.error(error);process.exitCode=1;});
