// Production link parsing, process inbox, modal leases, ability lifecycle and
// page dispatch. Device tests separately exercise OS resolution and real forms.
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const assert = require('node:assert/strict'), ts = require('./test_env.cjs')();
const root = path.resolve(__dirname, '../entry/src/main/ets'), modules = new Map(), storage = new Map();
let checks = 0;
const check = (value, label) => { assert(value, label); checks++; };
const same = (a, b, label) => { assert.deepEqual(JSON.parse(JSON.stringify(a)), JSON.parse(JSON.stringify(b)), label); checks++; };
const AppStorage = {get: key => storage.get(key), setOrCreate: (key, value) => storage.set(key, value)};
function evaluate(source, context) {
  const module = {exports: {}};
  const code = ts.transpileModule(source, {compilerOptions: {module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020}}).outputText;
  vm.runInNewContext(code, {module, exports: module.exports, ...context}); return module.exports;
}
function load(file) {
  if (modules.has(file)) return modules.get(file);
  const result = evaluate(fs.readFileSync(file, 'utf8'), {AppStorage, console, require: name => {
    if (name === '@ohos.url') return {default: {URL}};
    if (name === '@kit.ArkTS') return {util: {}};
    if (name === '@kit.AbilityKit') return {UIAbility: class { context = {filesDir: '/public-fixture', getApplicationContext: () => ({setColorMode() {}})}; }, ConfigurationConstant: {ColorMode: {}}};
    if (name === '@kit.ArkUI') return {window: {WindowStageEventType: {ACTIVE: 1, SHOWN: 2}}};
    if (name === '../service/AppearanceStore') return {loadAppearance: () => ({mode: 'system'})};
    if (name.startsWith('.')) return load(path.resolve(path.dirname(file), name + '.ets'));
    throw Error('Unexpected import ' + name);
  }});
  modules.set(file, result); return result;
}
const imports = load(path.join(root, 'service/SubscriptionImport.ets'));
const {parseSubscriptionLink: parse, SubscriptionImportInbox: Inbox} = imports;
const {DialogActivity} = load(path.join(root, 'service/DialogActivity.ets'));
const target = 'https://example.invalid/subscription?token=PUBLIC%2Bvalue%26tail&flag=meta&literal=a+b#section';
const link = (name = '公开链接 😀', scheme = 'clash', url = target) => scheme + '://install-config?url=' + encodeURIComponent(url) + '&name=' + encodeURIComponent(name);
for (const scheme of ['clash', 'clashos', 'clash-verge', 'CLASHOS']) same(parse(link('公开链接 😀', scheme)), {id: 0, url: target, name: '公开链接 😀'}, 'Outer decoding preserves nested query, literal plus, percent escapes, Unicode and fragment');
check(parse('clash://install-config/?url=https%3A%2F%2Fexample.invalid').name === '', 'Optional path slash and absent name retain server naming');
check(parse('clash://install-config?name=public+title&url=https://example.invalid').name === 'public title', 'Form-style plus decoding applies only to the outer query');
check(parse(link('  User title  ')).name === 'User title', 'Explicit names are trimmed');
check(parse(link('')).name === '', 'Explicit empty name also allows server naming');
const invalid = ['', 'file:///private', 'https://install-config?url=https://example.invalid', 'clash://other?url=https://example.invalid',
  'clash://user@install-config?url=https://example.invalid', 'clash://install-config:80?url=https://example.invalid',
  'clash://install-config/path?url=https://example.invalid', 'clash://install-config?url=https://example.invalid#outer',
  'clash://install-config', 'clash://install-config?name=public', 'clash://install-config?url=',
  'clash://install-config?url=https://example.invalid&url=https://other.invalid',
  'clash://install-config?url=https://example.invalid&%75rl=https://other.invalid',
  'clash://install-config?url=https://example.invalid&name=a&name=b',
  'clash://install-config?url=https://example.invalid&flag=meta',
  'clash://install-config?url=https://example.invalid&name=%ff',
  'clash://install-config?url=https://example.invalid&name=%',
  'clash://install-config?url=https://example.invalid&name',
  link('x'.repeat(101)), link('a\nb'), link('a\u0000b'), link('public', 'clash', 'javascript:alert(1)'),
  link('public', 'clash', 'file:///private'), link('public', 'clash', 'https://'),
  link('public', 'clash', ' https://example.invalid'), link('public', 'clash', 'https://example.invalid/a b'),
  link('public', 'clash', 'https://example.invalid/\r\nSECRET'), link('public', 'clash', 'https://example.invalid/' + 'a'.repeat(8192)),
  'clash://install-config?url=https://example.invalid&name=' + 'a'.repeat(32768)];
for (const uri of invalid) { assert.throws(() => parse(uri), error => error.message === '订阅导入链接无效，请检查链接格式和 URL 编码'); checks++; }
const inbox = new Inbox();
check(!inbox.receive(''), 'An ordinary home launch queues nothing');
check(inbox.receive(link()), 'A valid link is queued without downloading');
check(!inbox.receive(link()), 'Pending repeated deliveries deduplicate');
const first = inbox.take(); first.url = 'edited-local-draft';
check(!inbox.receive(link()), 'Editing a returned draft does not alter active deduplication identity');
check(inbox.take() === undefined, 'An active review serializes subsequent links');
check(inbox.receive(link('second')), 'A different link queues behind the draft');
inbox.receive('clash://install-config?url=javascript:SECRET');
check(inbox.takeError() === '订阅导入链接无效，请检查链接格式和 URL 编码' && inbox.takeError() === '', 'Invalid input gives one sanitized message without dropping valid pending requests');
inbox.finish(first.id + 10); check(!inbox.take(), 'A stale dialog cannot finish another request');
inbox.finish(first.id); const second = inbox.take(); check(second.name === 'second', 'The next queued link retains its own name');
inbox.finish(second.id); check(inbox.receive(link()), 'Explicit reopening after cancellation/import is allowed');
const bounded = new Inbox();
for (let i = 0; i < 8; i++) bounded.receive(link('public ' + i));
check(bounded.receive(link('overflow')) && bounded.takeError().includes('过多'), 'The memory inbox is bounded and overflow is visible');
const ordered = [];
for (let i = 0; i < 8; i++) { const r = bounded.take(); ordered.push(r.name); bounded.finish(r.id); }
same(ordered, Array.from({length: 8}, (_, i) => 'public ' + i), 'Overflow does not replace older links and FIFO order survives');
check(!bounded.take(), 'A processed inbox retains no requests');
const gate = new DialogActivity(); let idle = 0; gate.onIdle = () => idle++;
const old = gate.enter(), newer = gate.enter(); gate.leave(old);
check(gate.busy() && idle === 0, 'An older closing dialog cannot release a newer modal');
gate.leave(old); check(gate.busy(), 'Duplicate lifecycle releases are idempotent');
gate.leave(newer); check(!gate.busy() && idle === 1, 'Only the last disappearing modal resumes queued work');
gate.leave(newer); check(idle === 1, 'Duplicate close notifications do not dispatch twice');

const Ability = load(path.join(root, 'entryability/EntryAbility.ets')).default, ability = new Ability();
ability.onCreate({uri: link('cold')}, {});
check(storage.get('clashosImportRevision') === 1 && imports.subscriptionImports.take().name === 'cold', 'Production onCreate retains a cold-start request before a page exists');
ability.onNewWant({uri: link('cold')}); check(storage.get('clashosImportRevision') === 1, 'Warm duplicate delivery does not create another revision or review');
ability.onNewWant({uri: link('warm')}); check(storage.get('clashosImportRevision') === 2, 'Production onNewWant queues a distinct warm request');
ability.onNewWant({}); check(storage.get('clashosImportRevision') === 2, 'Home reactivation leaves the inbox untouched');
ability.onNewWant({uri: 'javascript:SECRET'}); check(storage.get('clashosImportRevision') === 3 && !JSON.stringify([...storage]).includes('SECRET'), 'AppStorage receives revision numbers, never a raw URL or token');

const page = fs.readFileSync(path.join(root, 'pages/Index.ets'), 'utf8');
const dispatch = page.slice(page.indexOf('  private reviewNextImport()'), page.indexOf('  private showMessageDialog('));
const pageInbox = new Inbox(), pageGate = new DialogActivity();
const Page = evaluate('export class Page {\n' + dispatch + '\n}', {subscriptionImports: pageInbox, dialogActivity: pageGate}).Page;
const component = new Page(), opened = [];
Object.assign(component, {pageActive: true, initializingCore: true, profileStore: {}, openProfileInfo: (_profile, request) => opened.push(request)});
pageInbox.receive(link('queued'));
component.reviewNextImport(); check(!opened.length, 'Real page dispatch waits for core/profile initialization');
component.initializingCore = false; const lease = pageGate.enter(); component.reviewNextImport();
check(!opened.length, 'Real page dispatch leaves an existing editor alone');
pageGate.leave(lease); component.pageActive = false; component.reviewNextImport(); check(!opened.length, 'A destroyed page cannot open a dialog');
component.pageActive = true; component.reviewNextImport();
check(opened.length === 1 && opened[0].name === 'queued' && component.selectedTab === 4, 'Ready idle page opens the original request on the subscription tab');
component.reviewNextImport(); check(opened.length === 1, 'Repeated foreground notifications do not overwrite an active draft');
pageInbox.finish(opened[0].id); pageInbox.receive(link('open failure')); component.openProfileInfo = () => {throw Error('SECRET');}; component.reviewNextImport();
check(component.notice === '无法打开订阅导入窗口，请重新打开链接' && !pageInbox.take(), 'A failed open releases its request and does not expose callback details');

// Guard the whole page's modal integration, not just its subscription form.
for (const match of page.matchAll(/builder:\s*(\w+Dialog)\(/g)) {
  const name = match[1], file = ['ProfileEditorDialog', 'ProfileInfoDialog'].includes(name) ? 'ProfileDialogs' : name;
  const source = fs.readFileSync(path.join(root, 'components', file + '.ets'), 'utf8').split('export struct ' + name + ' {')[1].split('\n@CustomDialog')[0];
  check(source.includes('dialogActivity.enter()') && source.includes('dialogActivity.leave(this.dialogActivityId)'), name + ' participates in actual component lifecycle coordination');
}
check(!page.includes('this.getUIContext().showAlertDialog('), 'Confirmation and detail dialogs participate in the same queue coordination');
const manifest = JSON.parse(fs.readFileSync(path.join(root, '../module.json5'), 'utf8')).module.abilities.find(a => a.name === 'EntryAbility');
check(manifest.launchType === 'singleton', 'Cold and warm links target the same ability');
same(manifest.skills.find(s => s.actions.includes('ohos.want.action.viewData')).uris.map(u => u.scheme), ['clash', 'clashos', 'clash-verge'], 'OS registration matches the parser aliases');
console.log('Subscription import scenarios passed: ' + checks + ' (production parser/inbox/ability/page dispatch and modal integration)');
