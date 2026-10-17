// Production ProfileStore + real native parser + independent serialized caches.
// Only Harmony filesystem/picker/network APIs are adapted for the host.
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), vm = require('node:vm');
const {spawnSync} = require('node:child_process'), assert = require('node:assert/strict');
const ts = require('./test_env.cjs')(), fixture = require('./provider_cache_fixture.cjs');
const native = process.env.CLASHOS_NATIVE_TESTS;
if (!native || !fs.existsSync(native)) throw Error('Set CLASHOS_NATIVE_TESTS to the compiled native_tests executable');
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'clashos-profile-cache-'));
let filesRoot = directory, checks = 0, afterValidate, responseBody = '', failCacheWrite = false;
const descriptors = new Map(), modules = new Map();
const check = (value, label) => {assert(value, label); checks++;};
const command = (kind, source, context = '', rules = '', objects = '', merges = '', profile = '') => {
  const request = path.join(directory, 'request.json');
  fs.writeFileSync(request, JSON.stringify({files: filesRoot, kind, source, context, rules, objects, merges, profile}), {mode: 0o600});
  const result = spawnSync(native, ['profile-cache-request', request], {encoding: 'utf8', timeout: 10000, maxBuffer: 4 * 1024 * 1024});
  assert.equal(result.status, 0, result.stderr); const value = JSON.parse(result.stdout);
  if (value.error) throw Error(value.error); if (afterValidate) afterValidate(); return value;
};
class Native {
  protectFile(fd) {fs.fchmodSync(fd, 0o600);}
  validate(source, context) {command('validate', source, context);}
  ruleEditor(source, rules, render, objects, merges, context) {return command('rules', source, context, rules, objects, merges);}
  objectEditor(source, objects, rules, validate, merges, context) {return command('objects', source, context, rules, objects, merges);}
  previewExtensions(source, rules, objects, merges, context) {try {return {...this.ruleEditor(source, rules, true, objects, merges, context), logs: []};} catch (e) {return {error: e.message, content: '', logs: []};}}
}
const fileIo = {
  OpenMode: {READ_ONLY: 0, CREATE: 64, READ_WRITE: 2, TRUNC: 512},
  openSync(name, flags) {const fd = fs.openSync(name, flags & 64 ? 'w+' : 'r'); descriptors.set(fd, name); return {fd};},
  closeSync(file) {const fd = typeof file === 'number' ? file : file.fd; fs.closeSync(fd); descriptors.delete(fd);},
  readSync(fd, buffer) {return fs.readSync(fd, new Uint8Array(buffer));},
  writeSync(fd, buffer) {if (failCacheWrite && descriptors.get(fd).includes('.provider-')) throw Error('Injected cache write failure'); return fs.writeSync(fd, Buffer.from(buffer));},
  statSync(value) {return typeof value === 'number' ? fs.fstatSync(value) : fs.statSync(value);},
  accessSync: fs.existsSync, mkdirSync: (p, recursive) => fs.mkdirSync(p, {recursive}),
  listFileSync: fs.readdirSync, readTextSync: p => fs.readFileSync(p, 'utf8'),
  fsyncSync: fs.fsyncSync, renameSync: fs.renameSync, unlinkSync: fs.unlinkSync
};
const util = {
  TextEncoder: class {encodeInto(text) {return new TextEncoder().encode(text);}},
  TextDecoder: {create: (encoding, options) => {const d = new TextDecoder(encoding, options); return {decodeToString: (b, o) => d.decode(b, o)};}},
  Base64Helper: class {encodeToStringSync(bytes) {return Buffer.from(bytes).toString('base64');} decodeSync(text) {return Uint8Array.from(Buffer.from(text, 'base64'));}},
  generateRandomUUID: () => require('node:crypto').randomUUID()
};
function load(name) {
  if (name === '@kit.AbilityKit') return {};
  if (name === '@kit.CoreFileKit') return {fileIo, picker: {}, fileUri: {}};
  if (name === '@kit.ArkTS') return {util};
  if (name === '@kit.NetworkKit') return {http: {RequestMethod: {GET: 'GET'}, HttpDataType: {STRING: 0}, createHttp: () => ({request: async () => ({responseCode: 200, result: responseBody}), destroy() {}})}};
  if (name === './ClashNativeCore') return {ClashNativeCore: Native};
  if (name === './NativeStyles') return load('../theme/NativeStyles');
  if (modules.has(name)) return modules.get(name);
  const file = path.resolve(__dirname, '../entry/src/main/ets/service', name + '.ets'), m = {exports: {}};
  const code = ts.transpileModule(fs.readFileSync(file, 'utf8'), {compilerOptions: {module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020}}).outputText;
  vm.runInNewContext(code, {require: load, module: m, exports: m.exports, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, Date, Number, JSON, Error, Set}, {filename: file});
  modules.set(name, m.exports); return m.exports;
}
(async () => {
  try {
    const {ProfileStore} = load('./ProfileStore'), store = new ProfileStore({filesDir: directory});
    let profile = store.create('Public cached refs', fixture.source, 'https://example.invalid/subscription');
    const cache = fixture.seed(profile.path), originalCache = fs.readFileSync(profile.path + cache.suffix);
    const draft = fixture.source.replace('proxies: [DIRECT]', 'proxies: ["' + fixture.node + '"]').replace('MATCH,Cached Route', 'MATCH,Manual Pick');
    assert.throws(() => store.checkDraft('New cacheless profile', draft), /Unknown proxy/); checks++;
    store.checkDraft(profile.name, draft, profile, fixture.source);
    check(store.read(profile) === fixture.source, 'Draft validation uses the saved cache without changing files');
    profile = store.save(profile, profile.name, draft, fixture.source);
    check(store.read(profile) === draft, 'Saving an explicit cached reference retains the exact document');
    const emptyRules = {version: 1, prepend: [], append: [], remove: []};
    const emptyObjects = {version: 1, proxies: {prepend: [], append: [], remove: []}, groups: {prepend: [], append: [], remove: []}};
    const rules = store.saveRuleEdits(profile, draft, '', emptyRules);
    const objects = store.saveObjectEdits(profile, draft, rules, '', emptyObjects);
    check(store.previewRules(draft, emptyRules, false, objects, '', store.providerCacheContext(profile)).policies.includes(fixture.node), 'Rule policy choices include the matching cached name');
    check(store.previewObjects(draft, emptyObjects, rules, true, '', store.providerCacheContext(profile)).choices.includes(fixture.node), 'Structured group/node choices use the same cache context');
    check(command('rules', store.effectiveContent(profile), store.providerCacheContext(profile)).policies.includes(fixture.node), 'Effective configuration export preserves the exact Unicode cached target after YAML serialization');
    const snapshot = store.mergeSnapshot(profile, false);
    check(command('rules', store.previewMerge(snapshot, 'log-level: debug\n'), store.providerCacheContext(profile)).policies.includes(fixture.node), 'YAML extension previews preserve cached references');
    store.saveMerge(snapshot, 'log-level: debug\n');
    const script = store.mergeSnapshot(profile, false, true);
    check(!store.previewScript(script, 'function main(config) { return config; }').error, 'Script previews validate the same owned cache');
    store.saveMerge(script, 'function main(config) { return config; }');
    profile = store.updateInfo(profile, 'Renamed public cached refs', profile.sourceUrl, 5);
    store.validateBackupGlobals(profile, store.backupGlobals());
    const copy = store.duplicate(profile);
    check(fs.readFileSync(copy.path + cache.suffix).equals(originalCache), 'Copy retains the exact cache used to validate its named references');
    check(command('load', '', '', '', '', '', copy.path).nodes === 2, 'A copied profile cold-loads its original native cached nodes');
    store.remove(copy);
    afterValidate = () => {afterValidate = undefined; fixture.seed(profile.path, 'proxies: [{name: Different, type: direct}]\n');};
    const racing = store.duplicate(profile);
    check(fs.readFileSync(racing.path + cache.suffix).equals(originalCache), 'A concurrent source-cache refresh cannot change the already-validated copy');
    store.remove(racing); fixture.seed(profile.path);
    const before = store.list().length;
    failCacheWrite = true; assert.throws(() => store.duplicate(profile)); checks++; failCacheWrite = false;
    check(store.list().length === before && !fs.readdirSync(path.dirname(profile.path)).some(n => n.endsWith('.tmp')), 'Failed copy removes the new profile and partial cache only');
    const archive = store.createBackup();
    fs.unlinkSync(profile.path + cache.suffix);
    check(store.inspectBackup(archive).rows.every(row => row.valid), 'Backup preview validates archived bytes after the live cache is removed');
    const foreign = JSON.parse(archive); foreign.profiles[0].content = foreign.profiles[0].content.replace('pool.yaml', 'foreign.yaml');
    check(!store.inspectBackup(JSON.stringify(foreign)).rows[0].valid, 'Backup preview rejects a resource belonging to another provider source');
    const restored = store.restoreBackup(archive, [0])[0];
    check(command('load', '', '', '', '', '', restored.path).nodes === 2, 'Restored profile cold-loads its own restored resources');
    check((fs.statSync(restored.path + cache.suffix).mode & 0o777) === 0o600, 'Restored cached credentials retain owner-only permissions');
    fixture.seed(profile.path); responseBody = draft + '# public subscription refresh\n';
    profile = await store.updateSubscription(profile);
    check(store.read(profile) === responseBody, 'Subscription validation and save both retain matching cached references');
    const fresh = path.join(directory, 'fresh'); fs.mkdirSync(fresh); filesRoot = fresh;
    const freshStore = new ProfileStore({filesDir: fresh});
    check(freshStore.inspectBackup(archive).rows[0].valid, 'A fresh installation previews a portable cached-reference archive');
    const migrated = freshStore.restoreBackup(archive, [0])[0];
    check(command('load', '', '', '', '', '', migrated.path).nodes === 2, 'A fresh installation starts with the restored cache without downloading its provider');
    check(descriptors.size === 0, 'Real store operations close every adapted filesystem descriptor');
    console.log('Provider cache/store integration scenarios passed: ' + checks + ' (production ArkTS + native parser + independent cache bytes)');
  } finally {fs.rmSync(directory, {recursive: true, force: true});}
})().catch(error => {console.error(error); process.exitCode = 1;});
