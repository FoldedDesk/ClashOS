// Shipping subscription client/types/store, actual native validation, real files.
// The Harmony HTTP adapter records requests and injects responses/failures.
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), vm = require('node:vm');
const assert = require('node:assert/strict'), cp = require('node:child_process'), zlib = require('node:zlib');
const ts = require('./test_env.cjs')(), native = process.env.CLASHOS_NATIVE_TESTS;
if (!native || !fs.existsSync(native)) throw Error('Set CLASHOS_NATIVE_TESTS to the compiled native_tests executable');
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'clashos-subscription-')), modules = new Map(), descriptors = new Map();
let root = directory, checks = 0, destroyed = 0, requests = [], responder, failMetadata = false, failSource = false, coreAvailable = true;
const check = (value, label) => {assert(value, label); checks++;};
const same = (a, b, label) => {assert.deepEqual(JSON.parse(JSON.stringify(a)), JSON.parse(JSON.stringify(b)), label); checks++;};
const source = "mode: direct\nproxies: []\nproxy-groups: []\nrules: ['MATCH,DIRECT']\n";
const headers = {'Subscription-Userinfo': 'upload=1024; download=3072; total=8192; expire=2000000000',
  'Content-Disposition': "attachment; filename=backup.yaml; filename*=UTF-8''%E5%85%AC%E5%BC%80%20%F0%9F%98%80.yaml",
  'Profile-Update-Interval': '2', 'Profile-Web-Page-Url': 'https://example.invalid/account'};
const reply = (body = source, header = headers, responseCode = 200) => ({responseCode, result: body, header});
responder = async () => reply();
function nativeCall(command, data) {
  const file = path.join(directory, 'request.json'); fs.writeFileSync(file, typeof data === 'string' ? data : JSON.stringify(data), {mode: 0o600});
  return cp.execFileSync(native, [command, file], {encoding: 'utf8', timeout: 10000, maxBuffer: 16 * 1024 * 1024});
}
class Native {
  protectFile(fd) {fs.fchmodSync(fd, 0o600);}
  validate(content, context = '') {this.ruleEditor(content, '', false, '', '', context);}
  ruleEditor(content, rules = '', render = false, objects = '', merges = '', context = '') {
    const result = JSON.parse(nativeCall('profile-cache-request', {files: root, source: content, rules, objects, merges, context, kind: 'rules'}));
    if (result.error) throw Error(result.error); return result;
  }
  localHttpProxy() {if (!coreAvailable) throw Error('内置 HTTP 代理不可用'); return {host: '127.0.0.1', port: 18890, username: 'public-fixture', password: 'SYNTHETIC-PROXY-PASSWORD', exclusionList: []};}
  backupYaml(text) {return nativeCall('archive-yaml', text);}
  backupInflate(bytes, expected) {const result = zlib.inflateRawSync(bytes); assert.equal(result.length, expected); return result;}
}
const fileIo = {
  OpenMode: {READ_ONLY: 0, CREATE: 64, READ_WRITE: 2, TRUNC: 512},
  openSync(name, flags) {const fd = fs.openSync(name, flags & 64 ? 'w+' : 'r'); descriptors.set(fd, name); return {fd};},
  closeSync(file) {const fd = typeof file === 'number' ? file : file.fd; fs.closeSync(fd); descriptors.delete(fd);},
  readSync: (fd, buffer) => fs.readSync(fd, new Uint8Array(buffer)),
  writeSync(fd, buffer) {if (failSource && /\.yaml\.tmp$/.test(descriptors.get(fd))) throw Error('injected source write failure'); return fs.writeSync(fd, Buffer.from(buffer));},
  renameSync(from, to) {if (failMetadata && to.endsWith('.meta.json')) {failMetadata = false; throw Error('injected metadata rename failure');} fs.renameSync(from, to);},
  statSync: value => typeof value === 'number' ? fs.fstatSync(value) : fs.statSync(value), accessSync: fs.existsSync,
  mkdirSync: (p, recursive) => fs.mkdirSync(p, {recursive}), listFileSync: fs.readdirSync, readTextSync: p => fs.readFileSync(p, 'utf8'), fsyncSync: fs.fsyncSync, unlinkSync: fs.unlinkSync
};
const util = {TextEncoder: class {encodeInto(s) {return new TextEncoder().encode(s);}},
  TextDecoder: {create: (encoding, options) => {const d = new TextDecoder(encoding, options); return {decodeToString: (b, o) => d.decode(b, o)};}},
  Base64Helper: class {encodeToStringSync(b) {return Buffer.from(b).toString('base64');} decodeSync(s) {return Uint8Array.from(Buffer.from(s, 'base64'));}},
  generateRandomUUID: () => require('node:crypto').randomUUID()};
function load(file) {
  if (modules.has(file)) return modules.get(file);
  const m = {exports: {}}, code = ts.transpileModule(fs.readFileSync(file, 'utf8'), {compilerOptions: {module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020}}).outputText;
  function requireShim(name) {
    if (name === '@kit.CoreFileKit') return {fileIo, picker: {}, fileUri: {}};
    if (name === '@kit.ArkTS') return {util};
    if (name === '@ohos.url') return {default: {URL}};
    if (name === '@kit.NetworkKit') return {http: {RequestMethod: {GET: 'GET'}, HttpDataType: {STRING: 0}, createHttp: () => ({
      request: (url, options) => {requests.push({url, options}); return responder(url, options);}, destroy: () => {destroyed++;}
    })}};
    if (name === './ClashNativeCore') return {ClashNativeCore: Native};
    if (name.startsWith('.')) return load(path.resolve(path.dirname(file), name + '.ets'));
    if (name === '@kit.AbilityKit') return {};
    throw Error('Unexpected import ' + name);
  }
  vm.runInNewContext(code, {module: m, exports: m.exports, require: requireShim, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView, Date, Set, setTimeout, clearTimeout}, {filename: file});
  modules.set(file, m.exports); return m.exports;
}
const service = name => load(path.resolve(__dirname, '../entry/src/main/ets/service', name + '.ets'));
(async () => {
  try {
    const types = service('SubscriptionTypes'), {SubscriptionClient} = service('SubscriptionClient'), client = new SubscriptionClient();
    same(types.subscriptionOptions(), {userAgent: 'clashos/1.0', timeoutSeconds: 20, route: 'system'}, 'Legacy profiles retain system routing with explicit defaults');
    const info = types.subscriptionInfo(headers, 123456);
    same(info, {checkedAt: 123456, usage: {upload: 1024, download: 3072, total: 8192, expire: 2000000000}, home: 'https://example.invalid/account', suggestedName: '公开 😀', suggestedInterval: 120}, 'HTTP metadata uses bytes, epoch seconds, RFC5987 Unicode names and hour-to-minute conversion');
    const data = {options: types.subscriptionOptions(), followInterval: true, info};
    check(types.subscriptionTraffic(data) === '已用 4.00 KB / 8.00 KB', 'Quota display sums upstream/downstream with binary units');
    check(types.subscriptionExpiry(data, 0).startsWith('到期') && types.subscriptionExpiry(data, 3000000000000).endsWith('过期'), 'Expiry compares seconds against the local millisecond clock');
    check(types.subscriptionExpiry({...data, info: {checkedAt: 0, usage: {expire: 0}}}) === '', 'Zero expiry does not invent a plan lifetime');
    check(types.subscriptionInfo({'subscription-userinfo': 'upload=1; download=2', 'x-amz-meta-subscription-userinfo': 'upload=9'}).usage.upload === 1, 'Standard usage header wins over prefixed aliases');
    check(types.subscriptionInfo({'X-Obs-Meta-Subscription-Userinfo': 'download=7'}).usage.download === 7, 'Single object-storage metadata prefix is recognized');
    for (const value of ['upload=9007199254740992', 'expire=8640000000001', 'upload=1; upload=2', 'upload=9007199254740991; download=1', 'nonsense']) {
      check(types.subscriptionInfo({'subscription-userinfo': value}).usage === undefined, 'Malformed or overflowing quota does not fabricate account data');
    }
    for (const value of ['-1', '1.5', '169', 'NaN']) check(types.subscriptionInfo({'profile-update-interval': value}).suggestedInterval === undefined, 'Invalid update interval is not auto-enabled');
    check(types.subscriptionInfo({'profile-update-interval': '0'}).suggestedInterval === 0, 'Explicit server interval zero disables automatic updates');
    check(types.subscriptionInfo({'content-disposition': 'attachment; filename="../../public.yaml"'}).suggestedName === 'public', 'Suggested names cannot introduce file paths');
    check(types.subscriptionInfo({'content-disposition': "attachment; filename*=UTF-8''%ff; filename=fallback.yml"}).suggestedName === 'fallback', 'Malformed extended names retain a valid ASCII fallback');
    for (const home of ['javascript:alert(1)', 'file:///private', 'https://user:pass@example.invalid', 'https://example.invalid/\n']) check(!types.subscriptionInfo({'profile-web-page-url': home}).home, 'Malformed or credential-bearing homepage is never opened');
    for (const options of [{userAgent: 'A\r\nAuthorization: x', timeoutSeconds: 2, route: 'direct'}, {userAgent: 'x', timeoutSeconds: 0, route: 'direct'}, {userAgent: 'x', timeoutSeconds: 121, route: 'direct'}, {userAgent: 'x', timeoutSeconds: 2, route: 'unknown'}]) {assert.throws(() => types.subscriptionOptions(options)); checks++;}
    for (const target of ['file:///private', 'https://', 'https://example.invalid/a b', 'https://example.invalid/a\nb']) {await assert.rejects(() => client.download(target)); checks++;}
    const settings = {userAgent: 'clash-public-fixture/2', timeoutSeconds: 3, route: 'direct'};
    for (const route of ['direct', 'system', 'core']) {
      const result = await client.download('https://example.invalid/subscription', {...settings, route});
      check(result.content === source && result.info.usage.total === 8192, 'Validated response metadata accompanies unchanged source bytes');
      const request = requests.at(-1).options;
      check(request.header['User-Agent'] === settings.userAgent && request.usingCache === false && request.maxLimit === 8 * 1024 * 1024 && request.readTimeout === 3000, 'Per-subscription UA, timeout and fresh bounded downloads reach the SDK');
      check(route === 'core' ? request.usingProxy.port === 18890 && request.usingProxy.password === 'SYNTHETIC-PROXY-PASSWORD' : request.usingProxy === (route === 'system'), 'Proxy routing is explicit and uses actual private internal HTTP options');
      check(!JSON.stringify(request.header).includes('SYNTHETIC-PROXY-PASSWORD'), 'Local ingress credentials are not origin request headers');
    }
    let beforeRequests = requests.length; coreAvailable = false;
    await assert.rejects(() => client.download('https://example.invalid/subscription', {...settings, route: 'core'}), /内置 HTTP 代理/); checks++;
    check(requests.length === beforeRequests, 'Unavailable internal proxy fails without falling back to a different route'); coreAvailable = true;
    responder = async () => reply('SYNTHETIC-PRIVATE-BODY', {'secret': 'SYNTHETIC-PRIVATE-HEADER'}, 401);
    await assert.rejects(() => client.download('https://example.invalid/?token=SYNTHETIC-TOKEN', settings), e => e.message === '订阅服务器返回 HTTP 401'); checks++;
    responder = async () => {throw Object.assign(Error('SYNTHETIC-TOKEN SYNTHETIC-PRIVATE-HEADER'), {code: 2300007});};
    await assert.rejects(() => client.download('https://example.invalid/?token=SYNTHETIC-TOKEN', settings), e => e.message.includes('2300007') && !e.message.includes('SYNTHETIC')); checks++;
    responder = () => new Promise(() => {});
    await assert.rejects(() => client.download('https://example.invalid/timeout', {...settings, timeoutSeconds: 1}), /下载超时/); checks++;
    check(destroyed === requests.length + 1, 'Every SDK client is destroyed, including timeout and pre-request proxy failure');
    responder = async () => reply();
    const {ProfileStore} = service('ProfileStore'), store = new ProfileStore({filesDir: root});
    const nameStore = new ProfileStore({filesDir: path.join(root, 'name-context')});
    nameStore.replaceBackupGlobals(nameStore.backupGlobals(), {merge: '', script: "function main(c, name) { if (name === '公开 😀') c.proxies = [{name: 'From selected title', type: 'direct'}]; return c; }"});
    const dependent = "proxies: []\nrules: ['MATCH,From selected title']\n";
    responder = async () => reply(dependent);
    const named = await nameStore.importSubscription('', 'https://example.invalid/named', settings);
    check(named.name === '公开 😀' && nameStore.read(named) === dependent, 'Header naming is resolved before name-dependent extension validation, retaining the downloaded source');
    await assert.rejects(() => nameStore.importSubscription('Explicit user name', 'https://example.invalid/named', settings), /校验失败/); checks++;
    check(nameStore.list().length === 1, 'Explicit names keep their own script semantics and failed imports leave no extra profile');
    nameStore.remove(named); responder = async () => reply();
    let profile = await store.importSubscription('', 'https://example.invalid/subscription', settings);
    check(profile.name === '公开 😀' && profile.updateInterval === 120 && profile.subscription.followInterval && profile.subscription.info.usage.total === 8192, 'Import applies server naming/interval only when the user leaves them unspecified');
    check(store.read(profile) === source && (fs.statSync(profile.path).mode & 0o777) === 0o600, 'Import retains exact configuration bytes privately');
    const disk = () => fs.readdirSync(path.join(root, 'profiles')).sort().map(n => [n, fs.readFileSync(path.join(root, 'profiles', n)).toString('base64')]);
    let before = JSON.stringify(disk()); responder = async () => reply('NOT A CONFIG');
    await assert.rejects(() => store.updateSubscription(profile), /校验失败/); checks++;
    check(JSON.stringify(disk()) === before, 'Invalid downloaded content preserves source, metadata and selected node sidecars');
    responder = async () => reply(source + '# updated\n', {...headers, 'Profile-Update-Interval': '8'});
    profile = store.updateInfo(profile, 'User title', profile.sourceUrl, 0, settings);
    profile = await store.updateSubscription(profile);
    check(profile.name === 'User title' && profile.updateInterval === 0 && !profile.subscription.followInterval, 'Server filename and interval never override explicit user name or manual-off setting');
    profile = store.updateInfo(profile, profile.name, profile.sourceUrl, undefined, settings);
    check(profile.updateInterval === 480, 'Following server intervals adopts the last actual suggestion');
    responder = async () => reply(source, {}); profile = await store.updateSubscription(profile);
    check(profile.updateInterval === 0 && !profile.subscription.info.usage && !profile.subscription.info.home, 'Absent fresh metadata does not fabricate quota, homepage or an automatic update interval');
    responder = async () => reply(); profile = await store.updateSubscription(profile);
    const changed = store.updateInfo(profile, profile.name, 'https://different.invalid/subscription', undefined, settings);
    check(!changed.subscription.info && changed.updateInterval === 0, 'Changing subscription source clears the previous provider account information');
    profile = store.updateInfo(changed, profile.name, 'https://example.invalid/subscription', undefined, settings);
    profile = await store.updateSubscription(profile);
    for (const mutation of ['source', 'metadata', 'extension']) {
      let release; responder = () => new Promise(resolve => {release = resolve;});
      const pending = store.updateSubscription(profile); assert(release);
      if (mutation === 'source') profile = store.save(profile, profile.name, source + '# newer editor\n');
      else if (mutation === 'metadata') profile = store.setPinned(profile);
      else fs.writeFileSync(profile.path + '.merge.yaml', 'log-level: debug\n', {mode: 0o600});
      before = JSON.stringify(disk()); release(reply(source + '# stale response\n'));
      await assert.rejects(() => pending, /已变化/); checks++;
      check(JSON.stringify(disk()) === before, 'An asynchronous update preserves newer ' + mutation + ' state');
      if (mutation === 'extension') fs.unlinkSync(profile.path + '.merge.yaml');
    }
    responder = async () => reply(source + '# metadata failure\n'); before = JSON.stringify(disk()); failMetadata = true;
    await assert.rejects(() => store.updateSubscription(profile), /原配置已保留/); checks++;
    check(JSON.stringify(disk()) === before, 'Metadata rename failure rolls back newly downloaded source bytes and removes staging files');
    failSource = true; await assert.rejects(() => store.updateSubscription(profile)); checks++; failSource = false;
    check(JSON.stringify(disk()) === before, 'Source write failure preserves prior subscription metadata and all original files');
    failMetadata = true; assert.throws(() => store.save(profile, profile.name, source + '# editor save\n'), /原配置已保留/); checks++;
    check(JSON.stringify(disk()) === before, 'Manual configuration saves also preserve source/metadata consistency on failure');
    failMetadata = true; await assert.rejects(() => store.importSubscription('New invalid write', 'https://example.invalid/new', settings)); checks++;
    check(JSON.stringify(disk()) === before, 'Failed initial metadata writes leave no orphan subscription');
    let applications = 0; before = JSON.stringify(disk()); responder = async () => reply(source + '# candidate runtime\n');
    await assert.rejects(() => store.updateSubscription(profile, async updated => {
      applications++;
      if (applications === 1) {check(store.read(updated).endsWith('# candidate runtime\n'), 'Live apply sees the validated candidate file'); throw Error('Injected port bind failure');}
      check(JSON.stringify(disk()) === before, 'Recovery applies the exact previous source and metadata');
    }), /订阅未能应用，原配置已恢复/); checks++;
    check(applications === 2 && JSON.stringify(disk()) === before, 'A rejected runtime apply restores the prior persisted subscription and confirms its reapplication');
    applications = 0;
    await assert.rejects(() => store.updateSubscription(profile, async () => {applications++; throw Error('lost acknowledgement');}), /原文件已恢复，内核状态未能确认/); checks++;
    check(applications === 2 && JSON.stringify(disk()) === before, 'Lost recovery acknowledgement is reported without claiming a confirmed runtime');
    applications = 0;
    await assert.rejects(() => store.updateSubscription(profile, async updated => {
      applications++; store.save(updated, updated.name, source + '# newer concurrent edit\n'); throw Error('late apply failure');
    }), /已被其他操作修改/); checks++;
    check(applications === 1 && store.read(profile).endsWith('# newer concurrent edit\n'), 'An apply failure never rolls back a newer editor save');
    await assert.rejects(() => store.updateSubscription(profile, async () => {
      fs.writeFileSync(profile.path + '.merge.yaml', 'log-level: debug\n', {mode: 0o600}); throw Error('late extension race');
    }), /已被其他操作修改/); checks++;
    check(fs.readFileSync(profile.path + '.merge.yaml', 'utf8') === 'log-level: debug\n' && store.read(profile).endsWith('# candidate runtime\n'), 'Late extension edits prevent rollback of a source they may depend on');
    fs.unlinkSync(profile.path + '.merge.yaml');
    responder = async () => reply(); profile = await store.updateSubscription(profile);
    const archive = store.createBackup(), fresh = path.join(directory, 'fresh'); fs.mkdirSync(fresh); root = fresh;
    const freshStore = new ProfileStore({filesDir: fresh}), restored = freshStore.restoreBackup(archive, [0])[0];
    same(restored.subscription, profile.subscription, 'Native backups preserve request routing, quota, homepage and server-interval policy on a fresh installation');
    const invalidArchive = JSON.parse(archive); invalidArchive.profiles[0].subscription.options.userAgent = 'x\r\nInjected: y';
    assert.throws(() => freshStore.inspectBackup(JSON.stringify(invalidArchive))); checks++;
    const {BackupArchiveCodec} = service('BackupArchiveCodec'), codec = new BackupArchiveCodec(new Native());
    const {readZip, writeZip} = service('BackupZip'), bytes = codec.encode(JSON.parse(archive)), entries = readZip(bytes, new Native());
    same(JSON.parse(codec.decode(bytes)).profiles[0].subscription, profile.subscription, 'ZIP native sidecar preserves all subscription state losslessly');
    const converted = JSON.parse(codec.decode(writeZip(entries.filter(e => e.name !== 'clashos-backup.json')))).profiles[0].subscription;
    same(converted.options, profile.subscription.options, 'Desktop-compatible ZIP metadata preserves actual supported UA, timeout and routing flags without the sidecar');
    same(converted.info.usage, profile.subscription.info.usage, 'Desktop-compatible ZIP metadata retains account counters and expiry');
    check(converted.info.home === profile.subscription.info.home, 'Desktop-compatible ZIP metadata retains the subscription homepage');
    check(descriptors.size === 0 && !fs.readdirSync(path.join(root, 'profiles')).some(n => n.endsWith('.tmp')), 'Success and failure paths close every descriptor and remove staging files');
    console.log('Subscription scenarios passed: ' + checks + ' (production client/store/codec, actual native validation, real temporary files)');
  } finally {fs.rmSync(directory, {recursive: true, force: true});}
})().catch(e => {console.error(e); process.exitCode = 1;});
