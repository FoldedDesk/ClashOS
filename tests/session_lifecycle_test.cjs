// Production ArkTS services/extension with two isolated native modules and mocked Harmony OS APIs.
// This checks ownership and failure handling; it does not verify the device VPN implementation.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const ts = require('./test_env.cjs')();
const root = path.resolve(__dirname, '../entry/src/main/ets');
const flush = async (count = 6) => { for (let i = 0; i < count; i++) await new Promise(setImmediate); };
function deferred() { let resolve; const promise = new Promise(r => resolve = r); return { promise, resolve }; }
function idle() { return { running: false, instance: '', configPath: '', mode: 'Rule', controllerPort: 9090, httpPort: 7890, socksPort: 7891 }; }

class Fixture {
  constructor() {
    this.directory = fs.mkdtempSync(path.join(os.tmpdir(), 'clahsos-session-'));
    this.now = Date.now(); this.timers = new Map(); this.nextTimer = 0; this.ports = new Map(); this.trace = [];
    this.profiles = new Map([['/profiles/a.yaml', [7890, 7891]], ['/profiles/b.yaml', [8890, 8891]]]);
    this.extension = null; this.background = null; this.nextUi = 0; this.sequence = 0;
    this.tun = { running: false, port: 0, starts: 0, stops: 0 };
    this.drivers = new Set(); this.nextDriver = 10000; this.destroyedDrivers = 0;
    this.context = { filesDir: this.directory, applicationInfo: { name: 'com.clash.harmony.pc' } };
    this.files = new Map(); this.nextFile = 20000;
    this.fileIo = {
      accessSync: name => fs.existsSync(name),
      statSync: name => fs.statSync(name),
      OpenMode: { CREATE: 1, READ_WRITE: 2, TRUNC: 4 },
      readTextSync: name => fs.readFileSync(name, 'utf8'),
      openSync: name => { const fd = this.nextFile++; this.files.set(fd, name); fs.writeFileSync(name, ''); return { fd }; },
      writeSync: (fd, value) => { const bytes=typeof value==='string'?value:Buffer.from(value);fs.writeFileSync(this.files.get(fd), bytes);return Buffer.byteLength(bytes); },
      fsyncSync: () => {},
      closeSync: value => { const fd = typeof value === 'number' ? value : value.fd; this.files.delete(fd); this.drivers.delete(fd); },
      renameSync: (from, to) => fs.renameSync(from, to),
      unlinkSync: name => fs.unlinkSync(name)
    };
  }

  native(name) {
    const host = { runtime: idle(), starts: 0, stops: 0, failStart: 0, failMode: false, startGate: null, stopGate: null };
    host.startAsync = async (configPath, controllerPort) => {
      this.trace.push(`${name}:start`); host.starts++;
      if (host.startGate) await host.startGate.promise;
      if (host.runtime.running) return true;
      if (host.failStart > 0) { host.failStart--; return false; }
      if (this.ports.has(controllerPort)) return false;
      this.ports.set(controllerPort, name);
      const ports = this.profiles.get(configPath) || [7890, 7891];
      host.runtime = { running: true, instance: `${name}-${++this.sequence}`, configPath, mode: 'Rule',
        controllerPort, httpPort: ports[0], socksPort: ports[1] };
      return true;
    };
    host.stopAsync = async () => {
      this.trace.push(`${name}:stop`); host.stops++;
      if (host.stopGate) await host.stopGate.promise;
      if (this.ports.get(host.runtime.controllerPort) === name) this.ports.delete(host.runtime.controllerPort);
      host.runtime.running = false;
      return true;
    };
    host.info = () => JSON.stringify(host.runtime);
    host.configureRuntimeDirectory = () => true;
    host.controllerToken = '';
    host.setControllerSecret = value => { host.controllerToken = value; return true; };
    host.controllerSecret = () => host.controllerToken;
    host.protectFile = () => true;
    host.setMode = mode => { if (host.failMode || !['Rule', 'Global', 'Direct'].includes(mode)) return false; host.runtime.mode = mode; return true; };
    host.validate = () => '';
    host.isRunning = () => host.runtime.running;
    return host;
  }

  loader(native) {
    const cache = new Map();
    const network = {
      VpnExtensionAbility: class { constructor() { this.context = network.context; } },
      context: this.context,
      vpnExtension: {
        startVpnExtensionAbility: async want => {
          this.lastWant = want;
          this.trace.push('vpn:start');
          if (this.hangStart) await new Promise(() => {});
          if (this.rejectWithoutError) throw undefined;
          if (this.authorizationGate) await this.authorizationGate.promise;
          if (this.denyAuthorization) throw new Error('User denied VPN authorization');
          this.background = this.native('background');
          this.background.startGate = this.backgroundStartGate || null;
          if (this.failBackgroundStart) this.background.failStart = 1;
          const load = this.loader(this.background);
          const Ability = load(path.join(root, 'vpnability/ClahsosVpnAbility.ets')).default;
          this.extension = new Ability(); this.extension.onCreate(this.dropParameters ? { bundleName: want.bundleName } : want);
        },
        stopVpnExtensionAbility: async () => {
          this.trace.push('vpn:stop');
          if (this.hangStop) await new Promise(() => {});
          if (this.extension) { const extension = this.extension; this.extension = null; extension.onDestroy(); }
        },
        createVpnConnection: () => ({
          create: async config => {
            assert.equal(this.ports.get(9090), 'background', 'VPN route is installed only after background core owns the controller');
            assert.deepEqual(Array.from(config.blockedApplications), ['com.clash.harmony.pc']);
            if (this.driverGate) await this.driverGate.promise;
            if (this.failDriver) throw new Error('VPN device unavailable');
            const fd = ++this.nextDriver; this.drivers.add(fd); return fd;
          },
          destroy: async () => { this.destroyedDrivers++; }
        })
      }
    };
    const tunnel = {
      start: async (fd, port) => {
        this.trace.push('tun:start'); this.tun.starts++;
        assert(this.drivers.has(fd)); assert(this.background.runtime.running);
        assert.equal(port, this.background.runtime.socksPort);
        if (this.failTunnel) { this.failTunnel = false; return false; }
        this.tun.running = true; this.tun.port = port; return true;
      },
      stop: async () => { this.tun.running = false; this.tun.stops++; return true; },
      stopSync: () => { this.tun.running = false; },
      status: () => JSON.stringify({ running: this.tun.running, error: '' })
    };
    const load = filename => {
      if (cache.has(filename)) return cache.get(filename).exports;
      const module = { exports: {} }; cache.set(filename, module);
      const code = ts.transpileModule(fs.readFileSync(filename, 'utf8'), { fileName: filename.replace(/\.ets$/, '.ts'),
        compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.CommonJS, esModuleInterop: true } }).outputText;
      const fixture = this;
      const context = {
        module, exports: module.exports, console,
        Date: class extends Date { static now() { return fixture.now; } },
        setInterval: callback => { const id = ++this.nextTimer; this.timers.set(id, callback); return id; },
        clearInterval: id => this.timers.delete(id),
        setTimeout: (callback, ms) => setImmediate(() => {
          this.now += ms;
          for (const tick of [...this.timers.values()]) Promise.resolve(tick()).catch(error => { this.timerError = error; });
          callback();
        }),
        require: request => {
          if (request === '@kit.NetworkKit') return network;
          if (request === '@kit.CoreFileKit') return { fileIo: this.fileIo };
          if (request === '@kit.ArkTS') return { util: { TextEncoder: class { encodeInto(text) { return new TextEncoder().encode(text); } } } };
          if (request === 'libclash_core.so') return native;
          if (request === 'libclahsos_tun.so') return tunnel;
          if (request.startsWith('.')) return load(path.resolve(path.dirname(filename), `${request}.ets`));
          throw new Error(`Unexpected module ${request}`);
        }
      };
      vm.runInNewContext(code, context, { filename });
      return module.exports;
    };
    return load;
  }

  ui() {
    const native = this.native(`ui${++this.nextUi}`);
    const load = this.loader(native);
    const Core = load(path.join(root, 'service/ClashNativeCore.ets')).ClashNativeCore;
    const Vpn = load(path.join(root, 'service/VpnTunnelService.ets')).VpnTunnelService;
    const Coordinator = load(path.join(root, 'service/CoreSessionCoordinator.ets')).CoreSessionCoordinator;
    const core = new Core(); core.configureControllerStore(this.directory); const vpn = new Vpn(this.directory, 'com.clash.harmony.pc');
    return { native, core, vpn, session: new Coordinator(core, vpn) };
  }
  state() { return JSON.parse(fs.readFileSync(path.join(this.directory, 'vpn-state.json'), 'utf8')); }
  async close() {
    this.authorizationGate?.resolve(); this.driverGate?.resolve(); this.backgroundStartGate?.resolve(); this.background?.stopGate?.resolve();
    this.extension?.onDestroy(); await flush(); this.timers.clear();
    assert.ifError(this.timerError); fs.rmSync(this.directory, { recursive: true, force: true });
  }
}

let scenarios = 0;
async function test(name, action) {
  const f = new Fixture();
  try { await action(f); assert.ifError(f.timerError); scenarios++; }
  catch (error) { console.error(`FAIL: ${name}`); throw error; }
  finally { await f.close(); }
}

(async () => {
  await test('first VPN start skips the nonexistent extension stop API', async f => {
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Rule'); await ui.session.enableTunnel();
    assert(!f.trace.includes('vpn:stop')); assert.equal(f.tun.running, true);
  });
  await test('first authorization without Want parameters restores the persisted request', async f => {
    f.dropParameters = true;
    const ui = f.ui(); await ui.session.initialize('/profiles/b.yaml', 'Global'); await ui.session.enableTunnel();
    assert.equal(f.background.runtime.configPath, '/profiles/b.yaml'); assert.equal(f.background.runtime.mode, 'Global');
    assert(f.state().session.length > 0); assert.equal(f.tun.running, true);
    await ui.session.disableTunnel(); assert(!fs.existsSync(path.join(f.directory, 'vpn-state.json.start')));
  });
  await test('unresolved system start API times out and restores the foreground proxy', async f => {
    f.hangStart = true;
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Global');
    await assert.rejects(ui.session.enableTunnel(), /启动调用超时/);
    assert.equal(ui.session.ownsLocalCore(), true); assert.equal(f.ports.get(9090), 'ui1');
    assert(!fs.existsSync(path.join(f.directory, 'vpn-state.json.start')));
  });
  await test('system rejection without an Error value is normalized and restores the foreground proxy', async f => {
    f.rejectWithoutError = true;
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Rule');
    await assert.rejects(ui.session.enableTunnel(), /系统 VPN 调用失败/);
    assert.equal(f.ports.get(9090), 'ui1'); assert.equal(ui.session.ownsLocalCore(), true);
  });
  await test('late authorization after a timeout cannot start a stale background core', async f => {
    f.authorizationGate = deferred(); f.dropParameters = true;
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Direct');
    await assert.rejects(ui.session.enableTunnel(), /启动调用超时/);
    f.authorizationGate.resolve(); await flush();
    assert.equal(f.background.starts, 0); assert.equal(f.tun.running, false); assert.equal(f.ports.get(9090), 'ui1');
  });
  await test('unresolved system stop API cannot hang after background cleanup is confirmed', async f => {
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Rule'); await ui.session.enableTunnel();
    f.hangStop = true; await ui.session.disableTunnel();
    assert.equal(f.tun.running, false); assert.equal(f.drivers.size, 0); assert.equal(f.ports.get(9090), 'ui1');
  });
  await test('handoff persists after window close and reopening attaches without another listener', async f => {
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Global');
    await ui.session.enableTunnel();
    assert.equal(f.ports.get(9090), 'background'); assert.equal(f.tun.running, true);
    assert.equal(f.state().core.mode, 'Global'); assert.equal(ui.session.ownsLocalCore(), false);
    assert(f.trace.indexOf('ui1:stop') < f.trace.indexOf('background:start'));
    await ui.session.dispose(); assert.equal(f.background.runtime.running, true); assert.equal(f.tun.running, true);
    const reopened = f.ui(); await reopened.session.initialize('/profiles/old.yaml', 'Direct');
    assert.equal(reopened.native.starts, 0); assert.equal(f.background.runtime.mode, 'Global');
    await reopened.session.dispose(); assert.equal(f.tun.running, true);
  });
  await test('disable reclaims latest profile and mode after background port reload', async f => {
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Global'); await ui.session.enableTunnel();
    f.background.runtime.configPath = '/profiles/b.yaml'; f.background.runtime.mode = 'Direct';
    f.background.runtime.httpPort = 8890; f.background.runtime.socksPort = 8891;
    await f.extension.tick(); assert.equal(f.tun.port, 8891); assert.equal(f.tun.starts, 2);
    await ui.session.disableTunnel(f.background.runtime);
    assert.equal(f.ports.get(9090), 'ui1'); assert.equal(f.tun.running, false); assert.equal(f.drivers.size, 0);
    assert.equal(ui.native.runtime.configPath, '/profiles/b.yaml'); assert.equal(ui.native.runtime.mode, 'Direct');
    assert.equal(ui.native.runtime.socksPort, 8891); assert.equal(ui.session.ownsLocalCore(), true);
  });
  await test('authorization denied restores local core before surfacing error', async f => {
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Global'); f.denyAuthorization = true;
    await assert.rejects(ui.session.enableTunnel(), /denied/);
    assert.equal(f.ports.get(9090), 'ui1'); assert.equal(ui.native.runtime.mode, 'Global');
    assert.equal(ui.session.ownsLocalCore(), true); assert.equal(f.drivers.size, 0);
  });
  await test('background bind failure rolls back without installing routes', async f => {
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Direct'); f.failBackgroundStart = true;
    await assert.rejects(ui.session.enableTunnel(), /后台内核启动失败/);
    assert.equal(f.ports.get(9090), 'ui1'); assert.equal(ui.native.runtime.mode, 'Direct'); assert.equal(f.drivers.size, 0);
  });
  await test('VPN device failure releases background listener then restores local core', async f => {
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Rule'); f.failDriver = true;
    await assert.rejects(ui.session.enableTunnel(), /device unavailable/);
    assert.equal(f.background.runtime.running, false); assert.equal(f.ports.get(9090), 'ui1'); assert.equal(f.tun.running, false);
  });
  await test('tunnel initialization failure releases device and native core', async f => {
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Rule'); f.failTunnel = true;
    await assert.rejects(ui.session.enableTunnel(), /转发引擎启动失败/);
    assert.equal(f.drivers.size, 0); assert(f.destroyedDrivers > 0); assert.equal(f.ports.get(9090), 'ui1');
  });
  await test('local rollback failure leaves no false ownership claim', async f => {
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Rule'); f.denyAuthorization = true; ui.native.failStart = 1;
    await assert.rejects(ui.session.enableTunnel(), /前台内核未能恢复/);
    assert.equal(ui.session.ownsLocalCore(), false); assert.equal(f.ports.size, 0);
  });
  await test('window closes during local startup', async f => {
    const ui = f.ui(); ui.native.startGate = deferred();
    const startup = ui.session.initialize('/profiles/a.yaml', 'Rule'); await flush();
    await ui.session.dispose(); ui.native.startGate.resolve(); await startup;
    assert.equal(ui.native.runtime.running, false); assert.equal(f.ports.size, 0);
  });
  await test('window closes before local listener is released during handoff', async f => {
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Rule'); ui.native.stopGate = deferred();
    const transfer = ui.session.enableTunnel(); await flush(); await ui.session.dispose();
    ui.native.stopGate.resolve(); await transfer; assert.equal(f.extension, null); assert.equal(f.ports.size, 0);
  });
  await test('window closes after VPN launch is requested', async f => {
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Rule'); f.authorizationGate = deferred();
    const transfer = ui.session.enableTunnel(); await flush(); await ui.session.dispose();
    f.authorizationGate.resolve(); await transfer; assert.equal(f.ports.get(9090), 'background'); assert.equal(f.tun.running, true);
  });
  await test('duplicate actions are rejected during handoff', async f => {
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Rule'); f.authorizationGate = deferred();
    const transfer = ui.session.enableTunnel(); await flush();
    await assert.rejects(ui.session.enableTunnel(), /正在切换/);
    await assert.rejects(ui.session.disableTunnel(), /正在切换/);
    f.authorizationGate.resolve(); await transfer; assert.equal(f.background.starts, 1);
  });
  await test('foreground does not restart until background stop has completed', async f => {
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Rule'); await ui.session.enableTunnel();
    f.background.stopGate = deferred(); const stop = ui.session.disableTunnel(); await flush();
    assert.equal(ui.native.starts, 1); assert.equal(f.ports.get(9090), 'background');
    assert.equal(f.state().state, 'stopping'); f.background.stopGate.resolve(); await stop;
    assert.equal(ui.native.starts, 2); assert.equal(f.ports.get(9090), 'ui1');
  });
  await test('window closes while background is stopping, without restarting UI core', async f => {
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Rule'); await ui.session.enableTunnel();
    f.background.stopGate = deferred(); const stop = ui.session.disableTunnel(); await flush(); await ui.session.dispose();
    f.background.stopGate.resolve(); await stop; assert.equal(f.ports.size, 0); assert.equal(ui.native.starts, 1);
  });
  await test('stale commands from an earlier session cannot stop a new VPN', async f => {
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Rule'); await ui.session.enableTunnel();
    const first = f.state().session; await ui.session.disableTunnel(); await ui.session.enableTunnel();
    assert.notEqual(f.state().session, first); await f.extension.tick(); assert.equal(f.state().state, 'running');
    assert.equal(f.tun.running, true); assert.equal(f.ports.get(9090), 'background');
  });
  await test('reopening during background startup never races for the controller', async f => {
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Global'); f.backgroundStartGate = deferred();
    const transfer = ui.session.enableTunnel(); await flush(); await ui.session.dispose();
    assert.equal(f.state().state, 'starting'); assert.equal(f.state().core.running, false);
    const reopened = f.ui(); await reopened.session.initialize('/profiles/old.yaml', 'Direct');
    assert.equal(reopened.native.starts, 0); f.backgroundStartGate.resolve(); await transfer;
    assert.equal(f.ports.get(9090), 'background'); assert.equal(f.background.runtime.mode, 'Global');
  });
  await test('reopening while service stops recovers latest runtime only after ports are released', async f => {
    const ui = f.ui(); await ui.session.initialize('/profiles/a.yaml', 'Global'); await ui.session.enableTunnel();
    f.background.runtime.configPath = '/profiles/b.yaml'; f.background.runtime.mode = 'Direct';
    f.background.runtime.socksPort = 8891; await f.extension.tick();
    f.background.stopGate = deferred(); const stop = ui.session.disableTunnel(); await flush(); await ui.session.dispose();
    const reopened = f.ui(); await reopened.session.initialize('/profiles/old.yaml', 'Rule');
    assert.equal(reopened.native.starts, 0);
    assert.equal(await reopened.session.recoverLocalIfStopped('/profiles/old.yaml', 'Rule'), false);
    f.background.stopGate.resolve(); await stop;
    assert.equal(await reopened.session.recoverLocalIfStopped('/profiles/old.yaml', 'Rule'), true);
    assert.equal(reopened.native.runtime.configPath, '/profiles/b.yaml'); assert.equal(reopened.native.runtime.mode, 'Direct');
    assert.equal(f.ports.get(9090), 'ui2');
  });
  await test('managed authentication survives foreground/VPN/reopened-window handoff without entering IPC state', async f => {
    const secret='public-lifecycle-auth';fs.writeFileSync(path.join(f.directory,'controller-access.json'),JSON.stringify({version:1,secret}));
    const ui=f.ui();await ui.session.initialize('/profiles/a.yaml','Rule');assert.equal(ui.native.controllerToken,secret);
    await ui.session.enableTunnel();assert.equal(f.background.controllerToken,secret);
    assert(!JSON.stringify(f.lastWant).includes(secret));assert(!JSON.stringify(f.state()).includes(secret));
    assert(!fs.readFileSync(path.join(f.directory,'vpn-state.json.start'),'utf8').includes(secret));
    await ui.session.dispose();const reopened=f.ui();await reopened.session.initialize('/profiles/a.yaml','Rule');
    assert.equal(reopened.native.starts,0);await reopened.session.disableTunnel();assert.equal(reopened.native.controllerToken,secret);
    assert.equal(f.ports.get(9090),'ui2');
  });
  await test('corrupt credentials fail closed before startup and recover after an explicit repair', async f => {
    const file=path.join(f.directory,'controller-access.json');fs.writeFileSync(file,'{broken');const ui=f.ui();
    await assert.rejects(ui.session.initialize('/profiles/a.yaml','Rule'),/认证设置无效/);
    assert.equal(ui.native.starts,0);assert.equal(f.ports.size,0);
    fs.writeFileSync(file,JSON.stringify({version:1,secret:'public-repaired-auth'}));
    assert.equal(await ui.session.recoverLocalIfStopped('/profiles/a.yaml','Rule'),true);
    assert.equal(ui.native.controllerToken,'public-repaired-auth');assert.equal(f.ports.get(9090),'ui1');
  });
  console.log(`Background lifecycle scenarios passed: ${scenarios} (Harmony OS APIs mocked; production services and VPN extension executed)`);
})().catch(error => { console.error(error); process.exitCode = 1; });
