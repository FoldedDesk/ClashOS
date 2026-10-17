import { Want } from '@kit.AbilityKit';
import { VpnExtensionAbility, vpnExtension } from '@kit.NetworkKit';
import { fileIo } from '@kit.CoreFileKit';
import tunnel from 'libclahsos_tun.so';
import { VpnStateStore } from '../service/VpnStateStore';
import { ClashNativeCore } from '../service/ClashNativeCore';
import { CoreRuntime, emptyRuntime } from '../service/CoreSessionTypes';

interface NativeTunnelStatus { running: boolean; error: string; }

export default class ClahsosVpnAbility extends VpnExtensionAbility {
  private connection: vpnExtension.VpnConnection | undefined = undefined;
  private store: VpnStateStore | undefined = undefined;
  private core: ClashNativeCore = new ClashNativeCore();
  private ownsCore: boolean = false;
  private fd: number = -1;
  private port: number = 0;
  private timer: number = -1;
  private destroyed: boolean = false;
  private closing: boolean = false;
  private checking: boolean = false;
  private phase: string = 'starting';
  private session: string = '';
  private bundleName: string = '';
  private lastRuntime: CoreRuntime = emptyRuntime();
  private coreStarting: Promise<boolean> | undefined = undefined;
  private creation: Promise<number> | undefined = undefined;
  private starting: Promise<boolean> | undefined = undefined;
  private cleanupTask: Promise<void> | undefined = undefined;

  onCreate(want: Want): void {
    this.core.configureControllerStore(this.context.filesDir);
    this.store = new VpnStateStore(this.context.filesDir);
    // Before API 22 the first authorization launch does not forward Want.parameters.
    const request = this.store.readStart();
    const wantedSession: string = String(want.parameters?.session ?? '');
    if (request === undefined || (wantedSession.length > 0 && wantedSession !== request.session)) return;
    this.session = request.session;
    this.bundleName = want.bundleName ?? this.context.applicationInfo.name;
    const path: string = request.configPath;
    const mode: string = request.mode;
    const controller: number = request.controllerPort;
    if (!Number.isInteger(controller) || controller < 1 || controller > 65535 ||
      ['Rule', 'Global', 'Direct'].indexOf(mode) < 0) {
      this.writeState('error', '内核启动参数无效');
      return;
    }
    this.lastRuntime = { running: false, instance: '', configPath: path, mode,
      controllerPort: controller, httpPort: 0, socksPort: 0 };
    this.writeState('starting');
    this.timer = setInterval(() => this.tick(), 1000);
    this.startTunnel(path, mode, controller);
  }

  private writeState(state: string, error: string = ''): void {
    if (this.session.length === 0) return;
    const live: CoreRuntime = this.core.info();
    if (live.instance.length > 0) this.lastRuntime = live;
    this.phase = state;
    try {
      this.store?.write({ state, error, port: this.port, session: this.session,
        updatedAt: Date.now(), core: this.lastRuntime });
    } catch (_) { }
  }

  private async startTunnel(path: string, mode: string, controller: number): Promise<void> {
    try {
      this.coreStarting = this.core.startAsync(path, controller);
      if (!await this.coreStarting) throw new Error(this.core.info().error || '后台内核启动失败，请检查配置或端口占用');
      this.ownsCore = true;
      if (this.destroyed || this.closing) { await this.cleanup(); return; }
      this.core.setMode(mode);
      this.port = this.core.info().socksPort;
      if (this.port <= 0) throw new Error('当前配置未开启 SOCKS5 端口');
      this.connection = vpnExtension.createVpnConnection(this.context);
      const config: vpnExtension.VpnConfig = {
        addresses: [
          { address: { address: '198.18.0.1', family: 1 }, prefixLength: 24 },
          { address: { address: 'fdfe:dcba:9876::1', family: 2 }, prefixLength: 64 }
        ],
        routes: [
          { interface: '', destination: { address: { address: '0.0.0.0', family: 1 }, prefixLength: 0 },
            gateway: { address: '0.0.0.0', family: 1 }, hasGateway: false, isDefaultRoute: true },
          { interface: '', destination: { address: { address: '::', family: 2 }, prefixLength: 0 },
            gateway: { address: '::', family: 2 }, hasGateway: false, isDefaultRoute: true }
        ],
        dnsAddresses: ['198.18.0.2'], mtu: 1500, isIPv4Accepted: true, isIPv6Accepted: true,
        isBlocking: false, blockedApplications: [this.bundleName]
      };
      this.creation = this.connection.create(config);
      this.fd = await this.creation;
      if (this.destroyed || this.closing) { await this.cleanup(); return; }
      this.starting = tunnel.start(this.fd, this.port);
      if (!await this.starting) {
        const status: NativeTunnelStatus = JSON.parse(tunnel.status()) as NativeTunnelStatus;
        throw new Error(status.error || 'TUN 转发引擎启动失败');
      }
      if (this.destroyed || this.closing) { await this.cleanup(); return; }
      this.writeState('running');
    } catch (error) {
      await this.fail(`VPN 启动失败：${(error as Error).message}`);
    }
  }

  private async tick(): Promise<void> {
    if (this.checking || this.closing || this.destroyed) return;
    this.checking = true;
    try {
      if (this.store?.shouldStop(this.session)) {
        this.writeState('stopping');
        await this.cleanup();
        this.writeState('stopped');
        return;
      }
      if (this.phase !== 'running') { this.writeState(this.phase); return; }
      const core: CoreRuntime = this.core.info();
      if (!core.running) throw new Error('后台内核已停止');
      const status: NativeTunnelStatus = JSON.parse(tunnel.status()) as NativeTunnelStatus;
      if (!status.running) throw new Error(status.error || 'TUN 转发已停止');
      if (core.socksPort !== this.port) {
        if (core.socksPort <= 0) throw new Error('当前配置已关闭 SOCKS5 端口');
        this.writeState('updating');
        await tunnel.stop();
        if (this.destroyed || this.closing) return;
        this.port = core.socksPort;
        this.starting = tunnel.start(this.fd, this.port);
        if (!await this.starting) throw new Error('TUN 无法连接新的 SOCKS5 端口');
        if (this.destroyed || this.closing) return;
      }
      this.writeState('running');
    } catch (error) { await this.fail((error as Error).message); }
    finally { this.checking = false; }
  }

  private async fail(error: string): Promise<void> {
    try { await this.cleanup(); } catch (cleanupError) { error += `；停止失败：${(cleanupError as Error).message}`; }
    if (!this.destroyed) this.writeState('error', error);
  }

  private cleanup(): Promise<void> {
    if (this.cleanupTask === undefined) this.cleanupTask = this.cleanupOnce();
    return this.cleanupTask;
  }

  private async cleanupOnce(): Promise<void> {
    this.closing = true;
    if (this.timer >= 0) { clearInterval(this.timer); this.timer = -1; }
    try { await this.coreStarting; } catch (_) { }
    try { await this.creation; } catch (_) { }
    try { await this.starting; } catch (_) { }
    await tunnel.stop();
    if (this.connection !== undefined) {
      try { await this.connection.destroy(); } catch (_) { }
      this.connection = undefined;
    }
    if (this.fd >= 0) {
      try { fileIo.closeSync(this.fd); } catch (_) { }
      this.fd = -1;
    }
    if (this.ownsCore) {
      await this.core.stopAsync();
      this.ownsCore = false;
    }
  }

  onDestroy(): void {
    if (this.session.length === 0) return;
    this.destroyed = true;
    if (this.timer >= 0) { clearInterval(this.timer); this.timer = -1; }
    tunnel.stopSync();
    this.cleanup().then(() => this.writeState('stopped')).catch(() => {});
  }
}
