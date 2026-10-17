import { CoreRuntime, VpnState, VpnStartOptions } from './CoreSessionTypes';

export interface CoreSessionHost {
  startAsync(path: string, port: number): Promise<boolean>;
  stopAsync(): Promise<void>;
  info(): CoreRuntime;
  setMode(mode: string): void;
}

export interface VpnSessionHost {
  status(): VpnState;
  start(options: VpnStartOptions): Promise<void>;
  stop(): Promise<void>;
}

export class CoreSessionCoordinator {
  private core: CoreSessionHost;
  private vpn: VpnSessionHost;
  private owned: boolean = false;
  private busy: boolean = false;
  private disposed: boolean = false;

  constructor(core: CoreSessionHost, vpn: VpnSessionHost) { this.core = core; this.vpn = vpn; }

  ownsLocalCore(): boolean { return this.owned; }

  private begin(): void {
    if (this.disposed) throw new Error('窗口已关闭');
    if (this.busy) throw new Error('内核正在切换，请稍后重试');
    this.busy = true;
  }

  private async restore(path: string, mode: string, port: number): Promise<boolean> {
    if (this.disposed) return false;
    if (!await this.core.startAsync(path, port)) return false;
    this.owned = true;
    if (this.disposed) { await this.core.stopAsync(); this.owned = false; return false; }
    try { if (mode.length > 0) this.core.setMode(mode); }
    catch (error) {
      await this.core.stopAsync();
      this.owned = false;
      throw new Error((error as Error).message || '模式恢复失败');
    }
    return true;
  }

  async initialize(path: string, mode: string): Promise<void> {
    this.begin();
    try {
      const state: VpnState = this.vpn.status();
      if (['starting', 'updating', 'stopping'].indexOf(state.state) >= 0 ||
        (state.state === 'running' && state.core.running)) return;
      await this.restore(path, mode, 9090);
    } finally { this.busy = false; }
  }

  async recoverLocalIfStopped(path: string, mode: string): Promise<boolean> {
    if (this.disposed || this.busy || this.owned) return false;
    const state: VpnState = this.vpn.status();
    if (state.core.running || ['starting', 'running', 'updating', 'stopping'].indexOf(state.state) >= 0) return false;
    this.begin();
    try {
      return state.core.instance.length > 0 ?
        await this.restore(state.core.configPath, state.core.mode, state.core.controllerPort) : await this.restore(path, mode, 9090);
    } finally { this.busy = false; }
  }

  async enableTunnel(): Promise<void> {
    this.begin();
    try {
      const previous: CoreRuntime = this.core.info();
      if (!this.owned || !previous.running) throw new Error('请先连接由当前窗口启动的内置内核');
      if (previous.socksPort <= 0) throw new Error('当前内核未开启 SOCKS5 端口');
      await this.core.stopAsync();
      this.owned = false;
      if (this.disposed) return;
      try {
        await this.vpn.start({ configPath: previous.configPath, mode: previous.mode, controllerPort: previous.controllerPort });
      } catch (error) {
        await this.vpn.stop();
        if (!this.disposed && !await this.restore(previous.configPath, previous.mode, previous.controllerPort)) {
          throw new Error(`VPN 启动失败，前台内核未能恢复：${(error as Error).message}`);
        }
        throw new Error((error as Error).message || 'VPN 启动失败，已恢复前台内核');
      }
    } finally { this.busy = false; }
  }

  async disableTunnel(current?: CoreRuntime): Promise<void> {
    this.begin();
    try {
      const state: VpnState = this.vpn.status();
      const runtime: CoreRuntime = current ?? state.core;
      await this.vpn.stop();
      if (this.disposed || this.owned || runtime.instance.length === 0) return;
      if (!await this.restore(runtime.configPath, runtime.mode, runtime.controllerPort)) throw new Error('TUN 已关闭，前台内核未能启动');
    } finally { this.busy = false; }
  }

  async dispose(): Promise<void> {
    this.disposed = true;
    // A running VPN owns its core in the extension process and outlives the UI.
    if (!this.busy && this.owned) {
      await this.core.stopAsync();
      this.owned = false;
    }
  }
}
