import { vpnExtension } from '@kit.NetworkKit';
import { VpnStateStore } from './VpnStateStore';
import { VpnState, VpnStartOptions } from './CoreSessionTypes';
import { VpnSessionHost } from './CoreSessionCoordinator';

export class VpnTunnelService implements VpnSessionHost {
  private store: VpnStateStore;
  private bundleName: string;

  constructor(filesDir: string, bundleName: string) {
    this.store = new VpnStateStore(filesDir);
    this.bundleName = bundleName;
  }

  status(): VpnState {
    const state: VpnState = this.store.read();
    const limit: number = state.state === 'running' ? 12000 : 60000;
    if (['running', 'starting', 'updating', 'stopping'].indexOf(state.state) >= 0 && Date.now() - state.updatedAt > limit) {
      return { state: 'error', error: 'VPN 进程没有响应，请重新开启 TUN', port: state.port,
        updatedAt: state.updatedAt, session: state.session, core: state.core };
    }
    return state;
  }

  private async systemCall(operation: Promise<void>, timeout: number, message: string): Promise<void> {
    let complete: boolean = false;
    let failure: string = '';
    operation.then(() => complete = true, (error: Error) => { failure = error?.message || '系统 VPN 调用失败'; complete = true; });
    await Promise.resolve();
    const until: number = Date.now() + timeout;
    while (!complete && Date.now() < until) await new Promise<void>((resolve: () => void) => setTimeout(resolve, 250));
    if (!complete) throw new Error(message);
    if (failure.length > 0) throw new Error(failure);
  }

  async start(options: VpnStartOptions): Promise<void> {
    if (!Number.isInteger(options.controllerPort) || options.controllerPort < 1 || options.controllerPort > 65535 ||
      ['Rule', 'Global', 'Direct'].indexOf(options.mode) < 0) throw new Error('内核启动参数无效');
    await this.stop();
    const session: string = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    this.store.requestStart(options, session);
    try {
      await this.systemCall(vpnExtension.startVpnExtensionAbility({ bundleName: this.bundleName, abilityName: 'ClahsosVpnAbility',
        parameters: { configPath: options.configPath, coreMode: options.mode, controllerPort: options.controllerPort, session } }),
        30000, '系统 VPN 启动调用超时，请确认 VPN 授权窗口或模拟器的 VPN 支持');
      for (let count: number = 0; count < 60; count++) {
        const state: VpnState = this.store.read();
        if (state.session === session && state.state === 'running' && state.core.running) return;
        if (state.session === session && state.state === 'error') throw new Error(state.error);
        await new Promise<void>((resolve: () => void) => setTimeout(resolve, 500));
      }
      throw new Error('VPN 启动超时，请检查系统 VPN 授权');
    } catch (error) {
      this.store.clearStart(session);
      try { await this.stop(); } catch (_) { }
      throw new Error((error as Error).message || 'VPN 启动失败');
    }
  }

  async stop(): Promise<void> {
    const previous: VpnState = this.store.read();
    this.store.clearStart();
    if (previous.session.length === 0) return;
    if (previous.session.length > 0 && (previous.core.running ||
      ['starting', 'running', 'updating', 'stopping'].indexOf(previous.state) >= 0) &&
      Date.now() - previous.updatedAt < 60000) {
      this.store.requestStop(previous.session);
      let stopped: boolean = false;
      for (let count: number = 0; count < 40; count++) {
        const state: VpnState = this.store.read();
        if (state.session !== previous.session && state.session.length > 0) throw new Error('VPN 会话已改变，请刷新后重试');
        if (state.session === previous.session && !state.core.running && ['stopped', 'error'].indexOf(state.state) >= 0) {
          stopped = true;
          break;
        }
        await new Promise<void>((resolve: () => void) => setTimeout(resolve, 500));
      }
      if (!stopped) throw new Error('后台内核未确认停止，请稍后重试');
    }
    try {
      await this.systemCall(vpnExtension.stopVpnExtensionAbility({ bundleName: this.bundleName, abilityName: 'ClahsosVpnAbility' }),
        5000, '系统 VPN 停止调用超时');
    } catch (error) {
      const state: VpnState = this.status();
      if (state.core.running && state.state !== 'error') throw new Error((error as Error).message || 'VPN 停止失败');
    }
  }
}
