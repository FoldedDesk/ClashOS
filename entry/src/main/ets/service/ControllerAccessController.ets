import { ControllerAccessStore, ControllerAccessSnapshot } from './ControllerAccessStore';
import { CoreRuntime, VpnState } from './CoreSessionTypes';

export interface ControllerAccessHost { controllerSecret(): string; setControllerSecret(secret: string): void; }

export class ControllerAccessController {
  private store: ControllerAccessStore;
  private host: ControllerAccessHost;
  constructor(store: ControllerAccessStore, host: ControllerAccessHost) { this.store = store; this.host = host; }
  save(previous: ControllerAccessSnapshot, secret: string): void {
    const live: string = this.host.controllerSecret();
    const next: ControllerAccessSnapshot = this.store.replace(previous, secret);
    try { this.host.setControllerSecret(secret); }
    catch (_) {
      const problems: string[] = [];
      try { this.store.rollback(next, previous); } catch (_) { problems.push('保存文件未能撤回'); }
      try { this.host.setControllerSecret(live); } catch (_) { problems.push('内核运行密钥未能恢复'); }
      throw new Error(problems.length ? `认证未能应用：${problems.join('；')}` : '认证未能应用，原设置已保留');
    }
  }
}

export function localControllerCredential(endpoint: string, store: ControllerAccessStore,
  local: CoreRuntime, background?: VpnState): string | undefined {
  const active: CoreRuntime | undefined = local.running ? local : background && background.core.running &&
    ['starting', 'running', 'updating', 'stopping'].indexOf(background.state) >= 0 ? background.core : undefined;
  if (!active || (endpoint !== `http://127.0.0.1:${active.controllerPort}` && endpoint !== `http://localhost:${active.controllerPort}`)) return undefined;
  return store.credential();
}
