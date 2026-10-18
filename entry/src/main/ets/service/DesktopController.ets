export interface DesktopPreferences {
  trayEnabled: boolean;
  closeToTray: boolean;
}

export function desktopPreferences(value: DesktopPreferences): DesktopPreferences {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
    typeof value.trayEnabled !== 'boolean' || typeof value.closeToTray !== 'boolean') throw new Error('窗口与托盘设置格式无效');
  return { trayEnabled: value.trayEnabled, closeToTray: value.closeToTray };
}

export function sameDesktopPreferences(a: DesktopPreferences, b: DesktopPreferences): boolean {
  return a.trayEnabled === b.trayEnabled && a.closeToTray === b.closeToTray;
}

export function desktopPreferencesSummary(value: DesktopPreferences): string {
  return `系统托盘${value.trayEnabled ? '开启' : '关闭'} · 关闭窗口${value.closeToTray ? '最小化到可用托盘' : '确认退出'}`;
}

export interface DesktopSnapshot extends DesktopPreferences {
  ready: boolean;
  busy: boolean;
  closeHook: boolean;
  error: string;
  exiting: boolean;
}

export interface DesktopHost {
  load(): DesktopPreferences;
  save(value: DesktopPreferences): void;
  supported(): boolean;
  addTray(): Promise<void>;
  removeTray(): Promise<void>;
  startResident(): Promise<void>;
  stopResident(): Promise<void>;
  hide(): Promise<void>;
  show(): Promise<void>;
  terminate(): Promise<void>;
}

export const DESKTOP_ACTIONS: string[] = ['show', 'mode-Rule', 'mode-Global', 'mode-Direct', 'system-proxy', 'network-check', 'exit'];

// Only a live tray plus its attached resident permits hiding the main window.
// Platform callbacks enqueue bounded, allowlisted actions; they never replace a
// live editor or call the controller of an unrelated external proxy process.
export class DesktopController {
  private preferences: DesktopPreferences = { trayEnabled: true, closeToTray: true };
  private ready: boolean = false;
  private busy: boolean = false;
  private closeHook: boolean = false;
  private error: string = '';
  private exiting: boolean = false;
  private actions: string[] = [];
  private activeAction: string = '';
  private showing: number = 0;
  private showFailed: boolean = false;
  private host: DesktopHost;
  private changed: () => void;

  constructor(host: DesktopHost, changed: () => void) { this.host = host; this.changed = changed; }
  snapshot(): DesktopSnapshot {
    return { trayEnabled: this.preferences.trayEnabled, closeToTray: this.preferences.closeToTray,
      ready: this.ready, busy: this.busy, closeHook: this.closeHook, error: this.error, exiting: this.exiting };
  }
  backupPreferences(): DesktopPreferences {
    if (this.busy || this.exiting) throw new Error('托盘正在切换，请稍后重试');
    const value: DesktopPreferences = desktopPreferences(this.host.load());
    if (!sameDesktopPreferences(value, this.preferences)) throw new Error('窗口与托盘设置已变化，请重新打开应用');
    return value;
  }
  setCloseHook(available: boolean): void { this.closeHook = available; this.changed(); }
  foreground(): void { if (this.showFailed) { this.showFailed = false; this.error = ''; this.publish(); } }
  private publish(): void { this.changed(); }
  private async add(): Promise<void> {
    if (!this.host.supported()) throw new Error('当前设备不支持 PC 系统托盘');
    await this.host.addTray();
    try { await this.host.startResident(); this.ready = true; }
    catch (error) { await this.host.removeTray(); throw error as Error; }
  }
  private async remove(): Promise<void> {
    await this.host.stopResident();
    this.ready = false;
    await this.host.removeTray();
  }
  async initialize(): Promise<void> {
    if (this.busy || this.exiting || this.ready) return;
    this.busy = true;
    try {
      this.preferences = this.host.load();
      if (this.preferences.trayEnabled) await this.add();
      this.error = '';
    } catch (error) { this.error = (error as Error).message || '无法启动系统托盘'; }
    finally { this.busy = false; this.publish(); }
  }
  async setEnabled(enabled: boolean): Promise<void> {
    if (this.busy || this.exiting) throw new Error('托盘正在切换，请稍后重试');
    if (enabled === this.preferences.trayEnabled && enabled === this.ready) return;
    this.busy = true; this.error = ''; this.publish();
    const previous: DesktopPreferences = { trayEnabled: this.preferences.trayEnabled, closeToTray: this.preferences.closeToTray };
    try {
      if (enabled) await this.add(); else await this.remove();
      const next: DesktopPreferences = { trayEnabled: enabled, closeToTray: previous.closeToTray };
      try { this.host.save(next); }
      catch (error) {
        if (enabled) await this.remove(); else if (previous.trayEnabled) await this.add();
        throw error as Error;
      }
      this.preferences = next;
    } catch (error) { this.error = (error as Error).message || '托盘切换失败'; throw new Error(this.error); }
    finally { this.busy = false; this.publish(); }
  }
  async replacePreferences(value: DesktopPreferences, expected: DesktopPreferences): Promise<void> {
    if (this.busy || this.exiting) throw new Error('托盘正在切换，请稍后重试');
    const next: DesktopPreferences = desktopPreferences(value);
    const previous: DesktopPreferences = this.backupPreferences();
    if (!sameDesktopPreferences(previous, desktopPreferences(expected)))
      throw new Error('窗口与托盘设置已变化，请重新预览备份');
    if (next.trayEnabled && !this.host.supported()) throw new Error('当前设备不支持 PC 系统托盘');
    if (next.trayEnabled && next.closeToTray && !this.closeHook) throw new Error('当前窗口不支持关闭到托盘');
    const wasReady: boolean = this.ready;
    let runtimeAttempted: boolean = false;
    this.busy = true; this.error = ''; this.publish();
    try {
      if (next.trayEnabled && !this.ready) { runtimeAttempted = true; await this.add(); }
      else if (!next.trayEnabled && this.ready) { runtimeAttempted = true; await this.remove(); }
      // OS registration can yield. Never overwrite preferences changed while it
      // was pending, even if the controller has not reloaded that file yet.
      if (!sameDesktopPreferences(previous, this.host.load())) throw new Error('窗口与托盘设置已变化，请重新预览备份');
      if (next.trayEnabled && next.closeToTray && !this.closeHook) throw new Error('当前窗口不支持关闭到托盘');
      this.host.save(next); this.preferences = next;
    } catch (error) {
      let rollbackFailed: boolean = false;
      if (runtimeAttempted) {
        try { await this.remove(); if (wasReady) await this.add(); }
        catch (_) { this.ready = false; rollbackFailed = true; }
      }
      this.error = `${(error as Error).message || '窗口与托盘设置恢复失败'}${rollbackFailed ? '；托盘状态未能撤回，窗口保持打开，请重新启用托盘' : ''}`;
      throw new Error(this.error);
    } finally { this.busy = false; this.publish(); }
  }
  setCloseToTray(value: boolean): void {
    if (this.busy || this.exiting) throw new Error('托盘正在切换，请稍后重试');
    if (value && (!this.ready || !this.closeHook)) throw new Error('请先启用可用的系统托盘');
    const next: DesktopPreferences = { trayEnabled: this.preferences.trayEnabled, closeToTray: value };
    this.host.save(next); this.preferences = next; this.error = ''; this.publish();
  }
  async hide(): Promise<void> {
    if (this.busy || !this.ready || this.exiting) throw new Error('系统托盘尚未就绪，窗口保持打开');
    await this.host.hide();
  }
  async windowClose(): Promise<boolean> {
    if (this.exiting) return false;
    if (this.ready && this.preferences.closeToTray && !this.busy) {
      try { await this.hide(); return true; }
      catch (_) { this.error = '无法最小化到托盘，窗口保持打开'; this.publish(); }
    }
    this.enqueue('exit');
    return true;
  }
  enqueue(action: string): void {
    if (this.exiting || DESKTOP_ACTIONS.indexOf(action) < 0) return;
    if (action !== 'show') {
      if (this.activeAction === action || this.actions.indexOf(action) >= 0 || this.actions.length >= 8) return;
      this.actions.push(action);
    }
    this.showing++;
    this.host.show().then(() => { this.foreground(); }).catch(() => {
      this.showFailed = true; this.error = '无法显示主窗口，请从任务栏打开 ClashOS';
    }).finally(() => { this.showing--; this.publish(); });
    this.publish();
  }
  takeAction(): string | undefined {
    if (this.exiting || this.activeAction || this.showing > 0 || this.showFailed) return undefined;
    const action: string | undefined = this.actions.shift();
    this.activeAction = action ?? ''; return action;
  }
  finishAction(action: string): void { if (this.activeAction === action) { this.activeAction = ''; this.publish(); } }
  hasActions(): boolean { return this.actions.length > 0; }
  async exit(): Promise<void> {
    if (this.exiting || this.busy) throw new Error('应用正在处理托盘操作，请稍后重试');
    this.exiting = true; this.publish();
    try { await this.remove(); await this.host.terminate(); this.actions = []; }
    catch (error) {
      this.exiting = false;
      try { if (this.preferences.trayEnabled && !this.ready) await this.add(); } catch (_) {}
      this.error = (error as Error).message || '退出失败，窗口保持打开';
      this.publish(); throw new Error(this.error);
    }
  }
  residentLost(): void {
    if (!this.ready || this.busy || this.exiting) return;
    this.ready = false; this.error = '托盘驻留已结束，请重新启用托盘';
    this.host.show().catch(() => {}); this.publish();
  }
}
