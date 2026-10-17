import { common, contextConstant } from '@kit.AbilityKit';
import { statusBarManager } from '@kit.StatusBarExtensionKit';
import { emitter, BusinessError } from '@kit.BasicServicesKit';
import deviceInfo from '@ohos.deviceInfo';
import { image } from '@kit.ImageKit';
import { window } from '@kit.ArkUI';
import { DesktopController, DesktopHost, DesktopPreferences } from './DesktopController';
import { DesktopStore } from './DesktopStore';
import { ClashNativeCore } from './ClashNativeCore';

function platformError(error: Error, operation: string): Error {
  const code: number | undefined = (error as BusinessError).code;
  return new Error(`${operation}${typeof code === 'number' ? `（代码 ${code}）` : ''}`);
}

class DesktopPlatform implements DesktopHost {
  context?: common.UIAbilityContext;
  mainWindow?: window.Window;
  resident?: common.UIAbilityContext;
  private store?: DesktopStore;
  private added: boolean = false;
  private listeners: boolean = false;
  private pixels: image.PixelMap[] = [];
  private mode: string = '';
  private updateTimer: number = -1;
  private residentReady?: () => void;
  private foreground: boolean = false;
  private foregroundReady?: () => void;
  private showing?: Promise<void>;
  private iconClick = (event: emitter.EventData): void => {
    if (event.data?.['iconClickType'] === 'leftClick') desktopSession.enqueue('show');
  };
  private menuClick = (event: emitter.EventData): void => {
    const code: string | undefined = event.data?.['menuCode'] as string | undefined;
    if (typeof code === 'string') desktopSession.enqueue(code);
  };
  private close = (): Promise<boolean> => desktopSession.windowClose();

  bind(context: common.UIAbilityContext, mainWindow: window.Window): void {
    this.context = context; this.mainWindow = mainWindow;
    this.store = new DesktopStore(context.filesDir, (fd: number): void => new ClashNativeCore().protectFile(fd));
    try { mainWindow.on('windowWillClose', this.close); desktopSession.setCloseHook(true); }
    catch (_) { desktopSession.setCloseHook(false); }
  }
  detach(): void {
    try { this.mainWindow?.off('windowWillClose', this.close); } catch (_) {}
    this.mainWindow = undefined; this.foreground = false; desktopSession.setCloseHook(false);
  }
  windowEvent(event: window.WindowStageEventType): void {
    if (event === window.WindowStageEventType.ACTIVE || event === window.WindowStageEventType.SHOWN) {
      this.foreground = true; this.foregroundReady?.(); desktopSession.foreground();
    } else if (event === window.WindowStageEventType.INACTIVE || event === window.WindowStageEventType.HIDDEN) this.foreground = false;
  }
  load(): DesktopPreferences { return this.store!.load(); }
  save(value: DesktopPreferences): void { this.store!.save(value); }
  supported(): boolean { return deviceInfo.sdkApiVersion >= 15 && canIUse('SystemCapability.PCService.StatusBarManager'); }
  private menus(): statusBarManager.StatusBarGroupMenu[] {
    const action = (code: string): statusBarManager.StatusBarMenuAction => ({ abilityName: 'EntryAbility', moduleName: 'entry', notifyOnly: true, menuCode: code });
    const label: string = this.mode === 'Rule' ? '规则' : this.mode === 'Global' ? '全局' : this.mode === 'Direct' ? '直连' : '';
    return [[
      { title: '显示主窗口', menuAction: action('show') },
      { title: label ? `代理模式：${label}` : '代理模式', subMenu: [
        { subTitle: '规则模式', menuAction: action('mode-Rule') },
        { subTitle: '全局模式', menuAction: action('mode-Global') },
        { subTitle: '直连模式', menuAction: action('mode-Direct') }
      ] },
      { title: '系统代理设置', menuAction: action('system-proxy') },
      { title: '系统联网检测', menuAction: action('network-check') }
    ], [{ title: '退出 ClashOS', menuAction: action('exit') }]];
  }
  private async icons(): Promise<statusBarManager.StatusBarIcon> {
    const bytes: Uint8Array = this.context!.resourceManager.getMediaContentSync($r('app.media.verge_mark').id);
    const source: image.ImageSource = image.createImageSource(bytes.buffer as ArrayBuffer);
    let original: image.PixelMap | undefined;
    try {
      original = await source.createPixelMap({ desiredSize: { width: 24, height: 24 }, desiredPixelFormat: image.PixelMapFormat.RGBA_8888 });
      const buffer: ArrayBuffer = new ArrayBuffer(24 * 24 * 4);
      await original.readPixelsToBuffer(buffer);
      const rgba: Uint8Array = new Uint8Array(buffer);
      for (let i: number = 0; i < rgba.length; i += 4) { rgba[i] = 255; rgba[i + 1] = 255; rgba[i + 2] = 255; }
      const white: image.PixelMap = await image.createPixelMap(buffer, { size: { width: 24, height: 24 }, pixelFormat: image.PixelMapFormat.RGBA_8888 });
      this.pixels.push(white);
      for (let i: number = 0; i < rgba.length; i += 4) { rgba[i] = 0; rgba[i + 1] = 0; rgba[i + 2] = 0; }
      const black: image.PixelMap = await image.createPixelMap(buffer, { size: { width: 24, height: 24 }, pixelFormat: image.PixelMapFormat.RGBA_8888 });
      this.pixels.push(black);
      return { white, black };
    } finally { await original?.release(); source.release(); }
  }
  private async releaseIcons(): Promise<void> { for (const pixel of this.pixels) await pixel.release(); this.pixels = []; }
  async addTray(): Promise<void> {
    if (this.added) return;
    try {
      const icons: statusBarManager.StatusBarIcon = await this.icons();
      statusBarManager.on('statusBarIconClick', this.iconClick);
      this.listeners = true;
      statusBarManager.on('rightMenuClick', this.menuClick);
      await new Promise<void>((resolve: () => void, reject: (error: Error) => void) => {
        statusBarManager.addToStatusBar(this.context!, { icons,
          quickOperation: { title: 'ClashOS', height: 30, abilityName: '', moduleName: 'entry' }, statusBarGroupMenu: this.menus() },
          (error): void => { if (error && error.code) reject(error); else resolve(); });
      });
      this.added = true;
    } catch (error) { await this.removeTray(); throw platformError(error as Error, '无法创建系统托盘'); }
  }
  async removeTray(): Promise<void> {
    if (this.updateTimer >= 0) { clearTimeout(this.updateTimer); this.updateTimer = -1; }
    if (this.added) {
      try { statusBarManager.removeFromStatusBar(this.context!); }
      catch (error) { throw platformError(error as Error, '无法移除系统托盘'); }
      this.added = false;
    }
    if (this.listeners) {
      try { statusBarManager.off('statusBarIconClick', this.iconClick); } catch (_) {}
      try { statusBarManager.off('rightMenuClick', this.menuClick); } catch (_) {}
      this.listeners = false;
    }
    await this.releaseIcons();
  }
  async startResident(): Promise<void> {
    if (this.resident) return;
    let timer: number = -1;
    const ready: Promise<void> = new Promise<void>((resolve: () => void, reject: (error: Error) => void) => {
      this.residentReady = resolve;
      timer = setTimeout(() => reject(new Error('托盘驻留启动超时')), 5000);
    });
    ready.catch(() => {});
    try {
      await this.context!.startAbility({ bundleName: this.context!.abilityInfo.bundleName, abilityName: 'TrayResidentAbility' }, {
        processMode: contextConstant.ProcessMode.ATTACH_TO_STATUS_BAR_ITEM,
        startupVisibility: contextConstant.StartupVisibility.STARTUP_HIDE
      });
      await ready;
    } catch (error) { await this.stopResident(); throw platformError(error as Error, '无法启动托盘驻留'); }
    finally { if (timer >= 0) clearTimeout(timer); this.residentReady = undefined; }
  }
  attachResident(context: common.UIAbilityContext): void { this.resident = context; this.residentReady?.(); }
  detachResident(context: common.UIAbilityContext): void {
    if (this.resident !== context) return;
    this.resident = undefined; desktopSession.residentLost();
  }
  async stopResident(): Promise<void> {
    const resident: common.UIAbilityContext | undefined = this.resident;
    if (resident) { await resident.terminateSelf(); if (this.resident === resident) this.resident = undefined; }
  }
  async hide(): Promise<void> {
    if (!this.mainWindow) throw new Error('主窗口不可用');
    await this.mainWindow.minimize();
  }
  async show(): Promise<void> {
    if (!this.context || !this.mainWindow) throw new Error('主窗口不可用');
    if (this.foreground) return;
    if (this.showing) return this.showing;
    this.showing = this.showForeground();
    try { await this.showing; } finally { this.showing = undefined; }
  }
  private async showForeground(): Promise<void> {
    let timer: number = -1;
    const shown: Promise<void> = new Promise<void>((resolve: () => void, reject: (error: Error) => void) => {
      this.foregroundReady = resolve;
      timer = setTimeout(() => reject(new Error('主窗口未能进入前台')), 5000);
    });
    shown.catch(() => {});
    try {
      await this.context!.startAbility({ bundleName: this.context!.abilityInfo.bundleName, abilityName: 'EntryAbility' });
      await shown;
    } finally { if (timer >= 0) clearTimeout(timer); this.foregroundReady = undefined; }
  }
  async terminate(): Promise<void> { await this.context!.terminateSelf(); }
  updateMode(mode: string): void {
    if (mode === this.mode || ['Rule', 'Global', 'Direct'].indexOf(mode) < 0) return;
    this.mode = mode;
    if (!this.added || this.updateTimer >= 0) return;
    this.updateTimer = setTimeout(() => {
      this.updateTimer = -1;
      try { if (this.added) statusBarManager.updateStatusBarMenu(this.context!, this.menus()); } catch (_) {}
    }, 600);
  }
}

const platform: DesktopPlatform = new DesktopPlatform();
export const desktopSession: DesktopController = new DesktopController(platform, (): void => {
  AppStorage.setOrCreate<number>('clashosDesktopRevision', (AppStorage.get<number>('clashosDesktopRevision') ?? 0) + 1);
});
export function attachDesktopWindow(context: common.UIAbilityContext, mainWindow: window.Window): void { platform.bind(context, mainWindow); desktopSession.initialize(); }
export function detachDesktopWindow(): void { platform.detach(); }
export function attachDesktopResident(context: common.UIAbilityContext): void { platform.attachResident(context); }
export function detachDesktopResident(context: common.UIAbilityContext): void { platform.detachResident(context); }
export function updateDesktopMode(mode: string): void { platform.updateMode(mode); }
export function desktopWindowEvent(event: window.WindowStageEventType): void { platform.windowEvent(event); }
