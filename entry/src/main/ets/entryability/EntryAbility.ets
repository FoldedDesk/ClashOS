import { UIAbility, Want, AbilityConstant, ConfigurationConstant } from '@kit.AbilityKit';
import { window } from '@kit.ArkUI';
import { loadAppearance } from '../service/AppearanceStore';
import { subscriptionImports } from '../service/SubscriptionImport';
import { attachDesktopWindow, detachDesktopWindow, desktopWindowEvent } from '../service/DesktopSession';

export default class EntryAbility extends UIAbility {
  private proxyWindowStage: window.WindowStage | undefined = undefined;
  private proxyWindowListener = (event: window.WindowStageEventType): void => {
    desktopWindowEvent(event);
    if (event === window.WindowStageEventType.ACTIVE || event === window.WindowStageEventType.SHOWN) this.onForeground();
  };
  onCreate(want: Want, _launchParam: AbilityConstant.LaunchParam): void {
    try {
      const mode: string = loadAppearance(this.context.filesDir).mode;
      this.context.getApplicationContext().setColorMode(mode === 'dark' ? ConfigurationConstant.ColorMode.COLOR_MODE_DARK :
        mode === 'light' ? ConfigurationConstant.ColorMode.COLOR_MODE_LIGHT : ConfigurationConstant.ColorMode.COLOR_MODE_NOT_SET);
    } catch (_) { console.warn('ClashOS appearance preferences unavailable; using system appearance'); }
    this.receiveSubscriptionLink(want);
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    this.proxyWindowStage = windowStage;
    try { attachDesktopWindow(this.context, windowStage.getMainWindowSync()); }
    catch (_) { console.warn('ClashOS desktop window integration unavailable'); }
    try { windowStage.on('windowStageEvent', this.proxyWindowListener); }
    catch (_) { console.warn('ClashOS window focus observation unavailable'); }
    windowStage.loadContent('pages/Index', (error) => {
      if (error.code) {
        console.error(`ClashOS load page failed: ${error.code}, ${error.message}`);
      }
    });
  }

  onNewWant(want: Want): void {
    this.receiveSubscriptionLink(want);
  }

  private receiveSubscriptionLink(want: Want): void {
    if (subscriptionImports.receive(want.uri ?? '')) {
      AppStorage.setOrCreate<number>('clashosImportRevision', (AppStorage.get<number>('clashosImportRevision') ?? 0) + 1);
    }
  }

  onForeground(): void {
    AppStorage.setOrCreate<number>('clashosForeground', Date.now());
  }

  onWindowStageDestroy(): void {
    detachDesktopWindow();
    try { this.proxyWindowStage?.off('windowStageEvent', this.proxyWindowListener); } catch (_) {}
    this.proxyWindowStage = undefined;
  }
}
