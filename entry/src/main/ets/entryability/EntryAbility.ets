import { UIAbility, Want, AbilityConstant, ConfigurationConstant } from '@kit.AbilityKit';
import { window } from '@kit.ArkUI';
import { loadAppearance } from '../service/AppearanceStore';

export default class EntryAbility extends UIAbility {
  private proxyWindowStage: window.WindowStage | undefined = undefined;
  private proxyWindowListener = (event: window.WindowStageEventType): void => {
    if (event === window.WindowStageEventType.ACTIVE || event === window.WindowStageEventType.SHOWN) this.onForeground();
  };
  onCreate(_want: Want, _launchParam: AbilityConstant.LaunchParam): void {
    try {
      const mode: string = loadAppearance(this.context.filesDir).mode;
      this.context.getApplicationContext().setColorMode(mode === 'dark' ? ConfigurationConstant.ColorMode.COLOR_MODE_DARK :
        mode === 'light' ? ConfigurationConstant.ColorMode.COLOR_MODE_LIGHT : ConfigurationConstant.ColorMode.COLOR_MODE_NOT_SET);
    } catch (_) { console.warn('ClashOS appearance preferences unavailable; using system appearance'); }
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    this.proxyWindowStage = windowStage;
    try { windowStage.on('windowStageEvent', this.proxyWindowListener); }
    catch (_) { console.warn('ClashOS window focus observation unavailable'); }
    windowStage.loadContent('pages/Index', (error) => {
      if (error.code) {
        console.error(`ClashOS load page failed: ${error.code}, ${error.message}`);
      }
    });
  }

  onNewWant(_want: Want): void {
    // Reserved for deep links to profiles and proxy groups in a later version.
  }

  onForeground(): void {
    AppStorage.setOrCreate<number>('clashosForeground', Date.now());
  }

  onWindowStageDestroy(): void {
    try { this.proxyWindowStage?.off('windowStageEvent', this.proxyWindowListener); } catch (_) {}
    this.proxyWindowStage = undefined;
  }
}
