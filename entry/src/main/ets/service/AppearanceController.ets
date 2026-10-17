import { common, Configuration, ConfigurationConstant } from '@kit.AbilityKit';
import { ThemeControl } from '@kit.ArkUI';
import { AppearanceSettings, VergePalette, DEFAULT_ACCENT, appearanceSettings, createPalette } from '../theme/VergeTheme';
import { AppearanceStore } from './AppearanceStore';
import { NativeStyles } from '../theme/NativeStyles';

export class AppearanceController {
  settings: AppearanceSettings = { mode: 'system', accent: DEFAULT_ACCENT };
  loadError: string = '';
  private store: AppearanceStore;
  private application: common.ApplicationContext;
  private callbackId: number = -1;
  private active: boolean = true;
  private systemDark: boolean = false;
  constructor(context: common.UIAbilityContext, protect: (fd: number) => void) {
    this.application = context.getApplicationContext();
    this.store = new AppearanceStore(context.filesDir, protect);
    this.systemDark = context.config.colorMode === ConfigurationConstant.ColorMode.COLOR_MODE_DARK;
    try { this.settings = this.store.load(); createPalette(false, this.settings.accent, this.settings.styles); createPalette(true, this.settings.accent, this.settings.styles); }
    catch (_) { this.settings = { mode: 'system', accent: DEFAULT_ACCENT }; this.loadError = '外观设置无法读取，已使用默认外观'; }
    const theme: VergePalette = this.palette(this.settings);
    this.nativeTheme(this.settings, theme); this.publish(theme);
    this.callbackId = this.application.on('environment', {
      onConfigurationUpdated: (config: Configuration): void => {
        if (!this.active || this.settings.mode !== 'system' || config.colorMode === undefined || config.colorMode === ConfigurationConstant.ColorMode.COLOR_MODE_NOT_SET) return;
        const dark: boolean = config.colorMode === ConfigurationConstant.ColorMode.COLOR_MODE_DARK;
        if (this.systemDark === dark) return;
        this.systemDark = dark;
        const updated: VergePalette = createPalette(dark, this.settings.accent, this.settings.styles);
        this.tokens(updated); this.publish(updated);
      }, onMemoryLevel: (): void => {}
    });
  }
  private palette(value: AppearanceSettings): VergePalette { return createPalette(value.mode === 'dark' || (value.mode === 'system' && this.systemDark), value.accent, value.styles); }
  private nativeTheme(value: AppearanceSettings, theme: VergePalette): void {
    this.application.setColorMode(value.mode === 'system' ? ConfigurationConstant.ColorMode.COLOR_MODE_NOT_SET :
      value.mode === 'dark' ? ConfigurationConstant.ColorMode.COLOR_MODE_DARK : ConfigurationConstant.ColorMode.COLOR_MODE_LIGHT);
    this.tokens(theme);
  }
  private tokens(theme: VergePalette): void {
    ThemeControl.setDefaultTheme({ colors: { brand: theme.primary, fontEmphasize: theme.primary, iconEmphasize: theme.primary,
      compBackgroundEmphasize: theme.primary, fontOnPrimary: theme.onPrimary,
      fontPrimary: theme.text, fontSecondary: theme.textSecondary, fontTertiary: theme.textMuted, fontFourth: theme.textMuted,
      iconPrimary: theme.text, iconSecondary: theme.textSecondary, iconTertiary: theme.textMuted, iconFourth: theme.textMuted,
      backgroundPrimary: theme.surface, backgroundSecondary: theme.field, backgroundTertiary: theme.canvas,
      backgroundFourth: theme.chrome, compBackgroundPrimary: theme.field, compBackgroundGray: theme.field,
      compBackgroundSecondary: theme.surfaceHover, compBackgroundTertiary: theme.field, compDivider: theme.divider,
      interactiveHover: theme.surfaceHover, interactiveSelect: theme.primarySoft } });
  }
  private publish(theme: VergePalette): void { AppStorage.setOrCreate('clashosTheme', theme); }
  savedSettings(): AppearanceSettings { return this.store.load(); }
  save(mode: string, accent: string, styles: NativeStyles | null | undefined = this.settings.styles): void {
    if (!this.active) throw new Error('外观会话已结束，请重新打开应用');
    const next: AppearanceSettings = appearanceSettings(mode, accent, styles === null ? undefined : styles), previous: AppearanceSettings = this.settings;
    createPalette(false, next.accent, next.styles); createPalette(true, next.accent, next.styles);
    const previousTheme: VergePalette = AppStorage.get<VergePalette>('clashosTheme') ?? this.palette(previous);
    this.settings = next;
    try {
      this.nativeTheme(next, this.palette(next));
      const resolved: VergePalette = this.palette(next);
      this.tokens(resolved); this.publish(resolved); this.store.save(next);
    } catch (error) {
      this.settings = previous;
      try { this.nativeTheme(previous, previousTheme); } catch (_) {}
      this.publish(previousTheme); throw new Error((error as Error).message || '外观未能保存，原设置已保留');
    }
  }
  dispose(): void {
    this.active = false;
    if (this.callbackId >= 0) this.application.off('environment', this.callbackId).catch(() => {});
    this.callbackId = -1;
  }
}
