import { NativeStyles, nativeStyles, sameNativeStyles } from './NativeStyles';
export const DEFAULT_ACCENT: string = '#3478F6';
export interface AppearanceSettings { mode: string; accent: string; styles?: NativeStyles; }
export function appearanceSettings(mode: string, accent: string, styles?: NativeStyles): AppearanceSettings {
  if (['system', 'light', 'dark'].indexOf(mode) < 0) throw new Error('请选择跟随系统、浅色或深色');
  if (!/^#[0-9a-fA-F]{6}$/.test(accent.trim())) throw new Error('主题色应为 #RRGGBB，例如 #3478F6');
  return { mode, accent: accent.trim().toUpperCase(), styles: styles === undefined ? undefined : nativeStyles(styles) };
}
export function sameAppearance(a: AppearanceSettings, b: AppearanceSettings): boolean {
  return a.mode === b.mode && a.accent === b.accent && sameNativeStyles(a.styles, b.styles);
}
