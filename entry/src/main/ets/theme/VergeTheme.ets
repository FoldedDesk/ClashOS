import { appearanceSettings } from './AppearanceTypes';
import { NativeStyles, NativeStyleColors, nativeStyles } from './NativeStyles';
export { AppearanceSettings, DEFAULT_ACCENT, appearanceSettings } from './AppearanceTypes';
function channels(color: string): number[] {
  return [parseInt(color.slice(1, 3), 16), parseInt(color.slice(3, 5), 16), parseInt(color.slice(5, 7), 16)];
}
export function mixColor(color: string, background: string, amount: number): string {
  const c: number[] = channels(color), b: number[] = channels(background);
  return '#' + c.map((value: number, i: number) => Math.round(value * amount + b[i] * (1 - amount)).toString(16).padStart(2, '0')).join('').toUpperCase();
}
function luminance(color: string): number {
  const c: number[] = channels(color).map((value: number) => {
    const n: number = value / 255; return n <= 0.04045 ? n / 12.92 : Math.pow((n + 0.055) / 1.055, 2.4);
  });
  return c[0] * 0.2126 + c[1] * 0.7152 + c[2] * 0.0722;
}
export function contrast(a: string, b: string): number {
  const x: number = luminance(a), y: number = luminance(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

// Each native page/dialog shares this observed object through AppStorage.
@Observed
export class VergePalette {
  dark: boolean = false;
  primary: string = '#2F6FE3';
  onPrimary: string = '#FFFFFF';
  primarySoft: string = '#EAF0FF';
  primaryHover: string = '#E0E9FD';
  primaryBorder: string = '#A6C1FA';
  navigationSelected: string = '#D8E2F7';
  navigationHover: string = '#E8E8EB';
  canvas: string = '#EFEFEF';
  chrome: string = '#F5F5F5';
  surface: string = '#FFFFFF';
  surfaceHover: string = '#FAFAFC';
  field: string = '#F6F6F9';
  text: string = '#171719';
  textSecondary: string = '#65656E';
  textMuted: string = '#74747E';
  border: string = '#E5E5E9';
  divider: string = '#EEEEF1';
  success: string = '#237D56';
  warning: string = '#9C612C';
  danger: string = '#BA3B52';
  purple: string = '#7D50B9';
  warningSoft: string = '#FFF5E9';
  dangerSoft: string = '#FFF0F2';
  navigationHeight: number = 64;
  navigationItemHeight: number = 42;
  pageHeaderHeight: number = 60;
  cardRadius: number = 8;
  contentGap: number = 12;
  fontFamily: string = 'HarmonyOS Sans';
  fontScale: number = 1;
  font(size: number): number { return size * this.fontScale; }
  radius(size: number): number { return Math.min(32, size * this.cardRadius / 8); }
}

function readable(color: string, backgrounds: string[]): string {
  const minimum = (value: string): number => Math.min(...backgrounds.map((background: string) => contrast(value, background)));
  const target: string = minimum('#FFFFFF') > minimum('#000000') ? '#FFFFFF' : '#000000';
  for (let step: number = 0; step < 80; ++step) { if (minimum(color) >= 4.5) return color; color = mixColor(target, color, 0.1); }
  throw new Error('背景颜色的明暗差异过大，请为浅色和深色分别使用亮度接近的背景色');
}
export function createPalette(dark: boolean, accent: string, custom?: NativeStyles): VergePalette {
  const theme: VergePalette = new VergePalette(); theme.dark = dark;
  if (dark) {
    theme.canvas = '#17171B'; theme.chrome = '#1D1D23'; theme.surface = '#24242B';
    theme.surfaceHover = '#2B2B34'; theme.field = '#2E2E38';
    theme.text = '#F1F1F5'; theme.textSecondary = '#C3C3CE'; theme.textMuted = '#A0A0AF';
    theme.border = '#41414D'; theme.divider = '#34343F'; theme.navigationHover = '#30303A';
    theme.success = '#62D3A0'; theme.warning = '#EDB47E'; theme.danger = '#FF8DA3'; theme.purple = '#B89AEE';
  }
  const styles: NativeStyles = nativeStyles(custom), colors: NativeStyleColors = dark ? styles.dark : styles.light;
  theme.fontFamily = styles.fontFamily || 'HarmonyOS Sans'; theme.fontScale = styles.fontScale;
  theme.cardRadius = styles.cardRadius; theme.contentGap = styles.contentGap;
  theme.canvas = colors.canvas ?? theme.canvas; theme.chrome = colors.chrome ?? theme.chrome;
  theme.surface = colors.surface ?? theme.surface; theme.field = colors.field ?? theme.field;
  theme.text = colors.text ?? theme.text; theme.textSecondary = colors.textSecondary ?? theme.textSecondary;
  theme.textMuted = colors.textMuted ?? theme.textMuted; theme.border = colors.border ?? theme.border; theme.divider = colors.divider ?? theme.divider;
  const customized: boolean = [colors.canvas, colors.chrome, colors.surface, colors.field, colors.text,
    colors.textSecondary, colors.textMuted, colors.border, colors.divider].some((value: string | undefined) => value !== undefined);
  if (customized) {
    const backgrounds: string[] = [theme.canvas, theme.chrome, theme.surface, theme.field];
    theme.text = readable(theme.text, backgrounds); theme.textSecondary = readable(theme.textSecondary, backgrounds); theme.textMuted = readable(theme.textMuted, backgrounds);
    theme.success = readable(theme.success, backgrounds); theme.warning = readable(theme.warning, backgrounds);
    theme.danger = readable(theme.danger, backgrounds); theme.purple = readable(theme.purple, backgrounds);
    theme.surfaceHover = mixColor(theme.text, theme.surface, 0.035); theme.navigationHover = mixColor(theme.text, theme.chrome, 0.06);
  }
  // Keep text accents readable, including user-selected very pale/dark colors.
  let primary: string = appearanceSettings('system', accent).accent;
  const backgrounds: string[] = [theme.surface, theme.chrome, theme.field, theme.canvas];
  if (customized) primary = readable(primary, backgrounds);
  const target: string = customized ? (contrast('#FFFFFF', theme.surface) > contrast('#000000', theme.surface) ? '#FFFFFF' : '#000000') : dark ? '#FFFFFF' : '#000000';
  for (let step: number = 0; step < 80; ++step) {
    const soft: string = mixColor(primary, theme.surface, dark ? 0.17 : 0.08);
    if (contrast(primary, theme.surface) >= 4.5 && contrast(primary, soft) >= 4.5 && (!customized || backgrounds.every((background: string) => contrast(primary, background) >= 4.5))) break;
    primary = mixColor(target, primary, 0.08);
  }
  if (customized && (!backgrounds.every((background: string) => contrast(primary, background) >= 4.5) ||
    contrast(primary, mixColor(primary, theme.surface, dark ? 0.17 : 0.08)) < 4.5)) throw new Error('背景色无法保持文字清晰，请调整颜色后重试');
  theme.primary = primary;
  theme.onPrimary = contrast('#FFFFFF', primary) >= contrast('#171719', primary) ? '#FFFFFF' : '#171719';
  theme.primarySoft = mixColor(primary, theme.surface, dark ? 0.17 : 0.08);
  theme.primaryHover = mixColor(primary, theme.surface, 0.15);
  theme.primaryBorder = mixColor(primary, theme.surface, 0.48);
  theme.navigationSelected = mixColor(primary, theme.chrome, dark ? 0.25 : 0.16);
  theme.warningSoft = mixColor(theme.warning, theme.surface, 0.12);
  theme.dangerSoft = mixColor(theme.danger, theme.surface, 0.12);
  return theme;
}
