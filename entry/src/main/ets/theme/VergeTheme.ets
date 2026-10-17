import { appearanceSettings } from './AppearanceTypes';
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
}

export function createPalette(dark: boolean, accent: string): VergePalette {
  const theme: VergePalette = new VergePalette(); theme.dark = dark;
  if (dark) {
    theme.canvas = '#17171B'; theme.chrome = '#1D1D23'; theme.surface = '#24242B';
    theme.surfaceHover = '#2B2B34'; theme.field = '#2E2E38';
    theme.text = '#F1F1F5'; theme.textSecondary = '#C3C3CE'; theme.textMuted = '#A0A0AF';
    theme.border = '#41414D'; theme.divider = '#34343F'; theme.navigationHover = '#30303A';
    theme.success = '#62D3A0'; theme.warning = '#EDB47E'; theme.danger = '#FF8DA3'; theme.purple = '#B89AEE';
  }
  // Keep text accents readable, including user-selected very pale/dark colors.
  let primary: string = appearanceSettings('system', accent).accent;
  const target: string = dark ? '#FFFFFF' : '#000000';
  for (let step: number = 0; step < 40; ++step) {
    const soft: string = mixColor(primary, theme.surface, dark ? 0.17 : 0.08);
    if (contrast(primary, theme.surface) >= 4.5 && contrast(primary, soft) >= 4.5) break;
    primary = mixColor(target, primary, 0.08);
  }
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
