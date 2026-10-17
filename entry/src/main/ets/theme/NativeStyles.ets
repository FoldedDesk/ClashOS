export interface NativeStyleColors {
  canvas?: string; chrome?: string; surface?: string; field?: string;
  text?: string; textSecondary?: string; textMuted?: string; border?: string; divider?: string;
}
export interface NativeStyles {
  version: number; fontFamily: string; fontScale: number; cardRadius: number; contentGap: number;
  light: NativeStyleColors; dark: NativeStyleColors;
}
const COLOR_KEYS: string[] = ['canvas', 'chrome', 'surface', 'field', 'text', 'textSecondary', 'textMuted', 'border', 'divider'];
function shape(value: object, keys: string[]): void {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some((key: string) => !keys.includes(key)))
    throw new Error('样式包含无效或不支持的字段');
}
function color(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !/^#[0-9a-fA-F]{6}$/.test(value)) throw new Error('样式颜色必须使用 #RRGGBB');
  return value.toUpperCase();
}
function colors(value: NativeStyleColors | undefined): NativeStyleColors {
  if (value === undefined) return {};
  shape(value, COLOR_KEYS);
  return { canvas: color(value.canvas), chrome: color(value.chrome), surface: color(value.surface), field: color(value.field),
    text: color(value.text), textSecondary: color(value.textSecondary), textMuted: color(value.textMuted), border: color(value.border), divider: color(value.divider) };
}
export function nativeStyles(value?: NativeStyles): NativeStyles {
  if (value === undefined) return { version: 1, fontFamily: '', fontScale: 1, cardRadius: 8, contentGap: 12, light: {}, dark: {} };
  shape(value, ['version', 'fontFamily', 'fontScale', 'cardRadius', 'contentGap', 'light', 'dark']);
  if (value.version !== 1 || typeof value.fontFamily !== 'string' || value.fontFamily.length > 120 || /[\u0000-\u001f\u007f]/.test(value.fontFamily) ||
    typeof value.fontScale !== 'number' || !Number.isFinite(value.fontScale) || value.fontScale < 0.85 || value.fontScale > 1.3 ||
    !Number.isInteger(value.cardRadius) || value.cardRadius < 0 || value.cardRadius > 24 ||
    !Number.isInteger(value.contentGap) || value.contentGap < 8 || value.contentGap > 24) throw new Error('请检查样式版本、字体、字号比例（0.85–1.3）、圆角（0–24）和页面边距（8–24）');
  return { version: 1, fontFamily: value.fontFamily.trim(), fontScale: value.fontScale, cardRadius: value.cardRadius,
    contentGap: value.contentGap, light: colors(value.light), dark: colors(value.dark) };
}
export function parseNativeStyles(text: string): NativeStyles {
  if (typeof text !== 'string' || text.length > 8192) throw new Error('样式超过 8 KB');
  let value: NativeStyles;
  try { value = JSON.parse(text) as NativeStyles; } catch (_) { throw new Error('样式不是有效的 JSON'); }
  return nativeStyles(value);
}
export function sameNativeStyles(a?: NativeStyles, b?: NativeStyles): boolean { return JSON.stringify(nativeStyles(a)) === JSON.stringify(nativeStyles(b)); }
