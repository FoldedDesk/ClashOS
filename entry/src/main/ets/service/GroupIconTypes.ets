import { utf8Bytes } from './TextCodec';

export interface GroupIconEntry { name: string; source: string; }
export interface GroupIconSettings { version: number; entries: GroupIconEntry[]; }
export interface GroupIconSnapshot { name: string; source: string; revision: string; error: string; }
export const GROUP_ICON_PRESETS: string[] = ['selector', 'speed', 'fallback', 'balance', 'proxies', 'server', 'shield', 'home'];
export const GROUP_ICON_LABELS: string[] = ['手动选择', '自动测速', '故障回退', '负载均衡', '网络', '服务器', '防护', '主页'];
export function iconImageUrl(value: string): string {
  if (typeof value !== 'string' || value.length > 4096 || /[\s\u0000-\u001f\u007f\\]/.test(value)) return '';
  const match: RegExpMatchArray | null = value.match(/^https?:\/\/(\[[0-9a-f:]+\]|[a-z0-9._-]+)(?::([0-9]{1,5}))?(?:[/?#][^\s]*)?$/i);
  if (!match || (match[2] !== undefined && (Number(match[2]) < 1 || Number(match[2]) > 65535))) return '';
  return value;
}
export function localIconName(source: string): string {
  return /^local:icon-[a-zA-Z0-9]{6}\/icon\.png$/.test(source) ? source.slice(6) : '';
}
export function groupIconSource(value: string): string {
  if (typeof value !== 'string') throw new Error('图标设置格式无效');
  const source: string = value.trim();
  if (!source || iconImageUrl(source) || localIconName(source) ||
    (source.startsWith('builtin:') && GROUP_ICON_PRESETS.includes(source.slice(8)))) return source;
  throw new Error('请选择内置图标、导入图片，或填写有效的 HTTP / HTTPS 图片链接');
}
export function groupIconName(name: string): void {
  if (typeof name !== 'string' || !name.length || utf8Bytes(name).length > 1024 || /[\u0000-\u001f\u007f]/.test(name)) throw new Error('代理组名称无效');
}
export function parseGroupIcons(text: string): GroupIconEntry[] {
  if (!text) return [];
  if (utf8Bytes(text).length > 512 * 1024) throw new Error('图标设置文件过大');
  const data: GroupIconSettings = JSON.parse(text) as GroupIconSettings;
  if (!data || data.version !== 1 || !Array.isArray(data.entries) || data.entries.length > 256) throw new Error('图标设置格式无效');
  const names: Set<string> = new Set<string>();
  return data.entries.map((entry: GroupIconEntry): GroupIconEntry => {
    if (!entry || typeof entry.name !== 'string') throw new Error('图标设置格式无效');
    groupIconName(entry.name); const source: string = groupIconSource(entry.source);
    if (!source || names.has(entry.name)) throw new Error('图标设置包含空值或重复的代理组');
    names.add(entry.name); return { name: entry.name, source };
  });
}
