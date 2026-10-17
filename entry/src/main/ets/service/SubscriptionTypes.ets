import url from '@ohos.url';
import { utf8Bytes } from './TextCodec';

export interface SubscriptionOptions { userAgent: string; timeoutSeconds: number; route: string; }
export interface SubscriptionUsage { upload?: number; download?: number; total?: number; expire?: number; }
export interface SubscriptionInfo { usage?: SubscriptionUsage; home?: string; suggestedName?: string; suggestedInterval?: number; checkedAt: number; }
export interface SubscriptionData { options: SubscriptionOptions; followInterval: boolean; info?: SubscriptionInfo; }

export function subscriptionOptions(value?: SubscriptionOptions): SubscriptionOptions {
  if (value === undefined) return { userAgent: 'clashos/1.0', timeoutSeconds: 20, route: 'system' };
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some((key: string) => !['userAgent', 'timeoutSeconds', 'route'].includes(key)) ||
    typeof value.userAgent !== 'string' || !value.userAgent.trim() || utf8Bytes(value.userAgent).length > 512 || /[\u0000-\u001f\u007f]/.test(value.userAgent) ||
    !Number.isInteger(value.timeoutSeconds) || value.timeoutSeconds < 1 || value.timeoutSeconds > 120 || !['system', 'direct', 'core'].includes(value.route)) throw new Error('订阅请求选项无效');
  return { userAgent: value.userAgent.trim(), timeoutSeconds: value.timeoutSeconds, route: value.route };
}

export function subscriptionUrl(text: string, homepage: boolean = false): string {
  const value: string = text.trim();
  try {
    if (!value || value.length > 8192 || /[\s\u0000-\u001f\u007f]/.test(value)) throw new Error('url');
    const parsed = new url.URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname || (homepage && (parsed.username || parsed.password))) throw new Error('url');
  } catch (_) { throw new Error(homepage ? '订阅主页地址无效' : '请输入完整的 HTTP 或 HTTPS 订阅地址'); }
  return value;
}

function unsigned(text: string): number | undefined {
  if (!/^\d+$/.test(text)) return undefined;
  const value: number = Number(text); return Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}
function header(headers: Record<string, string>, wanted: string, prefixed: boolean = false): string | undefined {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return undefined;
  let exact: string | undefined, extra: string | undefined;
  let extras: number = 0;
  for (const key of Object.keys(headers)) {
    const name: string = key.toLowerCase(), value: string = headers[key];
    if (typeof value !== 'string' || value.length > 8192 || /[\u0000-\u001f\u007f]/.test(value)) continue;
    if (name === wanted) { if (exact !== undefined) return undefined; exact = value; }
    else if (prefixed && name.endsWith(`-${wanted}`)) { extras++; extra = value; }
  }
  return exact ?? (extras === 1 ? extra : undefined);
}
function usageHeader(text?: string): SubscriptionUsage | undefined {
  if (!text) return undefined;
  const result: SubscriptionUsage = {}, seen: string[] = [];
  for (const field of text.split(';')) {
    const match = /^\s*(upload|download|total|expire)\s*=\s*(\d+)\s*$/i.exec(field);
    if (!match) continue;
    const key: string = match[1].toLowerCase(), value: number | undefined = unsigned(match[2]);
    if (seen.includes(key) || value === undefined || (key === 'expire' && value > 8640000000000)) return undefined;
    seen.push(key);
    if (key === 'upload') result.upload = value;
    else if (key === 'download') result.download = value;
    else if (key === 'total') result.total = value;
    else result.expire = value;
  }
  return seen.length > 0 && Number.isSafeInteger((result.upload ?? 0) + (result.download ?? 0)) ? result : undefined;
}
function suggestedName(text?: string): string | undefined {
  if (!text) return undefined;
  // RFC 5987 extended filename takes priority over the quoted ASCII fallback.
  const extended = /(?:^|;)\s*filename\*\s*=\s*(?:"([^"]*)"|([^;]*))/i.exec(text);
  const plain = /(?:^|;)\s*filename\s*=\s*(?:"((?:\\.|[^"\\])*)"|([^;]*))/i.exec(text);
  let value: string = '';
  try {
    if (extended) {
      const encoded: string = (extended[1] ?? extended[2]).trim();
      const parts = /^UTF-8'[^']*'(.*)$/i.exec(encoded);
      if (parts) value = decodeURIComponent(parts[1]);
    }
  } catch (_) {}
  if (!value && plain) value = (plain[1] ?? plain[2]).trim().replace(/\\(.)/g, '$1');
  value = value.split(/[\\/]/).pop()?.replace(/\.(yaml|yml|json)$/i, '').trim() ?? '';
  if (!value || value === '.' || value === '..' || value.length > 100 || /[\u0000-\u001f\u007f]/.test(value)) return undefined;
  return value;
}
export function subscriptionInfo(headers: Record<string, string>, now: number = Date.now()): SubscriptionInfo {
  const info: SubscriptionInfo = { checkedAt: now };
  info.usage = usageHeader(header(headers, 'subscription-userinfo', true));
  info.suggestedName = suggestedName(header(headers, 'content-disposition'));
  const raw: string | undefined = header(headers, 'profile-update-interval');
  const hours: number | undefined = raw === undefined ? undefined : unsigned(raw.trim());
  if (hours !== undefined && hours <= 168) info.suggestedInterval = hours * 60;
  const home: string | undefined = header(headers, 'profile-web-page-url');
  if (home) try { info.home = subscriptionUrl(home, true); } catch (_) {}
  return info;
}
export function subscriptionData(value?: SubscriptionData): SubscriptionData | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some((key: string) => !['options', 'followInterval', 'info'].includes(key)) || typeof value.followInterval !== 'boolean') throw new Error('订阅信息无效');
  const result: SubscriptionData = { options: subscriptionOptions(value.options), followInterval: value.followInterval };
  if (value.info !== undefined) {
    const info: SubscriptionInfo = value.info;
    if (!info || typeof info !== 'object' || Array.isArray(info) || Object.keys(info).some((key: string) => !['usage', 'home', 'suggestedName', 'suggestedInterval', 'checkedAt'].includes(key)) ||
      !Number.isSafeInteger(info.checkedAt) || info.checkedAt < 0 || info.checkedAt > 8640000000000000) throw new Error('订阅响应信息无效');
    const safe: SubscriptionInfo = { checkedAt: info.checkedAt };
    if (info.home !== undefined) { if (typeof info.home !== 'string') throw new Error('订阅主页地址无效'); safe.home = subscriptionUrl(info.home, true); }
    if (info.suggestedName !== undefined) {
      if (typeof info.suggestedName !== 'string' || !info.suggestedName.trim() || info.suggestedName.length > 100 || /[\\/\u0000-\u001f\u007f]/.test(info.suggestedName)) throw new Error('订阅建议名称无效');
      safe.suggestedName = info.suggestedName;
    }
    if (info.suggestedInterval !== undefined) {
      if (!Number.isInteger(info.suggestedInterval) || info.suggestedInterval < 0 || info.suggestedInterval > 10080) throw new Error('订阅建议间隔无效');
      safe.suggestedInterval = info.suggestedInterval;
    }
    if (info.usage !== undefined) {
      const usage: SubscriptionUsage = info.usage;
      if (!usage || typeof usage !== 'object' || Array.isArray(usage) || Object.keys(usage).some((key: string) => !['upload', 'download', 'total', 'expire'].includes(key))) throw new Error('订阅流量信息无效');
      for (const number of [usage.upload, usage.download, usage.total, usage.expire]) if (number !== undefined && (!Number.isSafeInteger(number) || number < 0)) throw new Error('订阅流量信息无效');
      if (!Number.isSafeInteger((usage.upload ?? 0) + (usage.download ?? 0))) throw new Error('订阅流量信息无效');
      if (usage.expire !== undefined && usage.expire > 8640000000000) throw new Error('订阅到期时间无效');
      safe.usage = { upload: usage.upload, download: usage.download, total: usage.total, expire: usage.expire };
    }
    result.info = safe;
  }
  return result;
}

function traffic(bytes: number): string {
  const units: string[] = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']; let value: number = bytes, index: number = 0;
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; }
  return `${index === 0 ? value : value.toFixed(2)} ${units[index]}`;
}
export function subscriptionTraffic(data?: SubscriptionData): string {
  const usage: SubscriptionUsage | undefined = data?.info?.usage;
  if (!usage) return '';
  if (usage.upload === undefined && usage.download === undefined) return usage.total !== undefined ? `总流量 ${traffic(usage.total)}` : '';
  const used: number = (usage.upload ?? 0) + (usage.download ?? 0);
  return `已用 ${traffic(used)}${usage.total !== undefined ? ` / ${traffic(usage.total)}` : ''}`;
}
export function subscriptionExpiry(data?: SubscriptionData, now: number = Date.now()): string {
  const expire: number | undefined = data?.info?.usage?.expire;
  if (expire === undefined || expire === 0) return '';
  return `${expire * 1000 <= now ? '已于' : '到期'} ${new Date(expire * 1000).toLocaleDateString()}${expire * 1000 <= now ? '过期' : ''}`;
}
