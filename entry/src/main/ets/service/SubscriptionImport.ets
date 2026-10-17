import { subscriptionUrl } from './SubscriptionTypes';

export interface SubscriptionImport {
  id: number;
  url: string;
  name: string;
}

// Decode the outer query once. Tokens and format flags in the nested URL must
// retain their original percent escapes, plus signs and parameter boundaries.
export function parseSubscriptionLink(uri: string): SubscriptionImport {
  try {
    if (!uri || uri.length > 32768 || /[\u0000-\u0020\u007f]/.test(uri)) throw new Error();
    const match: RegExpMatchArray | null = uri.match(/^(clash|clashos|clash-verge):\/\/install-config\/?\?([^#]*)$/i);
    if (!match) throw new Error();
    let source: string | undefined, name: string | undefined;
    for (const pair of match[2].split('&')) {
      if (!pair) continue;
      const separator: number = pair.indexOf('=');
      if (separator < 0) throw new Error();
      const key: string = decodeURIComponent(pair.substring(0, separator).replace(/\+/g, ' '));
      const value: string = decodeURIComponent(pair.substring(separator + 1).replace(/\+/g, ' '));
      if (key === 'url' && source === undefined) source = value;
      else if (key === 'name' && name === undefined) name = value;
      else throw new Error();
    }
    if (source === undefined || source !== source.trim() || /[\u0000-\u001f\u007f]/.test(name ?? '') || (name ?? '').length > 100) throw new Error();
    return { id: 0, url: subscriptionUrl(source), name: (name ?? '').trim() };
  } catch (_) { throw new Error('订阅导入链接无效，请检查链接格式和 URL 编码'); }
}

export class SubscriptionImportInbox {
  private pending: SubscriptionImport[] = [];
  private active?: SubscriptionImport;
  private nextId: number = 0;
  private error: string = '';

  receive(uri: string): boolean {
    if (!uri) return false;
    try {
      const request: SubscriptionImport = parseSubscriptionLink(uri);
      if ([...this.pending, ...(this.active ? [this.active] : [])].some((item: SubscriptionImport): boolean => item.url === request.url && item.name === request.name)) return false;
      if (this.pending.length + (this.active ? 1 : 0) >= 8) {
        this.error = '待导入的订阅过多，请处理已有链接后重试'; return true;
      }
      request.id = ++this.nextId;
      this.pending.push(request);
    } catch (_) { this.error = '订阅导入链接无效，请检查链接格式和 URL 编码'; }
    return true;
  }

  take(): SubscriptionImport | undefined {
    if (this.active) return undefined;
    this.active = this.pending.shift();
    // Consumers may edit their form without changing deduplication identity.
    return this.active ? { id: this.active.id, url: this.active.url, name: this.active.name } : undefined;
  }

  finish(id: number): void { if (this.active?.id === id) this.active = undefined; }
  takeError(): string { const message: string = this.error; this.error = ''; return message; }
}

// Process memory only: URLs may contain account tokens. AppStorage receives
// only a revision number, never a URL, and receiving a link performs no I/O.
export const subscriptionImports: SubscriptionImportInbox = new SubscriptionImportInbox();
