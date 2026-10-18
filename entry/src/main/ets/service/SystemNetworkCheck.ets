import { connection, http } from '@kit.NetworkKit';
import { BusinessError } from '@kit.BasicServicesKit';
import url from '@ohos.url';

export interface NetworkTarget { name: string; url: string; expected: number; }
export interface NetworkProxy { host: string; port: number; exclusions: string[]; }
export interface NetworkSample { name: string; url: string; expected: number; status: number; elapsed: number; error: number; }
export interface NetworkCheck { state: string; proxy?: NetworkProxy; samples: NetworkSample[]; total: number; }
export interface NetworkStatistics { responses: number; passed: number; httpErrors: number; networkErrors: number; }

export function networkTargets(custom: string = ''): NetworkTarget[] {
  if (custom.trim()) {
    const text = custom.trim();
    if (text.length > 4096 || /[\s\u0000-\u001f\u007f]/.test(text)) throw new Error('请输入有效的 HTTP(S) 地址');
    try {
      const parsed = new url.URL(text);
      if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password) throw new Error('url');
    } catch (_) { throw new Error('请输入不含账号密码的 HTTP(S) 地址'); }
    return [{ name: '自定义网站', url: text, expected: 0 }];
  }
  return [
    { name: 'Google', url: 'https://www.google.com/generate_204', expected: 204 },
    { name: 'Gstatic', url: 'https://www.gstatic.com/generate_204', expected: 204 },
    { name: 'GitHub API', url: 'https://api.github.com', expected: 200 }
  ];
}
export function emptyNetworkCheck(): NetworkCheck { return { state: 'idle', samples: [], total: 0 }; }
export function networkPassed(sample: NetworkSample): boolean { return sample.status > 0 && (sample.expected ? sample.status === sample.expected : sample.status >= 200 && sample.status < 400); }
export function networkStatistics(check: NetworkCheck): NetworkStatistics {
  const responses = check.samples.filter((s: NetworkSample) => s.status > 0).length;
  const passed = check.samples.filter(networkPassed).length;
  return { responses, passed, httpErrors: responses - passed, networkErrors: check.samples.length - responses };
}
export function networkErrorText(code: number): string {
  if (code === 2300005) return '系统无法解析代理服务器';
  if (code === 2300006) return '系统无法解析目标域名';
  if (code === 2300007) return '系统无法建立连接';
  if (code === 2300028) return '系统网络请求超时';
  if (code === 2300052) return '对端未返回 HTTP 响应';
  if (code === 2300055 || code === 2300056) return '网络发送或接收失败';
  if (code === 2300060) return '系统 TLS 证书校验失败';
  if (code === 2300058 || code === 2300077) return '系统 TLS 证书不可用';
  if (code === 2300063) return '响应超过检测大小限制';
  if (code === 2300094) return '系统代理或目标认证失败';
  return '系统网络请求失败';
}
export function networkSampleText(sample: NetworkSample): string {
  if (!sample.status) return `${networkErrorText(sample.error)}（代码 ${sample.error || '未知'}） · ${sample.elapsed} ms`;
  return networkPassed(sample) ? `HTTP ${sample.status} · ${sample.elapsed} ms` :
    `已收到 HTTP ${sample.status} · 期望 ${sample.expected || '200–399'} · ${sample.elapsed} ms`;
}
export function networkProxyEnabled(proxy?: NetworkProxy): boolean { return proxy !== undefined && proxy.host.trim().length > 0 && proxy.port > 0 && proxy.port <= 65535; }
export function networkProxyText(proxy?: NetworkProxy): string {
  if (!proxy) return '尚未读取系统代理';
  return networkProxyEnabled(proxy) ? `系统代理：${proxy.host.includes(':') && !proxy.host.startsWith('[') ? '[' + proxy.host + ']' : proxy.host}:${proxy.port}` : '系统代理未开启，本次按系统设置连接';
}
export function networkStateText(state: string): string {
  return state === 'running' ? '检测中…' : state === 'complete' ? '检测完成' : state === 'cancelled' ? '已停止' :
    state === 'stale' ? '代理、配置或连接状态已变化，请重新打开检测' : state === 'error' ? '无法读取系统代理，请重试' : '点击开始后访问所列网站';
}
export function networkReport(check: NetworkCheck): string {
  const stats = networkStatistics(check);
  return ['ClashOS 系统代理联网检测', networkStateText(check.state), networkProxyText(check.proxy),
    `排除项：${check.proxy?.exclusions.join(', ') || '无'}`,
    `已完成 ${check.samples.length}/${check.total} · 网站响应成功 ${stats.passed} · HTTP 状态异常 ${stats.httpErrors} · 网络请求失败 ${stats.networkErrors}`,
    ...check.samples.map((s: NetworkSample): string => `${s.name} ${s.url}\n${networkSampleText(s)}`),
    '使用鸿蒙系统 HTTP 客户端及当前系统代理规则；网站响应不证明所有应用均使用代理，也不证明长期稳定。'].join('\n');
}

// No explicit proxy override: this tests the system's actual proxy/exclusion
// policy. Keep credentials and HTTP bodies/headers out of UI state and reports.
export class SystemNetworkCheck {
  private current: NetworkCheck = emptyNetworkCheck();
  private busy: boolean = false;
  private disposed: boolean = false;
  private cancelled: boolean = false;
  private client?: http.HttpRequest;
  private changed: (state: NetworkCheck) => void = (_state: NetworkCheck): void => {};
  private isCurrent: () => Promise<boolean>;
  constructor(isCurrent: () => Promise<boolean> = async (): Promise<boolean> => true) { this.isCurrent = isCurrent; }
  private publish(): void {
    if (this.disposed) return;
    this.changed({ state: this.current.state, total: this.current.total,
      proxy: this.current.proxy ? { host: this.current.proxy.host, port: this.current.proxy.port, exclusions: this.current.proxy.exclusions.slice() } : undefined,
      samples: this.current.samples.map((s: NetworkSample): NetworkSample => ({ name: s.name, url: s.url, expected: s.expected, status: s.status, elapsed: s.elapsed, error: s.error })) });
  }
  private signature(proxy: connection.HttpProxy): string {
    // Authentication changes must invalidate a run too. This comparison value
    // stays local to run(); it is never included in a published snapshot.
    return JSON.stringify([proxy.host, proxy.port, proxy.exclusionList.slice().sort(), proxy.username || '', proxy.password || '']);
  }
  private closeRequest(): void { const client = this.client; this.client = undefined; if (client) client.destroy(); }
  private async valid(signature: string): Promise<boolean> {
    if (this.disposed || this.cancelled) return false;
    try { if (!await this.isCurrent()) { this.current.state = 'stale'; return false; } }
    catch (_) { this.current.state = 'stale'; return false; }
    if (this.disposed || this.cancelled) return false;
    try {
      const proxy = await connection.getDefaultHttpProxy();
      if (signature !== this.signature(proxy)) { this.current.state = 'stale'; return false; }
    } catch (_) { this.current.state = 'stale'; return false; }
    return !this.disposed && !this.cancelled;
  }
  async run(custom: string, changed: (state: NetworkCheck) => void): Promise<void> {
    if (this.disposed || this.busy) throw new Error('检测正在进行或已关闭');
    const targets = networkTargets(custom); this.busy = true; this.cancelled = false; this.changed = changed;
    this.current = { state: 'running', samples: [], total: targets.length }; this.publish();
    try {
      const proxy = await connection.getDefaultHttpProxy();
      if (this.disposed || this.cancelled) return;
      const signature = this.signature(proxy);
      this.current.proxy = { host: proxy.host, port: proxy.port, exclusions: proxy.exclusionList.slice() }; this.publish();
      for (const target of targets) {
        if (!await this.valid(signature)) break;
        const start: number = Date.now(); let status: number = 0, error: number = 0;
        try {
          const client = http.createHttp(); this.client = client;
          const response = await client.request(target.url, { method: http.RequestMethod.GET, usingProxy: true, usingCache: false,
            usingProtocol: http.HttpProtocol.HTTP1_1, connectTimeout: 8000, readTimeout: 8000, maxLimit: 256 * 1024,
            header: { 'User-Agent': 'ClashOS-system-network-check', 'Connection': 'close' } });
          const value: number = Number(response.responseCode); if (Number.isInteger(value) && value >= 100 && value <= 599) status = value;
        } catch (failure) { const code: number = (failure as BusinessError).code; if (Number.isSafeInteger(code)) error = code; }
        finally { this.closeRequest(); }
        if (!await this.valid(signature)) break;
        this.current.samples.push({ name: target.name, url: target.url, expected: target.expected, status, elapsed: Math.max(1, Date.now() - start), error }); this.publish();
      }
      if (this.current.state === 'running') this.current.state = this.cancelled ? 'cancelled' : 'complete';
    } catch (_) { if (!this.cancelled) this.current.state = 'error'; }
    finally {
      this.closeRequest(); this.busy = false;
      if (this.cancelled) this.current.state = 'cancelled';
      this.publish();
    }
  }
  cancel(): void { if (!this.busy || this.disposed) return; this.cancelled = true; this.closeRequest(); this.current.state = 'cancelled'; this.publish(); }
  dispose(): void { this.disposed = true; this.cancelled = true; this.closeRequest(); this.changed = (_state: NetworkCheck): void => {}; }
}
