import { http, connection } from '@kit.NetworkKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { ClashNativeCore } from './ClashNativeCore';
import { SubscriptionOptions, SubscriptionInfo, subscriptionOptions, subscriptionInfo, subscriptionUrl } from './SubscriptionTypes';

export interface SubscriptionDownload { content: string; info: SubscriptionInfo; }

export class SubscriptionClient {
  async download(url: string, options?: SubscriptionOptions): Promise<SubscriptionDownload> {
    const target: string = subscriptionUrl(url), settings: SubscriptionOptions = subscriptionOptions(options);
    const client = http.createHttp(); let timer: number = -1;
    try {
      let proxy: boolean | connection.HttpProxy = settings.route === 'system';
      if (settings.route === 'core') proxy = new ClashNativeCore().localHttpProxy();
      const timeout: number = settings.timeoutSeconds * 1000;
      const response: http.HttpResponse = await Promise.race([
        client.request(target, { method: http.RequestMethod.GET, usingProxy: proxy, usingCache: false,
          connectTimeout: Math.min(timeout, 10000), readTimeout: timeout, maxLimit: 8 * 1024 * 1024,
          header: { 'User-Agent': settings.userAgent, 'Accept': 'application/yaml, application/json, text/plain' }, expectDataType: http.HttpDataType.STRING }),
        new Promise<http.HttpResponse>((_resolve, reject) => { timer = setTimeout(() => reject(new Error('订阅下载超时')), timeout); })
      ]);
      if (response.responseCode < 200 || response.responseCode >= 300) throw new Error(`订阅服务器返回 HTTP ${response.responseCode}`);
      return { content: response.result.toString(), info: subscriptionInfo(response.header as Record<string, string>) };
    } catch (error) {
      const message: string = (error as Error).message || '';
      if (message === '订阅下载超时' || message.startsWith('订阅服务器返回 HTTP') || message.startsWith('内置 HTTP 代理')) throw new Error(message);
      const code: number = (error as BusinessError).code;
      throw new Error(`订阅下载失败${Number.isSafeInteger(code) ? `（代码 ${code}）` : ''}，原配置已保留`);
    } finally { if (timer >= 0) clearTimeout(timer); client.destroy(); }
  }
}
