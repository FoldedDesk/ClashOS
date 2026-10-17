import { http } from '@kit.NetworkKit';
import { BusinessError } from '@kit.BasicServicesKit';

// Independent OS HTTP/TLS client. Fixed public destinations only; never return
// response bodies, headers, credentials, node addresses or application files.
export async function probeNetworkHttps(site: string, protocol: string = ''): Promise<string> {
  const url: string = site === 'google' ? 'https://www.google.com/generate_204' : site === 'gstatic' ?
    'https://www.gstatic.com/generate_204' : site === 'github' ? 'https://api.github.com' : '';
  if (!url || !['', 'http1', 'http2', 'system', 'reference'].includes(protocol)) throw new Error('Unknown public probe');
  const client = http.createHttp(); const start: number = Date.now();
  const options: http.HttpRequestOptions = {
    method: http.RequestMethod.GET,
    usingCache: false,
    connectTimeout: 8000,
    readTimeout: 8000,
    usingProxy: { host: '127.0.0.1', port: protocol === 'reference' ? 18106 : 7890, exclusionList: [] },
    header: { 'User-Agent': 'ClashOS-independent-device-check', 'Connection': 'close' },
    maxLimit: 256 * 1024
  };
  if (protocol === 'system') options.usingProxy = true;
  if (protocol === 'http1' || protocol === 'http2' || protocol === 'reference') options.usingProtocol = protocol === 'http2' ? http.HttpProtocol.HTTP2 : http.HttpProtocol.HTTP1_1;
  try {
    const response = await client.request(url, options);
    const status: number = Number(response.responseCode);
    return JSON.stringify({ site, protocol, status, passed: status === (site === 'github' ? 200 : 204), elapsed: Date.now() - start });
  } catch (error) {
    return JSON.stringify({ site, protocol, passed: false, code: (error as BusinessError).code, elapsed: Date.now() - start });
  } finally { client.destroy(); }
}
