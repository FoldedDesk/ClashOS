import { http } from '@kit.NetworkKit';

export interface ClashProxyGroup {
  name: string;
  type: string;
  now: string;
  proxies: string[];
  checking?: boolean;
  manual?: string;
  strategy?: string;
  lastSelected?: string;
  icon?: string;
  hidden?: boolean;
}

export interface ClashProxyProvider {
  name: string;
  vehicleType: string;
  updatedAt: string;
  updating: boolean;
  checking: boolean;
  error: string;
  proxies: string[];
}

export interface ClashRuleProvider {
  name: string;
  vehicleType: string;
  behavior: string;
  format: string;
  ruleCount: number;
  ready: boolean;
  updating: boolean;
  updatedAt: string;
  error: string;
}

export interface ClashRulePayload {
  payload: string[];
  ruleCount: number;
  truncated: boolean;
}

export interface ClashDnsRecord {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

export interface ClashDnsQuestion {
  name: string;
  type: number;
}

export interface ClashDnsAnswer {
  Status: number;
  Question?: ClashDnsQuestion[];
  Answer?: ClashDnsRecord[];
  server?: string;
  cached?: boolean;
  delay?: number;
}

export interface ClashDnsStatus {
  enabled: boolean;
  ipv6: boolean;
  nameservers: number;
  policies: number;
  hosts: number;
  cacheEntries: number;
  queries: number;
  cacheHits: number;
  warnings: string[];
  listening?: boolean;
  listen?: string;
  listenerQueries?: number;
  listenerRejected?: number;
}

export interface ClashConnection {
  id: string;
  host: string;
  chains: string[];
  rule: string;
  download: number;
  upload: number;
  port: string;
  network: string;
  start: string;
}

export interface ClashRule {
  type: string;
  payload: string;
  proxy: string;
  noResolve?: boolean;
}

export interface ClashProxyNode {
  name: string;
  type: string;
  delay: number;
  udp: boolean;
}

export interface ClashCoreLog {
  id: number;
  time: string;
  type: string;
  payload: string;
}

export interface CoreDiagnostics {
  passed: boolean;
  random: boolean;
  md5: boolean;
  aesEncrypt: boolean;
  aesDecrypt: boolean;
  authentication: boolean;
  shadowsocks?: boolean;
  shadowsocksTcp?: boolean;
  vmess?: boolean;
  trojan?: boolean;
  vless?: boolean;
  certificateStore?: boolean;
  listeners: boolean;
  httpPort: number;
  socksPort: number;
}

export interface ClashSnapshot {
  connected: boolean;
  version: string;
  instance: string;
  configPath: string;
  temporaryConfig?: boolean;
  proxyHost?: string;
  allowLan?: boolean;
  sniffing?: boolean;
  mode: string;
  httpPort: number;
  socksPort: number;
  groups: ClashProxyGroup[];
  providers: ClashProxyProvider[];
  ruleProviders: ClashRuleProvider[];
  nodes: ClashProxyNode[];
  logs: ClashCoreLog[];
  connections: ClashConnection[];
  connectionCount: number;
  downloadTotal: number;
  uploadTotal: number;
  memoryBytes?: number;
  ruleCount: number;
  rules: ClashRule[];
  error: string;
}

export interface ClashProxyPorts {
  http: number;
  socks: number;
  mixed: number;
  overridden: boolean;
}

export interface ClashInboundAccount { username: string; password?: string; }
export interface ClashInboundSettings {
  allowLan: boolean;
  bindAddress: string;
  users: string[];
  skipAuth: string[];
  allowed: string[];
  denied: string[];
  localAddress: string;
  overridden: boolean;
  profile: string;
  revision: number;
}
export interface ClashInboundChanges {
  allowLan: boolean;
  bindAddress: string;
  users: ClashInboundAccount[];
  skipAuth: string[];
  allowed: string[];
  denied: string[];
}

export interface ClashRuntimeConfig {
  mode: string;
  logLevel: string;
  ipv6: boolean;
  sniffing?: boolean;
  path: string;
  origin?: string;
  temporary: boolean;
  revision: number;
}

interface ClashVersionResponse {
  version?: string;
  instance?: string;
}

interface ClashProxyHistory {
  delay?: number;
}

interface ClashProxyResponse {
  name?: string;
  type?: string;
  now?: string;
  all?: string[];
  checking?: boolean;
  manual?: string;
  strategy?: string;
  lastSelected?: string;
  proxies?: string[];
  history?: ClashProxyHistory[];
  udp?: boolean;
  icon?: string;
  hidden?: boolean;
}

interface ClashProviderResponse {
  name?: string;
  vehicleType?: string;
  updatedAt?: string;
  updating?: boolean;
  checking?: boolean;
  error?: string;
  proxies?: ClashProxyResponse[];
}
interface ClashProvidersResponse { providers?: Record<string, ClashProviderResponse>; }
interface ClashRuleProviderResponse {
  name?: string;
  vehicleType?: string;
  behavior?: string;
  format?: string;
  ruleCount?: number;
  ready?: boolean;
  updating?: boolean;
  updatedAt?: string;
  error?: string;
}
interface ClashRuleProvidersResponse { providers?: Record<string, ClashRuleProviderResponse>; }

interface ClashProxiesResponse {
  proxies?: Record<string, ClashProxyResponse>;
}

interface ClashMetadataResponse {
  host?: string;
  destinationIP?: string;
  destinationPort?: string | number;
  network?: string;
}

interface ClashConnectionResponse {
  id?: string;
  start?: string;
  metadata?: ClashMetadataResponse;
  chains?: string[];
  rule?: string;
  download?: number;
  upload?: number;
}

interface ClashConnectionsResponse {
  connections?: ClashConnectionResponse[];
  uploadTotal?: number;
  downloadTotal?: number;
  memory?: number;
}

interface ClashRuleResponse {
  type?: string;
  payload?: string;
  proxy?: string;
  noResolve?: boolean;
}

interface ClashRulesResponse {
  rules?: ClashRuleResponse[];
}

interface ClashDelayResponse {
  delay?: number;
}

interface ClashLogsResponse {
  logs?: ClashCoreLog[];
}

interface ClashErrorResponse {
  error?: string;
  message?: string;
}

export interface ClashGeoResource {
  kind: string;
  ready: boolean;
  required: boolean;
  updating: boolean;
  imported: boolean;
  sourceUrl: string;
  updatedAt: string;
  error: string;
  bytes: number;
  count: number;
  categories: number;
}

export interface ClashGeoStatus {
  mode: string;
  autoUpdate: boolean;
  interval: number;
  resources: ClashGeoResource[];
}

export class ClashApi {
  private localCredentialProvider?: (endpoint: string) => string | undefined;

  setLocalCredentialProvider(provider: (endpoint: string) => string | undefined): void { this.localCredentialProvider = provider; }
  private endpoint: string;
  private secret: string;
  private lastNativeLogId: number = 0;
  private nativeInstance: string = '';

  constructor(endpoint: string = 'http://127.0.0.1:9090', secret: string = '') {
    this.endpoint = endpoint;
    this.secret = secret;
  }

  setConfig(endpoint: string, secret: string): void {
    const value: string = endpoint.trim().length > 0 ? endpoint.trim() : 'http://127.0.0.1:9090';
    const withScheme: string = value.startsWith('http://') || value.startsWith('https://') ? value : `http://${value}`;
    const normalized: string = withScheme.replace(/\/$/, '');
    if (normalized !== this.endpoint) { this.lastNativeLogId = 0; this.nativeInstance = ''; }
    this.endpoint = normalized;
    this.secret = secret;
  }

  async readSnapshot(): Promise<ClashSnapshot> {
    try {
      const version: ClashVersionResponse = JSON.parse(await this.request('/version')) as ClashVersionResponse;
      const proxyData: ClashProxiesResponse = JSON.parse(await this.request('/proxies')) as ClashProxiesResponse;
      const groups: ClashProxyGroup[] = this.parseGroups(proxyData);
      const nodes: ClashProxyNode[] = this.parseNodes(proxyData);
      let logs: ClashCoreLog[] = [];
      if ((version.version ?? '').startsWith('ClashOS') || (version.version ?? '').startsWith('ClahsOS')) {
        if ((version.instance ?? '') !== this.nativeInstance) {
          this.nativeInstance = version.instance ?? '';
          this.lastNativeLogId = 0;
        }
        try {
          const logData: ClashLogsResponse = JSON.parse(await this.request(`/clahsos/logs?since=${this.lastNativeLogId}`)) as ClashLogsResponse;
          logs = logData.logs ?? [];
          logs.forEach((entry: ClashCoreLog) => this.lastNativeLogId = Math.max(this.lastNativeLogId, entry.id));
        } catch (_) {
          // Optional for older compatible cores.
        }
      }
      let providers: ClashProxyProvider[] = [];
      try {
        const data: ClashProvidersResponse = JSON.parse(await this.request('/providers/proxies')) as ClashProvidersResponse;
        const map: Record<string, ClashProviderResponse> = data.providers ?? {};
        providers = Object.keys(map).map((name: string): ClashProxyProvider => ({
          name: map[name].name ?? name, vehicleType: map[name].vehicleType ?? 'Unknown',
          updatedAt: map[name].updatedAt ?? '', updating: map[name].updating ?? false,
          checking: map[name].checking ?? false, error: map[name].error ?? '',
          proxies: (map[name].proxies ?? []).map((node: ClashProxyResponse) => node.name ?? '').filter((name: string) => name.length > 0)
        }));
      } catch (_) { /* Provider APIs are optional on older external cores. */ }
      let ruleProviders: ClashRuleProvider[] = [];
      try {
        const data: ClashRuleProvidersResponse = JSON.parse(await this.request('/providers/rules')) as ClashRuleProvidersResponse;
        const map: Record<string, ClashRuleProviderResponse> = data.providers ?? {};
        ruleProviders = Object.keys(map).map((name: string): ClashRuleProvider => ({
          name: map[name].name ?? name, vehicleType: map[name].vehicleType ?? 'Unknown',
          behavior: (map[name].behavior ?? '').toLowerCase(), format: (map[name].format ?? 'yaml').toLowerCase(),
          ruleCount: map[name].ruleCount ?? 0, ready: map[name].ready ?? true,
          updating: map[name].updating ?? false, updatedAt: map[name].updatedAt ?? '', error: map[name].error ?? ''
        }));
      } catch (_) { /* Rule providers are optional on older compatible cores. */ }
      let mode: string = 'Rule';
      let httpPort: number = 0;
      let socksPort: number = 0;
      let configPath: string = '';
      let temporaryConfig: boolean = false;
      let proxyHost: string = '127.0.0.1';
      let allowLan: boolean = false;
      let sniffing: boolean = false;
      try {
        const config: Record<string, string | number | boolean> = JSON.parse(await this.request('/configs')) as Record<string, string | number | boolean>;
        const modeValue: string | number | boolean = config['mode'];
        if (typeof modeValue === 'string') mode = this.normalizeMode(modeValue);
        const mixedValue: string | number | boolean = config['mixed-port'];
        const httpValue: string | number | boolean = config['port'];
        const socksValue: string | number | boolean = config['socks-port'];
        const pathValue: string | number | boolean = config['path'];
        configPath = typeof pathValue === 'string' ? pathValue : '';
        temporaryConfig = config['temporary'] === true;
        allowLan = config['allow-lan'] === true;
        sniffing = config['sniffing'] === true;
        const bind: string = typeof config['bind-address'] === 'string' ? config['bind-address'] as string : '*';
        proxyHost = !allowLan || bind === '*' || bind === '0.0.0.0' ? '127.0.0.1' : bind === '::' ? '::1' : bind.replace(/^\[|\]$/g, '');
        const mixedPort: number = typeof mixedValue === 'number' ? mixedValue : 0;
        httpPort = mixedPort > 0 ? mixedPort : typeof httpValue === 'number' ? httpValue : 0;
        socksPort = mixedPort > 0 ? mixedPort : typeof socksValue === 'number' ? socksValue : 0;
      } catch (_) {
        // Some compatible cores do not expose the config endpoint.
      }

      let connections: ClashConnection[] = [];
      let connectionCount: number = 0;
      let downloadTotal: number = 0;
      let uploadTotal: number = 0;
      let memoryBytes: number = 0;
      let ruleCount: number = 0;
      let rules: ClashRule[] = [];

      try {
        const connectionData: ClashConnectionsResponse = JSON.parse(await this.request('/connections')) as ClashConnectionsResponse;
        connections = this.parseConnections(connectionData);
        connectionCount = connectionData.connections?.length ?? 0;
        downloadTotal = connectionData.downloadTotal ?? 0;
        uploadTotal = connectionData.uploadTotal ?? 0;
        const memory: number = connectionData.memory ?? 0;
        memoryBytes = Number.isFinite(memory) && memory > 0 ? memory : 0;
      } catch (_) {
        // Older cores may not expose the connections endpoint. The core is still usable.
      }

      try {
        const ruleData: ClashRulesResponse = JSON.parse(await this.request('/rules')) as ClashRulesResponse;
        ruleCount = ruleData.rules?.length ?? 0;
        rules = (ruleData.rules ?? []).map((rule: ClashRuleResponse): ClashRule => ({
          type: rule.type ?? 'Unknown', payload: rule.payload ?? '', proxy: rule.proxy ?? '', noResolve: rule.noResolve ?? false
        }));
      } catch (_) {
        // Rules are optional for compatible cores.
      }

      return {
        connected: true,
        version: version.version ?? '未知版本',
        temporaryConfig,
        proxyHost,
        allowLan,
        sniffing,
        mode,
        httpPort,
        socksPort,
        groups,
        providers,
        ruleProviders,
        nodes,
        instance: version.instance ?? '',
        configPath,
        logs,
        connections,
        connectionCount,
        downloadTotal,
        uploadTotal,
        memoryBytes,
        ruleCount,
        rules,
        error: ''
      };
    } catch (error) {
      return {
        connected: false,
        version: '未连接',
        instance: '',
        configPath: '',
        mode: 'Rule',
        httpPort: 0,
        socksPort: 0,
        groups: [],
        providers: [],
        ruleProviders: [],
        nodes: [],
        logs: [],
        connections: [],
        connectionCount: 0,
        downloadTotal: 0,
        uploadTotal: 0,
        ruleCount: 0,
        rules: [],
        error: this.errorMessage(error)
      };
    }
  }

  async selectProxy(group: string, proxy: string): Promise<void> {
    await this.request(`/proxies/${encodeURIComponent(group)}`, http.RequestMethod.PUT, JSON.stringify({ name: proxy }));
  }

  async setMode(mode: string): Promise<void> {
    await this.request('/configs', 'PATCH' as http.RequestMethod, JSON.stringify({ mode }));
  }

  async loadConfig(path: string, original?: ClashRuntimeConfig): Promise<void> {
    const guard: string = original === undefined ? '' : `&profile=${encodeURIComponent(original.path)}&revision=${original.revision}`;
    await this.request(`/configs?force=true${guard}`, http.RequestMethod.PUT, JSON.stringify({ path }));
  }

  async runtimeConfig(): Promise<ClashRuntimeConfig> {
    const config: Record<string, string | number | boolean> = JSON.parse(await this.request('/configs')) as Record<string, string | number | boolean>;
    return { mode: this.normalizeMode(typeof config['mode'] === 'string' ? config['mode'] as string : 'Rule'),
      logLevel: typeof config['log-level'] === 'string' ? config['log-level'] as string : 'info',
      ipv6: config['ipv6'] === true, sniffing: config['sniffing'] === true, path: typeof config['path'] === 'string' ? config['path'] as string : '',
      origin: typeof config['origin'] === 'string' ? config['origin'] as string : '',
      temporary: config['temporary'] === true, revision: typeof config['revision'] === 'number' ? config['revision'] as number : 0 };
  }

  async saveRuntimeConfig(original: ClashRuntimeConfig, changed: ClashRuntimeConfig): Promise<void> {
    await this.request(`/configs?profile=${encodeURIComponent(original.path)}&revision=${original.revision}`, 'PATCH' as http.RequestMethod,
      JSON.stringify({ mode: changed.mode, 'log-level': changed.logLevel, ipv6: changed.ipv6, sniffing: changed.sniffing }));
  }

  async snifferDraft(): Promise<string> {
    const config: Record<string, string> = JSON.parse(await this.request('/configs')) as Record<string, string>;
    return JSON.stringify({ sniffer: config['sniffer'] }, null, 2);
  }

  async saveSnifferDraft(original: ClashRuntimeConfig, text: string): Promise<void> {
    await this.request(`/configs?profile=${encodeURIComponent(original.path)}&revision=${original.revision}`, 'PATCH' as http.RequestMethod, text);
  }

  async proxyPorts(): Promise<ClashProxyPorts> {
    return JSON.parse(await this.request('/clashos/ports')) as ClashProxyPorts;
  }

  async inboundSettings(): Promise<ClashInboundSettings> {
    const value: Record<string, string | number | boolean | string[]> = JSON.parse(await this.request('/clashos/inbound')) as Record<string, string | number | boolean | string[]>;
    return { allowLan: value['allow-lan'] === true, bindAddress: value['bind-address'] as string,
      users: value['users'] as string[], skipAuth: value['skip-auth-prefixes'] as string[], allowed: value['lan-allowed-ips'] as string[],
      denied: value['lan-disallowed-ips'] as string[], localAddress: value['localAddress'] as string,
      overridden: value['overridden'] === true, profile: value['profile'] as string, revision: value['revision'] as number };
  }

  async saveInboundSettings(original: ClashInboundSettings, changes?: ClashInboundChanges): Promise<void> {
    await this.request(`/clashos/inbound?profile=${encodeURIComponent(original.profile)}&revision=${original.revision}`,
      changes === undefined ? http.RequestMethod.DELETE : 'PATCH' as http.RequestMethod, changes === undefined ? undefined :
        JSON.stringify({ 'allow-lan': changes.allowLan, 'bind-address': changes.bindAddress, users: changes.users,
          'skip-auth-prefixes': changes.skipAuth, 'lan-allowed-ips': changes.allowed, 'lan-disallowed-ips': changes.denied }));
  }

  async saveProxyPorts(profile: string, ports?: ClashProxyPorts): Promise<void> {
    await this.request(`/clashos/ports?profile=${encodeURIComponent(profile)}`,
      ports === undefined ? http.RequestMethod.DELETE : 'PATCH' as http.RequestMethod,
      ports === undefined ? undefined : JSON.stringify({ http: ports.http, socks: ports.socks, mixed: ports.mixed }));
  }

  async updateRuleProvider(name: string, profile: string = ''): Promise<void> {
    await this.request(`/providers/rules/${encodeURIComponent(name)}${profile.length > 0 ? `?profile=${encodeURIComponent(profile)}` : ''}`, http.RequestMethod.PUT);
  }

  async ruleProviderPayload(name: string): Promise<ClashRulePayload> {
    return JSON.parse(await this.request(`/providers/rules/${encodeURIComponent(name)}/payload`)) as ClashRulePayload;
  }

  async importRuleProviderFile(name: string, profile: string, path: string): Promise<void> {
    await this.request(`/clahsos/rule-providers/${encodeURIComponent(name)}/file?profile=${encodeURIComponent(profile)}`,
      http.RequestMethod.PUT, JSON.stringify({ path }));
  }

  async resetRuleProviderFile(name: string, profile: string): Promise<void> {
    await this.request(`/clahsos/rule-providers/${encodeURIComponent(name)}/file?profile=${encodeURIComponent(profile)}`,
      http.RequestMethod.DELETE);
  }

  async diagnostics(): Promise<CoreDiagnostics> {
    return JSON.parse(await this.request('/clahsos/diagnostics')) as CoreDiagnostics;
  }

  async geoStatus(): Promise<ClashGeoStatus> {
    return JSON.parse(await this.request('/clahsos/geodata')) as ClashGeoStatus;
  }

  async geoAction(kind: string, profile: string, action: string, path: string = ''): Promise<void> {
    await this.request(`/clahsos/geodata/${encodeURIComponent(kind)}${action === 'update' ? '' : '/file'}`,
      action === 'clear' ? http.RequestMethod.DELETE : http.RequestMethod.PUT,
      JSON.stringify({ profile, path }), 15000);
  }

  async queryDns(name: string, type: string, server: string = ''): Promise<ClashDnsAnswer> {
    return JSON.parse(await this.request(`/dns/query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}${server.length > 0 ? `&server=${encodeURIComponent(server)}` : ''}`,
      http.RequestMethod.GET, undefined, 6500)) as ClashDnsAnswer;
  }

  async dnsStatus(): Promise<ClashDnsStatus> {
    return JSON.parse(await this.request('/clahsos/dns')) as ClashDnsStatus;
  }

  async clearDnsCache(): Promise<void> {
    await this.request('/clahsos/dns/cache', http.RequestMethod.DELETE);
  }

  async resetProviderFile(name: string, profilePath: string): Promise<void> {
    await this.request(`/clahsos/providers/${encodeURIComponent(name)}/file?profile=${encodeURIComponent(profilePath)}`,
      http.RequestMethod.DELETE);
  }

  async importProviderFile(name: string, content: string, profilePath: string): Promise<void> {
    await this.request(`/clahsos/providers/${encodeURIComponent(name)}/file?profile=${encodeURIComponent(profilePath)}`,
      http.RequestMethod.PUT, content, 65000, 'application/yaml');
  }

  async updateProvider(name: string): Promise<void> {
    await this.request(`/providers/proxies/${encodeURIComponent(name)}`, http.RequestMethod.PUT, undefined, 65000);
  }
  async checkProvider(name: string): Promise<void> {
    await this.request(`/providers/proxies/${encodeURIComponent(name)}/healthcheck`, http.RequestMethod.GET, undefined, 65000);
  }

  async groupAction(name: string, action: string): Promise<void> {
    await this.request(`/clahsos/groups/${encodeURIComponent(name)}/${action}`, http.RequestMethod.POST);
  }

  async testDelay(name: string, url: string, timeout: number = 5000): Promise<number> {
    const data: ClashDelayResponse = JSON.parse(await this.request(
      `/proxies/${encodeURIComponent(name)}/delay?timeout=${timeout}&url=${encodeURIComponent(url)}`,
      http.RequestMethod.GET, undefined, timeout + 12000)) as ClashDelayResponse;
    if (data.delay === undefined || !Number.isFinite(data.delay) || data.delay <= 0) {
      throw new Error('节点没有返回有效的延迟');
    }
    return data.delay;
  }

  async closeConnection(id: string): Promise<void> {
    await this.request(`/connections/${encodeURIComponent(id)}`, http.RequestMethod.DELETE);
  }

  async closeAllConnections(): Promise<void> {
    await this.request('/connections', http.RequestMethod.DELETE);
  }

  async closeProxyConnections(name: string): Promise<number> {
    const data: ClashConnectionsResponse = JSON.parse(await this.request('/connections')) as ClashConnectionsResponse;
    const matches: ClashConnection[] = this.parseConnections(data).filter((item: ClashConnection) => item.chains.indexOf(name) >= 0);
    for (let index: number = 0; index < matches.length; index += 4) {
      await Promise.all(matches.slice(index, index + 4).map((item: ClashConnection) => this.closeConnection(item.id)));
    }
    return matches.length;
  }

  private parseNodes(data: ClashProxiesResponse): ClashProxyNode[] {
    const nodes: ClashProxyNode[] = [];
    if (data.proxies === undefined) return nodes;
    Object.keys(data.proxies).forEach((name: string) => {
      const item: ClashProxyResponse = data.proxies![name];
      const history: ClashProxyHistory[] = item.history ?? [];
      nodes.push({ name, type: item.type ?? '', delay: history.length > 0 ? history[history.length - 1].delay ?? -1 : -1,
        udp: item.udp ?? false });
    });
    return nodes;
  }

  private parseGroups(data: ClashProxiesResponse): ClashProxyGroup[] {
    const groups: ClashProxyGroup[] = [];
    const groupTypes: string[] = ['selector', 'select', 'urltest', 'url-test', 'fallback', 'loadbalance', 'load-balance', 'relay', 'smart', 'compatible'];
    if (data.proxies === undefined) {
      return groups;
    }
    Object.keys(data.proxies).forEach((name: string) => {
      const item: ClashProxyResponse = data.proxies![name];
      const type: string = item.type ?? '';
      const normalizedType: string = type.toLowerCase();
      if (groupTypes.indexOf(normalizedType) >= 0) {
        groups.push({
          name,
          type,
          now: item.now ?? '',
          proxies: item.all ?? item.proxies ?? [],
          checking: item.checking ?? false,
          manual: item.manual ?? '',
          strategy: item.strategy ?? '',
          lastSelected: item.lastSelected ?? '',
          icon: typeof item.icon === 'string' ? item.icon : '', hidden: item.hidden === true
        });
      }
    });
    return groups;
  }

  private parseConnections(data: ClashConnectionsResponse): ClashConnection[] {
    const result: ClashConnection[] = [];
    (data.connections ?? []).forEach((item: ClashConnectionResponse, index: number) => {
      const host: string = item.metadata?.host ?? item.metadata?.destinationIP ?? '未知目标';
      result.push({
        id: item.id ?? `${index}`,
        host,
        chains: item.chains ?? [],
        rule: item.rule ?? 'MATCH',
        download: item.download ?? 0,
        upload: item.upload ?? 0,
        port: item.metadata?.destinationPort?.toString() ?? '',
        network: item.metadata?.network ?? 'tcp',
        start: item.start ?? ''
      });
    });
    return result;
  }

  private async request(path: string, method: http.RequestMethod = http.RequestMethod.GET, body?: string, readTimeout: number = 3500, contentType: string = 'application/json'): Promise<string> {
    const client: http.HttpRequest = http.createHttp();
    const headers: Record<string, string> = {
      'Accept': 'application/json',
      'Content-Type': contentType
    };
    try {
      const local: string | undefined = this.localCredentialProvider?.(this.endpoint);
      const secret: string = local === undefined ? this.secret : local;
      if (secret.length > 0) headers['Authorization'] = `Bearer ${secret}`;
      const options: http.HttpRequestOptions = {
        method,
        header: headers,
        extraData: body,
        connectTimeout: 2500,
        readTimeout
      };
      if (local !== undefined) options.usingProxy = false;
      const response: http.HttpResponse = await client.request(`${this.endpoint}${path}`, options);
      if (response.responseCode < 200 || response.responseCode >= 300) {
        let detail: string = `内核返回 HTTP ${response.responseCode}`;
        try {
          const failure: ClashErrorResponse = JSON.parse(response.result.toString()) as ClashErrorResponse;
          detail = failure.error ?? failure.message ?? detail;
        } catch (_) {
          // Keep the HTTP status when a reverse proxy returns non-JSON errors.
        }
        throw new Error(detail);
      }
      return response.result.toString();
    } catch (error) {
      throw new Error(this.errorMessage(error));
    } finally {
      client.destroy();
    }
  }

  private errorMessage(error: Object): string {
    const message: string | undefined = (error as Error).message;
    if (message !== undefined && message.length > 0) {
      return message;
    }
    return '无法连接 Clash 内核';
  }

  private normalizeMode(mode: string): string {
    const normalized: string = mode.toLowerCase();
    if (normalized === 'global') {
      return 'Global';
    }
    if (normalized === 'direct') {
      return 'Direct';
    }
    return 'Rule';
  }
}
