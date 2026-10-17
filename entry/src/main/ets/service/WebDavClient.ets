import { rcp } from '@kit.RemoteCommunicationKit';
import { util } from '@kit.ArkTS';
import url from '@ohos.url';
import xml from '@ohos.xml';
import { BACKUP_LIMIT, BACKUP_FILE_PATTERN, BackupEntry, WebDavSettings } from './BackupTypes';
import { utf8Bytes } from './TextCodec';

interface DavProperties {
  bytes: string;
  modified: string;
  etag: string;
  hasType: boolean;
  collection: boolean;
}

interface DavResponse {
  href: string;
  status: string;
  properties: DavProperties;
}

interface DavHttpResponse {
  status: number;
  text: string;
}

function emptyProperties(): DavProperties {
  return { bytes: '', modified: '', etag: '', hasType: false, collection: false };
}

function decodedPath(path: string): string {
  return path.split('/').map((part: string): string => {
    const value: string = decodeURIComponent(part);
    if (/[\\/\u0000-\u001f\u007f]/.test(value)) throw new Error('WebDAV 目录路径无效');
    return value;
  }).join('/');
}

export function webDavCollection(settings: WebDavSettings): string {
  try {
    const parsed = new url.URL(settings.url.trim());
    if ((parsed.protocol !== 'https:' && parsed.protocol !== 'http:') || !parsed.hostname || parsed.username || parsed.password || parsed.search || parsed.hash ||
      /[\u0000-\u0020\u007f]/.test(settings.url.trim()) || settings.username.indexOf(':') >= 0) throw new Error('invalid');
    decodedPath(parsed.pathname);
    return `${parsed.href.replace(/\/$/, '')}/ClashOS/`;
  } catch (_) { throw new Error('请输入完整的 HTTP/HTTPS WebDAV 目录地址，不含查询参数或账号；用户名不能包含冒号'); }
}

function strongEtag(value: string): string {
  return value.length <= 512 && /^"[\x21\x23-\x7e\u0080-\u00ff]*"$/.test(value) ? value : '';
}

export function parseDavListing(text: string, collection: string): BackupEntry[] {
  if (text.length === 0 || utf8Bytes(text).length > 1024 * 1024 || /<!\s*(?:DOCTYPE|ENTITY)\b/i.test(text)) throw new Error('WebDAV 列表过大或包含不受支持的 XML');
  const responses: DavResponse[] = [];
  const stack: string[] = [];
  let current: DavResponse | undefined = undefined;
  let pending: DavProperties = emptyProperties();
  let pendingStatus: string = '';
  let rootSeen: boolean = false;
  try {
    const parser = new xml.XmlPullParser(utf8Bytes(text).buffer as ArrayBuffer, 'UTF-8');
    parser.parse({ supportDoctype: false, ignoreNameSpace: false,
      tokenValueCallbackFunction: (event: xml.EventType, info: xml.ParseInfo): boolean => {
        if (event === xml.EventType.START_TAG) {
          const name: string = info.getNamespace() === 'DAV:' ? info.getName().split(':').pop() ?? '' : '';
          stack.push(name);
          if (stack.length > 32) throw new Error('depth');
          if (stack.length === 1) { if (name !== 'multistatus' || rootSeen) throw new Error('root'); rootSeen = true; }
          if (stack.length === 2 && name === 'response') current = { href: '', status: '', properties: emptyProperties() };
          if (current !== undefined && stack.length === 3 && name === 'propstat') { pending = emptyProperties(); pendingStatus = ''; }
          if (current !== undefined && stack.join('/') === 'multistatus/response/propstat/prop/resourcetype') pending.hasType = true;
          if (current !== undefined && stack.join('/') === 'multistatus/response/propstat/prop/resourcetype/collection') pending.collection = true;
        } else if (event === xml.EventType.TEXT || event === xml.EventType.CDSECT || event === xml.EventType.ENTITY_REFERENCE) {
          if (current === undefined) return true;
          const path: string = stack.join('/');
          const value: string = info.getText();
          if (value.length > 65536) throw new Error('value');
          if (path === 'multistatus/response/href') current.href += value;
          else if (path === 'multistatus/response/status') current.status += value;
          else if (path === 'multistatus/response/propstat/status') pendingStatus += value;
          else if (path === 'multistatus/response/propstat/prop/getcontentlength') pending.bytes += value;
          else if (path === 'multistatus/response/propstat/prop/getlastmodified') pending.modified += value;
          else if (path === 'multistatus/response/propstat/prop/getetag') pending.etag += value;
        } else if (event === xml.EventType.END_TAG) {
          if (current !== undefined && stack.length === 3 && stack[2] === 'propstat' && /^HTTP\/\d(?:\.\d)?\s+2\d\d(?:\s|$)/.test(pendingStatus.trim())) {
            if (pending.bytes) current.properties.bytes = pending.bytes;
            if (pending.modified) current.properties.modified = pending.modified;
            if (pending.etag) current.properties.etag = pending.etag;
            if (pending.hasType) { current.properties.hasType = true; current.properties.collection = pending.collection; }
          }
          if (current !== undefined && stack.length === 2 && stack[1] === 'response') { responses.push(current); current = undefined; if (responses.length > 2000) throw new Error('count'); }
          stack.pop();
        }
        return true;
      }
    });
    if (!rootSeen || stack.length !== 0) throw new Error('incomplete');
  } catch (_) { throw new Error('WebDAV 返回的文件列表不是有效的 DAV XML'); }
  const base = new url.URL(collection);
  const basePath: string = decodedPath(base.pathname);
  const seen: string[] = [];
  const entries: BackupEntry[] = [];
  responses.forEach((response: DavResponse) => {
    try {
      if (response.status && !/^HTTP\/\d(?:\.\d)?\s+2\d\d(?:\s|$)/.test(response.status.trim())) return;
      if (!response.properties.hasType || response.properties.collection) return;
      const target = new url.URL(response.href.trim(), collection);
      if (target.origin !== base.origin || target.username || target.password || target.search || target.hash) return;
      const path: string = decodedPath(target.pathname);
      if (!path.startsWith(basePath)) return;
      const name: string = path.substring(basePath.length);
      if (!BACKUP_FILE_PATTERN.test(name) || seen.indexOf(name) >= 0) return;
      const bytes: string = response.properties.bytes.trim();
      const modified: number = Date.parse(response.properties.modified.trim());
      entries.push({ name, bytes: /^\d{1,12}$/.test(bytes) ? Number(bytes) : 0,
        updatedAt: Number.isFinite(modified) ? new Date(modified).toISOString() : '', remote: true,
        etag: strongEtag(response.properties.etag.trim()) });
      seen.push(name);
    } catch (_) { /* Only direct children of the chosen dedicated collection are actionable. */ }
  });
  return entries.sort((a: BackupEntry, b: BackupEntry) => b.name.localeCompare(a.name));
}

export class WebDavClient {
  readonly collection: string;
  private authorization: string;
  private sessions: rcp.Session[] = [];
  private closed: boolean = false;

  constructor(settings: WebDavSettings) {
    this.collection = webDavCollection(settings);
    this.authorization = settings.username.length > 0 || settings.password.length > 0 ?
      `Basic ${new util.Base64Helper().encodeToStringSync(utf8Bytes(`${settings.username}:${settings.password}`))}` : '';
  }

  close(): void {
    this.closed = true;
    this.sessions.forEach((session: rcp.Session) => { try { session.cancel(); session.close(); } catch (_) {} });
    this.sessions = [];
  }

  private async request(method: string, name: string = '', body: string = '', etag: string = '', createOnly: boolean = false, modified: string = ''): Promise<DavHttpResponse> {
    if (this.closed) throw new Error('WebDAV 操作已取消');
    if (name && !BACKUP_FILE_PATTERN.test(name)) throw new Error('WebDAV 备份名称无效');
    const session = rcp.createSession({ requestConfiguration: { transfer: { autoRedirect: false,
      timeout: { connectMs: 10000, transferMs: 45000 } } } });
    this.sessions.push(session);
    const headers: rcp.RequestHeaders = { 'User-Agent': 'ClashOS/1.0', 'Accept': method === 'PROPFIND' ? 'application/xml, text/xml' : 'application/json',
      'Content-Type': method === 'PROPFIND' ? 'application/xml; charset=utf-8' : 'application/json; charset=utf-8' };
    if (this.authorization) headers['Authorization'] = this.authorization;
    if (method === 'PROPFIND') headers['Depth'] = '1';
    const condition: string = strongEtag(etag);
    if (condition) headers['If-Match'] = condition;
    else if (modified && Number.isFinite(Date.parse(modified))) headers['If-Unmodified-Since'] = new Date(modified).toUTCString();
    if (createOnly) headers['If-None-Match'] = '*';
    const request = new rcp.Request(this.collection + name, method, headers, body.length > 0 ? body : undefined);
    const limit: number = method === 'PROPFIND' ? 1024 * 1024 : method === 'GET' ? BACKUP_LIMIT : 65536;
    const chunks: Uint8Array[] = [];
    let length: number = 0;
    let oversized: boolean = false;
    request.destination = (buffer: ArrayBuffer): void => {
      length += buffer.byteLength;
      if (length > limit) { oversized = true; session.cancel(request); return; }
      chunks.push(new Uint8Array(buffer).slice());
    };
    try {
      const response: rcp.Response = await session.fetch(request);
      if (oversized) throw new Error('oversized');
      const bytes = new Uint8Array(length);
      let offset: number = 0;
      chunks.forEach((chunk: Uint8Array) => { bytes.set(chunk, offset); offset += chunk.length; });
      const text: string = bytes.length === 0 ? '' : util.TextDecoder.create('utf-8', { fatal: true }).decodeToString(bytes);
      if (response.statusCode >= 300 && response.statusCode < 400) throw new Error('redirect');
      return { status: response.statusCode, text };
    } catch (error) {
      if (oversized) throw new Error(method === 'GET' ? 'WebDAV 备份超过 32 MB' : 'WebDAV 响应超过大小上限');
      if (this.closed) throw new Error('WebDAV 操作已取消');
      if ((error as Error).message === 'redirect') throw new Error('WebDAV 地址发生重定向，请填写最终目录地址');
      throw new Error('WebDAV 请求失败，请检查网络、服务器和证书');
    } finally {
      this.sessions = this.sessions.filter((item: rcp.Session) => item !== session);
      try { session.close(); } catch (_) {}
    }
  }

  private requireStatus(response: DavHttpResponse, codes: number[]): void {
    if (codes.indexOf(response.status) >= 0) return;
    if (response.status === 401 || response.status === 403) throw new Error('WebDAV 账号、密码或目录权限不正确');
    if (response.status === 412) throw new Error('WebDAV 备份已变化或同名文件已存在，请刷新列表');
    if (response.status === 409) throw new Error('WebDAV 父目录不存在，请先在服务器创建该目录');
    throw new Error(`WebDAV 服务器返回 HTTP ${response.status}`);
  }

  async list(): Promise<BackupEntry[]> {
    const response = await this.request('PROPFIND', '', '<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getcontentlength/><d:getlastmodified/><d:getetag/></d:prop></d:propfind>');
    if (response.status === 404) return [];
    this.requireStatus(response, [207]);
    return parseDavListing(response.text, this.collection);
  }

  async upload(entry: BackupEntry, text: string): Promise<void> {
    if (utf8Bytes(text).length > BACKUP_LIMIT) throw new Error('备份超过 32 MB');
    const collection = await this.request('MKCOL');
    this.requireStatus(collection, [201, 405]);
    const result = await this.request('PUT', entry.name, text, '', true);
    this.requireStatus(result, [200, 201, 204]);
    const downloaded = await this.request('GET', entry.name);
    this.requireStatus(downloaded, [200]);
    if (downloaded.text !== text) throw new Error('WebDAV 上传后校验失败，本地备份已保留');
  }

  async download(entry: BackupEntry): Promise<string> {
    if (!entry.remote || entry.bytes > BACKUP_LIMIT) throw new Error('WebDAV 备份无效或超过 32 MB');
    const response = await this.request('GET', entry.name, '', entry.etag, false, entry.updatedAt);
    this.requireStatus(response, [200]); return response.text;
  }

  async remove(entry: BackupEntry): Promise<void> {
    if (!entry.remote) throw new Error('请选择 WebDAV 备份');
    if (!strongEtag(entry.etag) && !Number.isFinite(Date.parse(entry.updatedAt))) throw new Error('WebDAV 服务器未提供文件版本或修改时间，无法安全删除；请在服务器管理该文件');
    const response = await this.request('DELETE', entry.name, '', entry.etag, false, entry.updatedAt);
    this.requireStatus(response, [200, 204]);
  }
}
