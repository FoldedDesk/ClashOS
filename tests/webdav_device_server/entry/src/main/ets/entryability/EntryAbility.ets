import { UIAbility } from '@kit.AbilityKit';
import { window } from '@kit.ArkUI';
import { socket } from '@kit.NetworkKit';
import { util } from '@kit.ArkTS';
import xml from '@ohos.xml';
import { pasteboard } from '@kit.BasicServicesKit';
import { VlessFixtureServer } from './VlessFixtureServer';
import { probeVlessUdp } from './VlessFixtureProbe';
import { probeNetworkHttps } from './NetworkFixtureProbe';
import { HttpIngressFixtureServer } from './HttpIngressFixtureServer';
import { OsSsReference } from './OsSsReference';
import { SubscriptionFixture } from './SubscriptionFixture';

interface FixtureFile { text: string; revision: number; }

// An independent HTTP/WebDAV fixture in a separate, removable test application.
// Real user backup payloads are never logged and are held only in volatile memory.
export default class EntryAbility extends UIAbility {
  private server: socket.TCPSocketServer = socket.constructTCPSocketServerInstance();
  private files: Map<string, FixtureFile> = new Map();
  private collection: boolean = false;
  private mode: string = '';
  private methods: Record<string, number> = {};
  private clients: socket.TCPSocketConnection[] = [];
  private encoder: util.TextEncoder = new util.TextEncoder();
  private vless: VlessFixtureServer = new VlessFixtureServer();
  private httpIngress: HttpIngressFixtureServer = new HttpIngressFixtureServer();
  private ssReference: OsSsReference = new OsSsReference();
  private subscription: SubscriptionFixture = new SubscriptionFixture();

  onCreate(): void {
    this.server.on('connect', (client: socket.TCPSocketConnection): void => this.accept(client));
    this.server.listen({ address: '127.0.0.1', port: 18088, family: 1 }).catch(() => console.error('WebDAV fixture could not listen'));
  }

  onWindowStageCreate(stage: window.WindowStage): void { stage.loadContent('pages/Index'); }

  onDestroy(): void {
    this.vless.stop();
    this.httpIngress.stop();
    this.ssReference.stop();
    this.clients.forEach((client: socket.TCPSocketConnection) => client.close().catch(() => {}));
    this.server.close().catch(() => {}); this.files.clear();
  }

  private accept(client: socket.TCPSocketConnection): void {
    this.clients.push(client);
    let bytes = new Uint8Array(0);
    let handled: boolean = false;
    let continued: boolean = false;
    client.on('message', (message: socket.SocketMessageInfo): void => {
      if (handled) return;
      const incoming = new Uint8Array(message.message);
      const next = new Uint8Array(bytes.length + incoming.length); next.set(bytes); next.set(incoming, bytes.length); bytes = next;
      if (bytes.length > 34 * 1024 * 1024) { handled = true; this.respond(client, 413, ''); return; }
      let end: number = -1;
      for (let index: number = 0; index + 3 < bytes.length; index++) {
        if (bytes[index] === 13 && bytes[index + 1] === 10 && bytes[index + 2] === 13 && bytes[index + 3] === 10) { end = index; break; }
      }
      if (end < 0) { if (bytes.length > 65536) { handled = true; this.respond(client, 431, ''); } return; }
      const header: string = util.TextDecoder.create('utf-8').decodeToString(bytes.slice(0, end));
      const lines: string[] = header.split('\r\n');
      const first: string[] = lines.shift()!.split(' ');
      const fields: Record<string, string> = {};
      lines.forEach((line: string) => { const colon: number = line.indexOf(':'); if (colon > 0) fields[line.substring(0, colon).toLowerCase()] = line.substring(colon + 1).trim(); });
      if (fields['expect']?.toLowerCase() === '100-continue' && !continued) { continued = true; client.send({ data: this.encoder.encodeInto('HTTP/1.1 100 Continue\r\n\r\n').buffer as ArrayBuffer }).catch(() => {}); }
      const length: number = Number(fields['content-length'] ?? '0');
      if (!Number.isInteger(length) || length < 0 || length > 32 * 1024 * 1024 || fields['transfer-encoding']) { handled = true; this.respond(client, 400, ''); return; }
      if (bytes.length < end + 4 + length) return;
      handled = true;
      const body: string = length === 0 ? '' : util.TextDecoder.create('utf-8').decodeToString(bytes.slice(end + 4, end + 4 + length));
      this.handle(client, first[0], first[1], fields, body);
    });
    client.on('close', (): void => { this.clients = this.clients.filter((item: socket.TCPSocketConnection) => item !== client); });
  }

  private respond(client: socket.TCPSocketConnection, status: number, text: string, headers: string = ''): void {
    const body: Uint8Array = text.length === 0 ? new Uint8Array(0) : this.encoder.encodeInto(text);
    const head: Uint8Array = this.encoder.encodeInto(`HTTP/1.1 ${status} Fixture\r\nConnection: close\r\nContent-Length: ${body.length}\r\n${headers}\r\n`);
    const bytes = new Uint8Array(head.length + body.length); bytes.set(head); bytes.set(body, head.length);
    client.send({ data: bytes.buffer as ArrayBuffer }).finally(() => client.close().catch(() => {})).catch(() => {});
  }

  private handle(client: socket.TCPSocketConnection, method: string, path: string, headers: Record<string, string>, body: string): void {
    if (path === '/test-admin/subscription/state') { this.respond(client, 200, this.subscription.state()); return; }
    if (path.startsWith('/test-admin/subscription/mode/')) {
      const mode: string = path.substring('/test-admin/subscription/mode/'.length);
      if (!['ready', 'custom', 'bad-http', 'invalid-config', 'slow', 'no-metadata', 'port-conflict'].includes(mode)) { this.respond(client, 400, ''); return; }
      this.subscription.mode = mode; this.respond(client, 200, this.subscription.state()); return;
    }
    if (path === '/test-admin/subscription/source') { this.respond(client, 200, this.subscription.source); return; }
    if (path === '/public-install-links') { this.respond(client, 200, this.subscription.installPage(), 'Content-Type: text/html; charset=utf-8\r\n'); return; }
    if (path === '/public-home') { this.subscription.homeRequests++; this.respond(client, 200, '<html><title>ClashOS public subscription fixture</title><body>Public subscription homepage</body></html>', 'Content-Type: text/html\r\n'); return; }
    if (path.split('?')[0] === '/public-subscription.yaml' && method === 'GET') {
      if (!this.subscription.accept(headers['user-agent'] ?? '', path) || this.subscription.mode === 'bad-http') { this.respond(client, 401, ''); return; }
      if (this.subscription.mode === 'slow') { setTimeout(() => this.respond(client, 200, this.subscription.source, this.subscription.headers()), 4000); return; }
      this.respond(client, 200, this.subscription.mode === 'invalid-config' ? 'NOT A CONFIG' : this.subscription.mode === 'port-conflict' ? this.subscription.source.replace('port: 18890', 'port: 18088') : this.subscription.source, this.subscription.headers()); return;
    }
    if (path === '/test-admin/ss-reference/self-test' && method === 'POST') {
      this.context.resourceManager.getRawFileContent('ss/reference-vectors.json').then((data: Uint8Array) => {
        try { this.respond(client, 200, this.ssReference.selfTest(util.TextDecoder.create('utf-8').decodeToString(data))); }
        catch (error) { this.respond(client, 500, JSON.stringify({ passed: false, publicVectorError: (error as Error).message })); }
      }).catch(() => this.respond(client, 500, '{"passed":false}')); return;
    }
    if (path === '/test-admin/ss-reference/config' && method === 'POST') { this.ssReference.configure(body).then(() => this.respond(client, 200, this.ssReference.status())).catch(() => this.respond(client, 400, '{}')); return; }
    if (path === '/test-admin/ss-reference/state') { this.respond(client, 200, this.ssReference.status()); return; }
    if (path === '/test-admin/ss-reference/stop' && method === 'POST') { this.ssReference.stop().then(() => this.respond(client, 200, this.ssReference.status())); return; }
    if (path === '/test-admin/http/start' && method === 'POST') { this.httpIngress.start(); this.respond(client, 200, '{}'); return; }
    if (path === '/test-admin/http/release' && method === 'POST') { this.httpIngress.releaseEarly().then(() => this.respond(client, 200, '{}')).catch(() => this.respond(client, 500, '{}')); return; }
    if (path === '/test-admin/http/state') { this.respond(client, 200, this.httpIngress.status()); return; }
    if (path.startsWith('/test-admin/https/') && method === 'POST') {
      const parts: string[] = path.substring('/test-admin/https/'.length).split('/');
      if (parts.length > 2) { this.respond(client, 400, '{}'); return; }
      probeNetworkHttps(parts[0], parts[1] || '').then((result: string) => this.respond(client, 200, result)).catch(() => this.respond(client, 400, '{}')); return;
    }
    if (path === '/test-admin/vless/start' && method === 'POST') { this.vless.start(this.context); this.respond(client, 200, '{}'); return; }
    if (path === '/test-admin/forward/start' && method === 'POST') { this.vless.start(this.context); this.respond(client, 200, '{}'); return; }
    if (path === '/test-admin/forward/probe' && method === 'POST') { probeVlessUdp('forward.device.test').then((result: string) => this.respond(client, 200, result)).catch(() => this.respond(client, 500, '{}')); return; }
    if (path === '/test-admin/vless/state') { this.respond(client, 200, this.vless.status()); return; }
    if (path === '/test-admin/vless/probe' && method === 'POST') { probeVlessUdp().then((result: string) => this.respond(client, 200, result)).catch(() => this.respond(client, 500, '{}')); return; }
    if (path === '/test-admin/clipboard' && method === 'POST') {
      if (body.length > 256 * 1024) { this.respond(client, 413, ''); return; }
      // Fixture input only. This endpoint never reads or returns clipboard contents.
      pasteboard.getSystemPasteboard().setData(pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, body))
        .then(() => this.respond(client, 200, '{}')).catch(() => this.respond(client, 500, '{}'));
      return;
    }
    if (path === '/test-admin/xml-events') {
      const events: string[] = [];
      const parser = new xml.XmlPullParser(this.encoder.encodeInto('<d:root xmlns:d="DAV:"><d:getetag>&quot;fixture-2&quot;</d:getetag></d:root>').buffer as ArrayBuffer, 'UTF-8');
      parser.parse({ supportDoctype: false, ignoreNameSpace: false, tokenValueCallbackFunction: (event: xml.EventType, info: xml.ParseInfo): boolean => {
        if (event === xml.EventType.TEXT || event === xml.EventType.ENTITY_REFERENCE) events.push(JSON.stringify({ event, name: info.getName(), text: info.getText() }));
        return true;
      } });
      this.respond(client, 200, `[${events.join(',')}]`); return;
    }
    if (path === '/test-admin/state') {
      this.respond(client, 200, JSON.stringify({ methods: this.methods, files: Array.from(this.files.keys()), mode: this.mode, count: this.files.size })); return;
    }
    if (path.startsWith('/test-admin/mode/')) {
      this.mode = path.substring('/test-admin/mode/'.length);
      if (this.mode === 'change-etag') this.files.forEach((file: FixtureFile) => file.revision++);
      this.respond(client, 200, '{}'); return;
    }
    this.methods[method] = (this.methods[method] ?? 0) + 1;
    if (headers['if-match']) this.methods['IF-MATCH'] = (this.methods['IF-MATCH'] ?? 0) + 1;
    const authorization: string = 'Basic ' + new util.Base64Helper().encodeToStringSync(this.encoder.encodeInto('fixture:clashos-webdav-test'));
    if (headers['authorization'] !== authorization) { this.respond(client, 401, '', 'WWW-Authenticate: Basic realm="ClashOS fixture"\r\n'); return; }
    const directory: string = '/dav/ClashOS/';
    if (method === 'MKCOL' && path === directory) { const exists: boolean = this.collection; this.collection = true; this.respond(client, exists ? 405 : 201, ''); return; }
    if (method === 'PROPFIND' && path === directory) {
      if (!this.collection) { this.respond(client, 404, ''); return; }
      if (this.mode === 'bad-list') { this.respond(client, 207, '<broken>'); return; }
      let text: string = '<?xml version="1.0" encoding="utf-8"?><multistatus xmlns="DAV:"><response><href>/dav/ClashOS/</href><propstat><prop><resourcetype><collection/></resourcetype></prop><status>HTTP/1.1 200 OK</status></propstat></response>';
      this.files.forEach((file: FixtureFile, name: string) => {
        text += `<response><href>${directory}${name}</href><propstat><prop><getetag>&quot;fixture-${file.revision}&quot;</getetag><getcontentlength>${this.encoder.encodeInto(file.text).length}</getcontentlength><getlastmodified>Sat, 17 Oct 2026 00:00:00 GMT</getlastmodified><resourcetype/></prop><status>HTTP/1.1 200 OK</status></propstat><propstat><prop><getetag>ignored</getetag></prop><status>HTTP/1.1 404 Not Found</status></propstat></response>`;
      });
      text += '<response><href>http://untrusted.example.invalid/dav/ClashOS/clashos-backup-1792190000000-00000000000000000000000000000000.json</href><propstat><prop><resourcetype/></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>';
      this.respond(client, 207, text, 'Content-Type: application/xml; charset=utf-8\r\n'); return;
    }
    if (!path.startsWith(directory)) { this.respond(client, 404, ''); return; }
    const name: string = path.substring(directory.length);
    if (!/^clashos-backup-\d{13}-[0-9a-f]{32}\.json$/.test(name)) { this.respond(client, 404, ''); return; }
    const current: FixtureFile | undefined = this.files.get(name);
    if (headers['if-match'] && (!current || headers['if-match'] !== `"fixture-${current.revision}"`)) { this.respond(client, 412, ''); return; }
    if (method === 'PUT') {
      if (this.mode === 'fail-put') { this.respond(client, 500, ''); return; }
      if (current && headers['if-none-match'] === '*') { this.respond(client, 412, ''); return; }
      this.files.set(name, { text: body, revision: (current?.revision ?? 0) + 1 }); this.respond(client, 201, ''); return;
    }
    if (!current) { this.respond(client, 404, ''); return; }
    if (method === 'GET') { this.respond(client, 200, this.mode === 'corrupt-get' ? '{}' : current.text, 'Content-Type: application/json\r\n'); return; }
    if (method === 'DELETE') { this.files.delete(name); this.respond(client, 204, ''); return; }
    this.respond(client, 405, '');
  }
}
