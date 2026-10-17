import { socket } from '@kit.NetworkKit';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { util } from '@kit.ArkTS';
import { joinBytes, OsSsSession, ssMaster, verifyOsSsVectors } from './OsSsCrypto';

interface SsReferenceConfig { address: string; port: number; cipher: string; password: string; }
type Counter = (name: string, amount?: number) => void;

// Removable diagnostic application only. Fixed public HTTPS destinations, one
// in-memory SS endpoint, independent OS sockets/crypto; never log or export keys.
class ReferencePeer {
  private upstream: socket.TCPSocket = socket.constructTCPSocketInstance();
  private head: Uint8Array = new Uint8Array(0);
  private upload: Promise<void> = Promise.resolve();
  private download: Promise<void> = Promise.resolve();
  private started: boolean = false;
  private closed: boolean = false;
  private delivered: number = 0;
  private session: OsSsSession;
  private encoder: util.TextEncoder = new util.TextEncoder();
  private client: socket.TCPSocketConnection;
  private config: SsReferenceConfig;
  private count: Counter;
  private finished: () => void;
  constructor(client: socket.TCPSocketConnection, config: SsReferenceConfig,
    master: Uint8Array, count: Counter, finished: () => void) {
    this.client = client; this.config = config; this.count = count; this.finished = finished;
    this.session = new OsSsSession(master);
    this.client.on('message', (message: socket.SocketMessageInfo): void => {
      const data = new Uint8Array(message.message);
      this.upload = this.upload.then(() => this.send(data)).catch(() => this.fail('uploadErrors'));
    });
    this.client.on('close', (): void => { this.stop(); });
    this.client.on('error', (): void => { this.fail('clientErrors'); });
    this.upstream.on('message', (message: socket.SocketMessageInfo): void => {
      const data = new Uint8Array(message.message);
      this.download = this.download.then(async (): Promise<void> => {
        if (this.closed) return; this.count('wireDownloadBytes', data.length);
        for (const plain of this.session.feed(data)) {
          await this.client.send({ data: plain.buffer as ArrayBuffer }); this.delivered += plain.length; this.count('plainDownloadBytes', plain.length);
        }
      }).catch(() => this.fail('decodeErrors'));
    });
    this.upstream.on('close', (): void => {
      // Socket close follows queued records; drain them before closing the
      // HTTPKit client, otherwise the reference itself could lose a reply.
      this.download = this.download.then(async (): Promise<void> => {
        if (this.closed) return;
        if (!this.delivered) this.count('remoteEofBeforeData');
        try { this.session.finish(); } catch (_) { this.count('truncatedReplies'); }
        await this.stop();
      });
    });
    this.upstream.on('error', (): void => { this.download = this.download.then(() => this.fail('upstreamErrors')); });
  }
  private async send(bytes: Uint8Array): Promise<void> {
    if (this.closed) return;
    if (!this.started) {
      this.head = joinBytes(this.head, bytes); if (this.head.length > 32768) throw new Error('header');
      let end: number = -1; for (let i: number = 0; i + 3 < this.head.length; i++) if (this.head[i] === 13 && this.head[i + 1] === 10 && this.head[i + 2] === 13 && this.head[i + 3] === 10) { end = i; break; }
      if (end < 0) return;
      const header = util.TextDecoder.create('utf-8').decodeToString(this.head.slice(0, end));
      const match = /^CONNECT (www\.google\.com|www\.gstatic\.com|api\.github\.com):443 HTTP\/1\.[01]\r\n/.exec(header + '\r\n');
      if (!match) throw new Error('destination');
      const host = this.encoder.encodeInto(match[1]), prefix = this.head.slice(end + 4); this.head = new Uint8Array(0); this.started = true;
      await this.upstream.connect({ address: { address: this.config.address, port: this.config.port, family: 1 }, timeout: 8000 });
      if (this.closed) return; this.count('connected');
      const salt = cryptoFramework.createRandom().generateRandomSync(this.config.cipher === 'aes-128-gcm' ? 16 : 32).data;
      const target = joinBytes(new Uint8Array([3, host.length]), joinBytes(host, new Uint8Array([1, 187])));
      const first = joinBytes(this.session.start(salt), this.session.encode(target));
      await this.upstream.send({ data: first.buffer as ArrayBuffer }); this.count('wireUploadBytes', first.length);
      if (this.closed) return;
      await this.client.send({ data: this.encoder.encodeInto('HTTP/1.1 200 Connection Established\r\n\r\n').buffer as ArrayBuffer });
      if (prefix.length) await this.send(prefix); return;
    }
    for (let offset: number = 0; offset < bytes.length && !this.closed; offset += 16383) {
      const wire = this.session.encode(bytes.slice(offset, offset + 16383));
      await this.upstream.send({ data: wire.buffer as ArrayBuffer }); this.count('wireUploadBytes', wire.length);
    }
  }
  private async fail(name: string): Promise<void> { if (this.closed) return; this.count(name); await this.stop(); }
  async stop(): Promise<void> {
    if (this.closed) return; this.closed = true;
    try { await this.client.close(); } catch (_) {}
    try { await this.upstream.close(); } catch (_) {}
    this.finished();
  }
}

export class OsSsReference {
  private server?: socket.TCPSocketServer;
  private config?: SsReferenceConfig;
  private master: Uint8Array = new Uint8Array(0);
  private peers: ReferencePeer[] = [];
  private checks: number = 0;
  private ready: boolean = false;
  private counters: Record<string, number> = {};
  selfTest(text: string): string { this.checks = verifyOsSsVectors(text); return JSON.stringify({ passed: this.checks > 0, checks: this.checks, ciphers: ['aes-128-gcm', 'aes-256-gcm'] }); }
  async configure(text: string): Promise<void> {
    if (!this.checks) throw new Error('self-test');
    const config = JSON.parse(text) as SsReferenceConfig;
    if (typeof config.address !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(config.address) || config.address.split('.').some((value: string) => Number(value) > 255) ||
      !Number.isInteger(config.port) || config.port < 1 || config.port > 65535 || !['aes-128-gcm', 'aes-256-gcm'].includes(config.cipher) || typeof config.password !== 'string' || config.password.length > 4096) throw new Error('config');
    const master = ssMaster(config.password, config.cipher === 'aes-128-gcm' ? 16 : 32);
    await this.stop(); this.config = config; this.master = master; this.counters = {};
    this.server = socket.constructTCPSocketServerInstance();
    this.server.on('connect', (client: socket.TCPSocketConnection): void => {
      this.bump('accepted'); if (!this.config || this.peers.length >= 8) { client.close().catch(() => {}); return; }
      const peer = new ReferencePeer(client, this.config, this.master, (key: string, count: number = 1): void => this.bump(key, count), (): void => { this.peers = this.peers.filter((value: ReferencePeer) => value !== peer); });
      this.peers.push(peer);
    });
    await this.server.listen({ address: '127.0.0.1', port: 18106, family: 1 }); this.ready = true;
  }
  private bump(key: string, count: number = 1): void { this.counters[key] = (this.counters[key] || 0) + count; }
  status(): string { return JSON.stringify({ ready: this.ready, configured: this.config !== undefined, selfTestChecks: this.checks, activeConnections: this.peers.length, counters: this.counters }); }
  async stop(): Promise<void> {
    this.ready = false; if (this.server) { try { await this.server.close(); } catch (_) {} this.server = undefined; }
    await Promise.all(this.peers.slice().map((peer: ReferencePeer) => peer.stop())); this.config = undefined; this.master.fill(0); this.master = new Uint8Array(0);
  }
}
