import { socket } from '@kit.NetworkKit';
import { common } from '@kit.AbilityKit';
import { util } from '@kit.ArkTS';
import { joinBytes as join } from './OsSsCrypto';
import { OsSs2022Session, ss22Random, ss22Subkey, ss22Hash, ss22Number, ss22Read, ss22Equal, ss22Aead, ss22Block, ss22XChaCha, ss22Address, ss22Time, ss22SelfTest } from './OsSs2022Crypto';

type Count = (key: string) => void;
class Ss22TcpPeer {
  private upstream: socket.TCPSocket = socket.constructTCPSocketInstance();
  private client: socket.TCPSocketConnection;
  private codec: OsSs2022Session;
  private upload: Promise<void> = Promise.resolve();
  private download: Promise<void> = Promise.resolve();
  private connected: boolean = false;
  private closed: boolean = false;
  private count: Count;
  private finished: () => void;
  constructor(client: socket.TCPSocketConnection, method: string, keys: Uint8Array[], count: Count, finished: () => void) {
    this.client = client; this.codec = new OsSs2022Session(method, keys); this.count = count; this.finished = finished;
    client.on('message', (message: socket.SocketMessageInfo): void => {
      const bytes = new Uint8Array(message.message);
      this.upload = this.upload.then(async (): Promise<void> => {
        if (this.closed) return; const bodies = this.codec.feed(bytes);
        if (!this.connected && this.codec.target) {
          const target = this.codec.target;
          if (target.host !== '127.0.0.1' || ![18088, 18098].includes(target.port)) throw new Error('public-destination');
          await this.upstream.connect({ address: { address: target.host, port: target.port, family: 1 }, timeout: 4000 });
          this.connected = true; this.count('tcp-handshake');
        }
        for (const body of bodies) await this.upstream.send({ data: body.buffer as ArrayBuffer });
      }).catch(() => { this.count('tcp-rejected'); this.stop(); });
    });
    client.on('close', (): void => { this.upload.then(() => this.stop()); });
    this.upstream.on('message', (message: socket.SocketMessageInfo): void => {
      const bytes = new Uint8Array(message.message);
      this.download = this.download.then(async (): Promise<void> => { if (!this.closed) { const wire = this.codec.encode(bytes); await this.client.send({ data: wire.buffer as ArrayBuffer }); this.count('tcp-response'); } }).catch(() => this.stop());
    });
    this.upstream.on('close', (): void => { this.download.then(() => this.stop()); });
    this.upstream.on('error', (): void => { this.count('upstream-error'); this.stop(); });
  }
  async stop(): Promise<void> {
    if (this.closed) return; this.closed = true;
    await Promise.all([this.client.close().catch(() => {}), this.upstream.close().catch(() => {})]); this.finished();
  }
}
interface Ss22UdpState { server: Uint8Array; counter: number; seen: Set<string>; used: number; }

// Independent device peer: public fixed keys, loopback-only HTTP/TLS origins and
// a fixed synthetic DNS answer. No real subscription or arbitrary target API.
export class OsSs2022Server {
  private tcp: socket.TCPSocketServer[] = [];
  private udp: socket.UDPSocket[] = [];
  private peers: Ss22TcpPeer[] = [];
  private sessions: Map<string, Ss22UdpState> = new Map();
  private counters: Record<string, number> = {};
  private ready: number[] = [];
  private checks: number = 0;
  private methods: string[] = ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-aes-128-gcm'];
  private identities: number[] = [0, 0, 0, 1, 1, 2];
  async start(context: common.UIAbilityContext): Promise<void> {
    await this.stop(); this.counters = {}; this.ready = [];
    this.checks = ss22SelfTest(util.TextDecoder.create('utf-8').decodeToString(await context.resourceManager.getRawFileContent('ss/2022-vectors.json')));
    for (let index: number = 0; index < this.methods.length; ++index) {
      const method: string = this.methods[index], size: number = method.includes('aes-128') ? 16 : 32, keys: Uint8Array[] = [];
      for (let layer: number = 0; layer <= this.identities[index]; ++layer) { const key = new Uint8Array(size); for (let i: number = 0; i < size; ++i) key[i] = (i + 31 * layer) & 255; keys.push(key); }
      const tcp = socket.constructTCPSocketServerInstance(), udp = socket.constructUDPSocketInstance(), port: number = 18894 + index;
      tcp.on('connect', (client: socket.TCPSocketConnection): void => {
        if (this.peers.length >= 16) { client.close().catch(() => {}); return; }
        this.bump('tcp-accepted-' + index);
        const peer = new Ss22TcpPeer(client, method, keys, (key: string): void => this.bump(key + '-' + index), (): void => { this.peers = this.peers.filter((value: Ss22TcpPeer) => value !== peer); }); this.peers.push(peer);
      });
      udp.on('message', (message: socket.SocketMessageInfo): void => {
        try { const wire = this.datagram(index, method, keys, new Uint8Array(message.message));
          udp.send({ data: wire.buffer as ArrayBuffer, address: { address: message.remoteInfo.address, port: message.remoteInfo.port, family: 1 } }).then(() => this.bump('udp-response-' + index)).catch(() => this.bump('udp-send-error-' + index));
        } catch (_) { this.bump('udp-rejected-' + index); }
      });
      this.tcp.push(tcp); this.udp.push(udp);
      await tcp.listen({ address: '127.0.0.1', port, family: 1 }); await udp.bind({ address: '127.0.0.1', port, family: 1 }); this.ready.push(port);
    }
  }
  private bump(key: string): void { this.counters[key] = (this.counters[key] || 0) + 1; }
  private hex(bytes: Uint8Array): string { return Array.from(bytes).map((value: number): string => value.toString(16).padStart(2, '0')).join(''); }
  private dns(query: Uint8Array): Uint8Array {
    if (query.length < 12 || query[4] !== 0 || query[5] !== 1) throw new Error('public-dns');
    let at: number = 12; const labels: string[] = [];
    while (at < query.length && query[at]) { const size: number = query[at++]; if (size > 63 || at + size >= query.length) throw new Error('question'); labels.push(util.TextDecoder.create('utf-8').decodeToString(query.slice(at, at + size))); at += size; }
    if (labels.join('.') !== 'udp-fixture.test' || at + 5 > query.length || query[at + 1] !== 0 || query[at + 2] !== 1) throw new Error('public-question');
    const header = join(query.slice(0, 2), new Uint8Array([129, 128, 0, 1, 0, 1, 0, 0, 0, 0]));
    return join(join(header, query.slice(12, at + 5)), new Uint8Array([192, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 44]));
  }
  private datagram(index: number, method: string, keys: Uint8Array[], packet: Uint8Array): Uint8Array {
    if (packet.length > 65507 || packet.length < 48) throw new Error('packet');
    const key = keys[keys.length - 1]; let separate: Uint8Array, body: Uint8Array;
    if (method.includes('chacha')) { const combined = ss22XChaCha(key, packet.slice(0, 24), packet.slice(24), false); separate = combined.slice(0, 16); body = combined.slice(16); }
    else {
      separate = ss22Block(keys[0], packet.slice(0, 16), false); let offset: number = 16;
      for (let i: number = 0; i + 1 < keys.length; ++i) { const hash = ss22Block(keys[i], packet.slice(offset, offset + 16), false); hash.forEach((value: number, at: number): void => { hash[at] = value ^ separate[at]; }); if (!ss22Equal(hash, ss22Hash(keys[i + 1]))) throw new Error('identity'); offset += 16; }
      body = ss22Aead(method, ss22Subkey(key, separate.slice(0, 8)), separate.slice(4), packet.slice(offset), false);
    }
    if (body.length < 18 || body[0] !== 0) throw new Error('type'); ss22Time(body.slice(1, 9));
    const offset: number = 11 + ss22Read(body.slice(9, 11)), target = ss22Address(body, offset);
    if (target.host !== '127.0.0.1' || target.port !== 18553) throw new Error('public-udp-target');
    const payload = this.dns(body.slice(offset + target.size));
    const client = separate.slice(0, 8), id: string = index + ':' + this.hex(client), packetId: string = this.hex(separate.slice(8));
    let state = this.sessions.get(id); const now: number = Date.now();
    if (!state) { this.sessions.forEach((value: Ss22UdpState, key: string): void => { if (now - value.used >= 60000) this.sessions.delete(key); }); if (this.sessions.size >= 64) throw new Error('session-limit'); state = { server: ss22Random(8), counter: 0, seen: new Set(), used: now }; this.sessions.set(id, state); }
    if (state.seen.has(packetId) || state.seen.size >= 1024) throw new Error('replay'); state.seen.add(packetId); state.used = now;
    const responseHeader = join(state.server, ss22Number(state.counter++, 8));
    const responseBody = join(join(join(new Uint8Array([1]), ss22Number(Math.floor(now / 1000), 8)), join(client, new Uint8Array(2))), join(body.slice(offset, offset + target.size), payload));
    if (method.includes('chacha')) { const nonce = ss22Random(24); return join(nonce, ss22XChaCha(key, nonce, join(responseHeader, responseBody), true)); }
    return join(ss22Block(key, responseHeader, true), ss22Aead(method, ss22Subkey(key, state.server), responseHeader.slice(4), responseBody, true));
  }
  state(): string { return JSON.stringify({ ready: this.ready, selfTestChecks: this.checks, activeConnections: this.peers.length, counters: this.counters }); }
  async stop(): Promise<void> {
    await Promise.all(this.peers.slice().map((peer: Ss22TcpPeer) => peer.stop()));
    await Promise.all(this.tcp.map((server: socket.TCPSocketServer) => server.close().catch(() => {})));
    await Promise.all(this.udp.map((server: socket.UDPSocket) => server.close().catch(() => {})));
    this.tcp = []; this.udp = []; this.peers = []; this.sessions.clear(); this.ready = [];
  }
}
