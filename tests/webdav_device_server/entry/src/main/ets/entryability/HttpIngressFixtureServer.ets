import { socket } from '@kit.NetworkKit';
import { util } from '@kit.ArkTS';

interface HttpFixtureState {
  input: Uint8Array; head: boolean; path: string; method: string; fields: Record<string, string>;
  upgraded: boolean; closing: boolean; queue: Promise<void>;
}
interface EarlyHttpReply { client: socket.TCPSocketConnection; chunked: boolean; }

// A separate, fixed-response origin. It never routes traffic, reads app data or
// accepts arbitrary WebSocket messages. Only public test vectors are accepted.
export class HttpIngressFixtureServer {
  private server: socket.TCPSocketServer = socket.constructTCPSocketServerInstance();
  private clients: socket.TCPSocketConnection[] = [];
  private encoder: util.TextEncoder = new util.TextEncoder();
  private decoder: util.TextDecoder = util.TextDecoder.create('utf-8');
  private active: boolean = false;
  private ready: boolean = false;
  private failed: boolean = false;
  private accepted: number = 0;
  private rejected: number = 0;
  private frames: number = 0;
  private requests: Record<string, number> = {};
  private early: EarlyHttpReply[] = [];
  private earlyReplies: number = 0;
  private lateUploadBytes: number = 0;

  start(): void {
    if (this.active) return; this.active = true;
    this.server.on('connect', (client: socket.TCPSocketConnection): void => this.accept(client));
    this.server.listen({ address: '127.0.0.1', port: 18105, family: 1 }).then(() => { this.ready = true; }).catch(() => { this.failed = true; });
  }
  stop(): void { if (!this.active) return; this.active = false; this.clients.forEach((client: socket.TCPSocketConnection) => client.close().catch(() => {})); this.clients = []; this.server.close().catch(() => {}); }
  status(): string { return JSON.stringify({ ready: this.ready, failed: this.failed, accepted: this.accepted, rejected: this.rejected, frames: this.frames, requests: this.requests, earlyReplies: this.earlyReplies, lateUploadBytes: this.lateUploadBytes }); }
  async releaseEarly(): Promise<void> {
    const pending = this.early; this.early = [];
    for (const reply of pending) {
      try {
        await this.send(reply.client, this.encoder.encodeInto(reply.chunked ? '8\r\ndenied!!\r\n0\r\n\r\n' : 'denied!!'));
        await reply.client.close(); this.earlyReplies++;
      } catch (_) { /* An old proxy may already have discarded this response. */ }
    }
  }
  private join(first: Uint8Array, second: Uint8Array): Uint8Array { const bytes = new Uint8Array(first.length + second.length); bytes.set(first); bytes.set(second, first.length); return bytes; }
  private equal(first: Uint8Array, second: Uint8Array): boolean { return first.length === second.length && first.every((value: number, index: number) => value === second[index]); }
  private accept(client: socket.TCPSocketConnection): void {
    this.accepted++; this.clients.push(client);
    const state: HttpFixtureState = { input: new Uint8Array(0), head: false, path: '', method: '', fields: {}, upgraded: false, closing: false, queue: Promise.resolve() };
    client.on('message', (message: socket.SocketMessageInfo): void => {
      const bytes = new Uint8Array(message.message);
      state.queue = state.queue.then(() => this.receive(client, state, bytes)).catch(() => this.reject(client, state));
    });
    client.on('close', (): void => { this.clients = this.clients.filter((item: socket.TCPSocketConnection) => item !== client); });
  }
  private async reject(client: socket.TCPSocketConnection, state: HttpFixtureState): Promise<void> {
    if (state.closing) return; state.closing = true; this.rejected++; await client.close().catch(() => {});
  }
  private async send(client: socket.TCPSocketConnection, bytes: Uint8Array): Promise<void> { await client.send({ data: bytes.buffer as ArrayBuffer }); }
  private async response(client: socket.TCPSocketConnection, state: HttpFixtureState, body: Uint8Array, headOnly: boolean = false): Promise<void> {
    state.closing = true;
    await this.send(client, this.join(this.encoder.encodeInto(`HTTP/1.1 200 OK\r\nContent-Length: ${headOnly ? 999 : body.length}\r\nConnection: close\r\n\r\n`), headOnly ? new Uint8Array(0) : body));
    await client.close();
  }
  private async receive(client: socket.TCPSocketConnection, state: HttpFixtureState, bytes: Uint8Array): Promise<void> {
    if (state.closing) { if (state.path.startsWith('/early-')) this.lateUploadBytes += bytes.length; return; }
    if (state.input.length + bytes.length > 192 * 1024) { await this.reject(client, state); return; }
    state.input = this.join(state.input, bytes);
    if (!state.head) {
      let end: number = -1;
      for (let i: number = 0; i + 3 < state.input.length; i++) if (state.input[i] === 13 && state.input[i + 1] === 10 && state.input[i + 2] === 13 && state.input[i + 3] === 10) { end = i; break; }
      if (end < 0) { if (state.input.length > 16384) await this.reject(client, state); return; }
      const lines = this.decoder.decodeToString(state.input.slice(0, end)).split('\r\n'); const first = lines[0].split(' ');
      state.method = first[0]; state.path = first[1];
      lines.slice(1).forEach((line: string) => { const colon: number = line.indexOf(':'); if (colon > 0) state.fields[line.substring(0, colon).toLowerCase()] = line.substring(colon + 1).trim(); });
      if (!['HTTP/1.1', 'HTTP/1.0'].includes(first[2]) || !['origin.fixture.test:18105', 'origin1.fixture.test:18105', 'origin2.fixture.test:18105'].includes(state.fields['host']) ||
        state.fields['proxy-authorization'] || state.fields['proxy-connection'] || state.fields['x-hop'] || !['/1', '/2', '/upload', '/chunked', '/expect', '/socket', '/early-length', '/early-chunked', '/early-eof'].includes(state.path)) { await this.reject(client, state); return; }
      state.input = state.input.slice(end + 4); state.head = true;
      this.requests[state.path] = (this.requests[state.path] || 0) + 1;
      if (state.path.startsWith('/early-')) {
        if (state.method !== 'POST' || state.fields['expect']?.toLowerCase() !== '100-continue' || state.input.length !== 0) { await this.reject(client, state); return; }
        state.closing = true;
        const chunked: boolean = state.path === '/early-chunked';
        this.early.push({ client, chunked });
        const framing: string = chunked ? 'Transfer-Encoding: chunked\r\n' : state.path === '/early-length' ? 'Content-Length: 8\r\n' : '';
        await this.send(client, this.encoder.encodeInto('HTTP/1.1 413 Payload Too Large\r\n' + framing + 'Connection: close\r\n\r\n')); return;
      }
      if (state.path === '/socket') {
        if (state.method !== 'GET' || state.fields['upgrade']?.toLowerCase() !== 'websocket' || !state.fields['connection']?.toLowerCase().split(',').map((value: string) => value.trim()).includes('upgrade') || state.fields['sec-websocket-key'] !== 'dGhlIHNhbXBsZSBub25jZQ==') { await this.reject(client, state); return; }
        state.upgraded = true;
        await this.send(client, this.join(this.encoder.encodeInto('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n'), new Uint8Array([129, 5, 104, 101, 108, 108, 111])));
      } else if (state.path === '/expect') {
        if (state.fields['expect']?.toLowerCase() !== '100-continue') { await this.reject(client, state); return; }
        await this.send(client, this.encoder.encodeInto('HTTP/1.1 103 Early Hints\r\nLink: </style>; rel=preload\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n'));
      }
    }
    if (state.upgraded) {
      const frame = new Uint8Array([129, 130, 1, 2, 3, 4, 105, 107]);
      if (state.input.length < frame.length) return;
      if (!this.equal(state.input, frame)) { await this.reject(client, state); return; }
      this.frames++; state.closing = true; await this.send(client, new Uint8Array([136, 2, 3, 232])); await client.close(); return;
    }
    if (state.path === '/upload' || state.path === '/expect') {
      let expected: Uint8Array;
      if (state.fields['transfer-encoding'] === 'chunked') expected = this.encoder.encodeInto('4;ext="a,b"\r\ndata\r\n4\r\n\u0000xyz\r\n0\r\nX-Trailer: ok\r\n\r\n');
      else {
        const length: number = Number(state.fields['content-length']);
        if (length !== 8 && length !== 65536) { await this.reject(client, state); return; }
        expected = length === 8 ? new Uint8Array([100, 97, 116, 97, 0, 120, 121, 122]) : new Uint8Array(length);
        if (length === 65536) for (let i: number = 0; i < length; i++) expected[i] = (i * 13 + 7) & 255;
      }
      if (state.input.length < expected.length) return;
      if (!this.equal(state.input, expected)) { await this.reject(client, state); return; }
      await this.response(client, state, this.encoder.encodeInto('uploaded')); return;
    }
    if (state.input.length !== 0) { await this.reject(client, state); return; }
    if (state.path === '/chunked') {
      state.closing = true;
      const wire = this.encoder.encodeInto('HTTP/1.1 200 OK\r\nConnection: close, X-Hop\r\nX-Hop: remove\r\nTransfer-Encoding: chunked\r\nContent-Length: 999\r\n\r\n4;ext="a,b"\r\ndata\r\n4\r\n\u0000xyz\r\n0\r\nX-Trailer: ok\r\n\r\n');
      // Separate sends force incremental header/body processing on the device.
      for (let i: number = 0; i < wire.length; i += 7) await this.send(client, wire.slice(i, i + 7));
      await client.close(); return;
    }
    await this.response(client, state, this.encoder.encodeInto(state.path === '/1' ? 'origin-1' : 'origin-2'), state.method === 'HEAD');
  }
}
