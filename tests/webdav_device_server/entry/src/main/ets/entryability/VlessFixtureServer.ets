import { socket } from '@kit.NetworkKit';
import { util } from '@kit.ArkTS';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { common } from '@kit.AbilityKit';
import tlsBridge from 'libvlessfixture.so';
import { ForwardFixtureConnection } from './ForwardFixtureConnection';

interface FixtureTransport { send: (bytes: Uint8Array) => Promise<void>; close: () => Promise<void>; }
interface FixtureXudpStats { packets: number; empty: number; maximum: number; }
interface FixtureState { wire: Uint8Array; data: Uint8Array; websocket: boolean; header: boolean; udp: boolean; mux: boolean; muxStarted: boolean; responded: boolean; closing: boolean; queue: Promise<void>; forward?: ForwardFixtureConnection; }

// Independent, loopback-only VLESS server. It never dials a network destination:
// vless.device.test:80 receives fixed HTTP 204; :443 UDP receives byte echoes.
// Fixed public credentials and certificate are exclusively for this removable app.
export class VlessFixtureServer {
  private tcp: socket.TCPSocketServer = socket.constructTCPSocketServerInstance();
  private decrypted: socket.TCPSocketServer = socket.constructTCPSocketServerInstance();
  private clients: FixtureTransport[] = [];
  private encoder: util.TextEncoder = new util.TextEncoder();
  private decoder: util.TextDecoder = util.TextDecoder.create('utf-8');
  private active: boolean = false;
  private requests: number[] = [0, 0, 0, 0];
  private packets: number = 0;
  private xudpPackets: number = 0;
  private xudpEmpty: number = 0;
  private xudpMaximum: number = 0;
  private rejected: number = 0;
  private ready: string[] = [];
  private failures: string[] = [];
  private forward: Record<string, number> = {};

  start(context: common.UIAbilityContext): void {
    if (this.active) return;
    this.active = true;
    this.tcp.on('connect', (client: socket.TCPSocketConnection): void => this.accept(client, false));
    this.decrypted.on('connect', (client: socket.TCPSocketConnection): void => this.accept(client, true));
    this.tcp.listen({ address: '127.0.0.1', port: 18097, family: 1 }).then(() => this.ready.push('tcp')).catch(() => this.failures.push('tcp-listen'));
    this.decrypted.listen({ address: '127.0.0.1', port: 18099, family: 1 }).then(async (): Promise<void> => {
      const files = await Promise.all([context.resourceManager.getRawFileContent('vless/server.pem'), context.resourceManager.getRawFileContent('vless/server-key.pem')]);
      if (!tlsBridge.start(this.decoder.decodeToString(files[0]), this.decoder.decodeToString(files[1]))) throw new Error('TLS fixture unavailable');
      this.ready.push('tls');
    }).catch(() => this.failures.push('tls-listen'));
  }
  private accept(client: socket.TCPSocketConnection, tls: boolean): void {
    const transport: FixtureTransport = { send: (bytes: Uint8Array): Promise<void> => client.send({ data: bytes.buffer as ArrayBuffer }), close: (): Promise<void> => client.close() };
    const state = this.state(transport);
    client.on('message', (message: socket.SocketMessageInfo): void => this.receive(transport, state, new Uint8Array(message.message), tls));
    client.on('close', (): void => { state.forward?.stop(); this.remove(transport); });
  }
  stop(): void {
    if (!this.active) return;
    this.active = false; this.clients.forEach((client: FixtureTransport) => client.close().catch(() => {})); this.clients = [];
    tlsBridge.stop(); this.tcp.close().catch(() => {}); this.decrypted.close().catch(() => {});
  }
  status(): string {
    const xudp: FixtureXudpStats = { packets: this.xudpPackets, empty: this.xudpEmpty, maximum: this.xudpMaximum };
    return JSON.stringify({ ready: this.ready, failures: this.failures, requests: this.requests, packets: this.packets, xudp, rejected: this.rejected, forward: this.forward });
  }
  private state(client: FixtureTransport): FixtureState {
    this.clients.push(client);
    return { wire: new Uint8Array(0), data: new Uint8Array(0), websocket: false, header: false, udp: false, mux: false, muxStarted: false, responded: false, closing: false, queue: Promise.resolve() };
  }
  private remove(client: FixtureTransport): void { this.clients = this.clients.filter((item: FixtureTransport) => item !== client); }
  private join(first: Uint8Array, second: Uint8Array): Uint8Array { const result = new Uint8Array(first.length + second.length); result.set(first); result.set(second, first.length); return result; }
  private reject(client: FixtureTransport, state: FixtureState): void { if (!state.closing) { this.rejected++; state.closing = true; client.close().catch(() => {}); } }
  private receive(client: FixtureTransport, state: FixtureState, bytes: Uint8Array, tls: boolean): void {
    state.queue = state.queue.then(async (): Promise<void> => {
      if (state.closing) return;
      if (state.wire.length + state.data.length + bytes.length > 192 * 1024) { this.reject(client, state); return; }
      state.wire = this.join(state.wire, bytes);
      if (state.forward || (!state.header && !state.websocket && (state.wire[0] === 5 || state.wire[0] === 67))) {
        if (!state.forward) state.forward = new ForwardFixtureConnection(client.send, client.close, (name: string): void => {
          const key = name + (tls ? '-tls' : '-tcp'); this.forward[key] = (this.forward[key] || 0) + 1;
        });
        await state.forward.receive(state.wire); state.wire = new Uint8Array(0); return;
      }
      if (!state.header && !state.websocket && state.wire[0] === 71) {
        const request = this.decoder.decodeToString(state.wire); const end: number = request.indexOf('\r\n\r\n');
        if (end < 0) { if (state.wire.length > 16384) this.reject(client, state); return; }
        if (tls && request.startsWith('GET /ss2022-probe HTTP/1.1\r\n')) { this.forward['ss2022-https'] = (this.forward['ss2022-https'] || 0) + 1; state.closing = true; await client.send(this.encoder.encodeInto('HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')); await client.close(); return; }
        const lines = request.substring(0, end).split('\r\n'); const headers: Record<string, string> = {};
        lines.slice(1).forEach((line: string) => { const colon = line.indexOf(':'); if (colon > 0) headers[line.substring(0, colon).toLowerCase()] = line.substring(colon + 1).trim(); });
        if (lines[0] !== 'GET /vless-device HTTP/1.1' || headers['upgrade']?.toLowerCase() !== 'websocket' || !headers['sec-websocket-key']) { this.reject(client, state); return; }
        const hash = cryptoFramework.createMd('SHA1');
        await hash.update({ data: this.encoder.encodeInto(headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11') });
        const digest = await hash.digest();
        const accept = new util.Base64Helper().encodeToStringSync(digest.data);
        await client.send(this.encoder.encodeInto(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`));
        state.websocket = true; state.wire = state.wire.slice(end + 4);
      }
      if (!state.websocket) { state.data = this.join(state.data, state.wire); state.wire = new Uint8Array(0); }
      else {
        while (state.wire.length >= 2) {
          const first = state.wire[0], second = state.wire[1]; let size: number = second & 127; let prefix: number = 2;
          if (!(second & 128) || (first & 112) || !(first & 128)) { this.reject(client, state); return; }
          if (size === 126) { if (state.wire.length < 4) return; size = state.wire[2] * 256 + state.wire[3]; prefix = 4; }
          else if (size === 127) { if (state.wire.length < 10) return; if (state.wire.slice(2, 6).some((value: number) => value !== 0)) { this.reject(client, state); return; } size = state.wire[6] * 16777216 + state.wire[7] * 65536 + state.wire[8] * 256 + state.wire[9]; prefix = 10; }
          if (size > 65537) { this.reject(client, state); return; }
          if (state.wire.length < prefix + 4 + size) break;
          const mask = state.wire.slice(prefix, prefix + 4), payload = state.wire.slice(prefix + 4, prefix + 4 + size);
          for (let i: number = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
          state.wire = state.wire.slice(prefix + 4 + size);
          if ((first & 15) === 8) { state.closing = true; await client.close(); return; }
          if ((first & 15) === 10) continue;
          if ((first & 15) !== 2) { this.reject(client, state); return; }
          state.data = this.join(state.data, payload);
        }
      }
      if (!state.header) {
        if (state.data.length < 19) return;
        const id: number[] = [17,17,17,17,34,34,67,51,132,68,85,85,85,85,85,85];
        if (state.data[0] !== 0 || !id.every((value: number, i: number) => state.data[i + 1] === value) || state.data[17] !== 0 || ![1,2,3].includes(state.data[18])) { this.reject(client, state); return; }
        if (state.data[18] === 3) {
          state.mux = true; state.udp = true; state.header = true; state.data = state.data.slice(19);
        } else {
          if (state.data.length < 23) return;
          if (state.data[21] !== 2) { this.reject(client, state); return; }
          const length: number = state.data[22]; if (state.data.length < 23 + length) return;
          const host = this.decoder.decodeToString(state.data.slice(23, 23 + length)), port = state.data[19] * 256 + state.data[20];
          state.udp = state.data[18] === 2;
          if (host !== 'vless.device.test' || port !== (state.udp ? 443 : 80)) { this.reject(client, state); return; }
          state.header = true; state.data = state.data.slice(23 + length);
        }
        this.requests[(tls ? 1 : 0) + (state.websocket ? 2 : 0)]++;
        // Fragment the response header across native socket sends.
        await this.send(client, state, new Uint8Array([0])); await this.send(client, state, new Uint8Array([0]));
      }
      if (state.mux) {
        await this.receiveXudp(client, state);
      } else if (state.udp) {
        while (state.data.length >= 2) {
          const size: number = state.data[0] * 256 + state.data[1]; if (state.data.length < 2 + size) return;
          const packet = state.data.slice(0, size + 2); state.data = state.data.slice(size + 2); this.packets++;
          await this.send(client, state, packet);
        }
      } else if (!state.responded) {
        const request = this.decoder.decodeToString(state.data);
        if (!request.includes('\r\n\r\n')) return;
        if (!request.startsWith('GET /verify HTTP/1.1\r\n') || !/\r\nhost: vless\.device\.test(?::80)?\r\n/i.test(request)) { this.reject(client, state); return; }
        state.responded = true;
        await this.send(client, state, this.encoder.encodeInto('HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'));
        state.closing = true; await client.close();
      }
    }).catch(() => this.reject(client, state));
  }
  // Independent fixed-destination Mux peer, deliberately split across sends.
  // No production implementation is linked into this test app.
  private async receiveXudp(client: FixtureTransport, state: FixtureState): Promise<void> {
    while (state.data.length >= 2) {
      const size: number = state.data[0] * 256 + state.data[1];
      if (size < 9 || size > 512) { this.reject(client, state); return; }
      if (state.data.length < 2 + size + 2) return;
      const metadata = state.data.slice(2, 2 + size);
      const hostLength: number = metadata[8];
      const expected: number = 9 + hostLength;
      if (metadata[0] !== 0 || metadata[1] !== 0 || metadata[2] !== (state.muxStarted ? 2 : 1) || metadata[3] !== 1 || metadata[4] !== 2 || metadata[5] !== 1 || metadata[6] !== 187 || metadata[7] !== 2 ||
        this.decoder.decodeToString(metadata.slice(9, expected)) !== 'vless.device.test' || size !== expected + (state.muxStarted ? 0 : 8)) { this.reject(client, state); return; }
      const length: number = state.data[size + 2] * 256 + state.data[size + 3];
      if (length > 65507) { this.reject(client, state); return; }
      if (state.data.length < size + 4 + length) return;
      const payload = state.data.slice(size + 4, size + 4 + length);
      state.data = state.data.slice(size + 4 + length); state.muxStarted = true;
      this.xudpPackets++; if (length === 0) this.xudpEmpty++; this.xudpMaximum = Math.max(this.xudpMaximum, length);
      const reply = new Uint8Array(4 + expected + payload.length);
      reply[0] = expected >> 8; reply[1] = expected & 255; reply.set(metadata.slice(0, expected), 2); reply[4] = 2;
      reply[2 + expected] = length >> 8; reply[3 + expected] = length & 255; reply.set(payload, 4 + expected);
      await this.send(client, state, reply.slice(0, 3)); await this.send(client, state, reply.slice(3));
    }
  }
  private send(client: FixtureTransport, state: FixtureState, bytes: Uint8Array): Promise<void> {
    if (!state.websocket) return client.send(bytes);
    const prefix = bytes.length < 126 ? new Uint8Array([130, bytes.length]) : new Uint8Array([130, 126, bytes.length >> 8, bytes.length & 255]);
    return client.send(this.join(prefix, bytes));
  }
}
