import { socket } from '@kit.NetworkKit';
import { util } from '@kit.ArkTS';

// Independent fixed-target HTTP/SOCKS responder. Credentials are public fixture
// values; no arbitrary forwarding, production configuration or payload logging.
export class ForwardFixtureConnection {
  private input: Uint8Array = new Uint8Array(0);
  private phase: number = 0;
  private protocol: string = '';
  private closed: boolean = false;
  private udp?: socket.UDPSocket;
  private encoder: util.TextEncoder = new util.TextEncoder();
  private decoder: util.TextDecoder = util.TextDecoder.create('utf-8');
  private send: (bytes: Uint8Array) => Promise<void>;
  private close: () => Promise<void>;
  private event: (name: string) => void;
  constructor(send: (bytes: Uint8Array) => Promise<void>, close: () => Promise<void>, event: (name: string) => void) { this.send = send; this.close = close; this.event = event; }
  stop(): void { this.closed = true; this.udp?.close().catch(() => {}); }
  private async reject(): Promise<void> { this.event('rejected'); this.stop(); await this.close().catch(() => {}); }
  private headers(text: string): Record<string, string> {
    const result: Record<string, string> = {};
    text.split('\r\n').slice(1).forEach((line: string) => { const colon = line.indexOf(':'); if (colon > 0) result[line.substring(0, colon).toLowerCase()] = line.substring(colon + 1).trim(); });
    return result;
  }
  async receive(bytes: Uint8Array): Promise<void> {
    if (this.closed) return;
    const next = new Uint8Array(this.input.length + bytes.length); next.set(this.input); next.set(bytes, this.input.length); this.input = next;
    if (this.input.length > 32768) { await this.reject(); return; }
    if (this.phase === 0) {
      this.protocol = this.input[0] === 5 ? 'socks5' : 'http'; this.phase = this.protocol === 'http' ? 10 : 1;
    }
    for (;;) {
      if (this.phase === 10) {
        const text = this.decoder.decodeToString(this.input); const end = text.indexOf('\r\n\r\n'); if (end < 0) return;
        const fields = this.headers(text.substring(0, end));
        const expected = 'Basic ' + new util.Base64Helper().encodeToStringSync(this.encoder.encodeInto('fixture:p@ss:word'));
        if (fields['proxy-authorization'] && fields['proxy-authorization'] !== expected) {
          await this.send(this.encoder.encodeInto('HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n')); await this.reject(); return;
        }
        if (!text.startsWith('CONNECT forward.device.test:80 HTTP/1.1\r\n') || fields['host'] !== 'forward.device.test:80') { await this.reject(); return; }
        this.input = this.input.slice(end + 4); this.phase = 4; this.event('http');
        await this.send(this.encoder.encodeInto('HTTP/1.1 200 Connection established\r\n\r\n')); continue;
      }
      if (this.phase === 1) {
        if (this.input.length < 2 || this.input.length < 2 + this.input[1]) return;
        const methods = this.input.slice(2, 2 + this.input[1]); const selected: number = methods.includes(2) ? 2 : methods.includes(0) ? 0 : 255;
        this.input = this.input.slice(2 + this.input[1]); await this.send(new Uint8Array([5, selected]));
        if (selected === 255) { await this.reject(); return; } this.phase = selected === 2 ? 2 : 3; continue;
      }
      if (this.phase === 2) {
        if (this.input.length < 2 || this.input.length < 3 + this.input[1]) return;
        const size = 3 + this.input[1] + this.input[2 + this.input[1]]; if (this.input.length < size) return;
        const username = this.decoder.decodeToString(this.input.slice(2, 2 + this.input[1]));
        const password = this.decoder.decodeToString(this.input.slice(3 + this.input[1], size));
        const accepted = this.input[0] === 1 && username === 'fixture' && password === 'p@ss:word';
        await this.send(new Uint8Array([1, accepted ? 0 : 1]));
        if (!accepted) { await this.reject(); return; } this.input = this.input.slice(size); this.phase = 3; continue;
      }
      if (this.phase === 3) {
        if (this.input.length < 5) return;
        if (this.input[0] !== 5 || this.input[2] !== 0) { await this.reject(); return; }
        const command = this.input[1]; const length = this.input[3] === 1 ? 10 : this.input[3] === 4 ? 22 : this.input[3] === 3 ? 7 + this.input[4] : 0;
        if (!length) { await this.reject(); return; } if (this.input.length < length) return;
        const port = this.input[length - 2] * 256 + this.input[length - 1];
        if (command === 3) {
          if (this.input[3] !== 1 || this.input.slice(4, 10).some((value: number) => value !== 0)) { await this.reject(); return; }
          this.udp = socket.constructUDPSocketInstance(); this.udp.on('message', (message: socket.SocketMessageInfo): void => this.datagram(message));
          await this.udp.bind({ address: '127.0.0.1', port: 0, family: 1 }); const local = await this.udp.getLocalAddress();
          const reply = new Uint8Array([5,0,0,1,127,0,0,1,(local.port || 0) >> 8,(local.port || 0) & 255]);
          await this.send(reply); this.phase = 5; this.event('socks5');
        } else if (command === 1 && this.input[3] === 3 && this.decoder.decodeToString(this.input.slice(5, length - 2)) === 'forward.device.test' && port === 80) {
          await this.send(new Uint8Array([5,0,0,1,127,0,0,1,0,0])); this.phase = 4; this.event('socks5');
        } else { await this.reject(); return; }
        this.input = this.input.slice(length); continue;
      }
      if (this.phase === 4) {
        const text = this.decoder.decodeToString(this.input); if (!text.includes('\r\n\r\n')) return;
        if (!text.startsWith('GET /verify HTTP/1.1\r\n') || !/^forward\.device\.test(?::80)?$/.test(this.headers(text)['host'] || '')) { await this.reject(); return; }
        await this.send(this.encoder.encodeInto('HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'));
        this.stop(); await this.close().catch(() => {}); return;
      }
      if (this.phase === 5 && this.input.length) await this.reject();
      return;
    }
  }
  private datagram(message: socket.SocketMessageInfo): void {
    if (this.closed || !this.udp || message.remoteInfo.address !== '127.0.0.1') return;
    const packet = new Uint8Array(message.message); if (packet.length < 7 || packet.length > 65507 || packet[0] !== 0 || packet[1] !== 0 || packet[2] !== 0 || packet[3] !== 3) return;
    const end: number = packet[4] + 5;
    if (packet.length < end + 2 || packet[end] !== 1 || packet[end + 1] !== 187 || this.decoder.decodeToString(packet.slice(5, end)) !== 'forward.device.test') return;
    this.udp.send({ address: { address: message.remoteInfo.address, port: message.remoteInfo.port, family: 1 }, data: packet.buffer as ArrayBuffer })
      .then(() => this.event('packets')).catch(() => {});
  }
}
