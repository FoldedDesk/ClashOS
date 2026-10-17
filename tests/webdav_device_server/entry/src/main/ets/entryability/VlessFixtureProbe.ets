import { socket } from '@kit.NetworkKit';
import { util } from '@kit.ArkTS';

// Independent SOCKS5 UDP client in an INTERNET-authorized test app. No user data.
export async function probeVlessUdp(hostname: string = 'vless.device.test'): Promise<string> {
  const control = socket.constructTCPSocketInstance(), udp = socket.constructUDPSocketInstance();
  let input = new Uint8Array(0); const replies: Uint8Array[] = [];
  let failure: string = ''; const deadline: number = Date.now() + 12000;
  control.on('message', (message: socket.SocketMessageInfo): void => { const next = new Uint8Array(input.length + message.message.byteLength); next.set(input); next.set(new Uint8Array(message.message), input.length); input = next; });
  control.on('error', (): void => { failure = 'tcp-error'; });
  udp.on('message', (message: socket.SocketMessageInfo): void => { replies.push(new Uint8Array(message.message)); });
  udp.on('error', (): void => { failure = 'udp-error'; });
  const pause = (): Promise<void> => new Promise((resolve: () => void) => setTimeout(resolve, 10));
  try {
    await control.bind({ address: '127.0.0.1', port: 0, family: 1 });
    await udp.bind({ address: '127.0.0.1', port: 0, family: 1 });
    await control.connect({ address: { address: '127.0.0.1', port: 7891, family: 1 }, timeout: 4000 });
    await control.send({ data: new Uint8Array([5,1,0,5,3,0,1,0,0,0,0,0,0]).buffer as ArrayBuffer });
    while (input.length < 12 && !failure && Date.now() < deadline) await pause();
    if (failure || input.length < 12 || input[0] !== 5 || input[1] !== 0 || input[2] !== 5 || input[3] !== 0 || input[5] !== 1) throw new Error(failure || 'socks-associate');
    const port: number = input[10] * 256 + input[11];
    const host = new util.TextEncoder().encodeInto(hostname);
    const header = new Uint8Array(7 + host.length); header.set([0,0,0,3,host.length]); header.set(host, 5); header[header.length - 2] = 1; header[header.length - 1] = 187;
    const lengths: number[] = [0, 8, 4096, 65507 - header.length];
    for (const length of lengths) {
      const packet = new Uint8Array(header.length + length); packet.set(header);
      for (let i: number = 0; i < length; i++) packet[header.length + i] = i % 256;
      await udp.send({ address: { address: '127.0.0.1', port, family: 1 }, data: packet.buffer as ArrayBuffer });
      while (replies.length === 0 && !failure && Date.now() < deadline) await pause();
      const reply = replies.shift();
      if (failure || !reply || reply.length !== packet.length || !reply.every((value: number, i: number) => value === packet[i])) throw new Error(failure || 'udp-payload-or-timeout');
    }
    return JSON.stringify({ passed: true, packets: lengths.length, lengths });
  } catch (error) { return JSON.stringify({ passed: false, error: (error as Error).message }); }
  finally { await control.close().catch(() => {}); await udp.close().catch(() => {}); }
}
