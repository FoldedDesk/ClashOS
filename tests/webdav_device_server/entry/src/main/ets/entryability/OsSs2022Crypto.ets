import { cryptoFramework as crypto } from '@kit.CryptoArchitectureKit';
import { util } from '@kit.ArkTS';
import native from 'libvlessfixture.so';
import { joinBytes as join, fromHex } from './OsSsCrypto';

// Independent test codec. AEAD/ECB use HarmonyOS CryptoFramework; the standard
// BLAKE3 primitive alone is native. No production framing/parser is imported.
export function ss22Random(size: number): Uint8Array { return crypto.createRandom().generateRandomSync(size).data; }
export function ss22Subkey(key: Uint8Array, salt: Uint8Array, identity: boolean = false): Uint8Array {
  return native.blake3(join(key, salt), 'shadowsocks 2022 ' + (identity ? 'identity' : 'session') + ' subkey', key.length);
}
export function ss22Hash(key: Uint8Array): Uint8Array { return native.blake3(key, '', 16); }
export function ss22Number(value: number, size: number): Uint8Array {
  const result = new Uint8Array(size); for (let i: number = size - 1; i >= 0; --i) { result[i] = value % 256; value = Math.floor(value / 256); } return result;
}
export function ss22Read(value: Uint8Array): number { let result: number = 0; for (const byte of value) result = result * 256 + byte; return result; }
export function ss22Equal(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((byte: number, i: number): boolean => byte === b[i]); }
export function ss22Nonce(counter: number): Uint8Array { return ss22Number(counter, 12).reverse(); }
export function ss22Aead(method: string, key: Uint8Array, nonce: Uint8Array, input: Uint8Array, encrypt: boolean): Uint8Array {
  const chacha: boolean = method.includes('chacha'), algorithm: string = chacha ? 'ChaCha20' : 'AES' + key.length * 8;
  const material = crypto.createSymKeyGenerator(algorithm).convertKeySync({ data: key });
  const length: number = encrypt ? input.length : input.length - 16; if (length < 0) throw new Error('frame');
  const spec: crypto.GcmParamsSpec = { algName: chacha ? 'Poly1305ParamsSpec' : 'GcmParamsSpec', iv: { data: nonce.slice() }, aad: { data: new Uint8Array(0) }, authTag: { data: encrypt ? new Uint8Array(16) : input.slice(length) } };
  const cipher = crypto.createCipher(chacha ? 'ChaCha20|Poly1305' : algorithm + '|GCM|NoPadding');
  cipher.initSync(encrypt ? crypto.CryptoMode.ENCRYPT_MODE : crypto.CryptoMode.DECRYPT_MODE, material, spec);
  const prefix = length ? cipher.updateSync({ data: input.slice(0, length) }).data : new Uint8Array(0);
  // No unauthenticated update output leaves this function before final succeeds.
  const final = cipher.doFinalSync(null);
  return final ? join(prefix, final.data) : prefix;
}
export function ss22Block(key: Uint8Array, input: Uint8Array, encrypt: boolean): Uint8Array {
  const algorithm: string = 'AES' + key.length * 8, cipher = crypto.createCipher(algorithm + '|ECB|NoPadding');
  cipher.initSync(encrypt ? crypto.CryptoMode.ENCRYPT_MODE : crypto.CryptoMode.DECRYPT_MODE, crypto.createSymKeyGenerator(algorithm).convertKeySync({ data: key }), null);
  return cipher.doFinalSync({ data: input }).data;
}
function hchacha(key: Uint8Array, nonce: Uint8Array): Uint8Array {
  const state: number[] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
  const little = (bytes: Uint8Array, at: number): number => (bytes[at] | bytes[at + 1] << 8 | bytes[at + 2] << 16 | bytes[at + 3] << 24) >>> 0;
  for (let i: number = 0; i < 8; ++i) state.push(little(key, i * 4)); for (let i: number = 0; i < 4; ++i) state.push(little(nonce, i * 4));
  const rotate = (value: number, n: number): number => (value << n | value >>> (32 - n)) >>> 0;
  const round = (a: number, b: number, c: number, d: number): void => {
    state[a] = (state[a] + state[b]) >>> 0; state[d] = rotate(state[d] ^ state[a], 16); state[c] = (state[c] + state[d]) >>> 0; state[b] = rotate(state[b] ^ state[c], 12);
    state[a] = (state[a] + state[b]) >>> 0; state[d] = rotate(state[d] ^ state[a], 8); state[c] = (state[c] + state[d]) >>> 0; state[b] = rotate(state[b] ^ state[c], 7);
  };
  for (let i: number = 0; i < 10; ++i) { round(0, 4, 8, 12); round(1, 5, 9, 13); round(2, 6, 10, 14); round(3, 7, 11, 15); round(0, 5, 10, 15); round(1, 6, 11, 12); round(2, 7, 8, 13); round(3, 4, 9, 14); }
  const output = new Uint8Array(32); [0, 1, 2, 3, 12, 13, 14, 15].forEach((index: number, i: number): void => output.set(ss22Number(state[index], 4).reverse(), i * 4)); return output;
}
export function ss22XChaCha(key: Uint8Array, nonce: Uint8Array, input: Uint8Array, encrypt: boolean): Uint8Array {
  return ss22Aead('chacha', hchacha(key, nonce), join(new Uint8Array(4), nonce.slice(16)), input, encrypt);
}
export interface Ss22Target { size: number; host: string; port: number; }
export function ss22Address(input: Uint8Array, offset: number = 0): Ss22Target {
  if (input[offset] !== 1 || input.length < offset + 7) throw new Error('Only loopback IPv4 destinations are used by this public fixture');
  return { size: 7, host: Array.from(input.slice(offset + 1, offset + 5)).join('.'), port: input[offset + 5] * 256 + input[offset + 6] };
}
export function ss22Time(bytes: Uint8Array): void { if (Math.abs(ss22Read(bytes) - Math.floor(Date.now() / 1000)) > 30) throw new Error('timestamp'); }

export class OsSs2022Session {
  target?: Ss22Target;
  private method: string;
  private keys: Uint8Array[];
  private input: Uint8Array = new Uint8Array(0);
  private requestSalt?: Uint8Array;
  private readKey?: Uint8Array;
  private readCounter: number = 0;
  private writeKey?: Uint8Array;
  private writeCounter: number = 0;
  private stage: number = 0;
  private size: number = -1;
  constructor(method: string, keys: Uint8Array[]) { this.method = method; this.keys = keys; }
  private consume(size: number): Uint8Array { const data = this.input.slice(0, size); this.input = this.input.slice(size); return data; }
  private decrypt(size: number): Uint8Array { const plain = ss22Aead(this.method, this.readKey!, ss22Nonce(this.readCounter), this.consume(size), false); this.readCounter++; return plain; }
  feed(bytes: Uint8Array): Uint8Array[] {
    this.input = join(this.input, bytes); if (this.input.length > 1024 * 1024) throw new Error('input-limit');
    const output: Uint8Array[] = [], key = this.keys[this.keys.length - 1];
    if (!this.readKey) {
      if (this.input.length < key.length + (this.keys.length - 1) * 16) return output;
      this.requestSalt = this.consume(key.length);
      for (let i: number = 0; i + 1 < this.keys.length; ++i) if (!ss22Equal(ss22Block(ss22Subkey(this.keys[i], this.requestSalt, true), this.consume(16), false), ss22Hash(this.keys[i + 1]))) throw new Error('identity');
      this.readKey = ss22Subkey(key, this.requestSalt);
    }
    while (true) {
      if (this.stage === 0) {
        if (this.input.length < 27) return output; const header = this.decrypt(27);
        if (header.length !== 11 || header[0] !== 0) throw new Error('header'); ss22Time(header.slice(1, 9)); this.size = ss22Read(header.slice(9)); this.stage = 1;
      }
      if (this.stage === 2 && this.size < 0) { if (this.input.length < 18) return output; this.size = ss22Read(this.decrypt(18)); }
      if (this.size < 0 || this.size > 65535) throw new Error('size'); if (this.input.length < this.size + 16) return output;
      const plain = this.decrypt(this.size + 16); this.size = -1;
      if (this.stage === 1) {
        this.target = ss22Address(plain); const padding: number = ss22Read(plain.slice(this.target.size, this.target.size + 2));
        if (padding > 900 || this.target.size + 2 + padding > plain.length || (!padding && this.target.size + 2 === plain.length)) throw new Error('padding');
        this.stage = 2; if (plain.length > this.target.size + 2 + padding) output.push(plain.slice(this.target.size + 2 + padding));
      } else if (plain.length) output.push(plain);
    }
  }
  encode(bytes: Uint8Array): Uint8Array {
    let wire = new Uint8Array(0);
    for (let offset: number = 0; offset < bytes.length; offset += 65535) {
      const part = bytes.slice(offset, offset + 65535); let length = ss22Number(part.length, 2);
      if (!this.writeKey) {
        const salt = ss22Random(this.keys[this.keys.length - 1].length); wire = join(wire, salt); this.writeKey = ss22Subkey(this.keys[this.keys.length - 1], salt);
        length = join(join(new Uint8Array([1]), ss22Number(Math.floor(Date.now() / 1000), 8)), join(this.requestSalt!, length));
      }
      wire = join(wire, ss22Aead(this.method, this.writeKey, ss22Nonce(this.writeCounter++), length, true));
      wire = join(wire, ss22Aead(this.method, this.writeKey, ss22Nonce(this.writeCounter++), part, true));
    }
    return wire;
  }
}

interface Ss22Vector { method: string; key: string; salt: string; subkey: string; identity: string; hash: string; plain: string; sealed: string; nonce: string; udp: string; block: string; }
export function ss22SelfTest(text: string): number {
  const vectors = JSON.parse(text) as Ss22Vector[]; let count: number = 0;
  const check = (value: boolean): void => { if (!value) throw new Error('ss2022-vector-' + count); count++; };
  for (const v of vectors) {
    const key = fromHex(v.key), salt = fromHex(v.salt), plain = fromHex(v.plain), nonce = fromHex(v.nonce), derived = ss22Subkey(key, salt);
    check(ss22Equal(derived, fromHex(v.subkey))); check(ss22Equal(ss22Subkey(key, salt, true), fromHex(v.identity))); check(ss22Equal(ss22Hash(key), fromHex(v.hash)));
    check(ss22Equal(ss22Aead(v.method, derived, new Uint8Array(12), plain, true), fromHex(v.sealed)));
    check(ss22Equal(ss22Aead(v.method, derived, new Uint8Array(12), fromHex(v.sealed), false), plain));
    const corrupt = fromHex(v.sealed); corrupt[corrupt.length - 1] ^= 1; let rejected: boolean = false; try { ss22Aead(v.method, derived, new Uint8Array(12), corrupt, false); } catch (_) { rejected = true; } check(rejected);
    if (v.method.includes('chacha')) { check(ss22Equal(ss22XChaCha(key, nonce, plain, true), fromHex(v.udp))); check(ss22Equal(ss22XChaCha(key, nonce, fromHex(v.udp), false), plain)); }
    else { check(ss22Equal(ss22Block(key, new Uint8Array(16), true), fromHex(v.block))); check(ss22Equal(ss22Block(key, fromHex(v.block), false), new Uint8Array(16))); }
  }
  check(vectors.length === 3); return count;
}
