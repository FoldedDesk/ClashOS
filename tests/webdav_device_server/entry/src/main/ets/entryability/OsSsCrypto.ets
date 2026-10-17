import { cryptoFramework as crypto } from '@kit.CryptoArchitectureKit';
import { util } from '@kit.ArkTS';

// Independent test implementation: OS cryptography only, no production native
// crypto/protocol imports. Public known-answer data comes from Python/OpenSSL.
export function joinBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length); out.set(a); out.set(b, a.length); return out;
}
export function fromHex(text: string): Uint8Array {
  if (text.length % 2 || !/^[0-9a-f]*$/i.test(text)) throw new Error('vector');
  const out = new Uint8Array(text.length / 2); for (let i: number = 0; i < out.length; i++) out[i] = parseInt(text.substring(i * 2, i * 2 + 2), 16); return out;
}
function equal(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((v: number, i: number) => v === b[i]); }
function digest(name: string, bytes: Uint8Array): Uint8Array {
  const md = crypto.createMd(name); md.updateSync({ data: bytes }); return md.digestSync().data;
}
export function ssMaster(password: string, size: number): Uint8Array {
  const text = new util.TextEncoder().encodeInto(password); let out = new Uint8Array(0), previous = new Uint8Array(0);
  while (out.length < size) { previous = digest('MD5', joinBytes(previous, text)); out = joinBytes(out, previous); } return out.slice(0, size);
}
function hmac(key: Uint8Array, bytes: Uint8Array): Uint8Array {
  const material = key.length > 64 ? digest('SHA1', key) : key, inner = new Uint8Array(64), outer = new Uint8Array(64);
  for (let i: number = 0; i < 64; i++) { inner[i] = (material[i] || 0) ^ 54; outer[i] = (material[i] || 0) ^ 92; }
  return digest('SHA1', joinBytes(outer, digest('SHA1', joinBytes(inner, bytes))));
}
export function ssSubkey(master: Uint8Array, salt: Uint8Array): Uint8Array {
  const extracted = hmac(salt, master), info = new util.TextEncoder().encodeInto('ss-subkey');
  let out = new Uint8Array(0), previous = new Uint8Array(0), counter: number = 1;
  while (out.length < master.length) { previous = hmac(extracted, joinBytes(joinBytes(previous, info), new Uint8Array([counter++]))); out = joinBytes(out, previous); }
  return out.slice(0, master.length);
}
function aesKey(bytes: Uint8Array): crypto.SymKey { return crypto.createSymKeyGenerator('AES' + bytes.length * 8).convertKeySync({ data: bytes }); }
function crypt(key: crypto.SymKey, nonce: Uint8Array, data: Uint8Array, encrypt: boolean): Uint8Array {
  const length: number = encrypt ? data.length : data.length - 16; if (length < 0) throw new Error('framing');
  const spec: crypto.GcmParamsSpec = { algName: 'GcmParamsSpec', iv: { data: nonce.slice() }, aad: { data: new Uint8Array(0) }, authTag: { data: encrypt ? new Uint8Array(16) : data.slice(length) } };
  const cipher = crypto.createCipher('AES' + key.getEncoded().data.length * 8 + '|GCM|NoPadding');
  cipher.initSync(encrypt ? crypto.CryptoMode.ENCRYPT_MODE : crypto.CryptoMode.DECRYPT_MODE, key, spec);
  const output = length ? cipher.updateSync({ data: data.slice(0, length) }).data : new Uint8Array(0);
  // update may return unauthenticated plaintext; it is kept local until final
  // successfully checks the tag. An exception releases no application bytes.
  try { const tail = cipher.doFinalSync(null); return encrypt ? joinBytes(output, tail.data) : output; }
  catch (_) { throw new Error('authentication'); }
}
function advance(nonce: Uint8Array): void {
  for (let i: number = 0; i < nonce.length; i++) { nonce[i] = (nonce[i] + 1) & 255; if (nonce[i] !== 0) return; }
  throw new Error('nonce');
}
export class OsSsSession {
  private sendKey?: crypto.SymKey;
  private receiveKey?: crypto.SymKey;
  private sendNonce: Uint8Array = new Uint8Array(12);
  private receiveNonce: Uint8Array = new Uint8Array(12);
  private input: Uint8Array = new Uint8Array(0);
  private length: number = -1;
  private master: Uint8Array;
  constructor(master: Uint8Array) { this.master = master; }
  start(salt: Uint8Array): Uint8Array { this.sendKey = aesKey(ssSubkey(this.master, salt)); return salt; }
  encode(bytes: Uint8Array): Uint8Array {
    if (!this.sendKey || bytes.length > 16383) throw new Error('framing');
    const size = new Uint8Array([bytes.length >> 8, bytes.length & 255]);
    const head = crypt(this.sendKey, this.sendNonce, size, true); advance(this.sendNonce);
    const body = crypt(this.sendKey, this.sendNonce, bytes, true); advance(this.sendNonce); return joinBytes(head, body);
  }
  feed(bytes: Uint8Array): Uint8Array[] {
    this.input = joinBytes(this.input, bytes); if (this.input.length > 1024 * 1024) throw new Error('framing');
    const output: Uint8Array[] = [];
    if (!this.receiveKey) {
      if (this.input.length < this.master.length) return output;
      this.receiveKey = aesKey(ssSubkey(this.master, this.input.slice(0, this.master.length))); this.input = this.input.slice(this.master.length);
    }
    while (true) {
      if (this.length < 0) {
        if (this.input.length < 18) return output;
        const size = crypt(this.receiveKey, this.receiveNonce, this.input.slice(0, 18), false); advance(this.receiveNonce);
        this.input = this.input.slice(18); this.length = size[0] * 256 + size[1]; if (size.length !== 2 || this.length > 16383) throw new Error('framing');
      }
      if (this.input.length < this.length + 16) return output;
      const body = crypt(this.receiveKey, this.receiveNonce, this.input.slice(0, this.length + 16), false); advance(this.receiveNonce);
      this.input = this.input.slice(this.length + 16); this.length = -1; if (body.length) output.push(body);
    }
  }
  finish(): void { if (this.input.length || this.length >= 0) throw new Error('truncated'); }
}
interface OsSsVector { method: string; master: string; salt: string; key: string; client: string; server: string; reservedLength: string; emptyServer: string; carryPacket: string; }
export function verifyOsSsVectors(text: string): number {
  const vectors = JSON.parse(text) as OsSsVector[]; let checks: number = 0;
  const check = (value: boolean): void => { if (!value) throw new Error('known-answer-' + checks); checks++; };
  const encoder = new util.TextEncoder();
  for (const vector of vectors) {
    const size = vector.method === 'aes-128-gcm' ? 16 : 32, master = ssMaster('pässword-测试', size), salt = fromHex(vector.salt);
    check(equal(master, fromHex(vector.master))); check(equal(ssSubkey(master, salt), fromHex(vector.key)));
    const carry = new Uint8Array(12); carry[0] = 255; advance(carry); check(carry[0] === 0 && carry[1] === 1);
    check(equal(crypt(aesKey(ssSubkey(master, salt)), carry, new Uint8Array([120]), true), fromHex(vector.carryPacket)));
    const writer = new OsSsSession(master); writer.start(salt);
    check(equal(joinBytes(writer.encode(encoder.encodeInto('hello world')), writer.encode(encoder.encodeInto('next frame'))), fromHex(vector.client)));
    const wire = fromHex(vector.server), expected = encoder.encodeInto('HTTP/1.1 204 No Content\r\n\r\nserver data');
    for (let cut: number = 0; cut <= wire.length; cut++) {
      const reader = new OsSsSession(master); let decoded = new Uint8Array(0);
      for (const body of reader.feed(wire.slice(0, cut)).concat(reader.feed(wire.slice(cut)))) decoded = joinBytes(decoded, body);
      reader.finish(); check(equal(decoded, expected));
    }
    const byteReader = new OsSsSession(master); let bytes = new Uint8Array(0);
    for (const value of wire) for (const body of byteReader.feed(new Uint8Array([value]))) bytes = joinBytes(bytes, body);
    byteReader.finish(); check(equal(bytes, expected));
    const empty = new OsSsSession(master); const bodies = empty.feed(fromHex(vector.emptyServer)); empty.finish(); check(bodies.length === 1 && equal(bodies[0], encoder.encodeInto('empty-then-data')));
    for (const packet of [joinBytes(salt, fromHex(vector.reservedLength)), wire.slice(0, size + 17), wire.slice(0, size + 19)]) {
      let rejected: boolean = false; try { const reader = new OsSsSession(master); reader.feed(packet); reader.finish(); } catch (_) { rejected = true; } check(rejected);
    }
    for (const offset of [size + 17, wire.length - 1]) {
      const corrupted = wire.slice(); corrupted[offset] ^= 1; let rejected: boolean = false;
      try { new OsSsSession(master).feed(corrupted); } catch (_) { rejected = true; } check(rejected);
    }
  }
  check(vectors.length === 2); return checks;
}
