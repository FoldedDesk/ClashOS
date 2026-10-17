declare module 'libvlessfixture.so' {
  interface TlsFixtureBridge { start(certificate: string, key: string): boolean; stop(): void; blake3(input: Uint8Array, context: string, length: number): Uint8Array; }
  const bridge: TlsFixtureBridge;
  export default bridge;
}
