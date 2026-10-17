declare module 'libvlessfixture.so' {
  interface TlsFixtureBridge { start(certificate: string, key: string): boolean; stop(): void; }
  const bridge: TlsFixtureBridge;
  export default bridge;
}
