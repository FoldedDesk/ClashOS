declare module 'libclahsos_tun.so' {
  interface ClahsosTunModule {
    start(fd: number, port: number): Promise<boolean>;
    stop(): Promise<boolean>;
    stopSync(): void;
    status(): string;
  }
  const tunnel: ClahsosTunModule;
  export default tunnel;
}
