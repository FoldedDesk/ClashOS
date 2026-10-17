declare module 'libclash_core.so' {
  interface ClashCoreNativeModule {
    startAsync(configPath: string, port: number): Promise<boolean>;
    stopAsync(): Promise<boolean>;
    info(): string;
    localSocksOptions(): string;
  configureRuntimeDirectory(filesDir: string): boolean;
    setControllerSecret(secret: string): boolean;
    controllerSecret(): string;
    setMode(mode: string): boolean;
    start(configPath: string, port: number): boolean;
    stop(): void;
    isRunning(): boolean;
    validate(content: string): string;
    validateSniffer(content: string): string;
    protectFile(fd: number): boolean;
    backupYaml(content: string): string;
    backupInflate(bytes: Uint8Array, expected: number): Uint8Array;
  }

  const clashCore: ClashCoreNativeModule;
  export default clashCore;
}
