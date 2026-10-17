export interface CoreRuntime {
  running: boolean;
  instance: string;
  configPath: string;
  temporaryConfig?: boolean;
  mode: string;
  controllerPort: number;
  httpPort: number;
  socksPort: number;
  proxyHost?: string;
  allowLan?: boolean;
  error?: string;
}

export interface VpnStartOptions {
  configPath: string;
  mode: string;
  controllerPort: number;
}

export interface VpnStartRequest extends VpnStartOptions {
  session: string;
  createdAt: number;
}

export interface VpnState {
  state: string;
  error: string;
  port: number;
  updatedAt: number;
  session: string;
  core: CoreRuntime;
}

export function emptyRuntime(): CoreRuntime {
  return { running: false, instance: '', configPath: '', mode: 'Rule', controllerPort: 9090, httpPort: 0, socksPort: 0 };
}
