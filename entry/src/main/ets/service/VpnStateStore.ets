import { fileIo } from '@kit.CoreFileKit';
import { VpnState, VpnStartOptions, VpnStartRequest, emptyRuntime } from './CoreSessionTypes';

interface VpnCommand {
  action: string;
  session: string;
  createdAt: number;
}

export class VpnStateStore {
  private path: string;

  constructor(filesDir: string) { this.path = `${filesDir}/vpn-state.json`; }

  read(): VpnState {
    try {
      const state: VpnState = JSON.parse(fileIo.readTextSync(this.path)) as VpnState;
      if (['starting', 'running', 'updating', 'stopping', 'stopped', 'error'].indexOf(state.state) >= 0 &&
        typeof state.updatedAt === 'number' && typeof state.port === 'number' && typeof state.error === 'string' &&
        typeof state.session === 'string' && state.core !== undefined && typeof state.core.running === 'boolean' &&
        typeof state.core.instance === 'string' && typeof state.core.configPath === 'string' &&
        ['Rule', 'Global', 'Direct'].indexOf(state.core.mode) >= 0 && Number.isInteger(state.core.controllerPort) &&
        Number.isInteger(state.core.httpPort) && Number.isInteger(state.core.socksPort)) return state;
    } catch (_) { }
    return { state: 'stopped', error: '', port: 0, updatedAt: 0, session: '', core: emptyRuntime() };
  }

  private writeAtomic(path: string, value: string): void {
    const temporary: string = `${path}.${Date.now()}-${Math.random().toString(36).slice(2)}.tmp`;
    const file: fileIo.File = fileIo.openSync(temporary,
      fileIo.OpenMode.CREATE | fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.TRUNC);
    try {
      fileIo.writeSync(file.fd, value);
      fileIo.fsyncSync(file.fd);
    } finally { fileIo.closeSync(file); }
    fileIo.renameSync(temporary, path);
  }

  // Only the VPN extension writes runtime state; the UI sends a separate stop command.
  write(state: VpnState): void { this.writeAtomic(this.path, JSON.stringify(state)); }

  requestStart(options: VpnStartOptions, session: string): void {
    const request: VpnStartRequest = { configPath: options.configPath, mode: options.mode,
      controllerPort: options.controllerPort, session, createdAt: Date.now() };
    this.writeAtomic(`${this.path}.start`, JSON.stringify(request));
  }

  readStart(): VpnStartRequest | undefined {
    try {
      const request: VpnStartRequest = JSON.parse(fileIo.readTextSync(`${this.path}.start`)) as VpnStartRequest;
      const age: number = Date.now() - request.createdAt;
      if (typeof request.session === 'string' && request.session.length > 0 && typeof request.configPath === 'string' &&
        ['Rule', 'Global', 'Direct'].indexOf(request.mode) >= 0 && Number.isInteger(request.controllerPort) &&
        request.controllerPort > 0 && request.controllerPort < 65536 && Number.isFinite(age) && age >= -5000 && age < 90000) return request;
    } catch (_) { }
    return undefined;
  }

  clearStart(session?: string): void {
    try {
      const path: string = `${this.path}.start`;
      const request: VpnStartRequest = JSON.parse(fileIo.readTextSync(path)) as VpnStartRequest;
      if (session === undefined || request.session === session) fileIo.unlinkSync(path);
    } catch (_) { }
  }

  requestStop(session: string): void {
    const command: VpnCommand = { action: 'stop', session, createdAt: Date.now() };
    this.writeAtomic(`${this.path}.command`, JSON.stringify(command));
  }

  shouldStop(session: string): boolean {
    try {
      const command: VpnCommand = JSON.parse(fileIo.readTextSync(`${this.path}.command`)) as VpnCommand;
      return command.action === 'stop' && command.session === session && Date.now() - command.createdAt < 60000;
    } catch (_) { return false; }
  }
}
