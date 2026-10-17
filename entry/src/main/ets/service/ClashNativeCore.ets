import clashCore from 'libclash_core.so';
import { connection } from '@kit.NetworkKit';
import { CoreRuntime } from './CoreSessionTypes';
import { CoreSessionHost } from './CoreSessionCoordinator';
import { RuleEditorSnapshot } from './RuleEditsTypes';
import { ObjectEditorSnapshot, ProxyNodeDraft, ProxyGroupDraft } from './ObjectEditsTypes';
import { NodeLinkImport } from './NodeLinkTypes';
import { ScriptPreview } from './ConfigMergeTypes';
import { ControllerAccessStore } from './ControllerAccessStore';
import { ControllerAccessHost } from './ControllerAccessController';
import { NetworkBackup, NetworkBackupSnapshot, NetworkBackupResult } from './NetworkBackupTypes';
interface NetworkBackupValidation extends NetworkBackup { error?: string; }
interface LocalHttpOptions { address: string; port: number; username: string; password: string; error?: string; }

interface NativeCoreModule {
  startAsync(configPath: string, port: number): Promise<boolean>;
  stopAsync(): Promise<boolean>;
  info(): string;
  localSocksOptions(): string;
  localHttpOptions(): string;
  editorProviderReferences(profile: string, source: string, query: string): Promise<string>;
  networkBackupSnapshot(directory: string): string;
  validateNetworkBackup(content: string): string;
  restoreNetworkBackup(directory: string, content: string, expected: string, profile: string): string;
  configureRuntimeDirectory(filesDir: string): boolean;
  setControllerSecret(secret: string): boolean;
  controllerSecret(): string;
  setMode(mode: string): boolean;
  start(configPath: string, port: number): boolean;
  stop(): void;
  isRunning(): boolean;
  validate(content: string, providerContext: string): string;
  validateSniffer(content: string): string;
  ruleEditor(content: string, edits: string, render: boolean, objects: string, merges: string, providerContext: string): string;
  objectEditor(content: string, edits: string, rules: string, validate: boolean, merges: string, providerContext: string): string;
  objectDraft(kind: string, content: string, patch: string, validate: boolean): string;
  shareLinks(content: string, occupied: string): string;
  protectFile(fd: number): boolean;
  backupYaml(content: string): string;
  backupInflate(bytes: Uint8Array, expected: number): Uint8Array;
}

export class ClashNativeCore implements CoreSessionHost, ControllerAccessHost {
  private module: NativeCoreModule = clashCore as NativeCoreModule;
  private controllerStore?: ControllerAccessStore;
  backupYaml(content: string): string { return this.module.backupYaml(content); }
  backupInflate(bytes: Uint8Array, expected: number): Uint8Array { return this.module.backupInflate(bytes, expected); }
  editorProviderReferences(profile: string, source: string, query: string): Promise<string> {
    return this.module.editorProviderReferences(profile, source, query);
  }
  networkBackupSnapshot(directory: string): NetworkBackupSnapshot {
    const result = JSON.parse(this.module.networkBackupSnapshot(directory)) as NetworkBackupSnapshot;
    if (result.error) throw new Error(result.error);
    return result;
  }
  validateNetworkBackup(content: string): NetworkBackup {
    const result = JSON.parse(this.module.validateNetworkBackup(content)) as NetworkBackupValidation;
    if (result.error) throw new Error('备份中的端口或共享设置无效');
    return result;
  }
  restoreNetworkBackup(directory: string, value: NetworkBackup, expected: string, profile: string): NetworkBackupResult {
    const result = JSON.parse(this.module.restoreNetworkBackup(directory, JSON.stringify(value), expected, profile)) as NetworkBackupResult;
    if (result.error) throw new Error(result.error);
    return result;
  }

  configureControllerStore(filesDir: string): void {
    if (!this.module.configureRuntimeDirectory(filesDir)) throw new Error('无法初始化内核临时配置目录');
    this.controllerStore = new ControllerAccessStore(filesDir, (fd: number) => this.protectFile(fd));
  }
  controllerSecret(): string { return this.module.controllerSecret(); }
  setControllerSecret(secret: string): void {
    if (!this.module.setControllerSecret(secret)) throw new Error('内置控制器密钥未能应用');
  }
  private prepareController(): void {
    if (this.controllerStore) this.setControllerSecret(this.controllerStore.credential());
  }

  async startAsync(configPath: string, port: number = 9090): Promise<boolean> {
    this.prepareController();
    return this.module.startAsync(configPath, port);
  }

  async stopAsync(): Promise<void> {
    if (!await this.module.stopAsync()) throw new Error('内核未能停止');
  }

  info(): CoreRuntime {
    return JSON.parse(this.module.info()) as CoreRuntime;
  }

  localSocksOptions(): string { return this.module.localSocksOptions(); }
  localHttpProxy(): connection.HttpProxy {
    const options: LocalHttpOptions = JSON.parse(this.module.localHttpOptions()) as LocalHttpOptions;
    if (options.error || !options.address || options.port <= 0) throw new Error('内置 HTTP 代理不可用，请启动内核并检查端口及共享规则');
    return { host: options.address, port: options.port, exclusionList: [], username: options.username, password: options.password };
  }

  setMode(mode: string): void {
    if (!this.module.setMode(mode)) throw new Error('代理模式无效');
  }

  start(configPath: string = '', port: number = 9090): boolean {
    this.prepareController();
    return this.module.start(configPath, port);
  }

  stop(): void {
    this.module.stop();
  }

  isRunning(): boolean {
    return this.module.isRunning();
  }

  protectFile(fd: number): void {
    if (!this.module.protectFile(fd)) throw new Error('无法设置私有文件权限');
  }

  validate(content: string, providerContext: string = ''): void {
    const error: string = this.module.validate(content, providerContext);
    if (error.length > 0) {
      throw new Error(error);
    }
  }

  validateSniffer(content: string): void {
    const error: string = this.module.validateSniffer(content);
    if (error.length > 0) throw new Error(error);
  }

  ruleEditor(content: string, edits: string = '', render: boolean = false, objects: string = '', merges: string = '', providerContext: string = ''): RuleEditorSnapshot {
    const result: RuleEditorSnapshot = JSON.parse(this.module.ruleEditor(content, edits, render, objects, merges, providerContext)) as RuleEditorSnapshot;
    if (result.error) throw new Error(result.error);
    return result;
  }

  previewExtensions(content: string, rules: string, objects: string, extensions: string, providerContext: string = ''): ScriptPreview {
    const result: RuleEditorSnapshot = JSON.parse(this.module.ruleEditor(content, rules, true, objects, extensions, providerContext)) as RuleEditorSnapshot;
    return { error: result.error ?? '', content: result.content ?? '', logs: result.scriptLogs ?? [] };
  }

  objectEditor(content: string, edits: string, rules: string = '', validate: boolean = true, merges: string = '', providerContext: string = ''): ObjectEditorSnapshot {
    const result: ObjectEditorSnapshot = JSON.parse(this.module.objectEditor(content, edits, rules, validate, merges, providerContext)) as ObjectEditorSnapshot;
    if (result.error) throw new Error(result.error);
    return result;
  }

  nodeDraft(content: string, patch: string = '', validate: boolean = true): ProxyNodeDraft {
    const result: ProxyNodeDraft = JSON.parse(this.module.objectDraft('proxies', content, patch, validate)) as ProxyNodeDraft;
    if (result.error) throw new Error(result.error);
    return result;
  }

  groupDraft(content: string, patch: string = '', validate: boolean = true): ProxyGroupDraft {
    const result: ProxyGroupDraft = JSON.parse(this.module.objectDraft('groups', content, patch, validate)) as ProxyGroupDraft;
    if (result.error) throw new Error(result.error);
    return result;
  }

  shareLinks(content: string, occupied: string[] = []): NodeLinkImport {
    const result: NodeLinkImport = JSON.parse(this.module.shareLinks(content, JSON.stringify(occupied))) as NodeLinkImport;
    if (result.error) throw new Error(result.error);
    return result;
  }
}
