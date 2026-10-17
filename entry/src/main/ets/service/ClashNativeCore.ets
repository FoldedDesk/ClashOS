import clashCore from 'libclash_core.so';
import { CoreRuntime } from './CoreSessionTypes';
import { CoreSessionHost } from './CoreSessionCoordinator';
import { RuleEditorSnapshot } from './RuleEditsTypes';
import { ObjectEditorSnapshot, ProxyNodeDraft, ProxyGroupDraft } from './ObjectEditsTypes';
import { NodeLinkImport } from './NodeLinkTypes';
import { ScriptPreview } from './ConfigMergeTypes';
import { ControllerAccessStore } from './ControllerAccessStore';
import { ControllerAccessHost } from './ControllerAccessController';

interface NativeCoreModule {
  startAsync(configPath: string, port: number): Promise<boolean>;
  stopAsync(): Promise<boolean>;
  info(): string;
  configureRuntimeDirectory(filesDir: string): boolean;
  setControllerSecret(secret: string): boolean;
  controllerSecret(): string;
  setMode(mode: string): boolean;
  start(configPath: string, port: number): boolean;
  stop(): void;
  isRunning(): boolean;
  validate(content: string): string;
  ruleEditor(content: string, edits: string, render: boolean, objects: string, merges: string): string;
  objectEditor(content: string, edits: string, rules: string, validate: boolean, merges: string): string;
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

  validate(content: string): void {
    const error: string = this.module.validate(content);
    if (error.length > 0) {
      throw new Error(error);
    }
  }

  ruleEditor(content: string, edits: string = '', render: boolean = false, objects: string = '', merges: string = ''): RuleEditorSnapshot {
    const result: RuleEditorSnapshot = JSON.parse(this.module.ruleEditor(content, edits, render, objects, merges)) as RuleEditorSnapshot;
    if (result.error) throw new Error(result.error);
    return result;
  }

  previewExtensions(content: string, rules: string, objects: string, extensions: string): ScriptPreview {
    const result: RuleEditorSnapshot = JSON.parse(this.module.ruleEditor(content, rules, true, objects, extensions)) as RuleEditorSnapshot;
    return { error: result.error ?? '', content: result.content ?? '', logs: result.scriptLogs ?? [] };
  }

  objectEditor(content: string, edits: string, rules: string = '', validate: boolean = true, merges: string = ''): ObjectEditorSnapshot {
    const result: ObjectEditorSnapshot = JSON.parse(this.module.objectEditor(content, edits, rules, validate, merges)) as ObjectEditorSnapshot;
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
