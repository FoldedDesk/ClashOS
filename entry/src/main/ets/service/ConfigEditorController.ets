export interface ConfigEditorPort {
  read: () => Promise<string>;
  command: (name: string, value: number) => Promise<void>;
  markError: (message: string) => Promise<void>;
  replace?: (text: string, expected?: string) => Promise<void>;
}
interface EditorSnapshot { text: string; revision: number; composing: boolean; }

// Keep the document in the local editor, and read it at the actual save/validate
// action. A delayed selection/status notification is never the saved document.
export class ConfigEditorController {
  private port: ConfigEditorPort | undefined = undefined;
  private version: number = 0;
  private lastReadRevision: number = -1;

  bind(port: ConfigEditorPort): number { this.port = port; this.lastReadRevision = -1; return ++this.version; }
  unbind(version: number): void { if (this.version === version) { this.port = undefined; ++this.version; } }
  async text(): Promise<string> {
    const port: ConfigEditorPort | undefined = this.port, version: number = this.version;
    if (!port) throw new Error('编辑器尚未就绪');
    const raw: string = await port.read();
    if (version !== this.version || port !== this.port) throw new Error('编辑器已关闭，请重新打开配置');
    let value: EditorSnapshot | string;
    try {
      value = JSON.parse(raw) as EditorSnapshot | string;
      // ArkWeb versions differ in whether an evaluated JS string is JSON-wrapped.
      if (typeof value === 'string') value = JSON.parse(value) as EditorSnapshot;
    } catch (_) { throw new Error('无法读取编辑器内容，请保留当前窗口并重试'); }
    if (!value || typeof value !== 'object' || typeof value.text !== 'string' ||
      !Number.isSafeInteger(value.revision) || value.revision < 0 || typeof value.composing !== 'boolean')
      throw new Error('无法读取编辑器内容，请保留当前窗口并重试');
    if (value.composing) throw new Error('请先完成输入法候选，再校验或保存配置');
    this.lastReadRevision = value.revision;
    return value.text;
  }
  changedSinceRead(revision: number): boolean { return revision !== this.lastReadRevision; }
  async command(name: string, value: number = 0): Promise<void> {
    if (['complete', 'search', 'undo', 'redo', 'clear', 'wrap', 'goto', 'readonly'].indexOf(name) < 0 || !Number.isFinite(value)) return;
    await this.port?.command(name, value);
  }
  async markError(message: string): Promise<void> { await this.port?.markError(message); }
  async replace(text: string, expected?: string): Promise<void> {
    const port: ConfigEditorPort | undefined = this.port, version: number = this.version;
    if (!port?.replace) throw new Error('编辑器尚未就绪');
    await port.replace(text, expected);
    if (version !== this.version || port !== this.port) throw new Error('编辑器已关闭，请重新打开配置');
    this.lastReadRevision = -1;
  }
}
