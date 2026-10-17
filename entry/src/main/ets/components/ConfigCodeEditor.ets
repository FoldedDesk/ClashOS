import { webview } from '@kit.ArkWeb';
import { VergePalette } from '../theme/VergeTheme';
import { ConfigEditorController } from '../service/ConfigEditorController';

interface EditorPosition { line: number; column: number; lines: number; language: string; dirty: boolean; revision: number; }
interface ProviderReferenceRequest { id: number; revision: number; query: string; }
interface ProviderReferenceResponse { providers: Object[]; }
class EditorStatusBridge {
  onStatus: (value: string) => void = (_value: string): void => {};
  onProviders: (value: string) => void = (_value: string): void => {};
  status(value: string): void { if (typeof value === 'string' && value.length <= 512) this.onStatus(value); }
  providers(value: string): void { if (typeof value === 'string' && value.length <= 768 * 1024) this.onProviders(value); }
}

@Component
export struct ConfigCodeEditor {
  @StorageLink('clashosTheme') @Watch('updateTheme') theme: VergePalette = new VergePalette();
  editor: ConfigEditorController = new ConfigEditorController();
  initialContent: string = '';
  language: string = 'auto';
  scriptScope: string = '';
  providerReferences: ((query: string) => Promise<string>) | undefined = undefined;
  label: string = 'Clash YAML / JSON 配置编辑区';
  @Prop @Watch('updateReadOnly') disabled: boolean = false;
  onReady: (ready: boolean) => void = (_ready: boolean): void => {};
  onChange: (revision: number) => void = (_revision: number): void => {};
  private web: webview.WebviewController = new webview.WebviewController();
  private bridge: EditorStatusBridge = new EditorStatusBridge();
  private binding: number = 0;
  private active: boolean = true;
  private mounted: boolean = false;
  private lastRevision: number = 0;
  private startupTimer: number = -1;
  @State ready: boolean = false;
  @State failed: boolean = false;
  @State fallback: string = '';
  @State wrapped: boolean = true;
  @State status: string = '正在打开编辑器…';

  aboutToAppear(): void {
    this.startupTimer = setTimeout(() => this.startupFailed(), 8000);
    this.bridge.onStatus = (raw: string): void => {
      if (!this.active) return;
      try {
        const value: EditorPosition = JSON.parse(raw) as EditorPosition;
        if (Number.isSafeInteger(value.line) && value.line > 0 && Number.isSafeInteger(value.column) && value.column > 0)
          this.status = `第 ${value.line} 行，第 ${value.column} 列 · ${value.language === 'javascript' ? 'JavaScript' : value.language === 'json' ? 'JSON' : 'YAML'}${value.dirty ? ' · 已修改' : ''}`;
        if (Number.isSafeInteger(value.revision) && value.revision !== this.lastRevision) { this.lastRevision = value.revision; this.onChange(value.revision); }
      } catch (_) {}
    };
    this.bridge.onProviders = (raw: string): void => { this.readProviderReferences(raw); };
    this.binding = this.editor.bind({
      read: async (): Promise<string> => {
        if (this.failed) return JSON.stringify({ text: this.fallback, revision: this.lastRevision, composing: false });
        if (!this.ready) throw new Error('编辑器尚未就绪，请稍后重试');
        return await this.web.runJavaScript('JSON.stringify(window.ClashOSEditor.snapshot())');
      },
      command: async (name: string, value: number): Promise<void> => {
        if (this.failed && name === 'clear' && !this.disabled) { this.fallback = ''; this.onChange(++this.lastRevision); return; }
        if (this.ready && !this.failed) await this.web.runJavaScript(`window.ClashOSEditor.command(${JSON.stringify(name)},${value})`);
      },
      markError: async (message: string): Promise<void> => {
        if (this.ready && !this.failed) await this.web.runJavaScript(`window.ClashOSEditor.markError(${JSON.stringify(message)})`);
      },
      replace: async (text: string, expected?: string): Promise<void> => {
        if (this.disabled) throw new Error('编辑器当前只读');
        if (this.failed) { if (expected !== undefined && this.fallback !== expected) throw new Error('编辑内容已变化，请重试'); this.fallback = text; this.onChange(++this.lastRevision); return; }
        if (!this.ready) throw new Error('编辑器尚未就绪');
        const result: string = await this.web.runJavaScript(`window.ClashOSEditor.replace(${JSON.stringify(text)}${expected === undefined ? '' : ',' + JSON.stringify(expected)})`);
        if (result !== 'true') throw new Error('内容已变化或输入尚未完成，请重试');
      }
    });
  }
  aboutToDisappear(): void {
    if (this.startupTimer >= 0) clearTimeout(this.startupTimer);
    this.active = false; this.bridge.onStatus = (_value: string): void => {};
    this.bridge.onProviders = (_value: string): void => {};
    if (this.ready && !this.failed) this.web.runJavaScript('window.ClashOSEditor.dispose()').catch(() => {});
    this.editor.unbind(this.binding);
  }
  private async initialize(): Promise<void> {
    if (this.mounted || this.failed || !this.active) return;
    try {
      const payload: string = JSON.stringify({ text: this.initialContent, theme: this.theme, language: this.language, scriptScope: this.scriptScope, label: this.label,
        providerReferences: this.providerReferences !== undefined });
      await this.web.runJavaScript(`window.ClashOSEditor.mount(${payload})`);
      if (!this.active) return;
      if (this.startupTimer >= 0) clearTimeout(this.startupTimer);
      this.mounted = true; this.ready = true; this.onReady(true);
      await this.updateReadOnly();
    } catch (_) {
      if (!this.active) return;
      // Only fall back before editing starts, never replace a live unsaved draft.
      this.startupFailed();
    }
  }
  private startupFailed(): void {
    if (!this.active || this.mounted || this.failed) return;
    this.fallback = this.initialContent; this.failed = true; this.status = '代码编辑器不可用，已切换普通编辑'; this.onReady(true);
  }
  private async readProviderReferences(raw: string): Promise<void> {
    let request: ProviderReferenceRequest;
    try { request = JSON.parse(raw) as ProviderReferenceRequest; } catch (_) { return; }
    if (!this.active || !this.ready || this.failed || !Number.isSafeInteger(request?.id) || request.id <= 0 ||
      !Number.isSafeInteger(request.revision) || request.revision < 0 || typeof request.query !== 'string' || request.query.length > 256 * 1024) return;
    let result: ProviderReferenceResponse = { providers: [] };
    try {
      const lookup = this.providerReferences;
      if (lookup && !this.disabled) result = JSON.parse(await lookup(request.query)) as ProviderReferenceResponse;
    } catch (_) {}
    if (!this.active || !this.ready || this.failed) return;
    try { await this.web.runJavaScript(`window.ClashOSEditor.providerResult(${request.id},${request.revision},${JSON.stringify(result)})`); } catch (_) {}
  }
  private async updateTheme(): Promise<void> {
    if (this.ready && !this.failed) try { await this.web.runJavaScript(`window.ClashOSEditor.setTheme(${JSON.stringify(this.theme)})`); } catch (_) {}
  }
  private async updateReadOnly(): Promise<void> {
    try { await this.editor.command('readonly', this.disabled ? 1 : 0); } catch (_) {}
  }
  private action(name: string): void { this.editor.command(name).catch(() => { this.status = '编辑操作未完成，请重试'; }); }

  build() {
    Column({ space: 0 }) {
      if (!this.failed) Row({ space: 6 }) {
        Button('补全', { type: ButtonType.Normal }).onClick(() => this.action('complete'))
          .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).height(30).fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).borderRadius(this.theme.radius(4)).enabled(this.ready && !this.disabled);
        Button('查找', { type: ButtonType.Normal }).onClick(() => this.action('search'))
          .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).height(30).fontColor(this.theme.textSecondary).backgroundColor(this.theme.surface).borderRadius(this.theme.radius(4)).enabled(this.ready);
        Button('撤销', { type: ButtonType.Normal }).onClick(() => this.action('undo'))
          .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).height(30).fontColor(this.theme.textSecondary).backgroundColor(this.theme.surface).borderRadius(this.theme.radius(4)).enabled(this.ready && !this.disabled);
        Button('重做', { type: ButtonType.Normal }).onClick(() => this.action('redo'))
          .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).height(30).fontColor(this.theme.textSecondary).backgroundColor(this.theme.surface).borderRadius(this.theme.radius(4)).enabled(this.ready && !this.disabled);
        Blank();
        Button(this.wrapped ? '自动换行 ✓' : '自动换行', { type: ButtonType.Normal }).onClick(() => {
          this.wrapped = !this.wrapped; this.editor.command('wrap', this.wrapped ? 1 : 0).catch(() => {});
        }).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).height(30).fontColor(this.theme.textSecondary).backgroundColor(this.theme.surface).borderRadius(this.theme.radius(4)).enabled(this.ready);
      }.width('100%').padding(6).backgroundColor(this.theme.surface);
      if (this.failed) {
        TextArea({ text: this.fallback, placeholder: this.language === 'javascript' ? '输入 JavaScript 扩展脚本' : '输入 Clash YAML 或 JSON 配置' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted)
          .fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontFamily('monospace').backgroundColor(this.theme.field).width('100%').layoutWeight(1).enabled(!this.disabled)
          .onChange((text: string) => { this.fallback = text; this.onChange(++this.lastRevision); });
      } else {
        Web({ src: $rawfile('config-editor/index.html'), controller: this.web })
          .javaScriptAccess(true).fileAccess(false).domStorageAccess(false).databaseAccess(false).blockNetwork(true)
          .javaScriptProxy({ object: this.bridge, name: 'clashosEditorBridge', methodList: ['status', 'providers'], controller: this.web })
          .onOverrideUrlLoading(() => this.mounted)
          .onPageEnd(() => this.initialize())
          .width('100%').layoutWeight(1).enabled(!this.disabled);
      }
      Text(this.status).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%').padding({ left: 10, right: 10, top: 6, bottom: 6 })
        .backgroundColor(this.theme.surface).maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
    }.width('100%').layoutWeight(1).border({ width: 1, color: this.theme.border }).borderRadius(this.theme.radius(6)).clip(true);
  }
}
