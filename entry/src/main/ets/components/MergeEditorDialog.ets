import { VergePalette } from '../theme/VergeTheme';
import { ConfigCodeEditor } from './ConfigCodeEditor';
import { ConfigEditorController } from '../service/ConfigEditorController';

@CustomDialog
export struct MergeEditorDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  global: boolean = false;
  profileName: string = '';
  initialContent: string = '';
  onPreview: (text: string) => string = (_text: string): string => '';
  onSave: (text: string) => Promise<void> = async (_text: string): Promise<void> => {};
  onCopy: (text: string) => void = (_text: string): void => {};
  @State text: string = '';
  @State rendered: string = '';
  @State viewing: boolean = false;
  @State error: string = '';
  @State saving: boolean = false;
  @State editorReady: boolean = false;
  private editor: ConfigEditorController = new ConfigEditorController();

  aboutToAppear(): void { this.text = this.initialContent; }
  private async preview(): Promise<void> {
    if (this.saving || !this.editorReady) return;
    this.saving = true; this.error = '';
    try { this.text = await this.editor.text(); this.rendered = this.onPreview(this.text); this.viewing = true; }
    catch (error) { this.error = (error as Error).message; this.editor.markError(this.error).catch(() => {}); }
    finally { this.saving = false; }
  }
  private async save(): Promise<void> {
    if (this.saving || !this.editorReady) return;
    this.saving = true; this.error = '';
    try { this.text = await this.editor.text(); await this.onSave(this.text); this.controller?.close(); }
    catch (error) { this.viewing = false; this.error = (error as Error).message || '扩展配置未能保存'; this.editor.markError(this.error).catch(() => {}); }
    finally { this.saving = false; }
  }
  private async clear(): Promise<void> {
    if (this.saving || !this.editorReady) return;
    try { await this.editor.command('clear'); this.rendered = ''; this.error = ''; }
    catch (_) { this.error = '未能清除，请保留当前窗口并重试'; }
  }
  build() {
    Column({ space: 14 }) {
      Row({ space: 10 }) {
        Text(this.viewing ? '合并配置预览' : this.global ? '全局扩展配置' : '订阅扩展配置')
          .fontSize(20).fontWeight(FontWeight.Bold).fontColor(this.theme.text).layoutWeight(1);
        if (this.viewing) Button('复制合并配置', { type: ButtonType.Normal }).height(32).fontSize(12).borderRadius(5)
          .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).onClick(() => this.onCopy(this.rendered));
      }.width('100%');
      Text(this.global ? `应用于所有配置；当前以「${this.profileName || '默认配置'}」校验和预览。单个订阅的扩展可覆盖全局设置。` :
        `仅应用于「${this.profileName}」，订阅更新后保留。原始配置保持不变。`)
        .fontSize(12).fontColor(this.theme.textSecondary).width('100%');
      Text('列表和值整体替换；普通对象逐项合并。hosts 和 dns 下写出的子项整体替换。端口自定义设置、当前模式和 TUN 开关仍由应用管理。')
        .fontSize(11).fontColor(this.theme.textMuted).width('100%');
      // Keep the same Web editor mounted during previews so draft, selection,
      // undo history and language survive returning to edit.
      Column() {
        ConfigCodeEditor({ editor: this.editor, initialContent: this.initialContent, label: 'YAML 扩展配置编辑区', disabled: this.saving,
          onReady: (ready: boolean): void => { this.editorReady = ready; },
          onChange: (revision: number): void => { if (this.editor.changedSinceRead(revision)) { this.error = ''; this.rendered = ''; } } });
      }.width('100%').layoutWeight(this.viewing ? 0 : 1).visibility(this.viewing ? Visibility.None : Visibility.Visible);
      if (this.viewing) {
        Scroll() {
          Text(this.rendered).accessibilityText('合并配置预览').fontSize(12).fontFamily('monospace')
            .fontColor(this.theme.textSecondary).textAlign(TextAlign.Start).copyOption(CopyOptions.LocalDevice).width('100%').padding(12);
        }.width('100%').layoutWeight(1).backgroundColor(this.theme.field).borderRadius(6).clip(true);
      }
      if (this.error) Text(this.error).fontSize(12).fontColor(this.theme.danger).maxLines(3).width('100%');
      Row({ space: 10 }) {
        Button(this.viewing ? '返回编辑' : '清除扩展', { type: ButtonType.Normal }).height(34).fontSize(12).borderRadius(5)
          .fontColor(this.theme.primary).backgroundColor(Color.Transparent).enabled(!this.saving && this.editorReady)
          .onClick(() => { if (this.viewing) this.viewing = false; else this.clear(); });
        Blank();
        if (!this.viewing) Button('校验并预览', { type: ButtonType.Normal }).height(34).fontSize(12).borderRadius(5)
          .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(!this.saving && this.editorReady).onClick(() => this.preview());
        Button('取消', { type: ButtonType.Normal }).height(34).fontSize(12).borderRadius(5).fontColor(this.theme.textSecondary)
          .backgroundColor(this.theme.field).enabled(!this.saving).onClick(() => this.controller?.close());
        Button(this.saving ? '保存中…' : '保存并应用', { type: ButtonType.Normal }).height(34).fontSize(12).borderRadius(5)
          .fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).enabled(!this.saving && this.editorReady).onClick(() => this.save());
      }.width('100%');
    }.width('94%').constraintSize({ maxWidth: 1080 }).height('86%').padding(24).borderRadius(10).backgroundColor(this.theme.surface);
  }
}
