import { dialogActivity } from '../service/DialogActivity';
import { VergePalette } from '../theme/VergeTheme';
import { ScriptLog, ScriptPreview } from '../service/ConfigMergeTypes';
import { ConfigCodeEditor } from './ConfigCodeEditor';
import { ConfigEditorController } from '../service/ConfigEditorController';

@CustomDialog
export struct ScriptEditorDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  private dialogActivityId: number = 0;
  global: boolean = false;
  profileName: string = '';
  initialContent: string = '';
  onPreview: (text: string) => ScriptPreview = (_text: string): ScriptPreview => ({ error: '', content: '', logs: [] });
  onSave: (text: string) => Promise<void> = async (_text: string): Promise<void> => {};
  onCopy: (text: string, label: string) => void = (_text: string, _label: string): void => {};
  @State text: string = '';
  @State rendered: string = '';
  @State logs: ScriptLog[] = [];
  @State viewing: boolean = false;
  @State error: string = '';
  @State saving: boolean = false;
  @State editorReady: boolean = false;
  private editor: ConfigEditorController = new ConfigEditorController();

  aboutToAppear(): void { this.dialogActivityId = dialogActivity.enter(); this.text = this.initialContent; }
  private async preview(): Promise<void> {
    if (this.saving || !this.editorReady) return;
    this.saving = true; this.error = ''; this.logs = [];
    try {
      this.text = await this.editor.text();
      const result: ScriptPreview = this.onPreview(this.text); this.logs = result.logs; this.error = result.error;
      if (!result.error) { this.rendered = result.content; this.viewing = true; }
      else this.editor.markError(result.error).catch(() => {});
    } catch (error) { this.error = (error as Error).message; this.editor.markError(this.error).catch(() => {}); }
    finally { this.saving = false; }
  }
  private async save(): Promise<void> {
    if (this.saving || !this.editorReady) return;
    this.saving = true; this.error = '';
    try { this.text = await this.editor.text(); await this.onSave(this.text); this.controller?.close(); }
    catch (error) { this.viewing = false; this.error = (error as Error).message || '脚本未能保存，原配置已保留'; this.editor.markError(this.error).catch(() => {}); }
    finally { this.saving = false; }
  }
  private async clear(): Promise<void> {
    if (this.saving || !this.editorReady) return;
    try { await this.editor.command('clear'); this.rendered = ''; this.logs = []; this.error = ''; }
    catch (_) { this.error = '未能清除，请保留当前窗口并重试'; }
  }
  private copyLogs(): void {
    this.onCopy([this.error, ...this.logs.map((item: ScriptLog) => `[${item.scope}/${item.level}] ${item.text}`)].filter((line: string) => !!line).join('\n'), '脚本输出');
  }
  aboutToDisappear(): void { dialogActivity.leave(this.dialogActivityId); }

  build() {
    Column({ space: 12 }) {
      Row({ space: 10 }) {
        Text(this.viewing ? '脚本合并预览' : this.global ? '全局扩展脚本' : '订阅扩展脚本')
          .fontSize(this.theme.font(20)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text).layoutWeight(1);
        if (this.viewing) Button('复制合并配置', { type: ButtonType.Normal }).height(32).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).onClick(() => this.onCopy(this.rendered, '合并配置'));
      }.width('100%');
      Text(`${this.global ? '应用于所有配置' : '仅应用于当前订阅'}；当前 profileName 为「${this.profileName}」。入口 main(config, profileName) 需返回配置对象。`)
        .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
      Text('本地 JavaScript：每阶段限时 500 ms、内存 64 MB，不提供文件、网络或计时器。脚本在同范围 YAML 扩展之后运行，保存失败时保留原配置。')
        .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
      Column() {
        ConfigCodeEditor({ editor: this.editor, initialContent: this.initialContent, language: 'javascript', scriptScope: this.global ? 'global' : 'profile',
          label: 'JavaScript 扩展脚本编辑区', disabled: this.saving,
          onReady: (ready: boolean): void => { this.editorReady = ready; },
          onChange: (revision: number): void => { if (this.editor.changedSinceRead(revision)) { this.error = ''; this.rendered = ''; this.logs = []; } } });
      }.width('100%').layoutWeight(this.viewing ? 0 : 1).visibility(this.viewing ? Visibility.None : Visibility.Visible);
      if (this.viewing) {
        Scroll() {
          Text(this.rendered).accessibilityText('脚本合并配置预览').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontFamily('monospace')
            .fontColor(this.theme.textSecondary).textAlign(TextAlign.Start).copyOption(CopyOptions.LocalDevice).width('100%').padding(12);
        }.width('100%').layoutWeight(1).backgroundColor(this.theme.field).borderRadius(this.theme.radius(6)).clip(true);
      }
      if (this.logs.length || this.error) {
        Row() {
          Text('脚本输出').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).layoutWeight(1);
          Button('复制输出', { type: ButtonType.Normal }).height(26).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary).backgroundColor(Color.Transparent).onClick(() => this.copyLogs());
        }.width('100%');
        Scroll() {
          Column({ space: 4 }) {
            if (this.error) Text(this.error).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontFamily('monospace').fontColor(this.theme.danger).width('100%');
            ForEach(this.logs, (item: ScriptLog) => {
              Text(`[${item.scope}/${item.level}] ${item.text}`).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontFamily('monospace')
                .fontColor(item.level === 'error' ? this.theme.danger : item.level === 'warning' ? this.theme.warning : this.theme.textSecondary).width('100%');
            }, (_item: ScriptLog, index: number) => `${index}`);
          }.width('100%');
        }.width('100%').constraintSize({ maxHeight: 130 }).padding(8).borderRadius(this.theme.radius(5)).backgroundColor(this.theme.field);
      }
      Row({ space: 10 }) {
        Button(this.viewing ? '返回脚本' : '清除脚本', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.primary).backgroundColor(Color.Transparent).enabled(!this.saving && this.editorReady)
          .onClick(() => { if (this.viewing) this.viewing = false; else this.clear(); });
        Blank();
        if (!this.viewing) Button('试运行并预览', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(!this.saving && this.editorReady).onClick(() => this.preview());
        Button('取消', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).fontColor(this.theme.textSecondary)
          .backgroundColor(this.theme.field).enabled(!this.saving).onClick(() => this.controller?.close());
        Button(this.saving ? '保存中…' : '保存并应用', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).enabled(!this.saving && this.editorReady).onClick(() => this.save());
      }.width('100%');
    }.width('94%').constraintSize({ maxWidth: 1080 }).height('88%').padding(24).borderRadius(this.theme.radius(10)).backgroundColor(this.theme.surface);
  }
}
