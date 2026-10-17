import { dialogActivity } from '../service/DialogActivity';
import { VergePalette, createPalette } from '../theme/VergeTheme';
import { NativeStyles, nativeStyles, parseNativeStyles } from '../theme/NativeStyles';
import { ConfigCodeEditor } from './ConfigCodeEditor';
import { ConfigEditorController } from '../service/ConfigEditorController';

@CustomDialog
export struct NativeStyleDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  private dialogActivityId: number = 0;
  initialStyles?: NativeStyles;
  accent: string = '#3478F6';
  onSave: (value: NativeStyles) => void = (_value: NativeStyles): void => {};
  onCopy: (text: string) => Promise<void> = async (_text: string): Promise<void> => {};
  private editor: ConfigEditorController = new ConfigEditorController();
  @State initialContent: string = '';
  @State ready: boolean = false;
  @State busy: boolean = false;
  @State replacing: boolean = false;
  @State error: string = '';
  @State message: string = '';
  @State fonts: string[] = ['', 'HarmonyOS Sans', 'monospace', 'serif', 'sans-serif'];
  @State draft: NativeStyles = nativeStyles();
  @State light: VergePalette = new VergePalette();
  @State dark: VergePalette = new VergePalette();

  aboutToAppear(): void { this.dialogActivityId = dialogActivity.enter();
    this.draft = nativeStyles(this.initialStyles); this.initialContent = JSON.stringify(this.draft, null, 2); this.preview(this.draft);
    try { this.fonts = Array.from(new Set<string>(this.fonts.concat(this.getUIContext().getFont().getSystemFontList().filter((name: string) => name.length > 0 && name.length <= 120)))).slice(0, 256); } catch (_) {}
  }
  private preview(value: NativeStyles): void {
    this.light = createPalette(false, this.accent, value); this.dark = createPalette(true, this.accent, value); this.draft = value;
  }
  private async action(kind: number): Promise<void> {
    if (!this.ready || this.busy) return; this.replacing = false; this.busy = true; this.error = ''; this.message = '';
    try {
      const value: NativeStyles = parseNativeStyles(await this.editor.text()); this.preview(value);
      if (kind === 0) this.message = '样式校验通过，预览已更新';
      else if (kind === 1) { await this.onCopy(JSON.stringify(value, null, 2)); this.message = '样式已复制'; }
      else { this.onSave(value); this.controller?.close(); }
    } catch (error) { this.error = (error as Error).message || '样式未能应用'; this.editor.markError(this.error).catch(() => {}); }
    finally { this.busy = false; }
  }
  private async preset(kind: number): Promise<void> {
    if (!this.ready || this.busy) return; this.replacing = true; this.busy = true; this.error = ''; this.message = '';
    try {
      const value: NativeStyles = nativeStyles();
      if (kind === 1) { value.contentGap = 8; value.cardRadius = 4; }
      else if (kind === 2) { value.fontScale = 1.15; value.contentGap = 16; value.cardRadius = 10; }
      else if (kind === 3) {
        value.light = { canvas: '#EDF2F8', chrome: '#F4F7FC', surface: '#FFFFFF', field: '#F2F5FA' };
        value.dark = { canvas: '#151B27', chrome: '#192233', surface: '#202C40', field: '#26334B' };
      }
      await this.editor.replace(JSON.stringify(value, null, 2)); this.preview(value);
    } catch (error) { this.error = (error as Error).message || '未能填入样式'; }
    finally { this.busy = false; this.replacing = false; }
  }
  private async chooseFont(index: number): Promise<void> {
    if (!this.ready || this.busy || index < 0 || index >= this.fonts.length) return; this.replacing = true; this.busy = true; this.error = ''; this.message = '';
    try {
      const before: string = await this.editor.text(), value: NativeStyles = parseNativeStyles(before); value.fontFamily = this.fonts[index];
      await this.editor.replace(JSON.stringify(value, null, 2), before); this.preview(value);
    } catch (error) { this.error = (error as Error).message || '请先修正 JSON 样式'; }
    finally { this.busy = false; this.replacing = false; }
  }
  aboutToDisappear(): void { dialogActivity.leave(this.dialogActivityId); }

  build() {
    Column({ space: 10 }) {
      Text('自定义样式').fontSize(this.theme.font(20)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text).width('100%');
      Text('设置字体、字号比例、圆角、边距及浅色/深色配色。未安装字体由系统替代，代码保留等宽字体；预设替换可撤销。')
        .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
      Row({ space: 8 }) {
        Text('字体').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary);
        Select(this.fonts.map((name: string): SelectOption => ({ value: name || '系统默认' }))).value(this.draft.fontFamily || '系统默认')
          .selected(this.fonts.indexOf(this.draft.fontFamily)).font({ size: this.theme.font(12), family: this.theme.fontFamily })
          .height(36).layoutWeight(1).enabled(this.ready && !this.busy).onSelect((index: number) => this.chooseFont(index));
      }.width('100%');
      Row({ space: 10 }) {
        Column({ space: 4 }) {
          Text('浅色 · ClashOS Aa 123 中文').fontSize(this.light.font(16)).fontFamily(this.light.fontFamily).fontColor(this.light.text).maxLines(1);
          Text(`字号 ${Math.round(this.light.fontScale * 100)}% · 圆角 ${this.light.cardRadius} · 边距 ${this.light.contentGap}`)
            .fontSize(this.light.font(11)).fontFamily(this.light.fontFamily).fontColor(this.light.textSecondary);
        }.padding(12).layoutWeight(1).borderRadius(this.light.radius(8)).backgroundColor(this.light.surface).border({ width: 1, color: this.light.border });
        Column({ space: 4 }) {
          Text('深色 · ClashOS Aa 123 中文').fontSize(this.dark.font(16)).fontFamily(this.dark.fontFamily).fontColor(this.dark.text).maxLines(1);
          Text(`字号 ${Math.round(this.dark.fontScale * 100)}% · 圆角 ${this.dark.cardRadius} · 边距 ${this.dark.contentGap}`)
            .fontSize(this.dark.font(11)).fontFamily(this.dark.fontFamily).fontColor(this.dark.textSecondary);
        }.padding(12).layoutWeight(1).borderRadius(this.dark.radius(8)).backgroundColor(this.dark.surface).border({ width: 1, color: this.dark.border });
      }.width('100%');
      ConfigCodeEditor({ editor: this.editor, initialContent: this.initialContent, language: 'json', label: 'JSON 原生样式编辑区', disabled: this.busy && !this.replacing,
        onReady: (ready: boolean): void => { this.ready = ready; },
        onChange: (revision: number): void => { if (this.editor.changedSinceRead(revision)) { this.error = ''; this.message = ''; } } });
      Flex({ wrap: FlexWrap.Wrap }) {
        ForEach(['默认样式', '紧凑布局', '大字易读', '柔和配色'], (label: string, index: number) => {
          Button(label, { type: ButtonType.Normal }).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).height(32).borderRadius(this.theme.radius(5))
            .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).margin({ right: 8, bottom: 4 })
            .enabled(this.ready && !this.busy).onClick(() => this.preset(index));
        });
      }.width('100%');
      if (this.error) Text(this.error).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger).maxLines(3).width('100%');
      if (this.message) Text(this.message).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.success).width('100%');
      Flex({ wrap: FlexWrap.Wrap, justifyContent: FlexAlign.End }) {
        ForEach(['预览校验', '复制样式', '取消', '应用样式'], (label: string, index: number) => {
          Button(label, { type: ButtonType.Normal }).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).height(34).borderRadius(this.theme.radius(5))
            .fontColor(index === 3 ? this.theme.onPrimary : this.theme.primary).backgroundColor(index === 3 ? this.theme.primary : this.theme.field)
            .margin({ left: 8, bottom: 4 }).enabled(!this.busy && (index === 2 || this.ready))
            .onClick(() => { if (index === 2) this.controller?.close(); else this.action(index === 3 ? 2 : index); });
        });
      }.width('100%');
    }.padding(20).width('94%').constraintSize({ maxWidth: 1000 }).height('90%').borderRadius(this.theme.radius(10)).backgroundColor(this.theme.surface);
  }
}
