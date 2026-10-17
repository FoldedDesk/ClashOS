import { dialogActivity } from '../service/DialogActivity';
import { VergePalette } from '../theme/VergeTheme';
import { ConfigCodeEditor } from './ConfigCodeEditor';
import { ConfigEditorController } from '../service/ConfigEditorController';

const COMMON_SNIFFER: string = `{
  "sniffer": {
    "enable": true,
    "parse-pure-ip": true,
    "force-dns-mapping": true,
    "override-destination": true,
    "sniff": {
      "HTTP": { "ports": [80, "8080-8880"] },
      "TLS": { "ports": [443, 8443] },
      "QUIC": { "ports": [443, 8443] }
    },
    "force-domain": [],
    "skip-domain": [],
    "skip-src-address": [],
    "skip-dst-address": []
  }
}`;

@CustomDialog
export struct SnifferSettingsDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  private dialogActivityId: number = 0;
  initialContent: string = '';
  onValidate: (text: string) => void = (_text: string): void => {};
  onSave: (text: string) => Promise<void> = async (_text: string): Promise<void> => {};
  onCopy: (text: string) => void = (_text: string): void => {};
  private editor: ConfigEditorController = new ConfigEditorController();
  @State ready: boolean = false;
  @State busy: boolean = false;
  @State error: string = '';
  @State message: string = '';

  private async action(kind: number): Promise<void> {
    if (!this.ready || this.busy) return;
    this.busy = true; this.error = ''; this.message = '';
    try {
      const text: string = await this.editor.text(); this.onValidate(text);
      if (kind === 0) this.message = '嗅探配置校验通过';
      else if (kind === 1) { this.onCopy(text); this.message = '已复制，可将 sniffer 字段合并至全局或订阅扩展'; }
      else { await this.onSave(text); this.controller?.close(); }
    } catch (error) { this.error = (error as Error).message || '嗅探设置未能应用'; this.editor.markError(this.error).catch(() => {}); }
    finally { this.busy = false; }
  }

  aboutToAppear(): void { this.dialogActivityId = dialogActivity.enter(); }

  aboutToDisappear(): void { dialogActivity.leave(this.dialogActivityId); }

  build() {
    Column({ space: 14 }) {
      Text('域名嗅探配置').fontSize(this.theme.font(20)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text).width('100%');
      Text('修改立即作用于当前内核；重载或重启后恢复配置中的设置。需要长期保留时，将 sniffer 字段写入全局或订阅扩展。')
        .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
      Text('HTTP / TLS / QUIC 可分别设置端口和 override-destination。关闭目标改写时，仍按识别的域名匹配规则，连接原来的地址。')
        .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
      ConfigCodeEditor({ editor: this.editor, initialContent: this.initialContent, label: 'JSON 嗅探配置编辑区', disabled: this.busy,
        onReady: (ready: boolean): void => { this.ready = ready; },
        onChange: (revision: number): void => { if (this.editor.changedSinceRead(revision)) { this.error = ''; this.message = ''; } } });
      if (this.error) Text(this.error).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger).maxLines(3).width('100%');
      if (this.message) Text(this.message).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.success).width('100%');
      Flex({ wrap: FlexWrap.Wrap, justifyContent: FlexAlign.End }) {
        Button('常用配置', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).margin({ right: 8, bottom: 8 })
          .fontColor(this.theme.primary).backgroundColor(Color.Transparent).enabled(this.ready && !this.busy)
          .onClick(() => { this.editor.replace(COMMON_SNIFFER).catch(() => this.error = '未能填入常用配置'); });
        Button('校验', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).margin({ right: 8, bottom: 8 })
          .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(this.ready && !this.busy).onClick(() => this.action(0));
        Button('复制扩展配置', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).margin({ right: 8, bottom: 8 })
          .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(this.ready && !this.busy).onClick(() => this.action(1));
        Button('取消', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).margin({ right: 8, bottom: 8 })
          .fontColor(this.theme.textSecondary).backgroundColor(this.theme.field).enabled(!this.busy).onClick(() => this.controller?.close());
        Button(this.busy ? '应用中…' : '应用嗅探设置', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).margin({ bottom: 8 })
          .fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).enabled(this.ready && !this.busy).onClick(() => this.action(2));
      }.width('100%');
    }.width('94%').constraintSize({ maxWidth: 960 }).height('86%').padding(24).borderRadius(this.theme.radius(10)).backgroundColor(this.theme.surface);
  }
}
