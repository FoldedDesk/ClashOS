import { VergePalette } from '../theme/VergeTheme';
import { ClashProxyPorts } from '../service/ClashApi';

@CustomDialog
export struct ProxyPortsDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  initial: ClashProxyPorts = { http: 7890, socks: 7891, mixed: 0, overridden: false };
  onSave: (ports?: ClashProxyPorts) => Promise<void> = async (_ports?: ClashProxyPorts): Promise<void> => {};
  @State httpText: string = '';
  @State socksText: string = '';
  @State mixedText: string = '';
  @State mixedMode: boolean = false;
  @State saving: boolean = false;
  @State error: string = '';

  aboutToAppear(): void {
    this.httpText = `${this.initial.http}`;
    this.socksText = `${this.initial.socks}`;
    this.mixedText = `${this.initial.mixed || 7890}`;
    this.mixedMode = this.initial.mixed > 0;
  }

  private port(text: string): number {
    if (!/^\d{1,5}$/.test(text.trim()) || Number(text) > 65535) throw new Error('端口必须为 0 至 65535 的整数，0 表示关闭');
    return Number(text);
  }

  private async save(reset: boolean = false): Promise<void> {
    if (this.saving) return;
    this.error = '';
    try {
      const ports: ClashProxyPorts | undefined = reset ? undefined : {
        http: this.mixedMode ? this.initial.http : this.port(this.httpText),
        socks: this.mixedMode ? this.initial.socks : this.port(this.socksText),
        mixed: this.mixedMode ? this.port(this.mixedText) : 0, overridden: true
      };
      if (this.mixedMode && !reset && ports?.mixed === 0) throw new Error('混合模式的端口应为 1 至 65535');
      this.saving = true;
      await this.onSave(ports);
      this.controller?.close();
    } catch (error) {
      this.error = (error as Error).message || '端口未能保存，原设置已保留';
    } finally { this.saving = false; }
  }

  build() {
    Column({ space: 16 }) {
      Text('自定义代理端口').fontSize(20).fontWeight(FontWeight.Bold).fontColor(this.theme.text).width('100%');
      Text('应用于所有配置，订阅更新后仍保留。监听地址可在局域网共享设置中修改。')
        .fontSize(12).fontColor(this.theme.textSecondary).width('100%');
      Row() {
        Text('混合端口模式').fontSize(14).fontColor(this.theme.text).layoutWeight(1);
        Toggle({ type: ToggleType.Switch, isOn: this.mixedMode }).selectedColor(this.theme.primary)
          .width(38).height(24).enabled(!this.saving).onChange((value: boolean) => this.mixedMode = value);
      }.width('100%');
      if (this.mixedMode) {
        Row({ space: 18 }) {
          Text('混合端口').fontSize(13).fontColor(this.theme.textSecondary).width(100);
          TextInput({ text: this.mixedText, placeholder: '1 至 65535' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).type(InputType.Number)
            .accessibilityText('混合端口').height(40).fontSize(14).layoutWeight(1).borderRadius(5)
            .backgroundColor(this.theme.field).enabled(!this.saving).onChange((value: string) => this.mixedText = value);
        }.width('100%');
        Text('HTTP 与 SOCKS5 共用此端口。').fontSize(11).fontColor(this.theme.textMuted).width('100%');
      } else {
        Row({ space: 18 }) {
          Text('HTTP 端口').fontSize(13).fontColor(this.theme.textSecondary).width(100);
          TextInput({ text: this.httpText, placeholder: '0 为关闭' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).type(InputType.Number)
            .accessibilityText('HTTP 端口').height(40).fontSize(14).layoutWeight(1).borderRadius(5)
            .backgroundColor(this.theme.field).enabled(!this.saving).onChange((value: string) => this.httpText = value);
        }.width('100%');
        Row({ space: 18 }) {
          Text('SOCKS5 端口').fontSize(13).fontColor(this.theme.textSecondary).width(100);
          TextInput({ text: this.socksText, placeholder: '0 为关闭' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).type(InputType.Number)
            .accessibilityText('SOCKS5 端口').height(40).fontSize(14).layoutWeight(1).borderRadius(5)
            .backgroundColor(this.theme.field).enabled(!this.saving).onChange((value: string) => this.socksText = value);
        }.width('100%');
        Text('两项均设为 0 时关闭代理入口。').fontSize(11).fontColor(this.theme.textMuted).width('100%');
      }
      Text('修改后请同步更新系统网络代理中的端口。控制器地址不受影响。')
        .fontSize(12).fontColor(this.theme.textSecondary).width('100%');
      if (this.error.length > 0) Text(this.error).fontSize(12).fontColor(this.theme.danger).width('100%');
      Row({ space: 10 }) {
        Button('恢复配置端口', { type: ButtonType.Normal }).height(36).fontSize(12)
          .fontColor(this.theme.primary).backgroundColor(Color.Transparent).enabled(!this.saving)
          .onClick(() => this.save(true));
        Blank();
        Button('取消', { type: ButtonType.Normal }).height(36).fontSize(13).borderRadius(5)
          .fontColor(this.theme.textSecondary).backgroundColor(this.theme.field).enabled(!this.saving)
          .onClick(() => this.controller?.close());
        Button(this.saving ? '保存中…' : '保存并应用', { type: ButtonType.Normal }).height(36).fontSize(13)
          .fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).borderRadius(5).enabled(!this.saving)
          .onClick(() => this.save());
      }.width('100%');
    }.width('88%').constraintSize({ maxWidth: 580 }).padding(24).borderRadius(10).backgroundColor(this.theme.surface);
  }
}
