import { util } from '@kit.ArkTS';
import { VergePalette } from '../theme/VergeTheme';
import { ControllerAccessSnapshot, validateControllerSecret } from '../service/ControllerAccessStore';

@CustomDialog
export struct ControllerAccessDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  initial: ControllerAccessSnapshot = { secret: '', error: '' };
  onSave: (secret: string) => Promise<void> = async (_secret: string): Promise<void> => {};
  onCopy: (secret: string) => void = (_secret: string): void => {};
  @State draft: string = '';
  @State error: string = '';
  @State saving: boolean = false;
  aboutToAppear(): void { this.draft = this.initial.secret; this.error = this.initial.error; }
  private async save(): Promise<void> {
    if (this.saving) return;
    try {
      validateControllerSecret(this.draft); this.saving = true; this.error = '';
      await this.onSave(this.draft); this.controller?.close();
    } catch (error) { this.error = (error as Error).message || '控制器认证未能保存'; }
    finally { this.saving = false; }
  }
  build() {
    Column({ space: 16 }) {
      Text('内置控制器认证').fontSize(this.theme.font(20)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text).width('100%');
      Text('外部控制端需使用相同密钥。切换订阅后保留，密钥不会进入配置备份。')
        .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
      TextInput({ text: this.draft, placeholder: '留空可关闭认证' }).type(InputType.Password).maxLength(256)
        .accessibilityText('内置控制器密钥').fontColor(this.theme.text).placeholderColor(this.theme.textMuted)
        .height(42).fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).backgroundColor(this.theme.field).borderRadius(this.theme.radius(5)).enabled(!this.saving)
        .onChange((value: string) => { this.draft = value; this.error = ''; });
      Row({ space: 10 }) {
        Button('生成密钥', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(!this.saving)
          .onClick(() => { this.draft = util.generateRandomUUID().replace(/-/g, ''); this.error = ''; });
        Button('复制密钥', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(!this.saving && this.draft.length > 0)
          .onClick(() => this.onCopy(this.draft));
        Blank();
        Button('清空', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.textSecondary).backgroundColor(this.theme.field).enabled(!this.saving)
          .onClick(() => { this.draft = ''; this.error = ''; });
      }.width('100%');
      Text('修改后旧的实时订阅会断开。已有代理连接可继续使用。密钥最多 256 个 ASCII 字符，不含空格。')
        .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
      if (this.error) Text(this.error).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger).width('100%');
      Row({ space: 10 }) {
        Blank();
        Button('取消', { type: ButtonType.Normal }).height(36).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.textSecondary).backgroundColor(this.theme.field).enabled(!this.saving)
          .onClick(() => this.controller?.close());
        Button('保存并应用', { type: ButtonType.Normal }).height(36).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).enabled(!this.saving).onClick(() => this.save());
      }.width('100%');
    }.width('88%').constraintSize({ maxWidth: 580 }).padding(24).borderRadius(this.theme.radius(10)).backgroundColor(this.theme.surface);
  }
}
