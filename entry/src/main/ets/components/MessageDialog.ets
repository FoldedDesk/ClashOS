import { VergePalette } from '../theme/VergeTheme';
import { dialogActivity } from '../service/DialogActivity';

export interface MessageDialogButton {
  value: string;
  fontColor?: ResourceColor;
  action: () => void;
}

export interface MessageDialogOptions {
  title: string;
  message: string;
  primaryButton: MessageDialogButton;
  secondaryButton: MessageDialogButton;
  onDismiss?: () => void;
}

@CustomDialog
export struct MessageDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  options: MessageDialogOptions = { title: '', message: '', primaryButton: { value: '关闭', action: (): void => {} }, secondaryButton: { value: '确定', action: (): void => {} } };
  private dialogActivityId: number = 0;

  aboutToAppear(): void { this.dialogActivityId = dialogActivity.enter(); }
  aboutToDisappear(): void { this.options.onDismiss?.(); dialogActivity.leave(this.dialogActivityId); }

  private choose(button: MessageDialogButton): void {
    this.controller?.close();
    button.action();
  }

  build() {
    Column({ space: 20 }) {
      Text(this.options.title).fontSize(this.theme.font(19)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text).width('100%');
      Scroll() {
        Text(this.options.message).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
      }.constraintSize({ maxHeight: 440 }).width('100%');
      Row({ space: 12 }) {
        Blank();
        Button(this.options.primaryButton.value, { type: ButtonType.Normal }).height(36).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily)
          .fontColor(this.options.primaryButton.fontColor ?? this.theme.textSecondary).backgroundColor(this.theme.field).borderRadius(this.theme.radius(5))
          .onClick(() => this.choose(this.options.primaryButton));
        Button(this.options.secondaryButton.value, { type: ButtonType.Normal }).height(36).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily)
          .fontColor(this.options.secondaryButton.fontColor ?? this.theme.primary).backgroundColor(this.theme.primarySoft).borderRadius(this.theme.radius(5))
          .onClick(() => this.choose(this.options.secondaryButton));
      }.width('100%');
    }.width('86%').constraintSize({ maxWidth: 600 }).padding(24).borderRadius(this.theme.radius(10)).backgroundColor(this.theme.surface);
  }
}
