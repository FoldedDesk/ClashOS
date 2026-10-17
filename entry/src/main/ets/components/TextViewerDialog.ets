import { dialogActivity } from '../service/DialogActivity';
import { VergePalette } from '../theme/VergeTheme';
@CustomDialog
export struct TextViewerDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  private dialogActivityId: number = 0;
  title: string = '';
  content: string = '';

  aboutToAppear(): void { this.dialogActivityId = dialogActivity.enter(); }

  aboutToDisappear(): void { dialogActivity.leave(this.dialogActivityId); }

  build() {
    Column({ space: 20 }) {
      Text(this.title).fontSize(this.theme.font(19)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text).width('100%');
      Scroll() {
        Text(this.content).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).fontFamily('monospace')
          .copyOption(CopyOptions.LocalDevice).width('100%');
      }.width('100%').layoutWeight(1).scrollBar(BarState.Auto);
      Row() {
        Blank();
        Button('关闭', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.onPrimary)
          .borderRadius(this.theme.radius(5)).backgroundColor(this.theme.primary).onClick(() => this.controller?.close());
      }.width('100%');
    }.width('85%').height('78%').constraintSize({ maxWidth: 820 })
      .padding(24).borderRadius(this.theme.radius(10)).backgroundColor(this.theme.surface);
  }
}
