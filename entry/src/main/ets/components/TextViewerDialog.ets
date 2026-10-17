import { VergePalette } from '../theme/VergeTheme';
@CustomDialog
export struct TextViewerDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  title: string = '';
  content: string = '';

  build() {
    Column({ space: 20 }) {
      Text(this.title).fontSize(19).fontWeight(FontWeight.Bold).fontColor(this.theme.text).width('100%');
      Scroll() {
        Text(this.content).fontSize(12).fontColor(this.theme.textSecondary).fontFamily('monospace')
          .copyOption(CopyOptions.LocalDevice).width('100%');
      }.width('100%').layoutWeight(1).scrollBar(BarState.Auto);
      Row() {
        Blank();
        Button('关闭', { type: ButtonType.Normal }).height(34).fontSize(13).fontColor(this.theme.onPrimary)
          .borderRadius(5).backgroundColor(this.theme.primary).onClick(() => this.controller?.close());
      }.width('100%');
    }.width('85%').height('78%').constraintSize({ maxWidth: 820 })
      .padding(24).borderRadius(10).backgroundColor(this.theme.surface);
  }
}
