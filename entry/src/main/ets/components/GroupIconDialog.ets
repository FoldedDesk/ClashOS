import { VergePalette } from '../theme/VergeTheme';
import { ProxyGroupIcon } from './ProxyGroupIcon';
import { GROUP_ICON_PRESETS, GROUP_ICON_LABELS, groupIconSource, iconImageUrl } from '../service/GroupIconTypes';

const ICON_MODES: string[] = ['跟随配置', '内置图标', '图片链接', '本地图片'];
@CustomDialog
export struct GroupIconDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  groupName: string = '';
  initialSource: string = '';
  configured: string = '';
  storageError: string = '';
  fallback: Resource = $r('app.media.verge_selector');
  emoji: string = '';
  resolve: (source: string) => string = (source: string): string => source;
  onPick: () => Promise<string | undefined> = async (): Promise<string | undefined> => undefined;
  onSave: (source: string) => void = (_source: string): void => {};
  onClose: () => void = (): void => {};
  @State mode: number = 0;
  @State preset: string = 'selector';
  @State url: string = '';
  @State local: string = '';
  @State previewUrl: string = '';
  @State previewRevision: number = 0;
  @State previewFailed: boolean = false;
  @State busy: boolean = false;
  @State error: string = '';

  aboutToAppear(): void {
    if (this.initialSource.startsWith('builtin:')) { this.mode = 1; this.preset = this.initialSource.slice(8); }
    else if (iconImageUrl(this.initialSource)) { this.mode = 2; this.url = this.initialSource; this.previewUrl = this.url; }
    else if (this.initialSource.startsWith('local:')) { this.mode = 3; this.local = this.initialSource; }
  }
  aboutToDisappear(): void { this.onClose(); }
  private preview(): string {
    return this.mode === 0 ? iconImageUrl(this.configured) : this.mode === 1 ? `builtin:${this.preset}` :
      this.mode === 2 ? this.previewUrl : this.local ? this.resolve(this.local) : '';
  }
  private async pick(): Promise<void> {
    if (this.busy) return; this.busy = true; this.error = '';
    try {
      const selected: string | undefined = await this.onPick();
      if (selected) { this.local = selected; this.mode = 3; ++this.previewRevision; }
    } catch (error) { this.error = (error as Error).message || '图片未能导入'; }
    finally { this.busy = false; }
  }
  private save(reset: boolean = false): void {
    try {
      const source: string = reset || this.mode === 0 ? '' : this.mode === 1 ? `builtin:${this.preset}` : this.mode === 2 ? this.url.trim() : this.local;
      if (!reset && this.mode === 3 && !source) throw new Error('请先选择一张本地图片');
      if (!reset && this.mode === 2 && !source) throw new Error('请填写图片链接');
      this.onSave(groupIconSource(source)); this.controller?.close();
    } catch (error) { this.error = (error as Error).message || '图标未能保存'; }
  }
  build() {
    Column({ space: 16 }) {
      Text('自定义代理组图标').fontSize(20).fontWeight(FontWeight.Bold).fontColor(this.theme.text).width('100%');
      Text(this.groupName).fontSize(14).fontColor(this.theme.textSecondary).maxLines(2).width('100%');
      Text('按代理组名称保存到本机，同名代理组共用设置。跟随配置时优先显示 icon 链接，其次使用名称 Emoji 或类型图标。')
        .fontSize(12).fontColor(this.theme.textMuted).width('100%');
      if (this.storageError) Text(this.storageError).fontSize(12).fontColor(this.theme.danger).width('100%');
      Row({ space: 20 }) {
        ProxyGroupIcon({ source: this.preview(), revision: this.previewRevision, iconSize: 56, fallback: this.fallback, emoji: this.emoji,
          onFailure: (failed: boolean): void => { this.previewFailed = failed; } });
        Column({ space: 6 }) {
          Text('图标来源').fontSize(12).fontColor(this.theme.textSecondary).width('100%');
          Select(ICON_MODES.map((value: string): SelectOption => ({ value }))).value(ICON_MODES[this.mode]).selected(this.mode)
            .height(38).width('100%').font({ size: 13 }).enabled(!this.busy)
            .onSelect((index: number) => { this.mode = index; this.error = ''; ++this.previewRevision; });
        }.layoutWeight(1);
      }.width('100%');
      if (this.mode === 1) {
        GridRow({ columns: 4, gutter: 8 }) {
          ForEach(GROUP_ICON_PRESETS, (id: string, index: number) => {
            GridCol() {
              Button({ type: ButtonType.Normal }) {
                Column({ space: 7 }) {
                  ProxyGroupIcon({ source: `builtin:${id}`, iconSize: 26 });
                  Text(GROUP_ICON_LABELS[index]).fontSize(11).fontColor(this.theme.textSecondary);
                }.padding(10).width('100%');
              }.width('100%').borderRadius(6).backgroundColor(this.preset === id ? this.theme.primarySoft : this.theme.field)
                .border({ width: 1, color: this.preset === id ? this.theme.primaryBorder : Color.Transparent })
                .accessibilityText(`使用${GROUP_ICON_LABELS[index]}图标`).enabled(!this.busy).onClick(() => this.preset = id);
            }
          }, (id: string) => id);
        }.width('100%');
      } else if (this.mode === 2) {
        Row({ space: 8 }) {
          TextInput({ text: this.url, placeholder: 'https://…/icon.png 或 icon.svg' }).fontSize(13).height(38)
            .fontColor(this.theme.text).placeholderColor(this.theme.textMuted).backgroundColor(this.theme.field).layoutWeight(1)
            .enabled(!this.busy).onChange((value: string) => { this.url = value; this.error = ''; });
          Button('预览链接', { type: ButtonType.Normal }).height(36).fontSize(12).borderRadius(5).fontColor(this.theme.primary)
            .backgroundColor(this.theme.primarySoft).enabled(!this.busy).onClick(() => {
              if (!iconImageUrl(this.url.trim())) this.error = '请填写有效的 HTTP / HTTPS 图片链接';
              else { this.previewUrl = this.url.trim(); this.error = ''; ++this.previewRevision; }
            });
        }.width('100%');
      } else if (this.mode === 3) {
        Row() {
          Text(this.local ? '已选择图片，保存后将保留本机副本' : '支持 PNG、JPEG、WebP、GIF、BMP，最大 2 MB')
            .fontSize(12).fontColor(this.theme.textMuted).layoutWeight(1);
          Button(this.busy ? '导入中…' : '选择图片', { type: ButtonType.Normal }).height(36).fontSize(12).borderRadius(5)
            .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(!this.busy).onClick(() => this.pick());
        }.width('100%');
      }
      if (this.previewFailed) Text('图片暂时无法加载，将显示默认图标；可重新预览或稍后重试。').fontSize(12).fontColor(this.theme.warning).width('100%');
      if (this.error) Text(this.error).fontSize(12).fontColor(this.theme.danger).maxLines(3).width('100%');
      Flex({ wrap: FlexWrap.Wrap, justifyContent: FlexAlign.End }) {
        Button('恢复配置图标', { type: ButtonType.Normal }).height(36).fontSize(12).borderRadius(5).margin({ right: 8, bottom: 8 })
          .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(!this.busy).onClick(() => this.save(true));
        Button('取消', { type: ButtonType.Normal }).height(36).fontSize(12).borderRadius(5).margin({ right: 8, bottom: 8 })
          .fontColor(this.theme.textSecondary).backgroundColor(this.theme.field).enabled(!this.busy).onClick(() => this.controller?.close());
        Button('保存图标', { type: ButtonType.Normal }).height(36).fontSize(12).borderRadius(5).margin({ bottom: 8 })
          .fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).enabled(!this.busy).onClick(() => this.save());
      }.width('100%');
    }.padding(24).width('92%').constraintSize({ maxWidth: 680 }).borderRadius(10).backgroundColor(this.theme.surface);
  }
}
