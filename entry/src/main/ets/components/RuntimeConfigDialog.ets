import { VergePalette } from '../theme/VergeTheme';
import { ClashRuntimeConfig } from '../service/ClashApi';

@CustomDialog
export struct RuntimeConfigDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  initial: ClashRuntimeConfig = { mode: 'Rule', logLevel: 'info', ipv6: false, path: '', temporary: false, revision: 0 };
  onSave: (value: ClashRuntimeConfig) => Promise<void> = async (_value: ClashRuntimeConfig): Promise<void> => {};
  onReload: () => Promise<void> = async (): Promise<void> => {};
  @State mode: string = 'Rule';
  @State logLevel: string = 'info';
  @State ipv6: boolean = false;
  @State busy: boolean = false;
  @State error: string = '';

  aboutToAppear(): void {
    this.mode = this.initial.mode; this.logLevel = this.initial.logLevel; this.ipv6 = this.initial.ipv6;
  }

  private async apply(reload: boolean): Promise<void> {
    if (this.busy) return;
    this.busy = true; this.error = '';
    try {
      if (reload) await this.onReload();
      else await this.onSave({ mode: this.mode, logLevel: this.logLevel, ipv6: this.ipv6,
        path: this.initial.path, temporary: this.initial.temporary, revision: this.initial.revision });
      this.controller?.close();
    } catch (error) { this.error = (error as Error).message || '设置未能应用'; }
    finally { this.busy = false; }
  }

  build() {
    Column({ space: 18 }) {
      Text('内核运行设置').fontSize(20).fontWeight(FontWeight.Bold).fontColor(this.theme.text).width('100%');
      Text(this.initial.temporary ? (this.initial.origin ? '当前运行的是控制器加载的临时配置。重新加载将返回上一次保存的配置。' : '当前运行的是控制器加载的临时配置。可从订阅页选择或新建保存的配置。') :
        '修改立即生效，重新加载或重启后恢复配置中的设置。需要长期保留时，请编辑配置文件或全局扩展配置。')
        .fontSize(12).fontColor(this.theme.textSecondary).width('100%');
      Row({ space: 18 }) {
        Text('代理模式').fontSize(14).fontColor(this.theme.text).layoutWeight(1);
        Select([{ value: '规则模式' }, { value: '全局模式' }, { value: '直连模式' }])
          .selected(['Rule', 'Global', 'Direct'].indexOf(this.mode)).value(this.mode === 'Global' ? '全局模式' : this.mode === 'Direct' ? '直连模式' : '规则模式')
          .font({ size: 13 }).fontColor(this.theme.text).backgroundColor(this.theme.field).borderRadius(5)
          .enabled(!this.busy).accessibilityText('运行代理模式')
          .onSelect((index: number) => this.mode = ['Rule', 'Global', 'Direct'][index]);
      }.width('100%');
      Row({ space: 18 }) {
        Text('日志级别').fontSize(14).fontColor(this.theme.text).layoutWeight(1);
        Select([{ value: 'debug' }, { value: 'info' }, { value: 'warning' }, { value: 'error' }, { value: 'silent' }])
          .selected(['debug', 'info', 'warning', 'error', 'silent'].indexOf(this.logLevel)).value(this.logLevel)
          .font({ size: 13 }).fontColor(this.theme.text).backgroundColor(this.theme.field).borderRadius(5)
          .enabled(!this.busy).accessibilityText('内核日志级别')
          .onSelect((index: number) => this.logLevel = ['debug', 'info', 'warning', 'error', 'silent'][index]);
      }.width('100%');
      Row({ space: 18 }) {
        Column({ space: 5 }) {
          Text('IPv6 解析').fontSize(14).fontColor(this.theme.text);
          Text('允许内核查询 IPv6 地址；DNS 配置也需允许 IPv6。')
            .fontSize(11).fontColor(this.theme.textMuted);
        }.alignItems(HorizontalAlign.Start).layoutWeight(1);
        Toggle({ type: ToggleType.Switch, isOn: this.ipv6 }).width(38).height(24).selectedColor(this.theme.primary)
          .enabled(!this.busy).accessibilityText('允许内核 IPv6 解析').onChange((value: boolean) => this.ipv6 = value);
      }.width('100%');
      if (this.error) Text(this.error).fontSize(12).fontColor(this.theme.danger).width('100%');
      Flex({ wrap: FlexWrap.Wrap, justifyContent: FlexAlign.End }) {
        Button('重新加载配置', { type: ButtonType.Normal }).fontSize(12).height(36).borderRadius(5).margin({ right: 8, bottom: 8 })
          .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(!this.busy && (this.initial.temporary ? (this.initial.origin ?? '').length > 0 : this.initial.path.length > 0))
          .onClick(() => this.apply(true));
        Button('取消', { type: ButtonType.Normal }).fontSize(13).height(36).borderRadius(5).margin({ right: 8, bottom: 8 })
          .fontColor(this.theme.textSecondary).backgroundColor(this.theme.field).enabled(!this.busy).onClick(() => this.controller?.close());
        Button(this.busy ? '应用中…' : '应用运行设置', { type: ButtonType.Normal }).fontSize(13).height(36).borderRadius(5).margin({ bottom: 8 })
          .fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).enabled(!this.busy).onClick(() => this.apply(false));
      }.width('100%');
    }.width('88%').constraintSize({ maxWidth: 580 }).padding(24).borderRadius(10).backgroundColor(this.theme.surface);
  }
}
